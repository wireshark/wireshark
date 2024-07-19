/* packet-thread.c
 * Routines for Thread over CoAP and beacon packet dissection
 *
 * Robert Cragie <robert.cragie@arm.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdlib.h>
#include <math.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/wmem_scopes.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include "packet-coap.h"
#include "packet-ieee802154.h"
#include "packet-mle.h"

/* Use libgcrypt for cipher libraries. */
#include <wsutil/wsgcrypt.h>

/* Thread Vendor Sub IE Fields */
#define THREAD_IE_ID_MASK                      0xFFC0
#define THREAD_IE_LENGTH_MASK                  0x003F

/* Forward declarations */
void proto_register_thread_coap(void);

void proto_register_thread_address(void);
void proto_reg_handoff_thread_address(void);

void proto_register_thread_dg(void);
void proto_reg_handoff_thread_dg(void);

void proto_register_thread_mc(void);
void proto_reg_handoff_thread_mc(void);

void proto_register_thread_nwd(void);

void proto_register_thread_bcn(void);
void proto_reg_handoff_thread_bcn(void);

void proto_register_thread(void);
void proto_reg_handoff_thread(void);

void proto_register_thread_nm(void);
void proto_reg_handoff_thread_nm(void);

void proto_register_thread_bl(void);
void proto_reg_handoff_thread_bl(void);

static int proto_thread_address;
static int proto_thread_dg;
static int proto_thread_mc;
static int proto_thread_nwd;
static int proto_thread_coap;
static int proto_thread_bcn;
static int proto_thread_nm;
static int proto_thread_bl;
static int proto_thread;
static int proto_thread_ie;
static int proto_coap;

/* Header fields */

/* Thread address */

static int hf_thread_address_tlv;
static int hf_thread_address_tlv_type;
static int hf_thread_address_tlv_length;
static int hf_thread_address_tlv_unknown;
/* static int hf_thread_address_tlv_sub_tlvs; */

/* Target EID TLV fields */
static int hf_thread_address_tlv_target_eid;

/* Ext. MAC address TLV fields */
static int hf_thread_address_tlv_ext_mac_addr;

/* RLOC16 TLV fields */
static int hf_thread_address_tlv_rloc16;

/* Mesh Local IID TLV fields */
static int hf_thread_address_tlv_ml_eid;

/* Status TLV fields */
static int hf_thread_address_tlv_status;

/* Attached time TLV fields */
/* static int hf_thread_address_tlv_attached_time; */

/* Last transaction time TLV fields */
static int hf_thread_address_tlv_last_transaction_time;

/* Router Mask TLV fields */
static int hf_thread_address_tlv_router_mask_id_seq;
static int hf_thread_address_tlv_router_mask_assigned;

/* ND option fields */
static int hf_thread_address_tlv_nd_option;

/* ND data fields */
static int hf_thread_address_tlv_nd_data;
static int hf_thread_address_tlv_timeout;

/* Thread diagnostics */

static int hf_thread_dg_tlv;
static int hf_thread_dg_tlv_type;
static int hf_thread_dg_tlv_length8;
static int hf_thread_dg_tlv_length16;
static int hf_thread_dg_tlv_general;
static int hf_thread_dg_tlv_unknown;

#if 0
/**** TBC: will be added later. For now, just use general string ****/
static int hf_thread_dg_tlv_source_addr;
static int hf_thread_dg_tlv_mode_device_type;
static int hf_thread_dg_tlv_mode_idle_rx;
static int hf_thread_dg_tlv_mode_sec_data_req;
static int hf_thread_dg_tlv_mode_nwk_data;
static int hf_thread_dg_tlv_timeout;
static int hf_thread_dg_tlv_lqi_c;
static int hf_thread_dg_tlv_lqi_size;
static int hf_thread_dg_tlv_neighbor;
static int hf_thread_dg_tlv_neighbor_flagI;
static int hf_thread_dg_tlv_neighbor_flagO;
static int hf_thread_dg_tlv_neighbor_flagP;
static int hf_thread_dg_tlv_neighbor_idr;
static int hf_thread_dg_tlv_neighbor_addr;
static int hf_thread_dg_tlv_network_param_id;
static int hf_thread_dg_tlv_network_delay;
static int hf_thread_dg_tlv_network_channel;
static int hf_thread_dg_tlv_network_pan_id;
static int hf_thread_dg_tlv_network_pmt_join;
static int hf_thread_dg_tlv_network_bcn_payload;
static int hf_thread_dg_tlv_network_unknown;
static int hf_thread_dg_tlv_mle_frm_cntr;
static int hf_thread_dg_tlv_route_tbl_id_seq;
static int hf_thread_dg_tlv_route_tbl_id_mask;
static int hf_thread_dg_tlv_route_tbl_entry;
static int hf_thread_dg_tlv_route_tbl_nbr_out;
static int hf_thread_dg_tlv_route_tbl_nbr_in;
static int hf_thread_dg_tlv_route_tbl_cost;
static int hf_thread_dg_tlv_route_tbl_unknown;
static int hf_thread_dg_tlv_addr_16;
static int hf_thread_dg_tlv_leader_data_partition_id;
static int hf_thread_dg_tlv_leader_data_weighting;
static int hf_thread_dg_tlv_leader_data_version;
static int hf_thread_dg_tlv_leader_data_stable_version;
static int hf_thread_dg_tlv_leader_data_router_id;
static int hf_thread_dg_tlv_network_data;
static int hf_thread_dg_tlv_scan_mask_r;
static int hf_thread_dg_tlv_scan_mask_e;
static int hf_thread_dg_tlv_conn_max_child_cnt;
static int hf_thread_dg_tlv_conn_child_cnt;
static int hf_thread_dg_tlv_conn_lq3;
static int hf_thread_dg_tlv_conn_lq2;
static int hf_thread_dg_tlv_conn_lq1;
static int hf_thread_dg_tlv_conn_leader_cost;
static int hf_thread_dg_tlv_conn_id_seq;
static int hf_thread_dg_tlv_link_margin;
static int hf_thread_dg_tlv_status;
static int hf_thread_dg_tlv_version;
static int hf_thread_dg_tlv_addr_reg_entry;
static int hf_thread_dg_tlv_addr_reg_iid_type;
static int hf_thread_dg_tlv_addr_reg_cid;
static int hf_thread_dg_tlv_addr_reg_iid;
static int hf_thread_dg_tlv_addr_reg_ipv6;
static int hf_thread_dg_tlv_hold_time;
#endif

/* Thread MeshCoP */

static int hf_thread_mc_tlv;
static int hf_thread_mc_tlv_type;
static int hf_thread_mc_tlv_length8;
static int hf_thread_mc_tlv_length16;
static int hf_thread_mc_tlv_unknown;
/* static int hf_thread_mc_tlv_sub_tlvs; */

/* Channel TLV fields */
static int hf_thread_mc_tlv_channel_page;
static int hf_thread_mc_tlv_channel;

/* PAN ID TLV fields */
static int hf_thread_mc_tlv_pan_id;

/* Extended PAN ID TLV fields */
static int hf_thread_mc_tlv_xpan_id;

/* Network Name TLV fields */
static int hf_thread_mc_tlv_net_name;

/* PSKc TLV fields */
static int hf_thread_mc_tlv_pskc;

/* Master Key TLV fields */
static int hf_thread_mc_tlv_master_key;

/* Network Key Sequence TLV fields */
static int hf_thread_mc_tlv_net_key_seq_ctr;

/* Mesh Local ULA TLV fields */
static int hf_thread_mc_tlv_ml_prefix;

/* Steering Data TLV fields */
static int hf_thread_mc_tlv_steering_data;

/* Border Agent Locator TLV fields */
static int hf_thread_mc_tlv_ba_locator;

/* Commissioner ID TLV fields */
static int hf_thread_mc_tlv_commissioner_id;

/* Commissioner ID TLV fields */
static int hf_thread_mc_tlv_commissioner_sess_id;

/* Security Policy TLV fields */
static int hf_thread_mc_tlv_sec_policy_rot;
static int hf_thread_mc_tlv_sec_policy_o;
static int hf_thread_mc_tlv_sec_policy_n;
static int hf_thread_mc_tlv_sec_policy_r;
static int hf_thread_mc_tlv_sec_policy_c;
static int hf_thread_mc_tlv_sec_policy_b;
static int hf_thread_mc_tlv_sec_policy_ccm;
static int hf_thread_mc_tlv_sec_policy_ae;
static int hf_thread_mc_tlv_sec_policy_nmp;
static int hf_thread_mc_tlv_sec_policy_l;
static int hf_thread_mc_tlv_sec_policy_ncr;
static int hf_thread_mc_tlv_sec_policy_rsv;
static int hf_thread_mc_tlv_sec_policy_rsv1;
static int hf_thread_mc_tlv_sec_policy_vr;


/* State TLV fields */
static int hf_thread_mc_tlv_state;

/* Timestamp TLV fields */
static int hf_thread_mc_tlv_active_tstamp;
static int hf_thread_mc_tlv_pending_tstamp;

/* Delay Timer TLV fields */
static int hf_thread_mc_tlv_delay_timer;

/* UDP Encapsulation TLV fields */
static int hf_thread_mc_tlv_udp_encap_src_port;
static int hf_thread_mc_tlv_udp_encap_dst_port;

/* IPv6 Address fields */
static int hf_thread_mc_tlv_ipv6_addr;

/* UDP Port TLV fields */
static int hf_thread_mc_tlv_udp_port;

/* IID TLV fields */
static int hf_thread_mc_tlv_iid;

/* Joiner Router locator TLV fields */
static int hf_thread_mc_tlv_jr_locator;

/* KEK TLV fields */
static int hf_thread_mc_tlv_kek;

/* Provisioning URL TLV fields */
static int hf_thread_mc_tlv_provisioning_url;

/* Vendor TLV fields */
static int hf_thread_mc_tlv_vendor_name;
static int hf_thread_mc_tlv_vendor_model;
static int hf_thread_mc_tlv_vendor_sw_ver;
static int hf_thread_mc_tlv_vendor_data;
static int hf_thread_mc_tlv_vendor_stack_ver_oui;
static int hf_thread_mc_tlv_vendor_stack_ver_build;
static int hf_thread_mc_tlv_vendor_stack_ver_rev;
static int hf_thread_mc_tlv_vendor_stack_ver_min;
static int hf_thread_mc_tlv_vendor_stack_ver_maj;

/* Channel Mask TLV fields */
static int hf_thread_mc_tlv_chan_mask;
static int hf_thread_mc_tlv_chan_mask_page;
static int hf_thread_mc_tlv_chan_mask_len;
static int hf_thread_mc_tlv_chan_mask_mask;

/* Count TLV fields */
static int hf_thread_mc_tlv_count;

/* Period TLV fields */
static int hf_thread_mc_tlv_period;

/* Period TLV fields */
static int hf_thread_mc_tlv_scan_duration;

/* Energy List TLV fields */
static int hf_thread_mc_tlv_energy_list;
static int hf_thread_mc_tlv_el_count;

/* Domain Name TLV fields */
static int hf_thread_mc_tlv_domain_name;

/* AE Steering Data TLV fields */
static int hf_thread_mc_tlv_ae_steering_data;

/* NMKP Steering Data TLV fields */
static int hf_thread_mc_tlv_nmkp_steering_data;

/* Commissioner Signature TLV fields */
static int hf_thread_mc_tlv_commissioner_signature;

/* AE UDP Port TLV fields */
static int hf_thread_mc_tlv_ae_udp_port;

/* NMKP UDP Port TLV fields */
static int hf_thread_mc_tlv_nmkp_udp_port;

/* Registrar IPv6 Address fields */
static int hf_thread_mc_tlv_registrar_ipv6_addr;

/* Registrar Hostname fields */
static int hf_thread_mc_tlv_registrar_hostname;

/* Discovery Request TLV fields */
static int hf_thread_mc_tlv_discovery_req_ver;
static int hf_thread_mc_tlv_discovery_req_j;

/* Discovery Response TLV fields */
static int hf_thread_mc_tlv_discovery_rsp_ver;
static int hf_thread_mc_tlv_discovery_rsp_n;
static int hf_thread_mc_tlv_discovery_rsp_c;

/* Thread Network Data */

static int hf_thread_nwd_tlv;
static int hf_thread_nwd_tlv_type;
static int hf_thread_nwd_tlv_stable;
static int hf_thread_nwd_tlv_length;
static int hf_thread_nwd_tlv_unknown;
static int hf_thread_nwd_tlv_sub_tlvs;

/* Has Route TLV fields */
static int hf_thread_nwd_tlv_has_route;
static int hf_thread_nwd_tlv_has_route_br_16;
static int hf_thread_nwd_tlv_has_route_pref;
static int hf_thread_nwd_tlv_has_route_np;
static int hf_thread_nwd_tlv_has_route_reserved;


/* Prefix TLV fields */
static int hf_thread_nwd_tlv_prefix;
static int hf_thread_nwd_tlv_prefix_domain_id;
static int hf_thread_nwd_tlv_prefix_length;

/* Border Router TLV fields */
static int hf_thread_nwd_tlv_border_router;
static int hf_thread_nwd_tlv_border_router_16;
static int hf_thread_nwd_tlv_border_router_pref;
static int hf_thread_nwd_tlv_border_router_p;
static int hf_thread_nwd_tlv_border_router_s;
static int hf_thread_nwd_tlv_border_router_d;
static int hf_thread_nwd_tlv_border_router_c;
static int hf_thread_nwd_tlv_border_router_r;
static int hf_thread_nwd_tlv_border_router_o;
static int hf_thread_nwd_tlv_border_router_n;
static int hf_thread_nwd_tlv_border_router_dp;

/* 6LoWPAN ID TLV fields */
static int hf_thread_nwd_tlv_6lowpan_id_6co_context_length;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_c;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid;
static int hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved;

/* Commissioning Data fields */
/* static int hf_thread_nwd_tlv_comm_data; */

/* Service fields */
static int hf_thread_nwd_tlv_service_t;
static int hf_thread_nwd_tlv_service_s_id;
static int hf_thread_nwd_tlv_service_s_ent_num;
static int hf_thread_nwd_tlv_service_s_data_len;
static int hf_thread_nwd_tlv_service_s_data;
static int hf_thread_nwd_tlv_service_s_data_seqno;
static int hf_thread_nwd_tlv_service_s_data_rrdelay;
static int hf_thread_nwd_tlv_service_s_data_mlrtimeout;

// Thread 1.3 Service TLV code
static int hf_thread_nwd_tlv_service_srp_dataset_identifier;
static int hf_thread_nwd_tlv_service_anycast_seqno;
static int hf_thread_nwd_tlv_service_unicast_ipv6_address;
static int hf_thread_nwd_tlv_service_unicast_port_number;

/* Server fields */
static int hf_thread_nwd_tlv_server_16;
static int hf_thread_nwd_tlv_server_data;

/* Thread Beacon */

static int hf_thread_bcn_protocol;
static int hf_thread_bcn_joining;
static int hf_thread_bcn_native;
static int hf_thread_bcn_version;
static int hf_thread_bcn_network_id;
static int hf_thread_bcn_epid;
static int hf_thread_bcn_tlv;
static int hf_thread_bcn_tlv_type;
static int hf_thread_bcn_tlv_length;
static int hf_thread_bcn_tlv_steering_data;
static int hf_thread_bcn_tlv_unknown;

/* Tree types */

static int ett_thread_address;
static int ett_thread_address_tlv;
static int ett_thread_dg;
static int ett_thread_dg_tlv;
static int ett_thread_mc;
static int ett_thread_mc_tlv;
static int ett_thread_mc_chan_mask;
static int ett_thread_mc_el_count;
static int ett_thread_nwd;
static int ett_thread_nwd_tlv;
static int ett_thread_nwd_has_route;
static int ett_thread_nwd_6co_flag;
static int ett_thread_nwd_border_router;
static int ett_thread_nwd_prefix_sub_tlvs;
static int ett_thread_bcn;
static int ett_thread_bcn_tlv;
static int ett_thread_nm;
static int ett_thread_nm_tlv;
static int ett_thread_bl;
static int ett_thread_bl_tlv;

static int ett_thread;
/* static int ett_thread_header_ie; */
static int ett_thread_ie_fields;



/* Expert info. */

/* static expert_field ei_thread_address_tlv_length_failed; */
static expert_field ei_thread_address_len_size_mismatch;
/* static expert_field ei_thread_dg_tlv_length_failed; */
/* static expert_field ei_thread_dg_len_size_mismatch; */
static expert_field ei_thread_mc_tlv_length_failed;
static expert_field ei_thread_mc_len_size_mismatch;
static expert_field ei_thread_mc_len_too_long;
/* static expert_field ei_thread_nwd_tlv_length_failed; */
static expert_field ei_thread_nwd_len_size_mismatch;
static expert_field ei_thread_nm_len_size_mismatch;
static expert_field ei_thread_bl_len_size_mismatch;


static dissector_table_t thread_coap_namespace;

/* Dissector handles */
static dissector_handle_t thread_address_nwd_handle;
static dissector_handle_t thread_dg_handle;
static dissector_handle_t thread_mc_handle;
static dissector_handle_t thread_dtls_handle;
static dissector_handle_t thread_udp_handle;
static dissector_handle_t thread_coap_handle;
static dissector_handle_t thread_address_handle;
static dissector_handle_t thread_nm_handle;
static dissector_handle_t thread_bl_handle;

/* 802.15.4 Thread ID */
static int hf_ieee802154_thread_ie;
static int hf_ieee802154_thread_ie_id;
static int hf_ieee802154_thread_ie_length;

#define THREAD_SERVICE_DATA_BBR 0x1

#define THREAD_TLV_LENGTH_ESC  0xFF

#define THREAD_URI_NAMESPACE_IDX 1

#define THREAD_MC_32768_TO_NSEC_FACTOR ((double)30517.578125)
#define THREAD_MC_TSTAMP_MASK_U_MASK 0x80
#define THREAD_MC_SEC_POLICY_MASK_O_MASK 0x80
#define THREAD_MC_SEC_POLICY_MASK_N_MASK 0x40
#define THREAD_MC_SEC_POLICY_MASK_R_MASK 0x20
#define THREAD_MC_SEC_POLICY_MASK_C_MASK 0x10
#define THREAD_MC_SEC_POLICY_MASK_B_MASK 0x08
#define THREAD_MC_SEC_POLICY_MASK_CCM_MASK 0x04
#define THREAD_MC_SEC_POLICY_MASK_AE_MASK 0x02
#define THREAD_MC_SEC_POLICY_MASK_NMP_MASK 0x01
#define THREAD_MC_SEC_POLICY_MASK_L_MASK 0x80
#define THREAD_MC_SEC_POLICY_MASK_NCR_MASK 0x40
#define THREAD_MC_SEC_POLICY_MASK_RSV_MASK 0x38
#define THREAD_MC_SEC_POLICY_MASK_RSV1_MASK 0x07
#define THREAD_MC_SEC_POLICY_MASK_VR_MASK 0x07
#define THREAD_MC_STACK_VER_REV_MASK 0x0F
#define THREAD_MC_STACK_VER_MIN_MASK 0xF0
#define THREAD_MC_STACK_VER_MAJ_MASK 0x0F
#define THREAD_MC_DISCOVERY_REQ_MASK_VER_MASK 0xF0
#define THREAD_MC_DISCOVERY_REQ_MASK_J_MASK 0x08
#define THREAD_MC_DISCOVERY_RSP_MASK_VER_MASK 0xF0
#define THREAD_MC_DISCOVERY_RSP_MASK_N_MASK 0x08
#define THREAD_MC_DISCOVERY_RSP_MASK_C_MASK 0x04
#define THREAD_MC_INVALID_CHAN_COUNT 0xFFFF

#define THREAD_NWD_TLV_HAS_ROUTE_PREF       0xC0
#define THREAD_NWD_TLV_HAS_ROUTE_NP         0x20
#define THREAD_NWD_TLV_HAS_ROUTE_RESERVED   0x1F
#define THREAD_NWD_TLV_HAS_ROUTE_SIZE       3

#define THREAD_NWD_TLV_BORDER_ROUTER_PREF   0xC0
#define THREAD_NWD_TLV_HAS_ROUTE_NP         0x20
#define THREAD_NWD_TLV_HAS_ROUTE_RESERVED   0x1F
#define THREAD_NWD_TLV_BORDER_ROUTER_P      0x20
#define THREAD_NWD_TLV_BORDER_ROUTER_S      0x10
#define THREAD_NWD_TLV_BORDER_ROUTER_D      0x08
#define THREAD_NWD_TLV_BORDER_ROUTER_C      0x04
#define THREAD_NWD_TLV_BORDER_ROUTER_R      0x02
#define THREAD_NWD_TLV_BORDER_ROUTER_O      0x01
#define THREAD_NWD_TLV_BORDER_ROUTER_N      0x80
#define THREAD_NWD_TLV_BORDER_ROUTER_DP     0x40 //Thread 1.2 Draft5

#define THREAD_BCN_PROTOCOL_ID              0x03
#define THREAD_BCN_JOINING                  0x01
#define THREAD_BCN_NATIVE                   0x08
#define THREAD_BCN_PROTOCOL_VERSION         0xf0
#define THREAD_BCN_TLV_STEERING_DATA_S      0x80
#define THREAD_BCN_TLV_STEERING_DATA        8

#define ND_OPT_6CO_FLAG_C        0x10
#define ND_OPT_6CO_FLAG_CID      0x0F
#define ND_OPT_6CO_FLAG_RESERVED 0xE0

#define THREAD_NWD_TLV_SERVICE_T    0x80
#define THREAD_NWD_TLV_SERVICE_S_ID 0x0F

typedef enum {
    TLV_LEN_LEN8 = 1,
    TLV_LEN_LEN16 = 3
} tlv_len_len_e;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_hdr_t;

/* TLV values */

#define THREAD_ADDRESS_TLV_TARGET_EID               0
#define THREAD_ADDRESS_TLV_EXT_MAC_ADDR             1
#define THREAD_ADDRESS_TLV_RLOC16                   2
#define THREAD_ADDRESS_TLV_ML_EID                   3
#define THREAD_ADDRESS_TLV_STATUS                   4
/* Gap */
#define THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME    6
#define THREAD_ADDRESS_TLV_ROUTER_MASK              7
#define THREAD_ADDRESS_TLV_ND_OPTION                8
#define THREAD_ADDRESS_TLV_ND_DATA                  9
#define THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA      10
#define THREAD_ADDRESS_TLV_TIMEOUT                  11
#define THREAD_ADDRESS_TLV_THREAD_NETWORK_NAME      12
#define THREAD_ADDRESS_TLV_IPV6_ADDRESS             14

static const value_string thread_address_tlv_vals[] = {
{ THREAD_ADDRESS_TLV_TARGET_EID,            "Target EID" },
{ THREAD_ADDRESS_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
{ THREAD_ADDRESS_TLV_RLOC16,                "RLOC16" },
{ THREAD_ADDRESS_TLV_ML_EID,                "ML-EID" },
{ THREAD_ADDRESS_TLV_STATUS,                "Status" },
/* Gap */
{ THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME, "Last Transaction Time" },
{ THREAD_ADDRESS_TLV_ROUTER_MASK,           "Router Mask" },
{ THREAD_ADDRESS_TLV_ND_OPTION,             "ND Option" },
{ THREAD_ADDRESS_TLV_ND_DATA,               "ND Data" },
{ THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA,   "Thread Network Data" },
{ THREAD_ADDRESS_TLV_TIMEOUT,               "Timeout"},
{ THREAD_ADDRESS_TLV_THREAD_NETWORK_NAME,   "Thread Network Name" },
{ THREAD_ADDRESS_TLV_IPV6_ADDRESS,          "IPv6 Address"},
{ 0, NULL }
};

static const value_string thread_address_tlv_status_vals[] = {
{ 0, "Success" },
{ 1, "No Address Available" },
{ 2, "TOO_FEW_ROUTERS" },
{ 3, "HAVE_CHILD_ID_REQUEST" },
{ 4, "PARENT_PARTITION_CHANGE" },
{ 0, NULL }
};

/* Network Layer (Address) mirrors */
#define THREAD_DG_TLV_EXT_MAC_ADDR          0 /* As THREAD_ADDRESS_TLV_EXT_MAC_ADDR */
/* MLE mirrors */
#define THREAD_DG_TLV_ADDRESS16             1 /* As MLE_TLV_ADDRESS16 */
#define THREAD_DG_TLV_MODE                  2 /* As MLE_TLV_MODE */
#define THREAD_DG_TLV_TIMEOUT               3 /* As MLE_TLV_TIMEOUT */
#define THREAD_DG_TLV_CONNECTIVITY          4 /* As MLE_TLV_CONNECTIVITY */
#define THREAD_DG_TLV_ROUTE64               5 /* As MLE_TLV_ROUTE64 */
#define THREAD_DG_TLV_LEADER_DATA           6 /* As MLE_TLV_LEADER_DATA */
#define THREAD_DG_TLV_NETWORK_DATA          7 /* As MLE_TLV_NETWORK_DATA */
/* Statistics */
#define THREAD_DG_TLV_IPV6_ADDR_LIST        8
#define THREAD_DG_TLV_MAC_COUNTERS          9
/* Others */
#define THREAD_DG_TLV_BATTERY_LEVEL         14
#define THREAD_DG_TLV_VOLTAGE               15
#define THREAD_DG_TLV_CHILD_TABLE           16
#define THREAD_DG_TLV_CHANNEL_PAGES         17
#define THREAD_DG_TLV_TYPE_LIST             18
#define THREAD_DG_TLV_MAX_CHILD_TIMEOUT     19
#define THREAD_DG_TLV_LDEVID_SUBJECT_PUBLIC_KEY_INFO 20
#define THREAD_DG_TLV_IDEVID_CERTIFICATE    21
/*  Reserved      22*/
#define THREAD_DG_TLV_EUI_64                23
#define THREAD_DG_TLV_VERSION               24
#define THREAD_DG_TLV_VENDOR_NAME           25
#define THREAD_DG_TLV_VENDOR_MODEL          26
#define THREAD_DG_TLV_VENDOR_SW_VERSION     27
#define THREAD_DG_TLV_THREAD_STACK_VERSION  28
#define THREAD_DG_TLV_CHILD                 29
#define THREAD_DG_TLV_CHILD_IPV6_ADDRESS_LIST        30
#define THREAD_DG_TLV_ROUTER_NEIGHBOR       31
#define THREAD_DG_TLV_ANSWER                32
#define THREAD_DG_TLV_QUERY_ID              33
#define THREAD_DG_TLV_MLE_COUNTERS          34
#define THREAD_DG_TLV_UNKNOWN               255

static const value_string thread_dg_tlv_vals[] = {
/* Network Layer (Address) mirrors */
{ THREAD_DG_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
/* MLE mirrors */
{ THREAD_DG_TLV_ADDRESS16,             "Address16" },
{ THREAD_DG_TLV_MODE,                  "Mode" },
{ THREAD_DG_TLV_TIMEOUT,               "Timeout" },
{ THREAD_DG_TLV_CONNECTIVITY,          "Connectivity" },
{ THREAD_DG_TLV_ROUTE64,               "Route64" },
{ THREAD_DG_TLV_LEADER_DATA,           "Leader Data" },
{ THREAD_DG_TLV_NETWORK_DATA,          "Network Data" },
/* Statistics */
{ THREAD_DG_TLV_IPV6_ADDR_LIST,        "IPv6 Address List" },
{ THREAD_DG_TLV_MAC_COUNTERS,          "MAC Counters" },
/* Others */
{ THREAD_DG_TLV_BATTERY_LEVEL,         "Battery level (%)" },
{ THREAD_DG_TLV_VOLTAGE,               "Voltage (mV)" },
{ THREAD_DG_TLV_CHILD_TABLE,           "Child Table" },
{ THREAD_DG_TLV_CHANNEL_PAGES,         "Channel Pages" },
{ THREAD_DG_TLV_TYPE_LIST,             "Type List" },
{ THREAD_DG_TLV_MAX_CHILD_TIMEOUT,     "Max Child Timeout"},
{ THREAD_DG_TLV_LDEVID_SUBJECT_PUBLIC_KEY_INFO, "LDevID Subject Public Key Info"},
{ THREAD_DG_TLV_IDEVID_CERTIFICATE,    "IDevID Certificate"},
{ THREAD_DG_TLV_EUI_64,                "EUI-64"},
{ THREAD_DG_TLV_VERSION,               "Version"},
{ THREAD_DG_TLV_VENDOR_NAME,           "Vendor Name"},
{ THREAD_DG_TLV_VENDOR_MODEL,          "Vendor Model"},
{ THREAD_DG_TLV_VENDOR_SW_VERSION,     "Vendor SW Version"},
{ THREAD_DG_TLV_THREAD_STACK_VERSION,  "Thread Stack Version"},
{ THREAD_DG_TLV_CHILD,                 "Child"},
{ THREAD_DG_TLV_CHILD_IPV6_ADDRESS_LIST, "Child IPV6 Address List"},
{ THREAD_DG_TLV_ROUTER_NEIGHBOR,       "Router Neighbor"},
{ THREAD_DG_TLV_ANSWER,                "Answer"},
{ THREAD_DG_TLV_QUERY_ID,              "Query ID"},
{ THREAD_DG_TLV_MLE_COUNTERS,          "MLE Counters"},
{ THREAD_DG_TLV_UNKNOWN,               "Unknown" },
{ 0, NULL }
};

#define THREAD_MC_TLV_CHANNEL                      0 /* Modified for new features */
#define THREAD_MC_TLV_PANID                        1
#define THREAD_MC_TLV_XPANID                       2
#define THREAD_MC_TLV_NETWORK_NAME                 3
#define THREAD_MC_TLV_PSKC                         4
#define THREAD_MC_TLV_NETWORK_MASTER_KEY           5
#define THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR          6
#define THREAD_MC_TLV_NETWORK_ML_PREFIX            7
#define THREAD_MC_TLV_STEERING_DATA                8
#define THREAD_MC_TLV_BORDER_AGENT_LOCATOR         9
#define THREAD_MC_TLV_COMMISSIONER_ID              10
#define THREAD_MC_TLV_COMMISSIONER_SESSION_ID      11
#define THREAD_MC_TLV_SECURITY_POLICY              12
#define THREAD_MC_TLV_GET                          13
#define THREAD_MC_TLV_ACTIVE_TSTAMP                14 /* Was "Commissioning Dataset Timestamp TLV" */
#define THREAD_MC_TLV_COMMISSIONER_UDP_PORT        15
#define THREAD_MC_TLV_STATE                        16
#define THREAD_MC_TLV_JOINER_DTLS_ENCAP            17
#define THREAD_MC_TLV_JOINER_UDP_PORT              18
#define THREAD_MC_TLV_JOINER_IID                   19
#define THREAD_MC_TLV_JOINER_ROUTER_LOCATOR        20
#define THREAD_MC_TLV_JOINER_KEK                   21
/* Gap */
#define THREAD_MC_TLV_PROVISIONING_URL             32
#define THREAD_MC_TLV_VENDOR_NAME                  33
#define THREAD_MC_TLV_VENDOR_MODEL                 34
#define THREAD_MC_TLV_VENDOR_SW_VERSION            35
#define THREAD_MC_TLV_VENDOR_DATA                  36
#define THREAD_MC_TLV_VENDOR_STACK_VERSION         37
/* Gap */
#define THREAD_MC_TLV_UDP_ENCAPSULATION            48
#define THREAD_MC_TLV_IPV6_ADDRESS                 49
/* Gap */
/* New features */
#define THREAD_MC_TLV_PENDING_TSTAMP               51
#define THREAD_MC_TLV_DELAY_TIMER                  52
#define THREAD_MC_TLV_CHANNEL_MASK                 53
#define THREAD_MC_TLV_COUNT                        54
#define THREAD_MC_TLV_PERIOD                       55
#define THREAD_MC_TLV_SCAN_DURATION                56
#define THREAD_MC_TLV_ENERGY_LIST                  57
#define THREAD_MC_TLV_DOMAIN_NAME                  59
#define THREAD_MC_TLV_DOMAIN_PREFIX                60
#define THREAD_MC_TLV_AE_STEERING_DATA             61
#define THREAD_MC_TLV_NMKP_STEERING_DATA           62
#define THREAD_MC_TLV_COMMISSIONER_TOKEN           63
#define THREAD_MC_TLV_COMMISSIONER_SIGNATURE       64
#define THREAD_MC_TLV_AE_UDP_PORT                  65
#define THREAD_MC_TLV_NMKP_UDP_PORT                66
#define THREAD_MC_TLV_TRI_HOSTNAME                 67
#define THREAD_MC_TLV_REGISTRAR_IPV6_ADDRESS       68
#define THREAD_MC_TLV_REGISTRAR_HOSTNAME           69
#define THREAD_MC_TLV_COMMISSIONER_PEN_SIGNATURE   70
#define THREAD_MC_TLV_COMMISSIONER_PEN_TOKEN       71

/* Gap */
/* New discovery mechanism */
#define THREAD_MC_TLV_DISCOVERY_REQUEST            128
#define THREAD_MC_TLV_DISCOVERY_RESPONSE           129

static const value_string thread_mc_tlv_vals[] = {
{ THREAD_MC_TLV_CHANNEL,                   "Channel" },
{ THREAD_MC_TLV_PANID,                     "PAN ID" },
{ THREAD_MC_TLV_XPANID,                    "Extended PAN ID" },
{ THREAD_MC_TLV_NETWORK_NAME,              "Network Name" },
{ THREAD_MC_TLV_PSKC,                      "PSKc" },
{ THREAD_MC_TLV_NETWORK_MASTER_KEY,        "Network Master Key" },
{ THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR,       "Network Key Sequence Counter" },
{ THREAD_MC_TLV_NETWORK_ML_PREFIX,         "Mesh Local ULA Prefix" },
{ THREAD_MC_TLV_STEERING_DATA,             "Steering Data" },
{ THREAD_MC_TLV_BORDER_AGENT_LOCATOR,      "Border Agent Locator" },
{ THREAD_MC_TLV_COMMISSIONER_ID,           "Commissioner ID" },
{ THREAD_MC_TLV_COMMISSIONER_SESSION_ID,   "Commissioner Session ID" },
{ THREAD_MC_TLV_SECURITY_POLICY,           "Security Policy" },
{ THREAD_MC_TLV_GET,                       "Get" },
{ THREAD_MC_TLV_ACTIVE_TSTAMP,             "Active Timestamp" },
{ THREAD_MC_TLV_COMMISSIONER_UDP_PORT,     "Commissioner UDP Port" },
{ THREAD_MC_TLV_STATE,                     "State" },
{ THREAD_MC_TLV_JOINER_DTLS_ENCAP,         "Joiner DTLS Encapsulation" },
{ THREAD_MC_TLV_JOINER_UDP_PORT,           "Joiner UDP Port" },
{ THREAD_MC_TLV_JOINER_IID,                "Joiner IID" },
{ THREAD_MC_TLV_JOINER_ROUTER_LOCATOR,     "Joiner Router Locator" },
{ THREAD_MC_TLV_JOINER_KEK,                "Joiner KEK" },
{ THREAD_MC_TLV_PROVISIONING_URL,          "Provisioning URL" },
{ THREAD_MC_TLV_VENDOR_NAME,               "Vendor Name" },
{ THREAD_MC_TLV_VENDOR_MODEL,              "Vendor Model" },
{ THREAD_MC_TLV_VENDOR_SW_VERSION,         "Vendor Software Version" },
{ THREAD_MC_TLV_VENDOR_DATA,               "Vendor Data" },
{ THREAD_MC_TLV_VENDOR_STACK_VERSION,      "Vendor Stack Version" },
{ THREAD_MC_TLV_UDP_ENCAPSULATION,         "UDP Encapsulation" },
{ THREAD_MC_TLV_IPV6_ADDRESS,              "IPv6 Address" },
/* New features */
{ THREAD_MC_TLV_PENDING_TSTAMP,            "Pending Timestamp" },
{ THREAD_MC_TLV_DELAY_TIMER,               "Delay Timer" },
{ THREAD_MC_TLV_CHANNEL_MASK,              "Channel Mask" },
{ THREAD_MC_TLV_COUNT,                     "Count" },
{ THREAD_MC_TLV_PERIOD,                    "Period" },
{ THREAD_MC_TLV_SCAN_DURATION,             "Scan Duration" },
{ THREAD_MC_TLV_ENERGY_LIST,               "Energy List" },
{ THREAD_MC_TLV_DOMAIN_NAME,               "Domain Name" },
{ THREAD_MC_TLV_DOMAIN_PREFIX,             "Domain Prefix" },
{ THREAD_MC_TLV_AE_STEERING_DATA,          "AE Steering Data" },
{ THREAD_MC_TLV_NMKP_STEERING_DATA,        "NMKP Steering Data" },
{ THREAD_MC_TLV_COMMISSIONER_TOKEN,        "Commissioner Token" },
{ THREAD_MC_TLV_COMMISSIONER_SIGNATURE,    "Commissioner Signature" },
{ THREAD_MC_TLV_AE_UDP_PORT,               "AE UDP Port" },
{ THREAD_MC_TLV_NMKP_UDP_PORT,             "NMKP UDP Port" },
{ THREAD_MC_TLV_TRI_HOSTNAME,              "TRI Hostname" },
{ THREAD_MC_TLV_REGISTRAR_IPV6_ADDRESS,    "Registrar IPv6 Address" },
{ THREAD_MC_TLV_REGISTRAR_HOSTNAME,        "Registrar Hostname" },
{ THREAD_MC_TLV_COMMISSIONER_PEN_SIGNATURE,"Commissioner PEN Signature" },
{ THREAD_MC_TLV_COMMISSIONER_PEN_TOKEN,    "Commissioner PEN Token" },
/* New discovery mechanism */
{ THREAD_MC_TLV_DISCOVERY_REQUEST,         "Discovery Request" },
{ THREAD_MC_TLV_DISCOVERY_RESPONSE,        "Discovery Response" },
{ 0, NULL}
};

static const value_string thread_mc_state_vals[] = {
{ -1, "Reject" },
{ 0, "Pending" },
{ 1, "Accept" },
{ 0, NULL}
};

static const true_false_string thread_mc_tlv_join_intent = {
    "Intending",
    "Not Intending"
};

#define THREAD_NWD_TLV_HAS_ROUTE                    0
#define THREAD_NWD_TLV_PREFIX                       1
#define THREAD_NWD_TLV_BORDER_ROUTER                2
#define THREAD_NWD_TLV_6LOWPAN_ID                   3
#define THREAD_NWD_TLV_COMMISSIONING_DATA           4
#define THREAD_NWD_TLV_SERVICE                      5
#define THREAD_NWD_TLV_SERVER                       6

static const value_string thread_nwd_tlv_vals[] = {
{ THREAD_NWD_TLV_HAS_ROUTE,                 "Has Route" },
{ THREAD_NWD_TLV_PREFIX,                    "Prefix" },
{ THREAD_NWD_TLV_BORDER_ROUTER,             "Border Router" },
{ THREAD_NWD_TLV_6LOWPAN_ID,                "6LoWPAN ID" },
{ THREAD_NWD_TLV_COMMISSIONING_DATA,        "Commissioning Data" },
{ THREAD_NWD_TLV_SERVICE,                   "Service" },
{ THREAD_NWD_TLV_SERVER,                    "Server" },
{ 0, NULL}
};

#define THREAD_NWD_TLV_TYPE_M       0xFE
#define THREAD_NWD_TLV_STABLE_M     0x01

static const true_false_string tfs_thread_nwd_tlv_border_router_p = {
    "Autoconfigured preferred",
    "Autoconfigured deprecated"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_c = {
    "Additional config. data",
    "No additional config. data"
};

static const true_false_string tfs_thread_nwd_tlv_border_router_o = {
    "On mesh",
    "Not on mesh"
};

/*Network Management TLVs*/
static int hf_thread_nm_tlv;
static int hf_thread_nm_tlv_type;
static int hf_thread_nm_tlv_length;
static int hf_thread_nm_tlv_unknown;
/* static int hf_thread_nm_tlv_sub_tlvs; */

/* Target EID TLV fields */
static int hf_thread_nm_tlv_target_eid;

/* Ext. MAC address TLV fields */
static int hf_thread_nm_tlv_ext_mac_addr;

/* RLOC16 TLV fields */
static int hf_thread_nm_tlv_rloc16;

/* Mesh Local IID TLV fields */
static int hf_thread_nm_tlv_ml_eid;

/* Status TLV fields */
static int hf_thread_nm_tlv_status;

/* Last transaction time TLV fields */
static int hf_thread_nm_tlv_last_transaction_time;

/* Router Mask TLV fields */
static int hf_thread_nm_tlv_router_mask_id_seq;
static int hf_thread_nm_tlv_router_mask_assigned;

/* ND option fields */
static int hf_thread_nm_tlv_nd_option;

/* ND data fields */
static int hf_thread_nm_tlv_nd_data;

static int hf_thread_nm_tlv_timeout;

/* TLV values */

#define THREAD_NM_TLV_TARGET_EID               0
#define THREAD_NM_TLV_EXT_MAC_ADDR             1
#define THREAD_NM_TLV_RLOC16                   2
#define THREAD_NM_TLV_ML_EID                   3
#define THREAD_NM_TLV_STATUS                   4
/* Gap */
#define THREAD_NM_TLV_LAST_TRANSACTION_TIME    6
#define THREAD_NM_TLV_ROUTER_MASK              7
#define THREAD_NM_TLV_ND_OPTION                8
#define THREAD_NM_TLV_ND_DATA                  9
#define THREAD_NM_TLV_THREAD_NETWORK_DATA      10
#define THREAD_NM_TLV_TIMEOUT                  11
#define THREAD_NM_TLV_THREAD_NETWORK_NAME      12
#define THREAD_NM_TLV_IPV6_ADDRESS             14
#define THREAD_NM_TLV_COMMISSIONER_SESSION_ID  15

static const value_string thread_nm_tlv_vals[] = {
{ THREAD_NM_TLV_TARGET_EID,            "Target EID" },
{ THREAD_NM_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
{ THREAD_NM_TLV_RLOC16,                "RLOC16" },
{ THREAD_NM_TLV_ML_EID,                "ML-EID" },
{ THREAD_NM_TLV_STATUS,                "Status" },
/* Gap */
{ THREAD_NM_TLV_LAST_TRANSACTION_TIME, "Last Transaction Time" },
{ THREAD_NM_TLV_ROUTER_MASK,           "Router Mask" },
{ THREAD_NM_TLV_ND_OPTION,             "ND Option" },
{ THREAD_NM_TLV_ND_DATA,               "ND Data" },
{ THREAD_NM_TLV_THREAD_NETWORK_DATA,   "Thread Network Data" },
{ THREAD_NM_TLV_TIMEOUT,               "Timeout"},
{ THREAD_NM_TLV_THREAD_NETWORK_NAME,   "Thread Network Name" },
{ THREAD_NM_TLV_IPV6_ADDRESS,          "IPv6 Address"},
{ THREAD_NM_TLV_COMMISSIONER_SESSION_ID, "Commissioner Session ID"},
{ 0, NULL }
};


static const value_string thread_nm_tlv_status_vals[] = {
{ 0, "Successful registration" },
{ 1, "Registration was accepted but immediate reregistration is required \
     to resolve any potential conflicting state across Domain BBRs." },
{ 2, "Registration rejected: Target EID is not a valid DUA" },
{ 3, "Registration rejected: DUA is already in use by another Device" },
{ 4, "Registration rejected: BBR resource shortage" },
{ 5, "Registration rejected: BBR is not Primary at this moment" },
{ 6, "Registration failure: Reason(s) not further specified" },
{ 0, NULL }
};

/* Network Management TLVs end*/

/*Backbone Link TLVs*/

static int hf_thread_bl_tlv;
static int hf_thread_bl_tlv_type;
static int hf_thread_bl_tlv_length;
static int hf_thread_bl_tlv_unknown;
/* static int hf_thread_bl_tlv_sub_tlvs; */

/* Target EID TLV fields */
static int hf_thread_bl_tlv_target_eid;

/* Ext. MAC address TLV fields */
static int hf_thread_bl_tlv_ext_mac_addr;

/* RLOC16 TLV fields */
static int hf_thread_bl_tlv_rloc16;

/* Mesh Local IID TLV fields */
static int hf_thread_bl_tlv_ml_eid;

/* Status TLV fields */
static int hf_thread_bl_tlv_status;

/* Attached time TLV fields */
/* static int hf_thread_bl_tlv_attached_time; */

/* Last transaction time TLV fields */
static int hf_thread_bl_tlv_last_transaction_time;

/* Router Mask TLV fields */
static int hf_thread_bl_tlv_router_mask_id_seq;
static int hf_thread_bl_tlv_router_mask_assigned;

/* ND option fields */
static int hf_thread_bl_tlv_nd_option;

/* ND data fields */
static int hf_thread_bl_tlv_nd_data;

static int hf_thread_bl_tlv_timeout;

/* TLV values */
#define THREAD_BL_TLV_TARGET_EID               0
#define THREAD_BL_TLV_EXT_MAC_ADDR             1
#define THREAD_BL_TLV_RLOC16                   2
#define THREAD_BL_TLV_ML_EID                   3
#define THREAD_BL_TLV_STATUS                   4
/* Gap */
#define THREAD_BL_TLV_LAST_TRANSACTION_TIME    6
#define THREAD_BL_TLV_ROUTER_MASK              7
#define THREAD_BL_TLV_ND_OPTION                8
#define THREAD_BL_TLV_ND_DATA                  9
#define THREAD_BL_TLV_THREAD_NETWORK_DATA      10
#define THREAD_BL_TLV_TIMEOUT                  11
#define THREAD_BL_TLV_THREAD_NETWORK_NAME      12
#define THREAD_BL_TLV_IPV6_ADDRESS             14

static const value_string thread_bl_tlv_vals[] = {
{ THREAD_BL_TLV_TARGET_EID,            "Target EID" },
{ THREAD_BL_TLV_EXT_MAC_ADDR,          "Extended MAC Address" },
{ THREAD_BL_TLV_RLOC16,                "RLOC16" },
{ THREAD_BL_TLV_ML_EID,                "ML-EID" },
{ THREAD_BL_TLV_STATUS,                "Status" },
/* Gap */
{ THREAD_BL_TLV_LAST_TRANSACTION_TIME, "Last Transaction Time" },
{ THREAD_BL_TLV_ROUTER_MASK,           "Router Mask" },
{ THREAD_BL_TLV_ND_OPTION,             "ND Option" },
{ THREAD_BL_TLV_ND_DATA,               "ND Data" },
{ THREAD_BL_TLV_THREAD_NETWORK_DATA,   "Thread Network Data" },
{ THREAD_BL_TLV_TIMEOUT,               "Timeout"},
{ THREAD_BL_TLV_THREAD_NETWORK_NAME,   "Thread Network Name" },
{ THREAD_BL_TLV_IPV6_ADDRESS,          "IPv6 Address"},
{ 0, NULL }
};

static const value_string thread_bl_tlv_status_vals[] = {
{ 0, "Success" },
{ 1, "No Address Available" },
{ 2, "TOO_FEW_ROUTERS" },
{ 3, "HAVE_CHILD_ID_REQUEST" },
{ 4, "PARENT_PARTITION_CHANGE" },
{ 0, NULL }
};
/* Backbone Link TLVs end*/

/* Thread Beacon TLV Values. */
static const value_string thread_bcn_tlv_vals[] = {
    { THREAD_BCN_TLV_STEERING_DATA, "Steering Data" },
    { 0, NULL }
};

static int
dissect_thread_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Preferences */
static bool thread_use_pan_id_in_key;
static const char *thread_seq_ctr_str;
static bool thread_auto_acq_seq_ctr = true;


static bool thread_seq_ctr_acqd;
static uint8_t thread_seq_ctr_bytes[4];
static const uint8_t thread_well_known_key[IEEE802154_CIPHER_SIZE] =
{ 0x78, 0x58, 0x16, 0x86, 0xfd, 0xb4, 0x58, 0x0f, 0xb0, 0x92, 0x54, 0x6a, 0xec, 0xbd, 0x15, 0x66 };

static GByteArray *set_thread_seq_ctr_from_key_index(uint8_t key_index)
{
    GByteArray *seq_ctr_bytes = NULL;

    seq_ctr_bytes = g_byte_array_new();
    if (thread_seq_ctr_acqd) {
        seq_ctr_bytes = g_byte_array_set_size(seq_ctr_bytes, 4);
        memcpy(seq_ctr_bytes->data, thread_seq_ctr_bytes, 4);
    } else {
        hex_str_to_bytes(thread_seq_ctr_str, seq_ctr_bytes, false);
        if (seq_ctr_bytes->len != 4) {
            /* Not read correctly - assume value is 0 */
            seq_ctr_bytes = g_byte_array_set_size(seq_ctr_bytes, 4);
            memset(seq_ctr_bytes->data, 0, 4);
        }
    }
    /* Replace lower part with counter based on packet key index */
    seq_ctr_bytes->data[3] = (seq_ctr_bytes->data[3] & 0x80) + ((key_index - 1) & 0x7F);

    return seq_ctr_bytes;
}

static void create_thread_temp_keys(GByteArray *seq_ctr_bytes, uint16_t src_pan, ieee802154_key_t* key, unsigned char *mac_key, unsigned char *mle_key)
{
    GByteArray *bytes;
    char       buffer[10];
    bool       res;
    bool       key_valid;
    bool       verbatim_key = true;

    /* Get the IEEE 802.15.4 decryption key. */
    bytes = g_byte_array_new();
    res = hex_str_to_bytes(key->pref_key, bytes, false);
    key_valid = (res && bytes->len >= IEEE802154_CIPHER_SIZE);
    if (key_valid) {
        if (thread_use_pan_id_in_key) {
            /* Substitute the bottom two keys bytes with PAN ID */
            bytes->data[0] = (uint8_t)(src_pan & 0xFF);
            bytes->data[1] = (uint8_t)(src_pan >> 8);
        }
        if (key->hash_type != KEY_HASH_NONE) {
            char digest[32];

            if (key->hash_type == KEY_HASH_THREAD) {
                memcpy(buffer, seq_ctr_bytes->data, 4);
                memcpy(&buffer[4], "Thread", 6); /* len("Thread") */

                if (!ws_hmac_buffer(GCRY_MD_SHA256, digest, buffer, 10, bytes->data, IEEE802154_CIPHER_SIZE)) {
                    /* Copy upper hashed bytes to the MAC key */
                    if (mac_key) {
                        memcpy(mac_key, &digest[IEEE802154_CIPHER_SIZE], IEEE802154_CIPHER_SIZE);
                    }
                    /* Copy lower hashed bytes to the MLE key */
                    if (mle_key) {
                        memcpy(mle_key, digest, IEEE802154_CIPHER_SIZE);
                    }
                    verbatim_key = false;
                }
            }
        }
        if (verbatim_key) {
            /* Just copy the keys verbatim */
            if (mac_key) {
                memcpy(mac_key, bytes->data, IEEE802154_CIPHER_SIZE);
            }
            if (mle_key) {
                memcpy(mle_key, bytes->data, IEEE802154_CIPHER_SIZE);
            }
        }
    }
    g_byte_array_free(bytes, true);
}

/* Set MAC key for Thread hash */
static unsigned set_thread_mac_key(ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key)
{
    GByteArray *seq_ctr_bytes = NULL;

    if (packet->key_id_mode == KEY_ID_MODE_KEY_INDEX) {
        seq_ctr_bytes = set_thread_seq_ctr_from_key_index(packet->key_index);
    } else if ((packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_4) &&
               (packet->key_index == IEEE802154_THR_WELL_KNOWN_KEY_INDEX) &&
               (packet->key_source.addr32 == IEEE802154_THR_WELL_KNOWN_KEY_SRC))
    {
        /* This is the well-known Thread key. No need for an alternative key */
        memcpy(key, thread_well_known_key, IEEE802154_CIPHER_SIZE);
        return 1;
    }
    if (seq_ctr_bytes != NULL) {
        create_thread_temp_keys(seq_ctr_bytes, packet->src_pan, uat_key, key, NULL);
        /* Create an alternate key based on the wraparound case */
        seq_ctr_bytes->data[3] ^= 0x80;
        create_thread_temp_keys(seq_ctr_bytes, packet->src_pan, uat_key, alt_key, NULL);
        g_byte_array_free(seq_ctr_bytes, true);
        return 2;
    }

    return 0;
}

/* Set MLE key for Thread hash */
static unsigned set_thread_mle_key(ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key)
{
    GByteArray *seq_ctr_bytes = NULL;
    if (packet->key_id_mode == KEY_ID_MODE_KEY_INDEX) {
        seq_ctr_bytes = set_thread_seq_ctr_from_key_index(packet->key_index);
    }
    else if (packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_4) {
        /* Reconstruct the key source from the key source in the packet */
        seq_ctr_bytes = g_byte_array_new();
        seq_ctr_bytes = g_byte_array_set_size(seq_ctr_bytes, 4);
        seq_ctr_bytes->data[0] = (packet->key_source.addr32 >> 24) & 0xFF;
        seq_ctr_bytes->data[1] = (packet->key_source.addr32 >> 16) & 0xFF;
        seq_ctr_bytes->data[2] = (packet->key_source.addr32 >> 8) & 0xFF;
        seq_ctr_bytes->data[3] = packet->key_source.addr32 & 0xFF;
        /* Acquire the sequence counter if configured in preferences */
        if (thread_auto_acq_seq_ctr && !thread_seq_ctr_acqd) {
            memcpy(thread_seq_ctr_bytes, seq_ctr_bytes->data, 4);
            thread_seq_ctr_acqd = true;
        }
    }
    if (seq_ctr_bytes != NULL) {
        create_thread_temp_keys(seq_ctr_bytes, packet->src_pan, uat_key, NULL, key);
        /* Create an alternate key based on the wraparound case */
        seq_ctr_bytes->data[3] ^= 0x80;
        create_thread_temp_keys(seq_ctr_bytes, packet->src_pan, uat_key, NULL, alt_key);
        g_byte_array_free(seq_ctr_bytes, true);
        return 2;
    }

    return 0;
}

static unsigned
count_bits_in_byte(uint8_t byte)
{
    static const uint8_t lut[16] = {0, /* 0b0000 */
                                   1, /* 0b0001 */
                                   1, /* 0b0010 */
                                   2, /* 0b0011 */
                                   1, /* 0b0100 */
                                   2, /* 0b0101 */
                                   2, /* 0b0110 */
                                   3, /* 0b0111 */
                                   1, /* 0b1000 */
                                   2, /* 0b1001 */
                                   2, /* 0b1010 */
                                   3, /* 0b1011 */
                                   2, /* 0b1100 */
                                   3, /* 0b1101 */
                                   3, /* 0b1110 */
                                   4  /* 0b1111 */};
    return lut[byte >> 4] + lut[byte & 0xf];
}

static unsigned
get_chancount(tvbuff_t *tvb)
{
    unsigned      offset;
    uint8_t       tlv_type;
    uint16_t      tlv_len;
    tlv_len_len_e tlv_len_len;
    unsigned      chancount = THREAD_MC_INVALID_CHAN_COUNT;

    offset = 0;

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_uint8(tvb, offset);
        tlv_len = (uint16_t)tvb_get_uint8(tvb, offset + 1);

        /* TODO: need to make sure this applies to all MeshCoP TLVs */
        if (THREAD_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_len_len = TLV_LEN_LEN16;
        } else {
            tlv_len_len = TLV_LEN_LEN8;
        }

        /* Skip over Type and Length */
        offset += 1 + tlv_len_len;

        switch(tlv_type) {

            case THREAD_MC_TLV_CHANNEL_MASK:
                {
                    int i, j;
                    uint8_t entries = 0;
                    int32_t check_len = tlv_len;
                    int check_offset = offset + 1; /* Channel page first */
                    uint16_t masklen;

                    /* Check consistency of entries */
                    while (check_len > 0) {

                        masklen = tvb_get_uint8(tvb, check_offset);
                        if (masklen == 0) {
                            break; /* Get out or we might spin forever */
                        }
                        masklen += 2; /* Add in page and length */
                        check_offset += masklen;
                        check_len -= masklen;
                        entries++;
                    }

                    if (check_len != 0) {
                        /* Not an integer number of entries */
                        /* offset += tlv_len; */
                        return chancount;
                    } else {
                        chancount = 0;
                        for (i = 0; i < entries; i++) {
                            /* Skip over channel page */
                            offset++;
                            masklen = tvb_get_uint8(tvb, offset);
                            offset++;
                            /* Count the number of channels in the channel mask */
                            for (j = 0; j < masklen; j++) {
                                chancount += count_bits_in_byte(tvb_get_uint8(tvb, offset));
                                offset++;
                            }
                        }
                    }
                }
                break;

            default:
                /* Skip over any other TLVs */
                offset += tlv_len;
        }
    }
    return chancount;
}

static int
dissect_thread_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *proto_root;
    proto_tree  *thread_address_tree;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    unsigned    offset = 0;
    proto_item  *ti;
    uint8_t     tlv_type, tlv_len;

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_address, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_address_tree = proto_item_add_subtree(proto_root, ett_thread_address);

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_uint8(tvb, offset + 1);

        ti = proto_tree_add_item(thread_address_tree, hf_thread_address_tlv, tvb, offset, tlv_len+2, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_address_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        tlv_type = tvb_get_uint8(tvb, offset);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_address_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch(tlv_type) {
            case THREAD_ADDRESS_TLV_TARGET_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Target EID */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_target_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_EXT_MAC_ADDR:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Extended MAC address */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_ext_mac_addr, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_RLOC16:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Mesh Locator */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_rloc16, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_ML_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* ML IID */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_ml_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_STATUS:
                {
                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Status */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_status, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_LAST_TRANSACTION_TIME:
                {
                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Last transaction time */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_last_transaction_time, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_ADDRESS_TLV_ROUTER_MASK:
                {
                    /* Check length is consistent */
                    if (tlv_len != 9) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        /* Router Mask */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_router_mask_id_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        /*
                         * | | | | | | | | | | |1|1|1|1|1|1|...|6|
                         * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|...|3|
                         * ---------------------------------------
                         * |1|0|1|1|1|0|0|0|1|1|0|0|0|1|0|1|...
                         *
                         * is sent as 0xb8, 0xc5
                         * and represents table entry for routers 0, 2, 3, 4, 8, 9, 13, 15...
                         */

                        /* Just show the string of octets - best representation for a bit mask */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_router_mask_assigned, tvb, offset, 8, ENC_NA);
                        offset += 8;
                    }
                }
                break;

            case THREAD_ADDRESS_TLV_ND_OPTION:
                /* Just show the data */
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_nd_option, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_ADDRESS_TLV_ND_DATA:
                /* Just show the data. Note there is no icmpv6 options dissector so would have to copy it */
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_nd_data, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_ADDRESS_TLV_THREAD_NETWORK_DATA:
                if (tlv_len > 0) {
                    sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                    call_dissector(thread_address_nwd_handle, sub_tvb, pinfo, tlv_tree);
                }
                offset += tlv_len;
                break;

            case THREAD_ADDRESS_TLV_TIMEOUT:
                if (tlv_len > 4) {
                    expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Time out*/
                    proto_tree_add_item(tlv_tree, hf_thread_address_tlv_timeout, tvb, offset, tlv_len, ENC_NA);
                }
                offset += tlv_len;
                break;
            case THREAD_ADDRESS_TLV_THREAD_NETWORK_NAME:
                if (tlv_len > 16) {
                    expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Network Name */
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, ENC_ASCII | ENC_UTF_8  );
                }
                offset += tlv_len;
                break;
            case THREAD_ADDRESS_TLV_IPV6_ADDRESS:
                if ((tlv_len % 16) != 0) {
                    expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                }
                else {
                    //Need to only take 16 bytes for the IPv6 address
                    for (int i = 0; i < (tlv_len / 16); i++)
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, 16, ENC_NA);
                        offset += 16;
                    }
                }
                offset += tlv_len;
                break;
            default:
                proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    return tvb_captured_length(tvb);
}

static int
dissect_thread_nm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *proto_root;
    proto_tree  *thread_nm_tree;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    unsigned    offset = 0;
    proto_item  *ti;
    uint8_t     tlv_type, tlv_len;

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_nm, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_nm_tree = proto_item_add_subtree(proto_root, ett_thread_nm);

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_uint8(tvb, offset + 1);

        /* Create the tree */
        ti = proto_tree_add_item(thread_nm_tree, hf_thread_nm_tlv, tvb, offset, tlv_len+2, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_nm_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        tlv_type = tvb_get_uint8(tvb, offset);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_nm_tlv_vals, "Unknown (%d)"));

        /* Length */
                proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;


        switch(tlv_type) {
                case THREAD_NM_TLV_TARGET_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Target EID */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_target_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_EXT_MAC_ADDR:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Extended MAC address */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_ext_mac_addr, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_RLOC16:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Mesh Locator */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_rloc16, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_ML_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* ML IID */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_ml_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_STATUS:
                {
                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Status */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_status, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_LAST_TRANSACTION_TIME:
                {
                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Last transaction time */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_last_transaction_time, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_ROUTER_MASK:
                {
                    /* Check length is consistent */
                    if (tlv_len != 9) {
                        expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        /* Router Mask */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_router_mask_id_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        /*
                         * | | | | | | | | | | |1|1|1|1|1|1|...|6|
                         * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|...|3|
                         * ---------------------------------------
                         * |1|0|1|1|1|0|0|0|1|1|0|0|0|1|0|1|...
                         *
                         * is sent as 0xb8, 0xc5
                         * and represents table entry for routers 0, 2, 3, 4, 8, 9, 13, 15...
                         */

                        /* Just show the string of octets - best representation for a bit mask */
                        proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_router_mask_assigned, tvb, offset, 8, ENC_NA);
                        offset += 8;
                    }
                }
                break;

            case THREAD_NM_TLV_ND_OPTION:
                /* Just show the data */
                proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_nd_option, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_NM_TLV_ND_DATA:
                /* Just show the data. Note there is no icmpv6 options dissector so would have to copy it */
                proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_nd_data, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

           case THREAD_NM_TLV_THREAD_NETWORK_DATA:
                if (tlv_len > 0) {
                    sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                    call_dissector(thread_address_nwd_handle, sub_tvb, pinfo, tlv_tree);
                }
                offset += tlv_len;
                break;

           case THREAD_NM_TLV_TIMEOUT:
                if (tlv_len > 4) {
                    expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Time out*/
                    proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_timeout, tvb, offset, tlv_len, ENC_NA);
                }
                offset += tlv_len;


                break;

           case THREAD_NM_TLV_THREAD_NETWORK_NAME:
                if (tlv_len > 16) {
                    expert_add_info(pinfo, proto_root, &ei_thread_nm_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Network Name */
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, ENC_ASCII | ENC_UTF_8);
                }
                offset += tlv_len;

                break;

           case THREAD_NM_TLV_IPV6_ADDRESS:
                if ((tlv_len % 16) != 0) {
                    expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                }
                else {
                    //Need to only take 16 bytes for the IPv6 address
                    for (int i = 0; i < (tlv_len / 16); i++)
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, 16, ENC_NA);
                        offset += 16;
                    }
                }
                break;

           case THREAD_NM_TLV_COMMISSIONER_SESSION_ID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);

            proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_commissioner_sess_id, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            default:
                proto_tree_add_item(tlv_tree, hf_thread_nm_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    return tvb_captured_length(tvb);
}
static int
dissect_thread_bl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *proto_root;
    proto_tree  *thread_bl_tree;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    unsigned    offset = 0;
    proto_item  *ti;
    uint8_t     tlv_type, tlv_len;

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_bl, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_bl_tree = proto_item_add_subtree(proto_root, ett_thread_bl);

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_uint8(tvb, offset + 1);

       ti = proto_tree_add_item(thread_bl_tree, hf_thread_bl_tlv, tvb, offset, tlv_len+2, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_bl_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        tlv_type = tvb_get_uint8(tvb, offset);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_bl_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        switch(tlv_type) {
           case THREAD_NM_TLV_TARGET_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                       expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                   } else {
                        /* Target EID */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_target_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_EXT_MAC_ADDR:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Extended MAC address */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_ext_mac_addr, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_RLOC16:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_address_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Mesh Locator */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_rloc16, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_ML_EID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* ML IID */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_ml_eid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_STATUS:
                {
                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Status */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_status, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_LAST_TRANSACTION_TIME:
                {
                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Last transaction time */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_last_transaction_time, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NM_TLV_ROUTER_MASK:
                {
                    /* Check length is consistent */
                    if (tlv_len != 9) {
                        expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        /* Router Mask */
                        proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_router_mask_id_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        /*
                         * | | | | | | | | | | |1|1|1|1|1|1|...|6|
                         * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|...|3|
                         * ---------------------------------------
                         * |1|0|1|1|1|0|0|0|1|1|0|0|0|1|0|1|...
                         *
                         * is sent as 0xb8, 0xc5
                         * and represents table entry for routers 0, 2, 3, 4, 8, 9, 13, 15...
                         */

                        /* Just show the string of octets - best representation for a bit mask */
                        proto_tree_add_item(tlv_tree, hf_thread_address_tlv_router_mask_assigned, tvb, offset, 8, ENC_NA);
                        offset += 8;
                    }
                }
                break;

            case THREAD_NM_TLV_ND_OPTION:
                /* Just show the data */
                proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_nd_option, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_NM_TLV_ND_DATA:
                /* Just show the data. Note there is no icmpv6 options dissector so would have to copy it */
                proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_nd_data, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_NM_TLV_THREAD_NETWORK_DATA:
                if (tlv_len > 0) {
                    sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                    call_dissector(thread_address_nwd_handle, sub_tvb, pinfo, tlv_tree);
                }
                offset += tlv_len;
                break;

            case THREAD_NM_TLV_TIMEOUT:
                if (tlv_len > 4) {
                    expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Time out*/
                    proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_timeout, tvb, offset, tlv_len, ENC_NA);
                }
                offset += tlv_len;


                break;

            case THREAD_NM_TLV_THREAD_NETWORK_NAME:
                if (tlv_len > 16) {
                    expert_add_info(pinfo, proto_root, &ei_thread_bl_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                }
                else {
                    /* Network Name */
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, ENC_ASCII | ENC_UTF_8);
                }
                offset += tlv_len;

                break;

            case THREAD_NM_TLV_IPV6_ADDRESS:
                if ((tlv_len % 16) != 0) {
                    expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                }
                else {
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, tlv_len, ENC_NA);
                     for(int i = 0; i < (tlv_len/16) ; i ++)
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, 16, ENC_NA);
                        offset += 16;
                    }
                }
                offset += tlv_len;
                break;

            default:
                proto_tree_add_item(tlv_tree, hf_thread_bl_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    return tvb_captured_length(tvb);
}

static int
dissect_thread_dg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item    *proto_root;
    proto_tree    *thread_dg_tree;
    proto_tree    *tlv_tree;
    unsigned      offset = 0;
    proto_item    *ti;
    uint8_t       tlv_type;
    uint16_t      tlv_len;
    tlv_len_len_e tlv_len_len;

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_dg, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_dg_tree = proto_item_add_subtree(proto_root, ett_thread_dg);

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_uint8(tvb, offset);
        tlv_len = (uint16_t)tvb_get_uint8(tvb, offset + 1);

        /* TODO: need to make sure this applies to all Diagnostic TLVs */
        if (THREAD_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_len_len = TLV_LEN_LEN16;
        } else {
            tlv_len_len = TLV_LEN_LEN8;
        }

        /* Create the tree */
        ti = proto_tree_add_item(thread_dg_tree, hf_thread_dg_tlv, tvb, offset, 1 + tlv_len_len + tlv_len, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_dg_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_dg_tlv_vals, "Unknown (%d)"));

        /* Length */
        switch (tlv_len_len) {
            case TLV_LEN_LEN8:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case TLV_LEN_LEN16:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_length16, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }
        offset += tlv_len_len;

        switch(tlv_type) {
            case THREAD_DG_TLV_TYPE_LIST:
                {
                    int i;

                    for (i = 0; i < tlv_len; i++) {
                        proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    }
                }
                break;

            case THREAD_DG_TLV_EXT_MAC_ADDR:
            case THREAD_DG_TLV_ADDRESS16:
            case THREAD_DG_TLV_MODE:
            case THREAD_DG_TLV_TIMEOUT:
            case THREAD_DG_TLV_CONNECTIVITY:
            case THREAD_DG_TLV_ROUTE64:
            case THREAD_DG_TLV_LEADER_DATA:
            case THREAD_DG_TLV_NETWORK_DATA:
            case THREAD_DG_TLV_IPV6_ADDR_LIST:
            /* Counters */
            case THREAD_DG_TLV_MAC_COUNTERS:
            case THREAD_DG_TLV_BATTERY_LEVEL:
            case THREAD_DG_TLV_VOLTAGE:
            case THREAD_DG_TLV_CHILD_TABLE:
            case THREAD_DG_TLV_CHANNEL_PAGES:
            case THREAD_DG_TLV_MAX_CHILD_TIMEOUT:
            case THREAD_DG_TLV_LDEVID_SUBJECT_PUBLIC_KEY_INFO:
            case THREAD_DG_TLV_IDEVID_CERTIFICATE:
            case THREAD_DG_TLV_EUI_64:
            case THREAD_DG_TLV_VERSION:
            case THREAD_DG_TLV_VENDOR_NAME:
            case THREAD_DG_TLV_VENDOR_MODEL:
            case THREAD_DG_TLV_VENDOR_SW_VERSION:
            case THREAD_DG_TLV_THREAD_STACK_VERSION:
            case THREAD_DG_TLV_CHILD:
            case THREAD_DG_TLV_CHILD_IPV6_ADDRESS_LIST:
            case THREAD_DG_TLV_ROUTER_NEIGHBOR:
            case THREAD_DG_TLV_ANSWER:
            case THREAD_DG_TLV_QUERY_ID:
            case THREAD_DG_TLV_MLE_COUNTERS:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_general, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            default:
                proto_tree_add_item(tlv_tree, hf_thread_dg_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    return tvb_captured_length(tvb);
}

static int
dissect_thread_mc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item    *proto_root;
    proto_tree    *thread_mc_tree;
    proto_tree    *tlv_tree;
    unsigned      offset = 0;
    proto_item    *ti;
    proto_item    *pi;
    uint8_t       tlv_type;
    uint16_t      tlv_len;
    tlv_len_len_e tlv_len_len;
    unsigned      chancount;


    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_mc, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_mc_tree = proto_item_add_subtree(proto_root, ett_thread_mc);

    /* Get channel count a priori so we can process energy list better */
    chancount = get_chancount(tvb);

    /* Thread Network Data TLVs */
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the type and length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_type = tvb_get_uint8(tvb, offset);
        tlv_len = (uint16_t)tvb_get_uint8(tvb, offset + 1);

        /* TODO: need to make sure this applies to all MeshCoP TLVs */
        if (THREAD_TLV_LENGTH_ESC == tlv_len) {
            /* 16-bit length field */
            tlv_len = tvb_get_ntohs(tvb, offset + 2);
            tlv_len_len = TLV_LEN_LEN16;
        } else {
            tlv_len_len = TLV_LEN_LEN8;
        }

        /* Create the tree */
        ti = proto_tree_add_item(thread_mc_tree, hf_thread_mc_tlv, tvb, offset, 1 + tlv_len_len + tlv_len, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_mc_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_mc_tlv_vals, "Unknown (%d)"));

        /* Length */
        switch (tlv_len_len) {
            case TLV_LEN_LEN8:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case TLV_LEN_LEN16:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_length16, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }
        offset += tlv_len_len;

        switch(tlv_type) {
            case THREAD_MC_TLV_CHANNEL:
                {
                    /* Check length is consistent */
                    if (tlv_len != 3) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Channel page */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_channel_page, tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* Channel */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_channel, tvb, offset+1, 2, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_PANID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_pan_id, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_XPANID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_xpan_id, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NETWORK_NAME:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        //proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, ENC_ASCII | ENC_UTF_8);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_name, tvb, offset, tlv_len, ENC_ASCII | ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_PSKC:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_pskc, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NETWORK_MASTER_KEY:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_master_key, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NETWORK_KEY_SEQ_CTR:
                {
                    /* Check length is consistent */
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_net_key_seq_ctr, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NETWORK_ML_PREFIX:
                {
                    /* Check length is consistent */
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        ws_in6_addr prefix;

                        memset(&prefix, 0, sizeof(prefix));
                        tvb_memcpy(tvb, (uint8_t *)&prefix.bytes, offset, tlv_len);
                        pi = proto_tree_add_ipv6(tlv_tree, hf_thread_mc_tlv_ml_prefix, tvb, offset, tlv_len, &prefix);
                        proto_item_append_text(pi, "/%d", tlv_len * 8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_STEERING_DATA:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Display it simply */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_steering_data, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_BORDER_AGENT_LOCATOR:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ba_locator, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_COMMISSIONER_ID:
                {
                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_commissioner_id, tvb, offset, tlv_len, ENC_NA|ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_COMMISSIONER_SESSION_ID:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_commissioner_sess_id, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_SECURITY_POLICY:
                {
                    /* Check length is consistent */
                    //Thread 1.1 has length 3
                    //Thread 1.2 has length 4
                    //else throw error
                    if (tlv_len == 3) {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_rot, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_o, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_n, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_r, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_b, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_rsv1, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    } else if (tlv_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_rot, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_o, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_n, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_r, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_b, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_ccm, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_ae, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_nmp, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_l, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_ncr, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_sec_policy_vr, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                    } else{
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    }
                }
                break;

            case THREAD_MC_TLV_GET:
                {
                    int i;

                    for (i = 0; i < tlv_len; i++) {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    }
                }
                break;

            case THREAD_MC_TLV_ACTIVE_TSTAMP:
            case THREAD_MC_TLV_PENDING_TSTAMP:
                {
                    nstime_t timestamp;

                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        //proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_pending_tstamp, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Fill in the nstime_t structure */
                        timestamp.secs = (time_t)tvb_get_ntoh48(tvb, offset);
                        timestamp.nsecs = (int)lround((double)(tvb_get_ntohs(tvb, offset + 6) >> 1) * THREAD_MC_32768_TO_NSEC_FACTOR);
                        if (tlv_type == THREAD_MC_TLV_ACTIVE_TSTAMP) {
                            proto_tree_add_time(tlv_tree, hf_thread_mc_tlv_active_tstamp, tvb, offset, 8, &timestamp);
                        } else {
                            proto_tree_add_time(tlv_tree, hf_thread_mc_tlv_pending_tstamp, tvb, offset, 8, &timestamp);
                        }
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_STATE:
                {
                    /* Check length is consistent */
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        //proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_state, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_state, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_JOINER_DTLS_ENCAP:
                {
                    tvbuff_t *sub_tvb;

                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                        call_dissector(thread_dtls_handle, sub_tvb, pinfo, tree);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_COMMISSIONER_UDP_PORT:
            case THREAD_MC_TLV_JOINER_UDP_PORT:
                {
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        //proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_port, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* UDP Port */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_port, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_JOINER_IID:
                {
                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* IID */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_iid, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_JOINER_ROUTER_LOCATOR:
                {
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_jr_locator, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_JOINER_KEK:
                {
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_kek, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_PROVISIONING_URL:
                {
                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_provisioning_url, tvb, offset, tlv_len, ENC_NA|ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_VENDOR_NAME:
                {
                    /* Check length is consistent */
                    if (tlv_len > 32) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_name, tvb, offset, tlv_len, ENC_NA|ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_VENDOR_MODEL:
                {
                    /* Check length is consistent: TODO not specified in spec. */
                    if (tlv_len > 32) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_model, tvb, offset, tlv_len, ENC_NA|ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_VENDOR_SW_VERSION:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_sw_ver, tvb, offset, tlv_len, ENC_NA|ENC_UTF_8);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_VENDOR_DATA:
                {
                    /* Check length is consistent */
                    if (tlv_len > 64) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_too_long);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Display it simply */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_data, tvb, offset, tlv_len, ENC_ASCII);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_VENDOR_STACK_VERSION:
                {
                    /* Check length is consistent */
                    if (tlv_len != 6) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        uint8_t build_u8;
                        uint16_t build;

                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
                        offset += 3;
                        build_u8 = tvb_get_uint8(tvb, offset);
                        offset++;
                        build = (uint16_t)build_u8 << 4;
                        build_u8 = tvb_get_uint8(tvb, offset);
                        build |= (uint16_t)build_u8 >> 4;
                        pi = proto_tree_add_uint(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_build, tvb, 0, 0, build);
                        proto_item_set_generated(pi);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_rev, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_min, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_vendor_stack_ver_maj, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    }
                }
                break;

            case THREAD_MC_TLV_UDP_ENCAPSULATION:
                {
                    tvbuff_t *sub_tvb;
                    uint16_t src_port;
                    uint16_t dst_port;

                    src_port = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_encap_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    dst_port = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_udp_encap_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    if (tlv_len >= 4)
                    {
                        /* Allocate a buffer for the fake UDP datagram and create the fake header. */
                        udp_hdr_t* udp_hdr = (udp_hdr_t *)wmem_alloc(pinfo->pool, sizeof(udp_hdr_t) + (tlv_len - 4));

                        /* Create pseudo UDP header */
                        udp_hdr->src_port = g_htons(src_port);
                        udp_hdr->dst_port = g_htons(dst_port);
                        udp_hdr->length = g_htons(tlv_len + 4); /* Includes UDP header length */
                        udp_hdr->checksum = 0;
                        /* Copy UDP payload in */
                        tvb_memcpy(tvb, udp_hdr + 1, offset, tlv_len - 4);
                        /* Create child tvb */
                        sub_tvb = tvb_new_child_real_data(tvb, (uint8_t *)udp_hdr, tlv_len + 4, tvb_reported_length(tvb) + 4);
                        call_dissector(thread_udp_handle, sub_tvb, pinfo, tree);
                    }
                    offset += (tlv_len-4);
                }
                break;

            case THREAD_MC_TLV_IPV6_ADDRESS:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ipv6_addr, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            /* case THREAD_MC_TLV_PENDING_TSTAMP: Handled in THREAD_MC_TLV_ACTIVE_TSTAMP case */

            case THREAD_MC_TLV_DELAY_TIMER:
                {
                    if (tlv_len != 4) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_delay_timer, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_CHANNEL_MASK:
                {
                    proto_tree *cm_tree;
                    int i;
                    uint8_t entries = 0;
                    int32_t check_len = tlv_len;
                    int check_offset = offset + 1; /* Channel page first */
                    uint16_t masklen;

                    /* Check consistency of entries */
                    while (check_len > 0) {

                        masklen = tvb_get_uint8(tvb, check_offset);
                        if (masklen == 0) {
                            break; /* Get out or we might spin forever */
                        }
                        masklen += 2; /* Add in page and length */
                        check_offset += masklen;
                        check_len -= masklen;
                        entries++;
                    }

                    if (check_len != 0) {
                        /* Not an integer number of entries */
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        for (i = 0; i < entries; i++) {
                            pi = proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_chan_mask, tvb, offset, 1, ENC_NA);
                            cm_tree = proto_item_add_subtree(pi, ett_thread_mc_chan_mask);
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_page, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            masklen = tvb_get_uint8(tvb, offset);
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            proto_tree_add_item(cm_tree, hf_thread_mc_tlv_chan_mask_mask, tvb, offset, masklen, ENC_NA);
                            offset += masklen;
                        }
                    }
                }
                break;

            case THREAD_MC_TLV_COUNT:
                {
                    if (tlv_len != 1) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_count, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_PERIOD:
                {
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_period, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_SCAN_DURATION:
                {
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_scan_duration, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_ENERGY_LIST:
                {
                    proto_tree *it_tree;
                    int i;

                    if ((chancount != THREAD_MC_INVALID_CHAN_COUNT) && (chancount != 0) && ((tlv_len % chancount) == 0)) {
                        /* Go through the number of el_counts of scan */
                        for (i = 0; i < (int)(tlv_len / (uint16_t)chancount); i++) {
                            pi = proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_el_count, tvb, offset, 1, ENC_NA);
                            proto_item_append_text(pi, " %d", i + 1);
                            it_tree = proto_item_add_subtree(pi, ett_thread_mc_el_count);
                            proto_tree_add_item(it_tree, hf_thread_mc_tlv_energy_list, tvb, offset, chancount, ENC_NA);
                            offset += chancount;
                        }
                    } else {
                        /* This might not work but try and display as string */
                        /* Something wrong with channel count so just show it as a simple string */
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_energy_list, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_DOMAIN_NAME:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_domain_name, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_DOMAIN_PREFIX:
                //To be defined in future in draft
                break;

            case THREAD_MC_TLV_AE_STEERING_DATA:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ae_steering_data, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NMKP_STEERING_DATA:
                {
                    /* Check length is consistent */
                    if (tlv_len > 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_nmkp_steering_data, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_COMMISSIONER_TOKEN:
                break;

            case THREAD_MC_TLV_COMMISSIONER_SIGNATURE:
                    proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_commissioner_signature, tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                break;

            case THREAD_MC_TLV_AE_UDP_PORT:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_ae_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_NMKP_UDP_PORT:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_nmkp_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_TRI_HOSTNAME:
                break;

            case THREAD_MC_TLV_REGISTRAR_IPV6_ADDRESS:
                {
                    /* Check length is consistent */
                    if (tlv_len != 16) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_registrar_ipv6_addr, tvb, offset, tlv_len, ENC_NA);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_REGISTRAR_HOSTNAME:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_registrar_hostname, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case THREAD_MC_TLV_COMMISSIONER_PEN_SIGNATURE:
                break;

            case THREAD_MC_TLV_COMMISSIONER_PEN_TOKEN:
                break;

            case THREAD_MC_TLV_DISCOVERY_REQUEST:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_req_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_req_j, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_MC_TLV_DISCOVERY_RESPONSE:
                {
                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_thread_mc_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    } else {
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_rsp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_rsp_n, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_discovery_rsp_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            default:
                proto_tree_add_item(tlv_tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    return tvb_captured_length(tvb);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_thread_nwd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *proto_root;
    proto_tree  *thread_nwd_tree;
    proto_tree  *tlv_tree;
    tvbuff_t    *sub_tvb;
    unsigned    offset = 0, tlv_offset;
    proto_item  *ti;
    uint8_t     tlv_type, tlv_len;
    int         g_server_decode = 1;  /* used to check if the full decoding of Server TLV has to be done or not */

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_thread_nwd, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    thread_nwd_tree = proto_item_add_subtree(proto_root, ett_thread_nwd);

    /* Thread Network Data TLVs */
    increment_dissection_depth(pinfo);
    while (tvb_offset_exists(tvb, offset)) {

        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_uint8(tvb, offset + 1);

        ti = proto_tree_add_item(thread_nwd_tree, hf_thread_nwd_tlv, tvb, offset, tlv_len+2, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        tlv_type = tvb_get_uint8(tvb, offset) >> 1;

        /* Stable */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_stable, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_nwd_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch(tlv_type) {
            case THREAD_NWD_TLV_HAS_ROUTE:
                {
                    /* Has Route TLV can be top level TLV or sub-TLV */

                    /* Check length is consistent */
                    if ((tlv_len % THREAD_NWD_TLV_HAS_ROUTE_SIZE) != 0)
                    {
                        expert_add_info(pinfo, proto_root, &ei_thread_nwd_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        proto_tree *has_route_tree;
                        unsigned i;
                        unsigned count = tlv_len / THREAD_NWD_TLV_HAS_ROUTE_SIZE;

                        /* Add subtrees */
                        for (i = 0; i < count; i++) {
                            ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_has_route, tvb, offset, 1, ENC_NA);
                            has_route_tree = proto_item_add_subtree(ti, ett_thread_nwd_has_route);
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_br_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_pref, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_np, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(has_route_tree, hf_thread_nwd_tlv_has_route_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                        }
                    }
                }
                break;

            case THREAD_NWD_TLV_PREFIX:
                {
                    uint8_t prefix_len;
                    uint8_t prefix_byte_len;
                    ws_in6_addr prefix;
                    address prefix_addr;

                    /* Domain ID */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_prefix_domain_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    tlv_offset = 1;

                    /* Prefix Length */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                    prefix_len = tvb_get_uint8(tvb, offset);
                    prefix_byte_len = (prefix_len + 7) / 8;
                    offset++;
                    tlv_offset++;

                    /* Prefix */
                    memset(&prefix.bytes, 0, sizeof(prefix));
                    if (prefix_byte_len <= sizeof(prefix))
                        tvb_memcpy(tvb, (uint8_t *)&prefix.bytes, offset, prefix_byte_len);
                    proto_tree_add_ipv6(tlv_tree, hf_thread_nwd_tlv_prefix, tvb, offset, prefix_byte_len, &prefix);
                    set_address(&prefix_addr, AT_IPv6, 16, prefix.bytes);
                    proto_item_append_text(ti, " = %s/%d", address_to_str(pinfo->pool, &prefix_addr), prefix_len);
                    offset += prefix_byte_len;
                    tlv_offset += prefix_byte_len;

                    if (tlv_offset < tlv_len) {
                        proto_tree *sub_tlv_tree;
                        unsigned remaining = tlv_len - tlv_offset;

                        ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_sub_tlvs, tvb, offset, 1, ENC_NA);
                        sub_tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_prefix_sub_tlvs);
                        /* Call this dissector for sub-TLVs */
                        sub_tvb = tvb_new_subset_length(tvb, offset, remaining); /* remove prefix length (1) and prefix (prefix_byte_len) */
                        dissect_thread_nwd(sub_tvb, pinfo, sub_tlv_tree, data);
                        offset += remaining;
                    }
                }
                break;

            case THREAD_NWD_TLV_BORDER_ROUTER:
                {
                    /* Border Router TLV can only be sub-TLV */

                    /* Check length is consistent */
                    if ((tlv_len % 4) != 0)
                    {
                        expert_add_info(pinfo, proto_root, &ei_thread_nwd_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        proto_tree *border_router_tree;
                        unsigned i;
                        unsigned count = tlv_len / 4;

                        /* Add subtrees */
                        for (i = 0; i < count; i++) {
                            ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_border_router, tvb, offset, 1, ENC_NA);
                            border_router_tree = proto_item_add_subtree(ti, ett_thread_nwd_border_router);

                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_pref, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_s, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_d, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_r, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_o, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_n, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(border_router_tree, hf_thread_nwd_tlv_border_router_dp, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                        }
                    }
                }
                break;

            case THREAD_NWD_TLV_6LOWPAN_ID:
                {
                    static int * const nwd_6lowpan_flags[] = {
                        &hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved,
                        &hf_thread_nwd_tlv_6lowpan_id_6co_flag_c,
                        &hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid,
                        NULL
                    };

                    /* 6lowpan-ND */
                    proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_thread_nwd_tlv_6lowpan_id_6co_flag, ett_thread_nwd_6co_flag, nwd_6lowpan_flags, ENC_BIG_ENDIAN);
                    offset++;

                    /* Context Length */
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_6lowpan_id_6co_context_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                break;

            case THREAD_NWD_TLV_COMMISSIONING_DATA:
                {
                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(tvb, offset, tlv_len);
                        call_dissector(thread_mc_handle, sub_tvb, pinfo, tlv_tree);
                    }
                    offset += tlv_len;
                }
                break;

            case THREAD_NWD_TLV_SERVICE:
                {
                    uint8_t flags;
                    uint8_t s_data_len;

                    /* Flags and S_id */
                    flags = tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_t, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    tlv_offset = 1;

                    /* Enterprise number */
                    if ((flags & THREAD_NWD_TLV_SERVICE_T) == 0) {
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_ent_num, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        tlv_offset += 4;
                    }

                    /* S_data */
                    s_data_len = tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    tlv_offset++;
                    uint8_t thread_service_data = tvb_get_uint8(tvb, offset);
                    // Thread 1.3 Service TLV code
                    if((s_data_len == 2) && (thread_service_data == 0x5c))
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data, tvb, offset, s_data_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_srp_dataset_identifier, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_anycast_seqno, tvb, offset + 1, 1, ENC_NA);
                        offset += 2;
                        tlv_offset += 2;
                        g_server_decode = 2;
                    } else if(((s_data_len == 1) && (thread_service_data == 0x5d)) || ((s_data_len == 19) && (thread_service_data == 0x5d)))
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data, tvb, offset, s_data_len, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_srp_dataset_identifier, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        tlv_offset += 1;
                        if(s_data_len == 1)
                        {
                            g_server_decode = 3;
                        }
                        else if(s_data_len == 19)
                        {
                            g_server_decode = 2;
                            proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_unicast_ipv6_address, tvb, offset, 16, ENC_NA);
                            proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_unicast_port_number, tvb, offset  + 16, 2, ENC_NA);
                            offset += 18;
                            tlv_offset += 18;
                        }
                    }
                    else
                    {
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data, tvb, offset, s_data_len, ENC_NA);
                        offset += s_data_len;
                        tlv_offset += s_data_len;
                        //Flag to be 1 (BIG_ENDIAN so check the MSB)  and thread_service_data = 1 then Server Sub TLV needs to be decoded with s_server_data fields
                       if(((flags & THREAD_NWD_TLV_SERVICE_T) == THREAD_NWD_TLV_SERVICE_T) &&
                                      (thread_service_data == THREAD_SERVICE_DATA_BBR)) {
                            g_server_decode = 1;
                        }
                        else {
                            g_server_decode = 0;
                        }
                    }

                    // proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data, tvb, offset, s_data_len, ENC_NA);
                    // offset += s_data_len;
                    // tlv_offset += s_data_len;
                    // //Flag to be 1 (BIG_ENDIAN so check the MSB)  and thread_service_data = 1 then Server Sub TLV needs to be decoded with s_server_data fields
                    // if(((flags & THREAD_NWD_TLV_SERVICE_T) == THREAD_NWD_TLV_SERVICE_T) &&
                    //                   (thread_service_data == THREAD_SERVICE_DATA_BBR)) {
                    //     g_server_decode = 1;
                    // }
                    // else {
                    //     g_server_decode = 0;
                    // }
                    // Thread 1.3 Service TLV code

                    /* sub-TLVs */

                    if (tlv_offset < tlv_len) {
                        proto_tree *sub_tlv_tree;
                        unsigned remaining = tlv_len - tlv_offset;

                        ti = proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_sub_tlvs, tvb, offset, 1, ENC_NA);
                        sub_tlv_tree = proto_item_add_subtree(ti, ett_thread_nwd_prefix_sub_tlvs);
                        /* Call this dissector for sub-TLVs. Should only be server TLVs */
                        sub_tvb = tvb_new_subset_length(tvb, offset, remaining); /* remove prefix length (1) and prefix (prefix_byte_len) */
                        dissect_thread_nwd(sub_tvb, pinfo, sub_tlv_tree, data);
                        offset += remaining;
                    }
                }
                break;

            case THREAD_NWD_TLV_SERVER:
                {
                    if(g_server_decode == 1) {
                        //2 bytes of server 16
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        /* tlv_offset = 2; */
                        //7 bytes of server data
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data_seqno, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        /* tlv_offset += 1; */
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data_rrdelay, tvb, offset, 2, ENC_NA);
                        offset += 2;
                        /* tlv_offset += 2; */
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_s_data_mlrtimeout, tvb, offset, 4, ENC_NA);
                        offset += 4;
                    }
                    else if(g_server_decode == 0) {
                        //2 bytes of server 16
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        tlv_offset = 2;

                        if (tlv_offset < tlv_len)
                        {
                            unsigned remaining = tlv_len - tlv_offset;
                            //remaining bytes - server data
                            proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_data, tvb, offset, remaining, ENC_NA);
                            offset += remaining;
                        }

                    }
                    // Thread 1.3 Service TLV code
                    else if(g_server_decode == 2) {
                        //2 bytes of server 16
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        tlv_offset = 2;
                        if (tlv_offset < tlv_len)
                        {
                            unsigned remaining = tlv_len - tlv_offset;
                            //remaining bytes - server data
                            proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_data, tvb, offset, remaining, ENC_NA);
                            offset += remaining;
                        }
                    }
                    else if(g_server_decode == 3) {
                        //2 bytes of server 16
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_16, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        tlv_offset = 2;
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_unicast_ipv6_address, tvb, offset, 16, ENC_NA);
                        proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_service_unicast_port_number, tvb, offset  + 16, 2, ENC_NA);
                        offset += 18;
                        tlv_offset += 18;

                        if (tlv_offset < tlv_len)
                        {
                            unsigned remaining = tlv_len - tlv_offset;
                            //remaining bytes - server data
                            proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_server_data, tvb, offset, remaining, ENC_NA);
                            offset += remaining;
                        }
                    }
                    // Thread 1.3 Service TLV code
                }
                break;

            default:
                proto_tree_add_item(tlv_tree, hf_thread_nwd_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }
    decrement_dissection_depth(pinfo);
    return tvb_captured_length(tvb);
}

static int
dissect_thread_coap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    coap_info           *coinfo;
    const char          *uri;
    char                **tokens;

    /* Obtain the CoAP info */
    coinfo = (coap_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_coap, 0);

    /* Reject the packet if not CoAP */
    if (!coinfo) return 0;

    uri = wmem_strbuf_get_str(coinfo->uri_str_strbuf);

    tokens = wmem_strsplit(pinfo->pool, uri, "/", 3);
    if (g_strv_length(tokens) == 3) {
        /* No need to create a subset as we are dissecting the tvb as it is. */
        dissector_try_string(thread_coap_namespace, tokens[1], tvb, pinfo, tree, NULL);
    }

    return tvb_captured_length(tvb);
}

static int dissect_thread_bcn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;
    proto_item  *ti, *beacon_root;
    proto_tree  *beacon_tree;
    unsigned    offset = 0;
    const uint8_t *ssid;
    uint8_t     tlv_type, tlv_len;
    proto_tree  *tlv_tree = NULL;

    /* Reject the packet if data is NULL */
    if (!packet) return 0;

    /* Add ourself to the protocol column. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Thread");
    /* Create the tree for this beacon. */
    beacon_root = proto_tree_add_item(tree, proto_thread_bcn, tvb, 0, -1, ENC_NA);
    beacon_tree = proto_item_add_subtree(beacon_root, ett_thread_bcn);

    /* Update the info column. */
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Beacon, Src: 0x%04x", packet->src16);

    /* Get and display the protocol id, must be 0x03 on all Thread beacons. */
    proto_tree_add_item(beacon_tree, hf_thread_bcn_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the beacon flags */
    proto_tree_add_item(beacon_tree, hf_thread_bcn_joining, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(beacon_tree, hf_thread_bcn_native, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(beacon_tree, hf_thread_bcn_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Get and display the network ID. */
    proto_tree_add_item_ret_string(beacon_tree, hf_thread_bcn_network_id, tvb, offset, 16, ENC_ASCII|ENC_NA, pinfo->pool, &ssid);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Network ID: %s", ssid);
    offset += 16;

    /* See if we're at the end */
    if (offset >= tvb_captured_length(tvb)) {
        return tvb_captured_length(tvb);
    }

    /* XPANID */
    proto_tree_add_item(beacon_tree, hf_thread_bcn_epid, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* See if we're at the end */
    if (offset >= tvb_captured_length(tvb)) {
        return tvb_captured_length(tvb);
    }

    /* Steering data TLV present */

    /* Get the length ahead of time to pass to next function so we can highlight
       proper amount of bytes */
    tlv_len = tvb_get_uint8(tvb, offset+1);

    /* Type */
    ti = proto_tree_add_item(beacon_tree, hf_thread_bcn_tlv, tvb, offset, tlv_len+2, ENC_NA);
    tlv_tree = proto_item_add_subtree(ti, ett_thread_bcn_tlv);
    proto_tree_add_item(tlv_tree, hf_thread_bcn_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    tlv_type = tvb_get_uint8(tvb, offset);
    offset++;

    /* Add value name to value root label */
    proto_item_append_text(ti, " (%s)", val_to_str(tlv_type, thread_bcn_tlv_vals, "Unknown (%d)"));

    /* Length */
    proto_tree_add_item(tlv_tree, hf_thread_bcn_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (tlv_len) { /* Belt 'n' braces check */
        switch (tlv_type) {
            case THREAD_BCN_TLV_STEERING_DATA:
                proto_tree_add_item(tlv_tree, hf_thread_bcn_tlv_steering_data, tvb, offset, tlv_len, ENC_NA);
                /* offset += tlv_len; */
                break;
            default:
                proto_tree_add_item(tlv_tree, hf_thread_bcn_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                /* offset += tlv_len; */
                break;
        }
    }
    return tvb_captured_length(tvb);
}

static bool
dissect_thread_bcn_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;

    /* Thread beacon frames can be 16 or 64-bit source */
    if (!packet) return false;
    if (!((packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) ||
          (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT))) return false;

    if (tvb_captured_length(tvb) > 0) {
        /* Thread beacons begin with a protocol identifier. */
        if (tvb_get_uint8(tvb, 0) != THREAD_BCN_PROTOCOL_ID) return false;
        dissect_thread_bcn(tvb, pinfo, tree, packet);
        return true;
    }
    return false;
}

void
proto_register_thread_nm(void)
{
        static hf_register_info hf[] = {

            /* Generic TLV */
            { &hf_thread_nm_tlv,
                {   "TLV",
                    "thread_nm.tlv",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "Type-Length-Value",
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_type,
                {   "Type",
                    "thread_nm.tlv.type",
                    FT_UINT8, BASE_DEC, VALS(thread_nm_tlv_vals), 0x0,
                    "Type of value",
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_length,
                {   "Length",
                    "thread_nm.tlv.len",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Length of value",
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_unknown,
                {   "Unknown",
                    "thread_nm.tlv.unknown",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "Unknown TLV, raw value",
                HFILL }
            },
    #if 0
            { &hf_thread_nm_tlv_sub_tlvs,
                {   "Sub-TLV(s)",
                    "thread_nm.tlv.sub_tlvs",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
    #endif
                /* Type-Specific TLV Fields */
            { &hf_thread_nm_tlv_target_eid,
                {   "Target EID",
                    "thread_nm.tlv.target_eid",
                    FT_IPv6, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_ext_mac_addr,
                {   "Extended MAC Address",
                    "thread_nm.tlv.ext_mac_addr",
                    FT_EUI64, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_rloc16,
                {   "RLOC16",
                    "thread_nm.tlv.rloc16",
                    FT_UINT16, BASE_HEX, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_ml_eid,
                {   "ML-EID",
                    "thread_nm.tlv.ml_eid",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_status,
                {   "Status",
                    "thread_nm.tlv.status",
                    FT_UINT8, BASE_DEC, VALS(thread_nm_tlv_status_vals), 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_last_transaction_time,
                {   "Last Transaction Time",
                    "thread_nm.tlv.last_transaction_time",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_router_mask_id_seq,
                {   "ID Sequence",
                    "thread_nm.tlv.router_mask_id_seq",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_router_mask_assigned,
                {   "Assigned Router ID Mask",
                    "thread_nm.tlv.router_mask_assigned",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                 }
            },
            { &hf_thread_nm_tlv_nd_option,
                {   "ND Option",
                    "thread_nm.tlv.nd_option",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_nd_data,
                {   "ND Data",
                    "thread_nm.tlv.nd_data",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
            { &hf_thread_nm_tlv_timeout,
                {   "Timeout",
                    "thread_nm.tlv.timeout",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL,
                    HFILL
                }
            }
        };

        static int *ett[] = {
            &ett_thread_nm,
            &ett_thread_nm_tlv,
        };

        static ei_register_info ei[] = {
#if 0
            { &ei_thread_nm_tlv_length_failed,{ "thread_nm.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL } },
#endif
        { &ei_thread_nm_len_size_mismatch,{ "thread_nm.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL } },
        };

        expert_module_t* expert_thread_nm;

        proto_thread_nm = proto_register_protocol("Thread Network Management", "Thread Network Management", "thread_nm");
        proto_register_field_array(proto_thread_nm, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        expert_thread_nm = expert_register_protocol(proto_thread_nm);
        expert_register_field_array(expert_thread_nm, ei, array_length(ei));

        thread_nm_handle = register_dissector("thread_nm", dissect_thread_nm, proto_thread_nm);
}

void
proto_register_thread_bl(void)
{
        static hf_register_info hf[] = {

            /* Generic TLV */
            { &hf_thread_bl_tlv,
                {   "TLV",
                    "thread_bl.tlv",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "Type-Length-Value",
                    HFILL
                }
            },

            { &hf_thread_bl_tlv_type,
                {   "Type",
                    "thread_bl.tlv.type",
                    FT_UINT8, BASE_DEC, VALS(thread_bl_tlv_vals), 0x0,
                    "Type of value",
                    HFILL
                }
            },

            { &hf_thread_bl_tlv_length,
                {   "Length",
                    "thread_bl.tlv.len",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Length of value",
                    HFILL
                }
            },

            { &hf_thread_bl_tlv_unknown,
                {   "Unknown",
                    "thread_bl.tlv.unknown",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "Unknown TLV, raw value",
                    HFILL
                }
            },
    #if 0
            { &hf_thread_bl_tlv_sub_tlvs,
                {  "Sub-TLV(s)",
                    "thread_bl.tlv.sub_tlvs",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },
    #endif
                /* Type-Specific TLV Fields */
            { &hf_thread_bl_tlv_target_eid,
                {   "Target EID",
                    "thread_bl.tlv.target_eid",
                    FT_IPv6, BASE_NONE, NULL, 0x0,
                    NULL,
                    HFILL
                }
            },

            { &hf_thread_bl_tlv_ext_mac_addr,
            { "Extended MAC Address",
                "thread_bl.tlv.ext_mac_addr",
                FT_EUI64, BASE_NONE, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_rloc16,
            { "RLOC16",
                "thread_bl.tlv.rloc16",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_ml_eid,
            { "ML-EID",
                "thread_bl.tlv.ml_eid",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_status,
            { "Status",
                "thread_bl.tlv.status",
                FT_UINT8, BASE_DEC, VALS(thread_bl_tlv_status_vals), 0x0,
                NULL,
                HFILL }
            },
    #if 0
            { &hf_thread_bl_tlv_attached_time,
            { "Attached Time",
                "thread_bl.tlv.attached_time",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL,
                HFILL }
            },
    #endif
            { &hf_thread_bl_tlv_last_transaction_time,
            { "Last Transaction Time",
                "thread_bl.tlv.last_transaction_time",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_router_mask_id_seq,
            { "ID Sequence",
                "thread_bl.tlv.router_mask_id_seq",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_router_mask_assigned,
            { "Assigned Router ID Mask",
                "thread_bl.tlv.router_mask_assigned",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_nd_option,
            { "ND Option",
                "thread_bl.tlv.nd_option",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL,
                HFILL }
            },

            { &hf_thread_bl_tlv_nd_data,
            { "ND Data",
                "thread_bl.tlv.nd_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL,
                HFILL }
            },
            { &hf_thread_bl_tlv_timeout,
            { "Timeout",
                "thread_bl.tlv.timeout",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL,
                HFILL }
            }



        };

        static int *ett[] = {
            &ett_thread_bl,
            &ett_thread_bl_tlv,
        };

        static ei_register_info ei[] = {
#if 0
            { &ei_thread_bl_tlv_length_failed,{ "thread_bl.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL } },
#endif
        { &ei_thread_bl_len_size_mismatch,{ "thread_bl.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL } },
        };

        expert_module_t* expert_thread_bl;

        proto_thread_bl = proto_register_protocol("Thread Backbone Link", "Thread Backbone Link", "thread_bl");
        proto_register_field_array(proto_thread_bl, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        expert_thread_bl = expert_register_protocol(proto_thread_bl);
        expert_register_field_array(expert_thread_bl, ei, array_length(ei));

        thread_bl_handle = register_dissector("thread_bl", dissect_thread_bl, proto_thread_bl);
}

void
proto_register_thread_address(void)
{
    static hf_register_info hf[] = {

        /* Generic TLV */
        { &hf_thread_address_tlv,
            { "TLV",
            "thread_address.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Type-Length-Value",
            HFILL }
        },

        { &hf_thread_address_tlv_type,
            { "Type",
            "thread_address.tlv.type",
            FT_UINT8, BASE_DEC, VALS(thread_address_tlv_vals), 0x0,
            "Type of value",
            HFILL }
        },

        { &hf_thread_address_tlv_length,
            { "Length",
            "thread_address.tlv.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of value",
            HFILL }
        },

        { &hf_thread_address_tlv_unknown,
            { "Unknown",
            "thread_address.tlv.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Unknown TLV, raw value",
            HFILL }
        },
#if 0
        { &hf_thread_address_tlv_sub_tlvs,
            { "Sub-TLV(s)",
            "thread_address.tlv.sub_tlvs",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },
#endif
        /* Type-Specific TLV Fields */
        { &hf_thread_address_tlv_target_eid,
            { "Target EID",
            "thread_address.tlv.target_eid",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_ext_mac_addr,
            { "Extended MAC Address",
            "thread_address.tlv.ext_mac_addr",
            FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_rloc16,
            { "RLOC16",
            "thread_address.tlv.rloc16",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_ml_eid,
            { "ML-EID",
            "thread_address.tlv.ml_eid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_status,
            { "Status",
            "thread_address.tlv.status",
            FT_UINT8, BASE_DEC, VALS(thread_address_tlv_status_vals), 0x0,
            NULL,
            HFILL }
        },
#if 0
        { &hf_thread_address_tlv_attached_time,
            { "Attached Time",
            "thread_address.tlv.attached_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },
#endif
        { &hf_thread_address_tlv_last_transaction_time,
            { "Last Transaction Time",
            "thread_address.tlv.last_transaction_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_router_mask_id_seq,
            { "ID Sequence",
            "thread_address.tlv.router_mask_id_seq",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_router_mask_assigned,
            { "Assigned Router ID Mask",
            "thread_address.tlv.router_mask_assigned",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_nd_option,
            { "ND Option",
            "thread_address.tlv.nd_option",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_nd_data,
            { "ND Data",
            "thread_address.tlv.nd_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_address_tlv_timeout,
            { "Timeout",
            "thread_address.tlv.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        }
    };

    static int *ett[] = {
        &ett_thread_address,
        &ett_thread_address_tlv,
    };

    static ei_register_info ei[] = {
#if 0
        { &ei_thread_address_tlv_length_failed, { "thread_address.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
#endif
        { &ei_thread_address_len_size_mismatch, { "thread_address.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
    };

    expert_module_t* expert_thread_address;

    proto_thread_address = proto_register_protocol("Thread Address", "Thread Address", "thread_address");
    proto_register_field_array(proto_thread_address, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_thread_address = expert_register_protocol(proto_thread_address);
    expert_register_field_array(expert_thread_address, ei, array_length(ei));

    thread_address_handle = register_dissector("thread_address", dissect_thread_address, proto_thread_address);
}

void
proto_register_thread_dg(void)
{
    static hf_register_info hf[] = {

        /* Generic TLV */
        { &hf_thread_dg_tlv,
            { "TLV",
            "thread_diagnostic.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Type-Length-Value",
            HFILL }
        },

        { &hf_thread_dg_tlv_type,
            { "Type",
            "thread_diagnostic.tlv.type",
            FT_UINT8, BASE_DEC, VALS(thread_dg_tlv_vals), 0x0,
            "Type of value",
            HFILL }
        },

        { &hf_thread_dg_tlv_length8,
            { "Length",
            "thread_diagnostic.tlv.len8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of value (8-bit)",
            HFILL }
        },

        { &hf_thread_dg_tlv_length16,
            { "Length",
            "thread_diagnostic.tlv.len16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of value (16-bit)",
            HFILL }
        },

        { &hf_thread_dg_tlv_general,
            { "General",
            "thread_diagnostic.tlv.general",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "General TLV, raw value",
            HFILL }
        },

        { &hf_thread_dg_tlv_unknown,
            { "Unknown",
            "thread_diagnostic.tlv.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Unknown TLV, raw value",
            HFILL }
        }
    };

    static int *ett[] = {
        &ett_thread_dg,
        &ett_thread_dg_tlv,
    };

#if 0
    static ei_register_info ei[] = {
        { &ei_thread_dg_tlv_length_failed, { "thread_diagnostic.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
        { &ei_thread_dg_len_size_mismatch, { "thread_diagnostic.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
    };

    expert_module_t* expert_thread_dg;
#endif

    proto_thread_dg = proto_register_protocol("Thread Diagnostics", "Thread Diagnostics", "thread_diagnostic");
    proto_register_field_array(proto_thread_dg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
#if 0
    expert_thread_dg = expert_register_protocol(proto_thread_dg);
    expert_register_field_array(expert_thread_dg, ei, array_length(ei));
#endif

    thread_dg_handle = register_dissector("thread_diagnostic", dissect_thread_dg, proto_thread_dg);
}

void
proto_register_thread_mc(void)
{
    static hf_register_info hf[] = {

        /* Generic TLV */
        { &hf_thread_mc_tlv,
            { "TLV",
            "thread_meshcop.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Type-Length-Value",
            HFILL }
        },

        { &hf_thread_mc_tlv_type,
            { "Type",
            "thread_meshcop.tlv.type",
            FT_UINT8, BASE_DEC, VALS(thread_mc_tlv_vals), 0x0,
            "Type of value",
            HFILL }
        },

        { &hf_thread_mc_tlv_length8,
            { "Length",
            "thread_meshcop.tlv.len8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of value (8-bit)",
            HFILL }
        },

        { &hf_thread_mc_tlv_length16,
            { "Length",
            "thread_meshcop.tlv.len16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of value (16-bit)",
            HFILL }
        },

        { &hf_thread_mc_tlv_unknown,
            { "Unknown",
            "thread_meshcop.tlv.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Unknown TLV, raw value",
            HFILL }
        },
#if 0
        { &hf_thread_mc_tlv_sub_tlvs,
            { "Sub-TLV(s)",
            "thread_meshcop.tlv.sub_tlvs",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },
#endif
        /* Type-Specific TLV Fields */
        { &hf_thread_mc_tlv_channel_page,
            { "Channel Page",
            "thread_meshcop.tlv.channel_page",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_channel,
            { "Channel",
            "thread_meshcop.tlv.channel",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_pan_id,
            { "PAN ID",
            "thread_meshcop.tlv.pan_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_xpan_id,
            { "Extended PAN ID",
            "thread_meshcop.tlv.xpan_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_net_name,
            { "Network Name",
            "thread_meshcop.tlv.net_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_pskc,
            { "PSKc",
            "thread_meshcop.tlv.pskc",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_master_key,
            { "Master Key",
            "thread_meshcop.tlv.master_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_net_key_seq_ctr,
            { "Network Key Sequence Counter",
            "thread_meshcop.tlv.net_key_seq_ctr",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_ml_prefix,
            { "Mesh Local Prefix",
            "thread_meshcop.tlv.ml_prefix",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_steering_data,
            { "Steering Data",
            "thread_meshcop.tlv.steering_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_ba_locator,
            { "Border Agent Locator",
            "thread_meshcop.tlv.ba_locator",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_commissioner_id,
            { "Commissioner ID",
            "thread_meshcop.tlv.commissioner_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_commissioner_sess_id,
            { "Commissioner Session ID",
            "thread_meshcop.tlv.commissioner_sess_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_rot,
            { "Rotation Time",
            "thread_meshcop.tlv.sec_policy_rot",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_o,
            { "Out-of-band Commissioning",
            "thread_meshcop.tlv.sec_policy_o",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_MC_SEC_POLICY_MASK_O_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_n,
            { "Native Commissioning",
            "thread_meshcop.tlv.sec_policy_n",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_MC_SEC_POLICY_MASK_N_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_r,
            { "Thread 1.x Routers",
            "thread_meshcop.tlv.sec_policy_r",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_R_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_c,
            { "PSKc-based Commissioning",
            "thread_meshcop.tlv.sec_policy_c",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_MC_SEC_POLICY_MASK_C_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_b,
            { "Thread 1.x Beacons",
            "thread_meshcop.tlv.sec_policy_b",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_MC_SEC_POLICY_MASK_B_MASK,
            NULL,
            HFILL }
        },

         { &hf_thread_mc_tlv_sec_policy_ccm,
            { "Commercial Commissioning Mode Bit disabled",
            "thread_meshcop.tlv.sec_policy_ccm",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_CCM_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_ae,
            { "Autonomous Enrollment disabled",
            "thread_meshcop.tlv.sec_policy_ae",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_AE_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_nmp,
            { "Network Master-key Provisioning disabled",
            "thread_meshcop.tlv.sec_policy_nmp",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_NMP_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_l,
            { "ToBLE Link Enabled",
            "thread_meshcop.tlv.sec_policy_l",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_L_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_ncr,
            { "Non-CCM Routers disabled",
            "thread_meshcop.tlv.sec_policy_ncr",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), THREAD_MC_SEC_POLICY_MASK_NCR_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_rsv,
            { "Reserved Bits",
            "thread_meshcop.tlv.sec_policy_rsv",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_SEC_POLICY_MASK_RSV_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_rsv1,
            { "Reserved Bits",
            "thread_meshcop.tlv.sec_policy_rsv",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_SEC_POLICY_MASK_RSV1_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_sec_policy_vr,
            { "Version-threshold for Routing",
            "thread_meshcop.tlv.sec_policy_vr",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_SEC_POLICY_MASK_VR_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_state,
            { "State",
            "thread_meshcop.tlv.state",
            FT_INT8, BASE_DEC, VALS(thread_mc_state_vals), 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_active_tstamp,
            { "Active Timestamp",
            "thread_meshcop.tlv.active_tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_pending_tstamp,
            { "Pending Timestamp",
            "thread_meshcop.tlv.pending_tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_udp_port,
            { "UDP Port",
            "thread_meshcop.tlv.udp_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_iid,
            { "Interface Identifier",
            "thread_meshcop.tlv.iid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_jr_locator,
            { "Joiner Router Locator",
            "thread_meshcop.tlv.jr_locator",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_kek,
            { "Key Encryption Key (KEK)",
            "thread_meshcop.tlv.kek",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_provisioning_url,
            { "Provisioning URL",
            "thread_meshcop.tlv.provisioning_url",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_name,
            { "Vendor Name",
            "thread_meshcop.tlv.vendor_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_model,
            { "Vendor Model",
            "thread_meshcop.tlv.vendor_model",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_sw_ver,
            { "Vendor Software Version",
            "thread_meshcop.tlv.vendor_sw_ver",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_data,
            { "Vendor Data",
            "thread_meshcop.tlv.vendor_data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_stack_ver_oui,
            { "OUI",
            "thread_meshcop.tlv.vendor_stack_ver_oui",
            FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_stack_ver_build,
            { "Build",
            "thread_meshcop.tlv.vendor_stack_ver_build",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_stack_ver_rev,
            { "Revision",
            "thread_meshcop.tlv.vendor_stack_ver_rev",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_REV_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_stack_ver_min,
            { "Minor",
            "thread_meshcop.tlv.vendor_stack_ver_min",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_MIN_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_vendor_stack_ver_maj,
            { "Major",
            "thread_meshcop.tlv.vendor_stack_ver_maj",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_STACK_VER_MAJ_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_udp_encap_src_port,
            { "Source UDP Port",
            "thread_meshcop.tlv.udp_encap_src_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_udp_encap_dst_port,
            { "Destination UDP Port",
            "thread_meshcop.tlv.udp_encap_dst_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_ipv6_addr,
            { "IPv6 Address",
            "thread_meshcop.tlv.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_delay_timer,
            { "Delay Timer",
            "thread_meshcop.tlv.delay_timer",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_chan_mask,
            { "Channel Mask",
            "thread_meshcop.tlv.chan_mask",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_chan_mask_page,
            { "Channel Page",
            "thread_meshcop.tlv.chan_mask_page",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_chan_mask_len,
            { "Mask Length",
            "thread_meshcop.tlv.chan_mask_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_chan_mask_mask,
            { "Mask",
            "thread_meshcop.tlv.chan_mask_mask",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_el_count,
            { "Count",
            "thread_meshcop.tlv.el_count",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_count,
            { "Count",
            "thread_meshcop.tlv.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_period,
            { "Period",
            "thread_meshcop.tlv.period",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_scan_duration,
            { "Scan Duration",
            "thread_meshcop.tlv.scan_duration",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_energy_list,
            { "Energy List",
            "thread_meshcop.tlv.energy_list",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

         { &hf_thread_mc_tlv_domain_name,
            { "Domain Name",
            "thread_meshcop.tlv.domain_name",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_ae_steering_data,
            { "AE Steering Data",
            "thread_meshcop.tlv.ae_steering_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_nmkp_steering_data,
            { "NMKP Steering Data",
            "thread_meshcop.tlv.nmkp_steering_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_commissioner_signature,
            { "Commissioner Signature",
            "thread_meshcop.tlv.nmkp_commissioner_signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },


        { &hf_thread_mc_tlv_ae_udp_port,
            { "AE UDP Port",
            "thread_meshcop.tlv.ae_udp_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_nmkp_udp_port,
            { "NMKP UDP Port",
            "thread_meshcop.tlv.nmkp_udp_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_registrar_ipv6_addr,
            { "Registrar IPv6 Address",
            "thread_meshcop.tlv.registrar_ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_registrar_hostname,
            { "Registrar IPv6 Hostname",
            "thread_meshcop.tlv.registrar_hostname",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_discovery_req_ver,
            { "Version",
            "thread_meshcop.tlv.discovery_req_ver",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_DISCOVERY_REQ_MASK_VER_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_discovery_req_j,
            { "Joiner Flag",
            "thread_meshcop.tlv.discovery_req_j",
            FT_BOOLEAN, 8, TFS(&thread_mc_tlv_join_intent), THREAD_MC_DISCOVERY_REQ_MASK_J_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_discovery_rsp_ver,
            { "Version",
            "thread_meshcop.tlv.discovery_rsp_ver",
            FT_UINT8, BASE_DEC, NULL, THREAD_MC_DISCOVERY_RSP_MASK_VER_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_discovery_rsp_n,
            { "Native Commissioning",
            "thread_meshcop.tlv.discovery_rsp_n",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_MC_DISCOVERY_RSP_MASK_N_MASK,
            NULL,
            HFILL }
        },

        { &hf_thread_mc_tlv_discovery_rsp_c,
            { "Commercial Commissioning",
            "thread_meshcop.tlv.discovery_rsp_c",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), THREAD_MC_DISCOVERY_RSP_MASK_C_MASK,
            NULL,
            HFILL }
        }
    };

    static int *ett[] = {
        &ett_thread_mc,
        &ett_thread_mc_tlv,
        &ett_thread_mc_chan_mask,
        &ett_thread_mc_el_count
    };

    static ei_register_info ei[] = {
        { &ei_thread_mc_tlv_length_failed, { "thread_meshcop.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
        { &ei_thread_mc_len_size_mismatch, { "thread_meshcop.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
        { &ei_thread_mc_len_too_long, { "thread_meshcop.len_too_long", PI_UNDECODED, PI_WARN, "TLV Length too long", EXPFILL }}
    };

    expert_module_t* expert_thread_mc;

    proto_thread_mc = proto_register_protocol("Thread MeshCoP", "Thread MeshCoP", "thread_meshcop");
    proto_register_field_array(proto_thread_mc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_thread_mc = expert_register_protocol(proto_thread_mc);
    expert_register_field_array(expert_thread_mc, ei, array_length(ei));

    thread_mc_handle = register_dissector("thread_meshcop", dissect_thread_mc, proto_thread_mc);
}

void
proto_register_thread_nwd(void)
{
    static hf_register_info hf[] = {

    /* Generic TLV */
        { &hf_thread_nwd_tlv,
            { "TLV",
            "thread_nwd.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Type-Length-Value",
            HFILL }
        },

        { &hf_thread_nwd_tlv_type,
            { "Type",
            "thread_nwd.tlv.type",
            FT_UINT8, BASE_DEC, VALS(thread_nwd_tlv_vals), THREAD_NWD_TLV_TYPE_M,
            "Type of value",
            HFILL }
        },

        { &hf_thread_nwd_tlv_stable,
            { "Stable",
            "thread_nwd.tlv.stable",
            FT_BOOLEAN, 8, NULL, THREAD_NWD_TLV_STABLE_M,
            "Stability or transience of network data",
            HFILL }
        },

        { &hf_thread_nwd_tlv_length,
            { "Length",
            "thread_nwd.tlv.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of value",
            HFILL }
        },

        { &hf_thread_nwd_tlv_unknown,
            { "Unknown",
            "thread_nwd.tlv.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Unknown TLV, raw value",
            HFILL }
        },

        { &hf_thread_nwd_tlv_sub_tlvs,
            { "Sub-TLV(s)",
            "thread_nwd.tlv.sub_tlvs",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        /* Type-Specific TLV Fields */
        { &hf_thread_nwd_tlv_has_route,
            { "Has Route",
            "thread_nwd.tlv.has_route",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_has_route_br_16,
            { "Border Router 16",
            "thread_nwd.tlv.has_route.br_16",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Has Route Border Router 16-bit address",
            HFILL }
        },

        { &hf_thread_nwd_tlv_has_route_pref,
            { "Preference",
            "thread_nwd.tlv.has_route.pref",
            FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_HAS_ROUTE_PREF,
            "Has Route preference",
            HFILL }
        },

        { &hf_thread_nwd_tlv_has_route_np,
            { "NP",
            "thread_nwd.tlv.has_route.np",
            FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_HAS_ROUTE_NP,
            "Has Route NP",
            HFILL }
        },

        { &hf_thread_nwd_tlv_has_route_reserved,
            { "Reserved",
            "thread_nwd.tlv.has_route.reserved",
            FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_HAS_ROUTE_RESERVED,
            "Has Route Reserved",
            HFILL }
        },

        { &hf_thread_nwd_tlv_prefix_domain_id,
            { "Domain ID",
            "thread_nwd.tlv.prefix.domain_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Prefix Domain ID",
            HFILL }
        },

        { &hf_thread_nwd_tlv_prefix_length,
            { "Prefix Length",
            "thread_nwd.tlv.prefix.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of Prefix",
            HFILL }
        },

        { &hf_thread_nwd_tlv_prefix,
            { "Prefix",
            "thread_nwd.tlv.prefix",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "IPv6 prefix",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router,
            { "Border Router",
            "thread_nwd.tlv.border_router",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_16,
            { "Border Router 16",
            "thread_nwd.tlv.border_router.16",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Border Router 16-bit address",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_pref,
            { "Preference",
            "thread_nwd.tlv.border_router.pref",
            FT_UINT8, BASE_DEC, NULL, THREAD_NWD_TLV_BORDER_ROUTER_PREF,
            "Value of P_preference",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_p,
            { "P Flag",
            "thread_nwd.tlv.border_router.flag.p",
            FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_p), THREAD_NWD_TLV_BORDER_ROUTER_P,
            "Value of P_preferred",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_s,
            { "SLAAC",
            "thread_nwd.tlv.border_router.flag.s",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_NWD_TLV_BORDER_ROUTER_S,
            "Value of P_slaac",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_d,
            { "DHCPv6",
            "thread_nwd.tlv.border_router.flag.d",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), THREAD_NWD_TLV_BORDER_ROUTER_D,
            "Value of P_dhcp",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_c,
            { "C Flag",
            "thread_nwd.tlv.border_router.flag.c",
            FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_c), THREAD_NWD_TLV_BORDER_ROUTER_C,
            "Value of P_configure",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_r,
            { "Default route",
            "thread_nwd.tlv.border_router.flag.r",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), THREAD_NWD_TLV_BORDER_ROUTER_R,
            "Value of P_default",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_o,
            { "O Flag",
            "thread_nwd.tlv.border_router.flag.o",
            FT_BOOLEAN, 8, TFS(&tfs_thread_nwd_tlv_border_router_o), THREAD_NWD_TLV_BORDER_ROUTER_O,
            "Value of P_on_mesh",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_n,
            { "DNS",
            "thread_nwd.tlv.border_router.flag.n",
            FT_BOOLEAN, 8, TFS(&tfs_available_not_available), THREAD_NWD_TLV_BORDER_ROUTER_N,
            "Value of P_nd_dns",
            HFILL }
        },

        { &hf_thread_nwd_tlv_border_router_dp,
            { "DP Flag",
            "thread_nwd.tlv.border_router.flag.dp",
            FT_BOOLEAN, 8, TFS(&tfs_available_not_available), THREAD_NWD_TLV_BORDER_ROUTER_DP,
            "Value of P_dp",
            HFILL }
        },

        { &hf_thread_nwd_tlv_6lowpan_id_6co_flag,
            { "Flag",
            "thread_nwd.tlv.6co.flag",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_c,
            { "Compression Flag",
            "thread_nwd.tlv.6co.flag.c",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_OPT_6CO_FLAG_C,
            "This flag indicates if the context is valid for use in compression",
            HFILL }
        },

        { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_cid,
            { "CID",
            "thread_nwd.tlv.6co.flag.cid",
            FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_CID,
            "Context Identifier for this prefix information",
            HFILL }
        },

        { &hf_thread_nwd_tlv_6lowpan_id_6co_flag_reserved,
            { "Reserved",
            "thread_nwd.tlv.6co.flag.reserved",
            FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_RESERVED,
            "Must be zero",
            HFILL }
        },

        { &hf_thread_nwd_tlv_6lowpan_id_6co_context_length,
            { "Context Length",
            "thread_nwd.tlv.6co.context_length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "The number of leading bits in the Context Prefix field that are valid",
            HFILL }
        },
#if 0
        { &hf_thread_nwd_tlv_comm_data,
            { "Commissioning Data",
            "thread_nwd.tlv.comm_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Contains Thread Commissioning data",
            HFILL }
        },
#endif
        { &hf_thread_nwd_tlv_service_t,
            { "T flag",
            "thread_nwd.tlv.service.t",
            FT_UINT8, BASE_HEX, NULL, THREAD_NWD_TLV_SERVICE_T,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_id,
            { "Service Type ID",
            "thread_nwd.tlv.service.s_id",
            FT_UINT8, BASE_HEX, NULL, THREAD_NWD_TLV_SERVICE_S_ID,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_ent_num,
            { "Enterprise Number",
            "thread_nwd.tlv.service.s_ent_num",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_data_len,
            { "Service Data Length",
            "thread_nwd.tlv.service.s_data_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_data,
            { "Service Data",
            "thread_nwd.tlv.service.s_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Service data in raw bytes",
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_data_seqno,
        { "Service Data - BBR Sequence Number",
            "thread_nwd.tlv.service.s_data.seqno",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Service data in raw bytes",
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_data_rrdelay,
        { "Service Data - Reregistration Delay(s)",
            "thread_nwd.tlv.service.s_data.rrdelay",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Service data in raw bytes",
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_s_data_mlrtimeout,
        { "Service Data - MLR Timeout(s)",
            "thread_nwd.tlv.service.s_data.mlrtimeout",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Service data in raw bytes",
            HFILL }
        },

        { &hf_thread_nwd_tlv_server_16,
            { "Server 16",
            "thread_nwd.tlv.server.16",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Server 16-bit address",
            HFILL }
        },

        { &hf_thread_nwd_tlv_server_data,
            { "Server Data",
            "thread_nwd.tlv.server.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Server data in raw bytes",
            HFILL }
        },

        // Thread 1.3 Service TLV code

        { &hf_thread_nwd_tlv_service_srp_dataset_identifier,
        { "Service Data SRP Dataset Identifier",
            "thread_nwd.tlv.service.srp_dataset_identifier",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL,
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_anycast_seqno,
        { "Service Data Anycast Sequence Number",
           "thread_nwd.tlv.service.anycast_seqno",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Sequence Number of Anycast Dataset",
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_unicast_ipv6_address,
        { "Service Data Unicast Server IPV6 Address",
            "thread_nwd.tlv.service.unicast_server_ipv6_address",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "IPV6 Address of Unicast SRP Server",
            HFILL }
        },

        { &hf_thread_nwd_tlv_service_unicast_port_number,
        { "Service Data Unicast Port Number",
            "thread_nwd.tlv.service.unicast_port_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Port Number of Unicast SRP Server",
            HFILL }
         }

    };

    static int *ett[] = {
        &ett_thread_nwd,
        &ett_thread_nwd_tlv,
        &ett_thread_nwd_has_route,
        &ett_thread_nwd_6co_flag,
        &ett_thread_nwd_border_router,
        &ett_thread_nwd_prefix_sub_tlvs
    };

    static ei_register_info ei[] = {
#if 0
        { &ei_thread_nwd_tlv_length_failed, { "thread_nwd.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
#endif
        { &ei_thread_nwd_len_size_mismatch, { "thread_nwd.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
    };

    expert_module_t* expert_thread_nwd;

    proto_thread_nwd = proto_register_protocol("Thread Network Data", "Thread NWD", "thread_nwd");
    proto_register_field_array(proto_thread_nwd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_thread_nwd = expert_register_protocol(proto_thread_nwd);
    expert_register_field_array(expert_thread_nwd, ei, array_length(ei));

    thread_address_nwd_handle = register_dissector("thread_nwd", dissect_thread_nwd, proto_thread_nwd);
}

void proto_register_thread_bcn(void)
{
    static hf_register_info hf[] = {

        { &hf_thread_bcn_protocol,
        { "Protocol ID",          "thread_bcn.protocol", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_thread_bcn_joining,
        { "Joining",              "thread_bcn.joining", FT_BOOLEAN, 8, NULL, THREAD_BCN_JOINING,
          NULL, HFILL }},

        { &hf_thread_bcn_native,
        { "Native",               "thread_bcn.native", FT_BOOLEAN, 8, NULL, THREAD_BCN_NATIVE,
          NULL, HFILL }},

        { &hf_thread_bcn_version,
        { "Version",              "thread_bcn.version", FT_UINT8, BASE_DEC, NULL, THREAD_BCN_PROTOCOL_VERSION,
          NULL, HFILL }},

        { &hf_thread_bcn_network_id,
        { "Network Name",         "thread_bcn.network_name", FT_STRING, BASE_NONE, NULL, 0x0,
          "A string that uniquely identifies this network.", HFILL }},

        { &hf_thread_bcn_epid,
        { "Extended PAN ID",      "thread_bcn.epid", FT_EUI64, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_thread_bcn_tlv,
        { "TLV",                  "thread_bcn.tlv", FT_NONE, BASE_NONE, NULL, 0x0,
          "Type-Length-Value", HFILL }},

        { &hf_thread_bcn_tlv_type,
        { "Type",                 "thread_bcn.tlv.type", FT_UINT8, BASE_DEC, VALS(thread_bcn_tlv_vals), 0x0,
          "Type of Value", HFILL }},

        { &hf_thread_bcn_tlv_length,
        { "Length",               "thread_bcn.tlv.len", FT_UINT8, BASE_DEC, NULL, 0x0,
          "Length of Value", HFILL }},

        { &hf_thread_bcn_tlv_steering_data,
        { "Steering Data",         "thread_bcn.tlv.steering_data", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Steering data for joining devices", HFILL }},

        { &hf_thread_bcn_tlv_unknown,
        { "Unknown",              "thread_bcn.tlv.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
          "Unknown TLV, raw value", HFILL }}
    };

    /*  NWK Layer subtrees */
    static int *ett[] = {
        &ett_thread_bcn,
        &ett_thread_bcn_tlv
    };

    /* Register the protocol with Wireshark. */
    proto_thread_bcn = proto_register_protocol("Thread Beacon", "Thread Beacon", "thread_bcn");
    proto_register_field_array(proto_thread_bcn, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissectors with Wireshark. */
    register_dissector("thread_bcn", dissect_thread_bcn, proto_thread_bcn);
}

static void
proto_init_thread(void)
{
    /* Reset the sequence counter variables */
    thread_seq_ctr_acqd = false;
    memset(thread_seq_ctr_bytes, 0, 4);
}

void
proto_register_thread(void)
{
    module_t *thread_module;

    proto_thread = proto_register_protocol("Thread", "Thread", "thread");

    thread_module = prefs_register_protocol(proto_thread, NULL);
    prefs_register_obsolete_preference(thread_module, "thr_coap_decode");
    prefs_register_string_preference(thread_module, "thr_seq_ctr",
                                     "Thread sequence counter",
                                     "32-bit sequence counter for hash",
                                     (const char **)&thread_seq_ctr_str);

    prefs_register_bool_preference(thread_module, "thr_use_pan_id_in_key",
                                   "Use PAN ID as first two octets of master key",
                                   "Set if the PAN ID should be used as the first two octets of the master key (PAN ID LSB), (PAN ID MSB), Key[2]...",
                                   &thread_use_pan_id_in_key);

    prefs_register_bool_preference(thread_module, "thr_auto_acq_thr_seq_ctr",
                                   "Automatically acquire Thread sequence counter",
                                   "Set if the Thread sequence counter should be automatically acquired from Key ID mode 2 MLE messages.",
                                   &thread_auto_acq_seq_ctr);

     /*static hf_register_info hf[] = {
        { &hf_ieee802154_thread_ie,
        { "IE header",                       "thread_ie", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_thread_ie_length,
        { "Length",                           "thread_ie.length", FT_UINT16, BASE_DEC, NULL,
                THREAD_IE_LENGTH_MASK, NULL, HFILL }}
     };

      static int *ett[] = {
        &ett_thread_header_ie,
     };*/

    register_init_routine(proto_init_thread);

    // proto_register_field_array(proto_thread_ie, hf, array_length(hf));
   // proto_register_subtree_array(ett, array_length(ett));

    /* Register Dissector */
    register_dissector("thread_ie", dissect_thread_ie, proto_thread_ie);
}

void
proto_register_thread_coap(void)
{
    proto_thread_coap = proto_register_protocol("Thread CoAP", "Thread CoAP", "thread_coap");
    thread_coap_handle = register_dissector("thread_coap", dissect_thread_coap, proto_thread_coap);

    dissector_add_string("coap_tmf_media_type", "application/octet-stream", thread_coap_handle);
    thread_coap_namespace = register_dissector_table("thread.coap_namespace", "Thread CoAP namespace", proto_thread_coap, FT_STRING, STRING_CASE_SENSITIVE);
}

void
proto_reg_handoff_thread_mc(void)
{
    thread_dtls_handle = find_dissector_add_dependency("dtls", proto_thread_mc);
    thread_udp_handle = find_dissector_add_dependency("udp", proto_thread_mc);

    dissector_add_string("thread.coap_namespace", "c", thread_mc_handle);
}

void
proto_reg_handoff_thread_address(void)
{
    dissector_add_string("thread.coap_namespace", "a", thread_address_handle);
    dissector_add_string("thread.coap_namespace", "n", thread_address_handle);
}

void
proto_reg_handoff_thread_nm(void)
{
    dissector_add_string("thread.coap_namespace", "n", thread_nm_handle);
}

void
proto_reg_handoff_thread_bl(void)
{
    dissector_add_string("thread.coap_namespace", "b", thread_bl_handle);
}

void
proto_reg_handoff_thread_dg(void)
{
    dissector_add_string("thread.coap_namespace", "d", thread_dg_handle);
}

void proto_reg_handoff_thread_bcn(void)
{
    /* Register our dissector with IEEE 802.15.4 */
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN_BEACON, dissect_thread_bcn_heur, "Thread Beacon", "thread_wlan_beacon", proto_thread_bcn, HEURISTIC_ENABLE);

    register_mle_key_hash_handler(KEY_HASH_THREAD, set_thread_mle_key);
    register_ieee802154_mac_key_hash_handler(KEY_HASH_THREAD, set_thread_mac_key);
}

void
proto_reg_handoff_thread(void)
{
    /* Thread Content-Format is opaque byte string, i.e. application/octet-stream */
    /* Enable decoding "Internet media type" as Thread over CoAP */
    // dissector_add_for_decode_as("media_type", thread_coap_handle);
    dissector_add_string("media_type", "application/octet-stream", thread_coap_handle);

    proto_coap = proto_get_id_by_filter_name("coap");
}

/**
 *Subdissector command for Thread Specific IEs (Information Elements)
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields (unused).
 *@param tree pointer to command subtree.
 *@param data pointer to the length of the payload IE.
*/
static int
dissect_thread_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{

    proto_tree *subtree;
    //tvbuff_t   *ie_tvb;
    uint16_t    thread_ie;
    uint16_t    id;
    uint16_t    length;
    unsigned    pie_length;
    unsigned    offset = 0;

    static int * fields[] = {
        &hf_ieee802154_thread_ie_id,
        &hf_ieee802154_thread_ie_length,
        NULL
    };

    pie_length = *(int *)data;

    do {
        thread_ie =  tvb_get_letohs(tvb, offset);
        id        = (thread_ie & THREAD_IE_ID_MASK) >> 6;
        length    =  thread_ie & THREAD_IE_LENGTH_MASK;

        /* Create a subtree for this command frame. */
        subtree = proto_tree_add_subtree(tree, tvb, offset, 2+length, ett_thread, NULL, "Thread IE");
        //proto_item_append_text(subtree, ", %s, Length: %d", val_to_str_const(id, ieee802154_zigbee_ie_names, "Unknown"), length);

        proto_tree_add_bitmask(subtree, tvb, offset, hf_ieee802154_thread_ie,
                               ett_thread_ie_fields, fields, ENC_LITTLE_ENDIAN);
        offset += 2;

        switch (id) {
            /*case ZBEE_ZIGBEE_IE_REJOIN:
                dissect_ieee802154_zigbee_rejoin(tvb, pinfo, subtree, &offset);
                break;

            case ZBEE_ZIGBEE_IE_TX_POWER:
                dissect_ieee802154_zigbee_txpower(tvb, pinfo, subtree, &offset);
                break;

            case ZBEE_ZIGBEE_IE_BEACON_PAYLOAD:
                ie_tvb = tvb_new_subset_length(tvb, offset, ZBEE_NWK_BEACON_LENGTH);
                offset += dissect_zbee_beacon(ie_tvb, pinfo, subtree, NULL);
                dissect_ieee802154_superframe(tvb, pinfo, subtree, &offset);
                proto_tree_add_item(subtree, hf_ieee802154_zigbee_ie_source_addr, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;*/

            default:
                if (length > 0) {
                    //proto_tree_add_item(tree, hf_thread_mc_tlv_unknown, tvb, offset, tlv_len, ENC_NA);
                    offset += length;
                }
                break;
        }
    } while (offset < pie_length);
    return tvb_captured_length(tvb);
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
