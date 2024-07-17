/* packet-lldp.c
 * Routines for LLDP dissection
 * By Juan Gonzalez <juan.gonzalez@pikatech.com>
 * Copyright 2005 MITEL
 *
 * July 2005
 * Modified by: Brian Bogora <brian_bogora@mitel.com>
 *
 * October 2014
 * Modified by:
 * Hans-Christian Goeckeritz <hans.christian.goeckeritz@gmx.de>
 * Gregor Miernik <gregor.miernik@hytec.de>
 * Expansion of dissector for Hytec-OUI
 *
 * August 2016
 * Added Avaya IP Phone OUI, Uli Heilmeier <uh@heilmeier.eu>
 *
 * IEEE 802.1AB
 *
 * IEEE 802.1Q for the 802.1 Organizationally Specific TLVs.
 *
 * TIA-1057 for TIA Organizationally Specific TLVs.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/afn.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/wmem_scopes.h>
#include <epan/oui.h>

#include "packet-enip.h"

#define DEFAULT_COLUMN_INFO            1
#define PROFINET_SPECIAL_COLUMN_INFO   2

/* Structure for general station information */
typedef struct _profinet_lldp_column_info {
	/* general information */
	char     *chassis_id_mac;
	char     *chassis_id_locally_assigned;
	char     *port_id_locally_assigned;
	bool is_nos_assigned;
	bool is_port_id_assigned;
}profinet_lldp_column_info;

static int column_info_selection = DEFAULT_COLUMN_INFO;
static bool assume_unrecognized_tlv = false;

static dissector_handle_t lldp_handle;

void proto_register_lldp(void);
void proto_reg_handoff_lldp(void);

static int hf_ex_avaya_tlv_subtype;
static int hf_ex_avaya_hmac_shi;
static int hf_ex_avaya_element_type;
static int hf_ex_avaya_state;
static int hf_ex_avaya_vlan;
static int hf_ex_avaya_mgnt_vlan;
static int hf_ex_avaya_rsvd;
static int hf_ex_avaya_system_id;
static int hf_ex_avaya_status;
static int hf_ex_avaya_i_sid;

static int hf_ex_avaya2_tlv_subtype;
static int hf_ex_avaya2_fabric_connect;
static int hf_ex_avaya2_fabric_numbvlans;
static int hf_ex_avaya2_fabric_bvlanid;
static int hf_ex_avaya2_fabric_sysidlength;
static int hf_ex_avaya2_fabric_sysid;

/* Sub Dissector Tables */
static dissector_table_t oui_unique_code_table;

/* Initialize the protocol and registered fields */
static int proto_lldp;
static int hf_lldp_tlv_type;
static int hf_lldp_tlv_len;
static int hf_lldp_tlv_system_cap;
static int hf_lldp_tlv_system_cap_other;
static int hf_lldp_tlv_system_cap_repeater;
static int hf_lldp_tlv_system_cap_bridge;
static int hf_lldp_tlv_system_cap_wlan_access_pt;
static int hf_lldp_tlv_system_cap_router;
static int hf_lldp_tlv_system_cap_telephone;
static int hf_lldp_tlv_system_cap_docsis_cable_device;
static int hf_lldp_tlv_system_cap_station_only;
static int hf_lldp_tlv_system_cap_cvlan_component;
static int hf_lldp_tlv_system_cap_svlan_component;
static int hf_lldp_tlv_system_cap_tpmr_component;
static int hf_lldp_tlv_system_name;
static int hf_lldp_tlv_system_desc;
static int hf_lldp_tlv_enable_system_cap;
static int hf_lldp_tlv_enable_system_cap_other;
static int hf_lldp_tlv_enable_system_cap_repeater;
static int hf_lldp_tlv_enable_system_cap_bridge;
static int hf_lldp_tlv_enable_system_cap_wlan_access_pt;
static int hf_lldp_tlv_enable_system_cap_router;
static int hf_lldp_tlv_enable_system_cap_telephone;
static int hf_lldp_tlv_enable_system_cap_docsis_cable_device;
static int hf_lldp_tlv_enable_system_cap_station_only;
static int hf_lldp_tlv_enable_system_cap_cvlan_component;
static int hf_lldp_tlv_enable_system_cap_svlan_component;
static int hf_lldp_tlv_enable_system_cap_tpmr_component;
static int hf_chassis_id_subtype;
static int hf_chassis_id;
static int hf_chassis_id_mac;
static int hf_chassis_id_ip4;
static int hf_chassis_id_ip6;
static int hf_port_id_subtype;
static int hf_port_id;
static int hf_port_desc;
static int hf_port_id_mac;
static int hf_lldp_network_address_family;
static int hf_port_id_ip4;
static int hf_port_id_ip6;
static int hf_time_to_live;
static int hf_pdu_type;
static int hf_mgn_address_len;
static int hf_mgn_address_subtype;
static int hf_mgn_addr_ipv4;
static int hf_mgn_addr_ipv6;
static int hf_mgn_addr_hex;
static int hf_mgn_interface_subtype;
static int hf_mgn_interface_number;
static int hf_mgn_oid_len;
static int hf_mgn_obj_id;
static int hf_org_spc_oui;
static int hf_dcbx_type;
static int hf_dcbx_tlv_type;
static int hf_dcbx_tlv_len;
static int hf_dcbx_tlv_oper_version;
static int hf_dcbx_tlv_max_version;
static int hf_dcbx_control_sequence;
static int hf_dcbx_control_ack;
static int hf_dcbx_feature_flag_enabled;
static int hf_dcbx_feature_flag_error;
static int hf_dcbx_feature_flag_willing;
static int hf_dcbx_feature_subtype;
static int hf_dcbx_feature_pgid_reserved;
static int hf_dcbx_feature_pgid_prio_0;
static int hf_dcbx_feature_pgid_prio_1;
static int hf_dcbx_feature_pgid_prio_2;
static int hf_dcbx_feature_pgid_prio_3;
static int hf_dcbx_feature_pgid_prio_4;
static int hf_dcbx_feature_pgid_prio_5;
static int hf_dcbx_feature_pgid_prio_6;
static int hf_dcbx_feature_pgid_prio_7;
static int hf_dcbx_feature_pg_per_0;
static int hf_dcbx_feature_pg_per_1;
static int hf_dcbx_feature_pg_per_2;
static int hf_dcbx_feature_pg_per_3;
static int hf_dcbx_feature_pg_per_4;
static int hf_dcbx_feature_pg_per_5;
static int hf_dcbx_feature_pg_per_6;
static int hf_dcbx_feature_pg_per_7;
static int hf_dcbx_feature_pg_numtcs;
static int hf_dcbx_feature_pfc_prio0;
static int hf_dcbx_feature_pfc_prio1;
static int hf_dcbx_feature_pfc_prio2;
static int hf_dcbx_feature_pfc_prio3;
static int hf_dcbx_feature_pfc_prio4;
static int hf_dcbx_feature_pfc_prio5;
static int hf_dcbx_feature_pfc_prio6;
static int hf_dcbx_feature_pfc_prio7;
static int hf_dcbx_feature_pfc_numtcs;
static int hf_dcbx_feature_app_proto;
static int hf_dcbx_feature_app_selector;
static int hf_dcbx_feature_app_oui;
static int hf_dcbx_feature_app_prio;
static int hf_dcbx_feature_flag_llink_type;
static int hf_ieee_802_1_subtype;
static int hf_ieee_802_1_port_and_vlan_id_flag;
static int hf_ieee_802_1_port_and_vlan_id_flag_supported;
static int hf_ieee_802_1_port_and_vlan_id_flag_enabled;
static int hf_ieee_802_1_port_vlan_id;
static int hf_ieee_802_1_port_proto_vlan_id;
static int hf_ieee_802_1_vlan_id;
static int hf_ieee_802_1_vlan_name_length;
static int hf_ieee_802_1_vlan_name;
static int hf_ieee_802_1_proto_id_length;
static int hf_ieee_802_1_proto_id;
static int hf_ieee_802_1_aggregation_status;
static int hf_ieee_802_1_aggregation_status_cap;
static int hf_ieee_802_1_aggregation_status_enabled;
static int hf_ieee_802_1_aggregation_status_porttype;
static int hf_ieee_802_1_aggregated_port_id;
static int hf_ieee_8021qau_cnpv_prio0;
static int hf_ieee_8021qau_cnpv_prio1;
static int hf_ieee_8021qau_cnpv_prio2;
static int hf_ieee_8021qau_cnpv_prio3;
static int hf_ieee_8021qau_cnpv_prio4;
static int hf_ieee_8021qau_cnpv_prio5;
static int hf_ieee_8021qau_cnpv_prio6;
static int hf_ieee_8021qau_cnpv_prio7;
static int hf_ieee_8021qau_ready_prio0;
static int hf_ieee_8021qau_ready_prio1;
static int hf_ieee_8021qau_ready_prio2;
static int hf_ieee_8021qau_ready_prio3;
static int hf_ieee_8021qau_ready_prio4;
static int hf_ieee_8021qau_ready_prio5;
static int hf_ieee_8021qau_ready_prio6;
static int hf_ieee_8021qau_ready_prio7;
static int hf_ieee_8021az_feature_flag_willing;
static int hf_ieee_8021az_feature_flag_cbs;
static int hf_ieee_8021az_maxtcs;
static int hf_ieee_8021az_tsa_class0;
static int hf_ieee_8021az_tsa_class1;
static int hf_ieee_8021az_tsa_class2;
static int hf_ieee_8021az_tsa_class3;
static int hf_ieee_8021az_tsa_class4;
static int hf_ieee_8021az_tsa_class5;
static int hf_ieee_8021az_tsa_class6;
static int hf_ieee_8021az_tsa_class7;
static int hf_ieee_8021az_feature_flag_mbc;
static int hf_ieee_8021az_pfc_numtcs;
static int hf_ieee_8021az_app_reserved;
static int hf_ieee_8021az_app_prio;
static int hf_ieee_8021az_app_selector;
static int hf_ieee_802_3_subtype;
static int hf_ieee_802_3_mac_phy_auto_neg_status;
static int hf_ieee_802_3_mac_phy_auto_neg_status_supported;
static int hf_ieee_802_3_mac_phy_auto_neg_status_enabled;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_other;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other;
static int hf_ieee_802_3_pmd_mau_type;
static int hf_ieee_802_3_mdi_power_support;
static int hf_ieee_802_3_mdi_power_support_port_class;
static int hf_ieee_802_3_mdi_power_support_pse_power_support;
static int hf_ieee_802_3_mdi_power_support_pse_power_enabled;
static int hf_ieee_802_3_mdi_power_support_pse_pairs;
static int hf_ieee_802_3_mdi_power_pse_pair;
static int hf_ieee_802_3_mdi_power_class;
static int hf_ieee_802_3_mdi_power_type;
static int hf_ieee_802_3_mdi_power_source;
static int hf_ieee_802_3_mdi_power_pd4pid;
static int hf_ieee_802_3_mdi_power_priority;
static int hf_ieee_802_3_mdi_requested_power;
static int hf_ieee_802_3_mdi_allocated_power;

static int hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_a;
static int hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_b;
static int hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_a;
static int hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_b;
static int hf_ieee_802_3_bt_power_status;
static int hf_ieee_802_3_bt_pse_powering_status;
static int hf_ieee_802_3_bt_pd_powered_status;
static int hf_ieee_802_3_bt_pse_power_pairs_ext;
static int hf_ieee_802_3_bt_ds_pwr_class_ext_a;
static int hf_ieee_802_3_bt_ds_pwr_class_ext_b;
static int hf_ieee_802_3_bt_pwr_class_ext;
static int hf_ieee_802_3_bt_system_setup;
static int hf_ieee_802_3_bt_power_type_ext;
static int hf_ieee_802_3_bt_power_pd_load;
static int hf_ieee_802_3_bt_pse_maximum_available_power_value;
static int hf_ieee_802_3_bt_autoclass;
static int hf_ieee_802_3_bt_pse_autoclass_support;
static int hf_ieee_802_3_bt_autoclass_completed;
static int hf_ieee_802_3_bt_autoclass_request;
static int hf_ieee_802_3_bt_autoclass_reserved;
static int hf_ieee_802_3_bt_power_down;
static int hf_ieee_802_3_bt_power_down_request;
static int hf_ieee_802_3_bt_power_down_time;
static int hf_ieee_802_3_aggregation_status;
static int hf_ieee_802_3_aggregation_status_cap;
static int hf_ieee_802_3_aggregation_status_enabled;
static int hf_ieee_802_3_aggregated_port_id;
static int hf_ieee_802_3_max_frame_size;
static int hf_ieee_802_3_eee_transmit;
static int hf_ieee_802_3_eee_receive;
static int hf_ieee_802_3_eee_fallback_receive;
static int hf_ieee_802_3_eee_echo_transmit;
static int hf_ieee_802_3_eee_echo_receive;
static int hf_ieee_802_1qbg_subtype;
static int hf_ieee_802_1qbg_evb_support_caps;
static int hf_ieee_802_1qbg_evb_support_caps_std;
static int hf_ieee_802_1qbg_evb_support_caps_rr;
static int hf_ieee_802_1qbg_evb_support_caps_rte;
static int hf_ieee_802_1qbg_evb_support_caps_ecp;
static int hf_ieee_802_1qbg_evb_support_caps_vdp;
static int hf_ieee_802_1qbg_evb_configure_caps;
static int hf_ieee_802_1qbg_evb_configure_caps_std;
static int hf_ieee_802_1qbg_evb_configure_caps_rr;
static int hf_ieee_802_1qbg_evb_configure_caps_rte;
static int hf_ieee_802_1qbg_evb_configure_caps_ecp;
static int hf_ieee_802_1qbg_evb_configure_caps_vdp;
static int hf_ieee_802_1qbg_evb_supported_vsi;
static int hf_ieee_802_1qbg_evb_configured_vsi;
static int hf_ieee_802_1qbg_evb_retrans_timer;
static int hf_ieee_802_3br_aec;
static int hf_ieee_802_3br_aec_support;
static int hf_ieee_802_3br_aec_enable;
static int hf_ieee_802_3br_aec_active;
static int hf_ieee_802_3br_aec_addfragsize;
static int hf_ieee_802_3br_aec_reserved;
static int hf_media_tlv_subtype;
static int hf_media_tlv_subtype_caps;
static int hf_media_tlv_subtype_caps_llpd;
static int hf_media_tlv_subtype_caps_network_policy;
static int hf_media_tlv_subtype_caps_location_id;
static int hf_media_tlv_subtype_caps_mdi_pse;
static int hf_media_tlv_subtype_caps_mid_pd;
static int hf_media_tlv_subtype_caps_inventory;
static int hf_media_tlv_subtype_class;
static int hf_media_application_type;
static int hf_media_policy_flag;
static int hf_media_tag_flag;
static int hf_media_vlan_id;
static int hf_media_l2_prio;
static int hf_media_dscp;
static int hf_media_loc_data_format;
static int hf_media_loc_lat_resolution;
static int hf_media_loc_lat;
static int hf_media_loc_long_resolution;
static int hf_media_loc_long;
static int hf_media_loc_alt_type;
static int hf_media_loc_alt_resolution;
static int hf_media_loc_alt;
static int hf_media_loc_ver;
static int hf_media_loc_reserved;
static int hf_media_loc_datum;
static int hf_media_civic_lci_length;
static int hf_media_civic_what;
static int hf_media_civic_country;
static int hf_media_civic_addr_type;
static int hf_media_civic_addr_len;
static int hf_media_civic_addr_value;
static int hf_media_ecs;
static int hf_media_power_type;
static int hf_media_power_source;
static int hf_media_power_priority;
static int hf_media_power_value;
static int hf_media_hardware;
static int hf_media_firmware;
static int hf_media_software;
static int hf_media_sn;
static int hf_media_manufacturer;
static int hf_media_model;
static int hf_media_asset;
static int hf_profinet_tlv_subtype;
static int hf_profinet_class2_port_status;
static int hf_profinet_class3_port_status;
static int hf_profinet_class3_port_status_Fragmentation;
static int hf_profinet_class3_port_status_reserved;
static int hf_profinet_class3_port_status_PreambleLength;
static int hf_profinet_port_rx_delay_local;
static int hf_profinet_port_rx_delay_remote;
static int hf_profinet_port_tx_delay_local;
static int hf_profinet_port_tx_delay_remote;
static int hf_profinet_cable_delay_local;
static int hf_profinet_mrp_domain_uuid;
static int hf_profinet_tsn_domain_uuid;
static int hf_profinet_tsn_nme_management_addr;
static int hf_profinet_tsn_nme_management_addr_str_length;
static int hf_profinet_tsn_nme_management_addr_subtype;
static int hf_profinet_tsn_nme_name_uuid;
static int hf_profinet_tsn_nme_parameter_uuid;
static int hf_profinet_time_domain_number;
static int hf_profinet_time_domain_uuid;
static int hf_profinet_time_domain_master_identity;
static int hf_profinet_mrrt_port_status;
static int hf_profinet_cm_mac;
static int hf_profinet_master_source_address;
static int hf_profinet_subdomain_uuid;
static int hf_profinet_ir_data_uuid;
static int hf_profinet_length_of_period_valid;
static int hf_profinet_length_of_period_length;
static int hf_profinet_red_period_begin_valid;
static int hf_profinet_red_period_begin_offset;
static int hf_profinet_orange_period_begin_valid;
static int hf_profinet_orange_period_begin_offset;
static int hf_profinet_green_period_begin_valid;
static int hf_profinet_green_period_begin_offset;
static int hf_cisco_subtype;
static int hf_cisco_upoe;
static int hf_cisco_upoe_supported;
static int hf_cisco_upoe_altb_detection;
static int hf_cisco_upoe_req_spare_pair;
static int hf_cisco_upoe_pse_spare_pair_oper;
static int hf_cisco_aci_portstate;
static int hf_cisco_aci_noderole;
static int hf_cisco_aci_nodeid;
static int hf_cisco_aci_spinelevel;
static int hf_cisco_aci_podid;
static int hf_cisco_aci_fabricname;
static int hf_cisco_aci_apiclist;
static int hf_cisco_aci_apicid;
static int hf_cisco_aci_apicipv4;
static int hf_cisco_aci_apicuuid;
static int hf_cisco_aci_nodeip;
static int hf_cisco_aci_portrole;
static int hf_cisco_aci_version;
static int hf_cisco_aci_fabricvlan;
static int hf_cisco_aci_serialno;
static int hf_cisco_aci_model;
static int hf_cisco_aci_nodename;
static int hf_cisco_aci_portmode;
static int hf_cisco_aci_authcookie;
static int hf_cisco_aci_apicmode;
static int hf_cisco_aci_fabricid;
static int hf_hytec_tlv_subtype;
static int hf_hytec_group;
static int hf_hytec_identifier;
static int hf_hytec_transceiver_vendor_product_revision;
static int hf_hytec_single_mode;
static int hf_hytec_multi_mode_50;
static int hf_hytec_multi_mode_62_5;
static int hf_hytec_tx_current_output_power;
static int hf_hytec_rx_current_input_power;
static int hf_hytec_rx_input_snr;
static int hf_hytec_lineloss;
static int hf_hytec_mac_trace_request;
static int hf_hytec_trace_mac_address;
static int hf_hytec_request_mac_address;
static int hf_hytec_maximum_depth;
static int hf_hytec_mac_trace_reply;
static int hf_hytec_answering_mac_address;
static int hf_hytec_actual_depth;
static int hf_hytec_name_of_replying_device;
static int hf_hytec_outgoing_port_name;
static int hf_hytec_ipv4_address_of_replying_device;
static int hf_hytec_end_of_trace;
static int hf_hytec_ipv6_address_of_replying_device;
static int hf_hytec_incoming_port_name;
static int hf_hytec_trace_identifier;
static int hf_hytec_invalid_object_data;
static int hf_hytec_unknown_identifier_content;
static int hf_avaya_subtype;
static int hf_avaya_poe;
static int hf_avaya_call_server;
static int hf_avaya_cna_server;
static int hf_avaya_file_server;
static int hf_avaya_dot1q;
static int hf_avaya_ipphone;
static int hf_avaya_ipphone_ip;
static int hf_avaya_ipphone_mask;
static int hf_avaya_ipphone_gateway;
static int hf_unknown_subtype;
static int hf_unknown_subtype_content;
static int hf_subtype_content_remaining;
static int hf_iana_subtype;
static int hf_iana_mudurl;
static int hf_onos_subtype;
static int hf_onos_chassis;
static int hf_onos_port;
static int hf_onos_ttl;

/* Initialize the subtree pointers */
static int ett_lldp;
static int ett_chassis_id;
static int ett_port_id;
static int ett_time_to_live;
static int ett_end_of_lldpdu;
static int ett_port_description;
static int ett_system_name;
static int ett_system_desc;
static int ett_system_cap;
static int ett_system_cap_summary;
static int ett_system_cap_enabled;
static int ett_management_address;
static int ett_unknown_tlv;
static int ett_org_spc_def;
static int ett_org_spc_dcbx_cin;
static int ett_org_spc_dcbx_cee;
static int ett_org_spc_dcbx_cee_1;
static int ett_org_spc_dcbx_cee_2;
static int ett_org_spc_dcbx_cee_3;
static int ett_org_spc_dcbx_cee_4;
static int ett_org_spc_dcbx_cin_6;
static int ett_org_spc_dcbx_cee_app;
static int ett_org_spc_ieee_802_1_1;
static int ett_org_spc_ieee_802_1_2;
static int ett_org_spc_ieee_802_1_3;
static int ett_org_spc_ieee_802_1_4;
static int ett_org_spc_ieee_802_1_8;
static int ett_org_spc_ieee_802_1_9;
static int ett_org_spc_ieee_802_1_a;
static int ett_org_spc_ieee_802_1_b;
static int ett_org_spc_ieee_802_1_c;
static int ett_org_spc_ieee_dcbx_app;

static int ett_org_spc_ieee_802_3_1;
static int ett_org_spc_ieee_802_3_2;
static int ett_org_spc_ieee_802_3_3;
static int ett_org_spc_ieee_802_3_4;
static int ett_org_spc_ieee_802_3_5;
static int ett_org_spc_ieee_802_3_7;

static int ett_org_spc_media_1;
static int ett_org_spc_media_2;
static int ett_org_spc_media_3;
static int ett_org_spc_media_4;
static int ett_org_spc_media_5;
static int ett_org_spc_media_6;
static int ett_org_spc_media_7;
static int ett_org_spc_media_8;
static int ett_org_spc_media_9;
static int ett_org_spc_media_10;
static int ett_org_spc_media_11;

static int ett_ex_avayaSubTypes_11;
static int ett_ex_avayaSubTypes_12;
static int ett_ex_avaya2SubTypes_4;
static int ett_org_spc_ProfinetSubTypes_1;
static int ett_org_spc_ProfinetSubTypes_2;
static int ett_org_spc_ProfinetSubTypes_3;
static int ett_org_spc_ProfinetSubTypes_4;
static int ett_org_spc_ProfinetSubTypes_5;
static int ett_org_spc_ProfinetSubTypes_6;
static int ett_org_spc_tlv;
static int ett_port_vlan_flags;
static int ett_802_3_flags;
static int ett_802_3_autoneg_advertised;
static int ett_802_3_power;
static int ett_802_3_bt_power;
static int ett_802_3_bt_system_setup;
static int ett_802_3_bt_autoclass;
static int ett_802_3_bt_power_down;
static int ett_802_3_aggregation;
static int ett_802_1_aggregation;
static int ett_802_1qbg_capabilities_flags;
static int ett_802_3br_capabilities_flags;
static int ett_media_capabilities;
static int ett_profinet_period;
static int ett_cisco_upoe_tlv;
static int ett_avaya_ipphone_tlv;
static int ett_org_spc_hytec_subtype_transceiver;
static int ett_org_spc_hytec_subtype_trace;
static int ett_org_spc_hytec_trace_request;
static int ett_org_spc_hytec_trace_reply;

static expert_field ei_lldp_bad_length;
static expert_field ei_lldp_bad_length_excess;
static expert_field ei_lldp_shutdown_excess_tlv;
static expert_field ei_lldp_bad_type;
static expert_field ei_lldp_tlv_deprecated;

/* TLV Types */
#define END_OF_LLDPDU_TLV_TYPE		0x00
#define CHASSIS_ID_TLV_TYPE		0x01	/* Mandatory */
#define PORT_ID_TLV_TYPE		0x02	/* Mandatory */
#define TIME_TO_LIVE_TLV_TYPE		0x03	/* Mandatory */
#define PORT_DESCRIPTION_TLV_TYPE	0x04
#define SYSTEM_NAME_TLV_TYPE		0x05
#define SYSTEM_DESCRIPTION_TLV_TYPE	0x06
#define SYSTEM_CAPABILITIES_TLV_TYPE	0x07
#define MANAGEMENT_ADDR_TLV_TYPE	0x08
#define ORGANIZATION_SPECIFIC_TLV_TYPE	0x7F

/* Masks */
#define TLV_TYPE_MASK		0xFE00
#define TLV_TYPE(value)		(((value) & TLV_TYPE_MASK) >> 9)
#define TLV_INFO_LEN_MASK	0x01FF
#define TLV_INFO_LEN(value)	((value) & TLV_INFO_LEN_MASK)

static const value_string tlv_types[] = {
	{ END_OF_LLDPDU_TLV_TYPE,		"End of LLDPDU"},
	{ CHASSIS_ID_TLV_TYPE,			"Chassis Id"},
	{ PORT_ID_TLV_TYPE,			"Port Id"},
	{ TIME_TO_LIVE_TLV_TYPE,		"Time to Live"},
	{ PORT_DESCRIPTION_TLV_TYPE,		"Port Description"},
	{ SYSTEM_NAME_TLV_TYPE,			"System Name"},
	{ SYSTEM_DESCRIPTION_TLV_TYPE,		"System Description"},
	{ SYSTEM_CAPABILITIES_TLV_TYPE,		"System Capabilities"},
	{ MANAGEMENT_ADDR_TLV_TYPE,		"Management Address"},
	{ ORGANIZATION_SPECIFIC_TLV_TYPE,	"Organization Specific"},
	{ 0, NULL}
};

static const value_string chassis_id_subtypes[] = {
	{ 0,	"Reserved"},
	{ 1,	"Chassis component"},
	{ 2,	"Interface alias"},
	{ 3,	"Port component"},
	{ 4,	"MAC address"},
	{ 5,	"Network address"},
	{ 6,	"Interface name"},
	{ 7,	"Locally assigned"},
	{ 0, NULL}
};

static const value_string porttype_values[] = {
	{ 0,	"Not specified"},
	{ 1,	"From aggregation port"},
	{ 2,	"From aggregator"},
	{ 3,	"From single-port aggregator"},
	{ 0, NULL}
};

static const value_string port_id_subtypes[] = {
	{ 0,	"Reserved"},
	{ 1,	"Interface alias"},
	{ 2,	"Port component"},
	{ 3,	"MAC address"},
	{ 4,	"Network address"},
	{ 5,	"Interface name"},
	{ 6,	"Agent circuit Id"},
	{ 7,	"Locally assigned"},
	{ 0, NULL}
};

static const value_string interface_subtype_values[] = {
	{ 1,	"Unknown"},
	{ 2,	"ifIndex"},
	{ 3,	"System port number"},
	{ 0, NULL}
};

static const value_string dcbx_protocol_types[] = {
	{ 0x01,	"1.0 CIN" },
	{ 0x02,	"1.01 CEE" },
	{ 0, NULL }
};

static const value_string dcbx_subtypes[] = {
	{ 0x01,	"DCBx Control" },
	{ 0x02,	"Priority Groups" },
	{ 0x03,	"Priority-Based Flow Control" },
	{ 0x04,	"Application Protocol" },
	{ 0x06,	"Logical Link Down" },
	{ 0, NULL }
};

static const value_string dcbx_app_selector[] = {
	{ 0,	"EtherType" },
	{ 1,	"Socket Number" },
	{ 0, NULL }
};

static const value_string dcbx_app_types[] = {
	{ 0xcbc,	"iSCSI" },
	{ 0x8906,	"FCoE" },
	{ 0x8914,	"FiP" },
	{ 0, NULL }
};

static const value_string dcbx_llink_types[] = {
	{ 0x0,	"FCoE Status" },
	{ 0x1,	"LAN Status" },
	{ 0, NULL }
};

/* IEEE 802.1 Subtypes */
static const value_string ieee_802_1_subtypes[] = {
	{ 0x01,	"Port VLAN ID" },			/* 802.1Q - D.2.1 */
	{ 0x02, "Port and Protocol VLAN ID" },		/* 802.1Q - D.2.2 */
	{ 0x03, "VLAN Name" },				/* 802.1Q - D.2.3 */
	{ 0x04, "Protocol Identity" },			/* 802.1Q - D.2.4 */
	{ 0x05, "VID Usage Digest" },			/* 802.1Q - D.2.5 */
	{ 0x06, "Management VID" },			/* 802.1Q - D.2.6 */
	{ 0x07,	"Link Aggregation" },			/* 802.1Q - D.2.7 */
	{ 0x08,	"Congestion Notification" },		/* 802.1Q - D.2.8 */
	{ 0x09, "ETS Configuration" },			/* 802.1Q - D.2.9 */
	{ 0x0A, "ETS Recommendation" },			/* 802.1Q - D.2.10 */
	{ 0x0B, "Priority Flow Control Configuration" },/* 802.1Q - D.2.11 */
	{ 0x0C, "Application Protocol" },		/* 802.1Q - D.2.12 */
	{ 0x0D, "EVB" },				/* 802.1Q - D.2.13 */
	{ 0x0E, "CDCP" },				/* 802.1Q - D.2.14 */
	{ 0x0F, "Port extension" },			/* 802.1BR - B.2 */
	{ 0x10, "Application VLAN" },			/* 802.1Q - D.2.15 */
	{ 0x11, "LRP ECP Discovery" },			/* 802.1CS - C.2.1 */
	{ 0x12, "LRP TCP Discovery" },			/* 802.1CS - C.2.2 */
	{ 0x13, "Congestion Isolation" },		/* 802.1Qcz - D.2.15 */
	{ 0x14, "Topology Recognition" },		/* 802.1Qcz - D.2.16 */
	{ 0, NULL }
};

static const value_string dcbx_ieee_8021az_tsa[] = {
	{ 0,	"Strict Priority" },
	{ 1,	"Credit-Based Shaper" },
	{ 2,	"Enhanced Transmission Selection" },
	/* All other bits Reserved */
	{ 255,	"Vendor Specific Algorithm" },
	{ 0, NULL }
};

static const value_string dcbx_ieee_8021az_sf[] = {
	{ 0,	"Reserved" },
	{ 1,	"Default or Ethertype" },
	{ 2,	"Port over TCP/SCTP" },
	{ 3,	"Port over UDP/DCCP" },
	{ 4,	"Port over TCP/SCTP/UDP/DCCP" },
	{ 5,	"Reserved" },
	{ 6,	"Reserved" },
	{ 7,	"Reserved" },
	{ 0, NULL }
};

/* IEEE 802.3 Subtypes */
static const value_string ieee_802_3_subtypes[] = {
	{ 0x01,	"MAC/PHY Configuration/Status" },
	{ 0x02,	"Power Via MDI" },
	{ 0x03,	"Link Aggregation" },
	{ 0x04,	"Maximum Frame Size" },
	{ 0x05,	"EEE (Energy-Efficient Ethernet)" },
	{ 0x07,	"IEEE 802.3br Additional Ethernet capabilities" },
	{ 0, NULL }
};

/* Media Subtypes */
static const value_string media_subtypes[] = {
	{ 1,	"Media Capabilities" },
	{ 2,	"Network Policy" },
	{ 3,	"Location Identification" },
	{ 4,	"Extended Power-via-MDI" },
	{ 5,	"Inventory - Hardware Revision" },
	{ 6,	"Inventory - Firmware Revision" },
	{ 7,	"Inventory - Software Revision" },
	{ 8,	"Inventory - Serial Number" },
	{ 9,	"Inventory - Manufacturer Name" },
	{ 10,	"Inventory - Model Name" },
	{ 11,	"Inventory - Asset ID" },
	{ 0, NULL }
};

/* Media Class Values */
static const value_string media_class_values[] = {
	{ 0,	"Type Not Defined" },
	{ 1,	"Endpoint Class I" },
	{ 2,	"Endpoint Class II" },
	{ 3,	"Endpoint Class III" },
	{ 4,	"Network Connectivity" },
	{ 0, NULL }
};

/* Media Application Types */
static const value_string media_application_type[] = {
	{ 0,	"Reserved" },
	{ 1,	"Voice" },
	{ 2,	"Voice Signaling" },
	{ 3,	"Guest Voice" },
	{ 4,	"Guest Voice Signaling" },
	{ 5,	"Softphone Voice" },
	{ 6,	"Video Conferencing" },
	{ 7,	"Streaming Video" },
	{ 8,	"Video Signaling" },
	{ 0, NULL }
};

/* PROFINET subtypes */
static const value_string profinet_subtypes[] = {
	{ 1,  "Measured Delay Values" },
	{ 2,  "Port Status" },
	{ 3,  "Alias" },
	{ 4,  "MRP Port Status" },
	{ 5,  "Chassis MAC" },
	{ 6,  "PTCP Status" },
	{ 7,  "MauType Extension" },
	{ 8,  "MRPIC Port Status" },
	{ 9,  "TSN Domain"},
	{ 10, "TSN NME Management Address"},
	{ 11, "TSN NME Name UUID"},
	{ 12, "TSN NME Parameter UUID"},
	{ 13, "AS Working Clock"},
	{ 14, "AS Global Time"},
	{ 0, NULL }
};
/* extreme avaya ap subtypes */
#define EX_AVAYA_SUBTYPE_ELEMENT_TLV 11
#define EX_AVAYA_SUBTYPE_ASSIGNMENT_TLV 12
static const value_string ex_avaya_subtypes[] = {
	{ EX_AVAYA_SUBTYPE_ELEMENT_TLV, "Extreme Fabric Attach Element TLV" },
	{ EX_AVAYA_SUBTYPE_ASSIGNMENT_TLV, "Extreme Fabric Attach Assignment TLV" },
	{ 0, NULL }
};

/* extreme avaya2 (fabric) subtypes */
#define EX_AVAYA2_SUBTYPE_ZTFv2_FC_TLV 4
static const value_string ex_avaya2_subtypes[] = {
	{ EX_AVAYA2_SUBTYPE_ZTFv2_FC_TLV, "Extreme Zero Touch Fabric v2 Fabric Connect TLV" },
	{ 0, NULL }
};

/* ONOS subtypes */
/* https://github.com/opennetworkinglab/onos/blob/master/utils/misc/src/main/java/org/onlab/packet/LLDP.java */
#define ONOS_CHASSIS_TLV_TYPE 1
#define ONOS_PORT_TLV_TYPE 2
#define ONOS_TTL_TLV_TYPE 3
static const value_string onos_subtypes[] = {
	{ ONOS_CHASSIS_TLV_TYPE, "ONOS Chassis" },
	{ ONOS_PORT_TLV_TYPE, "ONOS Port" },
	{ ONOS_TTL_TLV_TYPE, "ONOS TTL" },
	{ 0, NULL }
};


/* Cisco Subtypes */
static const value_string cisco_subtypes[] = {
	/* UPOE: https://www.cisco.com/c/dam/en/us/solutions/collateral/workforce-experience/digital-building/digital-building-partner-guide.pdf */
	{ 0x01, "4-wire Power-via-MDI (UPOE)" },
	/* ACI */
	{ 0xc9, "ACI Port State" },
	{ 0xca, "ACI Node Role" },
	{ 0xcb, "ACI Node ID" },
	{ 0xcc, "ACI Spine Level" },
	{ 0xcd, "ACI Pod ID" },
	{ 0xce, "ACI Fabric Name" },
	{ 0xcf, "ACI Appliance Vector" },
	{ 0xd0, "ACI Node IP" },
	{ 0xd1, "ACI Port Role" },
	{ 0xd2, "ACI Firmware Version" },
	{ 0xd3, "ACI Infra VLAN" },
	{ 0xd4, "ACI Serial Number" },
	{ 0xd6, "ACI Model" },
	{ 0xd7, "ACI Node Name" },
	{ 0xd8, "ACI Port Mode" },
	{ 0xd9, "ACI Authentication Cookie" },
	{ 0xda, "ACI APIC-Mode" },
	{ 0xdb, "ACI Fabric ID" },
	{ 0, NULL }
};

static const true_false_string tfs_desired_not_desired = { "Desired", "Not Desired" };

static const value_string cisco_portstate_vals[] = {
	{ 1,	"In Service" },
	{ 2,	"Out of Service" },
	{ 0, NULL }
};

static const value_string cisco_portrole_vals[] = {
	{ 1,	"Active" },
	{ 2,	"Backup" },
	{ 0, NULL }
};
static const value_string cisco_portmode_vals[] = {
	{ 0,	"Normal" },
	{ 1,	"Recovery Mode" },
	{ 0, NULL }
};

/* Guessing here, the output of apic show commands only has leaf and spine, and
   those values are leaf=2, spine=3 (off by 1) */
static const value_string cisco_noderole_vals[] = {
	{ 0,	"APIC" },
	{ 1,	"Leaf" },
	{ 2,	"Spine" },
	{ 3,	"vLeaf" },
	{ 0, NULL }
};

static const value_string cisco_apicmode_vals[] = {
	{ 0,	"Active" },
	{ 1,	"Standby" },
	{ 0, NULL }
};

/* Avaya Subtypes */
static const value_string avaya_subtypes[] = {
	{ 1, "PoE Conservation Level Support" },
	{ 3, "Call Server IP Address" },
	{ 4, "IP Phone Addresses" },
	{ 5, "CNA Server IP Address" },
	{ 6, "File Server" },
	{ 7, "802.1Q Framing" },
	{ 0, NULL }
};

/* Avaya 802.1Q Framing Subtypes */
static const value_string avaya_dot1q_subtypes[] = {
	{ 1, "Tagging" },
	{ 2, "No Tagging" },
	{ 0, NULL }
};

/* IANA Subtypes */
static const value_string iana_subtypes[] = {
	{  1, "Manufacturer Usage Description URL" },
	{  0, NULL }
};



/* 802.3 Power Class */
static const value_string power_class_802_3[] = {
	{ 1,	"0" },
	{ 2,	"1" },
	{ 3,	"2" },
	{ 4,	"3" },
	{ 5,	"4" },
	{ 0, NULL }
};

/* 802.3bt Extended Power Class */
static const value_string power_class_ext_802_3_bt[] = {
	{  1,	"Class 1" },
	{  2,	"Class 2" },
	{  3,	"Class 3" },
	{  4,	"Class 4" },
	{  5,	"Class 5" },
	{  6,	"Class 6" },
	{  7,	"Class 7" },
	{  8,	"Class 8" },
	{ 15,	"Dual signature" },
	{ 0, NULL }
};

/* 802.3 Power Pair */
static const value_string power_pair_802_3[] = {
	{ 1,	"Signal" },
	{ 2,	"Spare" },
	{ 0, NULL }
};

/* 802.3bt extended powering pairs */
static const value_string power_pairs_ext_802_3_bt[] = {
	{ 0,	"Ignore" },
	{ 1,	"Alternative A" },
	{ 2,	"Alternative B" },
	{ 3,	"Both alternatives" },
	{ 0, NULL }
};

/* 802.3 Power Type */
static const value_string power_type_802_3[] = {
	{ 0,	"Type 2 PSE Device" },
	{ 1,	"Type 2 PD Device" },
	{ 2,	"Type 1 PSE Device" },
	{ 3,	"Type 1 PD Device" },
	{ 0, NULL }
};

/* 802.3bt Extended Power Type */
static const value_string power_type_ext_802_3_bt[] = {
	{ 0,	"Type 3 PSE Device" },
	{ 1,	"Type 4 PSE Device" },
	{ 2,	"Type 3 single-signature PD Device" },
	{ 3,	"Type 3 dual-signature PD Device" },
	{ 4,	"Type 4 single-signature PD Device" },
	{ 5,	"Type 4 dual-signature PD Device" },
	{ 6,	"Reserved/Ignore" },
	{ 7,	"Reserved/Ignore" },
	{ 0, NULL }
};

/* 802.3bt Dual-signature Extended Power Class Mode A|B */
static const value_string power_type_ext_mode_ab_802_3_bt[] = {
	{ 0,	"Reserved/Ignore" },
	{ 1,	"Class 1" },
	{ 2,	"Class 2" },
	{ 3,	"Class 3" },
	{ 4,	"Class 4" },
	{ 5,	"Class 5" },
	{ 6,	"Reserved/Ignore" },
	{ 7,	"Single-signature or 2-pair PD" },
	{ 0, NULL }
};

/* 802.3bt extended PSE powering status */
static const value_string pse_powering_status_802_3_bt[] = {
	{ 0,	"Ignore" },
	{ 1,	"2-pair" },
	{ 2,	"4-pair single-signature" },
	{ 3,	"4-pair dual-signature" },
	{ 0, NULL }
};

/* 802.3bt extended PD powering status */
static const value_string pd_powered_status_802_3_bt[] = {
	{ 0,	"Ignore" },
	{ 1,	"Single-signature PD" },
	{ 2,	"2-pair dual-signature PD" },
	{ 3,	"4-pair dual-signature PD" },
	{ 0, NULL }
};

static const true_false_string tfs_ieee_802_3_pse_pd = { "PSE", "PD" };
static const true_false_string tfs_ieee_802_3_pd_load = { "Isolated", "Not isolated" };
static const true_false_string tfs_unknown_defined = { "Unknown", "Defined" };

/* Power Type */
static const value_string media_power_type[] = {
	{ 0,	"PSE Device" },
	{ 1,	"PD Device" },
	{ 2,	"PSE Device" },
	{ 3,	"PD Device" },
	{ 0, NULL }
};

/* Power Priority */
static const value_string media_power_priority[] = {
	{ 0,	"Unknown" },
	{ 1,	"Critical" },
	{ 2,	"High" },
	{ 3,	"Low" },
	{ 0, NULL }
};

/* Power Sources */
static const value_string media_power_pd_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"PSE" },
	{ 2,	"Local" },
	{ 3,	"PSE and Local" },
	{ 0, NULL }
};
static const value_string media_power_pse_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"Primary Power Source" },
	{ 2,	"Backup Power Source" },
	{ 0, NULL }
};

/* Location data format */
static const value_string location_data_format[] = {
	{ 0,	"Invalid " },
	{ 1,	"Coordinate-based LCI" },
	{ 2,	"Civic Address LCI" },
	{ 3,	"ECS ELIN" },
	{ 0, NULL }
};

/* Altitude Type */
static const value_string altitude_type[] = {
	{ 1,	"Meters" },
	{ 2,	"Floors" },
	{ 0, NULL }
};

/* Datum Type */
static const value_string datum_type_values[] = {
	{ 1,	"WGS84" },
	{ 2,	"NAD83 (Latitude, Longitude) + NAVD88" },
	{ 3,	"NAD83 (Latitude, Longitude) + MLLW" },
	{ 0, NULL }
};

/* Civic Address LCI - What field */
static const value_string civic_address_what_values[] = {
	{ 0,	"Location of the DHCP server" },
	{ 1,	"Location of the network element believed to be closest to the client" },
	{ 2,	"Location of the client"},
	{ 0, NULL}
};

/* Civic Address Type field */
static const value_string civic_address_type_values[] = {
	{ 0,	"Language" },
	{ 1,	"National subdivisions (province, state, etc)" },
	{ 2,	"County, parish, district" },
	{ 3,	"City, township" },
	{ 4,	"City division, borough, ward" },
	{ 5,	"Neighborhood, block" },
	{ 6,	"Street" },
	{ 16,	"Leading street direction" },
	{ 17,	"Trailing street suffix" },
	{ 18,	"Street suffix" },
	{ 19,	"House number" },
	{ 20,	"House number suffix" },
	{ 21,	"Landmark or vanity address" },
	{ 22,	"Additional location information" },
	{ 23,	"Name" },
	{ 24,	"Postal/ZIP code" },
	{ 25,	"Building" },
	{ 26,	"Unit" },
	{ 27,	"Floor" },
	{ 28,	"Room number" },
	{ 29,	"Place type" },
	{ 128,	"Script" },
	{ 0, NULL }
};

/*
 * Define the text strings for the LLDP 802.3 MAC/PHY Configuration/Status
 * Operational MAU Type field.
 *
 * These values are taken from the DESCRIPTION field of the dot3MauType
 * objects defined in RFC 4836
 */

/* from rfc 4836 dot3MauType */
static const value_string operational_mau_type_values[] = {
	{ 0,	"other or unknown" },
	/* rfc 1515 values */
	{ 1,	"AUI - no internal MAU, view from AUI" },
	{ 2,	"10Base5 - thick coax MAU" },
	{ 3,	"Foirl - FOIRL MAU" },
	{ 4,	"10Base2 - thin coax MAU" },
	{ 5,	"10BaseT - UTP MAU" },
	{ 6,	"10BaseFP - passive fiber MAU" },
	{ 7,	"10BaseFB - sync fiber MAU" },
	{ 8,	"10BaseFL - async fiber MAU" },
	{ 9,	"10Broad36 - broadband DTE MAU" },
	/* rfc 2239 updates */
	{ 10,	"10BaseTHD - UTP MAU, half duplex mode" },
	{ 11,	"10BaseTFD - UTP MAU, full duplex mode" },
	{ 12,	"10BaseFLHD - async fiber MAU, half duplex mode" },
	{ 13,	"10BaseFLDF - async fiber MAU, full duplex mode" },
	{ 14,	"10BaseT4 - 4 pair category 3 UTP" },
	{ 15,	"100BaseTXHD - 2 pair category 5 UTP, half duplex mode" },
	{ 16,	"100BaseTXFD - 2 pair category 5 UTP, full duplex mode" },
	{ 17,	"100BaseFXHD - X fiber over PMT, half duplex mode" },
	{ 18,	"100BaseFXFD - X fiber over PMT, full duplex mode" },
	{ 19,	"100BaseT2HD - 2 pair category 3 UTP, half duplex mode" },
	{ 20,	"100BaseT2DF - 2 pair category 3 UTP, full duplex mode" },
	/* rfc 2668 updates */
	{ 21,	"1000BaseXHD - PCS/PMA, unknown PMD, half duplex mode" },
	{ 22,	"1000BaseXFD - PCS/PMA, unknown PMD, full duplex mode" },
	{ 23,	"1000BaseLXHD - Fiber over long-wavelength laser, half duplex mode" },
	{ 24,	"1000BaseLXFD - Fiber over long-wavelength laser, full duplex mode" },
	{ 25,	"1000BaseSXHD - Fiber over short-wavelength laser, half duplex mode" },
	{ 26,	"1000BaseSXFD - Fiber over short-wavelength laser, full duplex mode" },
	{ 27,	"1000BaseCXHD - Copper over 150-Ohm balanced cable, half duplex mode" },
	{ 28,	"1000BaseCXFD - Copper over 150-Ohm balanced cable, full duplex mode" },
	{ 29,	"1000BaseTHD - Four-pair Category 5 UTP, half duplex mode" },
	{ 30,	"1000BaseTFD - Four-pair Category 5 UTP, full duplex mode" },
	/* rfc 3636 updates */
	{ 31,	"10GigBaseX - X PCS/PMA, unknown PMD." },
	{ 32,	"10GigBaseLX4 - X fiber over WWDM optics" },
	{ 33,	"10GigBaseR - R PCS/PMA, unknown PMD." },
	{ 34,	"10GigBaseER - R fiber over 1550 nm optics" },
	{ 35,	"10GigBaseLR - R fiber over 1310 nm optics" },
	{ 36,	"10GigBaseSR - R fiber over 850 nm optics" },
	{ 37,	"10GigBaseW - W PCS/PMA, unknown PMD." },
	{ 38,	"10GigBaseEW - W fiber over 1550 nm optics" },
	{ 39,	"10GigBaseLW - W fiber over 1310 nm optics" },
	{ 40,	"10GigBaseSW - W fiber over 850 nm optics" },
	/* rfc 4836 updates */
	{ 41,	"10GBASE-CX4 - X copper over 8 pair 100-Ohm balanced cable" },
	{ 42,	"2BASE-TL - Voice grade UTP copper, up to 2700m, optional PAF" },
	{ 43,	"10PASS-TS - Voice grade UTP copper, up to 750m, optional PAF" },
	{ 44,	"100BASE-BX10D - One single-mode fiber OLT, long wavelength, 10km" },
	{ 45,	"100BASE-BX10U - One single-mode fiber ONU, long wavelength, 10km" },
	{ 46,	"100BASE-LX10 - One single-mode fiber ONU, long wavelength, 10km" },
	{ 47,	"1000BASE-BX10D - One single-mode fiber OLT, long wavelength, 10km" },
	{ 48,	"1000BASE-BX10U - One single-mode fiber ONU, long wavelength, 10km" },
	{ 49,	"1000BASE-LX10 - Two single-mode fiber, long wavelength, 10km" },
	{ 50,	"1000BASE-PX10D - One single-mode fiber EPON OLT, 10km" },
	{ 51,	"1000BASE-PX10U - One single-mode fiber EPON ONU, 10km" },
	{ 52,	"1000BASE-PX20D - One single-mode fiber EPON OLT, 20km" },
	{ 53,	"1000BASE-PX20U - One single-mode fiber EPON ONU, 20km" },
	{ 0, NULL }
};

/* Hytec Masks */
#define HYTEC_GROUP_MASK				0xE0
#define HYTEC_GROUP_MASK_OFFSET			0
#define HYTEC_GROUP_MASK_SIZE			3
#define HYTEC_IDENTIFIER_MASK			0x1F
#define HYTEC_IDENTIFIER_MASK_OFFSET	HYTEC_GROUP_MASK_SIZE
#define HYTEC_IDENTIFIER_MASK_SIZE		5

/* Hytec Subtypes */
#define HYTEC_SUBTYPE__TRANSCEIVER	1
#define HYTEC_SUBTYPE__TRACE		2

/* Hytec Transceiver Groups */
#define HYTEC_TRANSG__TRANCEIVER_IDENTIFIER				1
#define HYTEC_TRANSG__TRANSCEIVER_BRIDGEABLE_DISTANCE	2
#define HYTEC_TRANSG__MEASUREMENT_DATA					3

/* Hytec Trace Groups */
#define HYTEC_TRACEG__MAC_TRACE 1

/* Hytec Transceiver Identifiers */
#define HYTEC_TID__VENDOR_PRODUCT_REVISION 1

#define HYTEC_TID__VENDOR_PRODUCT_REVISION_STR	"Transceiver vendor, product and revision"

/* Hytec Transceiver Bridgeable Distance Values */
#define HYTEC_TBD__SINGLE_MODE		1
#define HYTEC_TBD__MULTI_MODE_50	2
#define HYTEC_TBD__MULTI_MODE_62_5	3

#define HYTEC_TBD__SINGLE_MODE_STR		"Single mode (9/125 um)"
#define HYTEC_TBD__MULTI_MODE_50_STR	"Multi mode (50/125 um)"
#define HYTEC_TBD__MULTI_MODE_62_5_STR	"Multi mode (62.5/125 um)"


/* Hytec Measurement Data Values */
#define HYTEC_MD__TX_CURRENT_OUTPUT_POWER	1
#define HYTEC_MD__RX_CURRENT_INPUT_POWER	2
#define HYTEC_MD__RX_INPUT_SNR				3
#define HYTEC_MD__LINELOSS					4

#define HYTEC_MD__TX_CURRENT_OUTPUT_POWER_STR	"Tx current output power"
#define HYTEC_MD__RX_CURRENT_INPUT_POWER_STR	"Rx current input power"
#define HYTEC_MD__RX_INPUT_SNR_STR				"Rx input SNR"
#define HYTEC_MD__LINELOSS_STR					"Lineloss"


/* Hytec MAC Trace Values */
#define HYTEC_MC__MAC_TRACE_REQUEST					1
#define HYTEC_MC__MAC_TRACE_REPLY					2
#define HYTEC_MC__NAME_OF_REPLYING_DEVICE			3
#define HYTEC_MC__OUTGOING_PORT_NAME				4
#define HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE	5
#define HYTEC_MC__END_OF_TRACE						6
#define HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE	7
#define HYTEC_MC__INCOMING_PORT_NAME				8
#define HYTEC_MC__TRACE_IDENTIFIER					9

#define HYTEC_MC__MAC_TRACE_REQUEST_STR					"MAC Trace Request"
#define HYTEC_MC__MAC_TRACE_REPLY_STR					"MAC Trace Reply"
#define HYTEC_MC__NAME_OF_REPLYING_DEVICE_STR			"Name of replying device"
#define HYTEC_MC__OUTGOING_PORT_NAME_STR				"Outgoing port name"
#define HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE_STR	"IPv4 address of replying device"
#define HYTEC_MC__END_OF_TRACE_STR						"End of Trace"
#define HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE_STR	"IPv6 address of replying device"
#define HYTEC_MC__INCOMING_PORT_NAME_STR				"Incoming port name"
#define HYTEC_MC__TRACE_IDENTIFIER_STR					"Trace identifier"


static const value_string hytec_subtypes[] = {
	{HYTEC_SUBTYPE__TRANSCEIVER, "Transceiver"},
	{HYTEC_SUBTYPE__TRACE, "Trace"},
	{0, NULL}
};

static const value_string hytec_transceiver_groups[] = {
	{HYTEC_TRANSG__TRANCEIVER_IDENTIFIER, "Transceiver identifier"},
	{HYTEC_TRANSG__TRANSCEIVER_BRIDGEABLE_DISTANCE, "Transceiver bridgeable distance"},
	{HYTEC_TRANSG__MEASUREMENT_DATA, "Measurement data"},
	{0, NULL}
};

static const value_string hytec_trace_groups[] = {
	{HYTEC_TRACEG__MAC_TRACE, "MAC Trace"},
	{0, NULL}
};

static const value_string hytec_tid[] = {
	{HYTEC_TID__VENDOR_PRODUCT_REVISION, HYTEC_TID__VENDOR_PRODUCT_REVISION_STR},
	{0, NULL}
};

static const value_string hytec_tbd[] = {
	{HYTEC_TBD__SINGLE_MODE, HYTEC_TBD__SINGLE_MODE_STR},
	{HYTEC_TBD__MULTI_MODE_50, HYTEC_TBD__MULTI_MODE_50_STR},
	{HYTEC_TBD__MULTI_MODE_62_5, HYTEC_TBD__MULTI_MODE_62_5_STR},
	{0, NULL}
};

static const value_string hytec_md[] = {
	{HYTEC_MD__TX_CURRENT_OUTPUT_POWER, HYTEC_MD__TX_CURRENT_OUTPUT_POWER_STR},
	{HYTEC_MD__RX_CURRENT_INPUT_POWER, HYTEC_MD__RX_CURRENT_INPUT_POWER_STR},
	{HYTEC_MD__RX_INPUT_SNR, HYTEC_MD__RX_INPUT_SNR_STR},
	{HYTEC_MD__LINELOSS, HYTEC_MD__LINELOSS_STR},
	{0, NULL}
};

static const value_string hytec_mc[] = {
	{HYTEC_MC__MAC_TRACE_REQUEST, HYTEC_MC__MAC_TRACE_REQUEST_STR},
	{HYTEC_MC__MAC_TRACE_REPLY, HYTEC_MC__MAC_TRACE_REPLY_STR},
	{HYTEC_MC__NAME_OF_REPLYING_DEVICE, HYTEC_MC__NAME_OF_REPLYING_DEVICE_STR},
	{HYTEC_MC__OUTGOING_PORT_NAME, HYTEC_MC__OUTGOING_PORT_NAME_STR},
	{HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE, HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE_STR},
	{HYTEC_MC__END_OF_TRACE, HYTEC_MC__END_OF_TRACE_STR},
	{HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE, HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE_STR},
	{HYTEC_MC__INCOMING_PORT_NAME, HYTEC_MC__INCOMING_PORT_NAME_STR},
	{HYTEC_MC__TRACE_IDENTIFIER, HYTEC_MC__TRACE_IDENTIFIER_STR},
	{0, NULL}
};


/* System Capabilities */
#define SYSTEM_CAPABILITY_OTHER		0x0001
#define SYSTEM_CAPABILITY_REPEATER	0x0002
#define SYSTEM_CAPABILITY_BRIDGE	0x0004
#define SYSTEM_CAPABILITY_WLAN		0x0008
#define SYSTEM_CAPABILITY_ROUTER	0x0010
#define SYSTEM_CAPABILITY_TELEPHONE	0x0020
#define SYSTEM_CAPABILITY_DOCSIS	0x0040
#define SYSTEM_CAPABILITY_STATION	0x0080
#define SYSTEM_CAPABILITY_CVLAN		0x0100
#define SYSTEM_CAPABILITY_SVLAN		0x0200
#define SYSTEM_CAPABILITY_TPMR		0x0400

/* Media Capabilities */
#define MEDIA_CAPABILITY_LLDP				0x0001
#define MEDIA_CAPABILITY_NETWORK_POLICY			0x0002
#define MEDIA_CAPABILITY_LOCATION_ID			0x0004
#define MEDIA_CAPABILITY_MDI_PSE			0x0008
#define MEDIA_CAPABILITY_MDI_PD				0x0010
#define MEDIA_CAPABILITY_INVENTORY			0x0020

/*
 * Define constants for the LLDP 802.3 MAC/PHY Configuration/Status
 * PMD Auto-Negotiation Advertised Capability field.
 * These values are taken from the ifMauAutoNegCapAdvertisedBits
 * object defined in RFC 3636.
 */

#define AUTONEG_OTHER			0x8000 /* bOther(0),        -- other or unknown */
#define AUTONEG_10BASE_T		0x4000 /* b10baseT(1),      -- 10BASE-T  half duplex mode */
#define AUTONEG_10BASET_FD		0x2000 /* b10baseTFD(2),    -- 10BASE-T  full duplex mode */
#define AUTONEG_100BASE_T4		0x1000 /* b100baseT4(3),    -- 100BASE-T4 */
#define AUTONEG_100BASE_TX		0x0800 /* b100baseTX(4),    -- 100BASE-TX half duplex mode */
#define AUTONEG_100BASE_TXFD		0x0400 /* b100baseTXFD(5),  -- 100BASE-TX full duplex mode */
#define AUTONEG_100BASE_T2		0x0200 /* b100baseT2(6),    -- 100BASE-T2 half duplex mode */
#define AUTONEG_100BASE_T2FD		0x0100 /* b100baseT2FD(7),  -- 100BASE-T2 full duplex mode */
#define AUTONEG_FDX_PAUSE		0x0080 /* bFdxPause(8),     -- PAUSE for full-duplex links */
#define AUTONEG_FDX_APAUSE		0x0040 /* bFdxAPause(9),    -- Asymmetric PAUSE for full-duplex links */
#define AUTONEG_FDX_SPAUSE		0x0020 /* bFdxSPause(10),   -- Symmetric PAUSE for full-duplex links */
#define AUTONEG_FDX_BPAUSE		0x0010 /* bFdxBPause(11),   -- Asymmetric and Symmetric PAUSE for full-duplex links */
#define AUTONEG_1000BASE_X		0x0008 /* b1000baseX(12),   -- 1000BASE-X, -LX, -SX, -CX half duplex mode */
#define AUTONEG_1000BASE_XFD		0x0004 /* b1000baseXFD(13), -- 1000BASE-X, -LX, -SX, -CX full duplex mode */
#define AUTONEG_1000BASE_T		0x0002 /* b1000baseT(14),   -- 1000BASE-T half duplex mode */
#define AUTONEG_1000BASE_TFD		0x0001 /* b1000baseTFD(15)  -- 1000BASE-T full duplex mode */

/* Some vendors interpreted the standard to invert the bitorder:
 * according to a IEEE ruling, this is now officially wrong.
 * See https://gitlab.com/wireshark/wireshark/-/issues/1455
 * for all the gory details
 */

#define INV_AUTONEG_OTHER		0x0001 /* bOther(0),        -- other or unknown */
#define INV_AUTONEG_10BASE_T		0x0002 /* b10baseT(1),      -- 10BASE-T  half duplex mode */
#define INV_AUTONEG_10BASET_FD		0x0004 /* b10baseTFD(2),    -- 10BASE-T  full duplex mode */
#define INV_AUTONEG_100BASE_T4		0x0008 /* b100baseT4(3),    -- 100BASE-T4 */
#define INV_AUTONEG_100BASE_TX		0x0010 /* b100baseTX(4),    -- 100BASE-TX half duplex mode */
#define INV_AUTONEG_100BASE_TXFD	0x0020 /* b100baseTXFD(5),  -- 100BASE-TX full duplex mode */
#define INV_AUTONEG_100BASE_T2		0x0040 /* b100baseT2(6),    -- 100BASE-T2 half duplex mode */
#define INV_AUTONEG_100BASE_T2FD	0x0080 /* b100baseT2FD(7),  -- 100BASE-T2 full duplex mode */
#define INV_AUTONEG_FDX_PAUSE		0x0100 /* bFdxPause(8),     -- PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_APAUSE		0x0200 /* bFdxAPause(9),    -- Asymmetric PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_SPAUSE		0x0400 /* bFdxSPause(10),   -- Symmetric PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_BPAUSE		0x0800 /* bFdxBPause(11),   -- Asymmetric and Symmetric PAUSE for full-duplex links */
#define INV_AUTONEG_1000BASE_X		0x1000 /* b1000baseX(12),   -- 1000BASE-X, -LX, -SX, -CX half duplex mode */
#define INV_AUTONEG_1000BASE_XFD	0x2000 /* b1000baseXFD(13), -- 1000BASE-X, -LX, -SX, -CX full duplex mode */
#define INV_AUTONEG_1000BASE_T		0x4000 /* b1000baseT(14),   -- 1000BASE-T half duplex mode */
#define INV_AUTONEG_1000BASE_TFD	0x8000 /* b1000baseTFD(15)  -- 1000BASE-T full duplex mode */

#define EVB_CAPA_STD		0x8000
#define EVB_CAPA_RR		0x4000

#define EVB_CAPA_RTE		0x0004
#define EVB_CAPA_ECP		0x0002
#define EVB_CAPA_VDP		0x0001

/* IEEE 802.3br Additional Ethernet Capabilities flags */
#define IEEE_802_3BR_AEC_SUPPORT		0x0001
#define IEEE_802_3BR_AEC_ENABLE			0x0002
#define IEEE_802_3BR_AEC_ACTIVE			0x0004
#define IEEE_802_3BR_AEC_ADDFRAGSIZE		0x0018
#define IEEE_802_3BR_AEC_RESERVED		0xFFE0

#define MAX_MAC_LEN	6


static const value_string profinet_port2_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"SYNCDATA_LOADED" },
	{ 2,	"RTCLASS2_UP" },
	{ 3,	"Reserved" },
	/* all other bits reserved */
	{ 0,	NULL }
};

static const value_string profinet_port3_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"reserved" },
	{ 2,	"RTCLASS3_UP" },
	{ 3,	"RTCLASS3_DOWN" },
	{ 4,	"RTCLASS3_RUN" },
	/* all other bits reserved */
	{ 0,	NULL }
};

static const value_string profinet_port3_status_PreambleLength[] = {
	{ 0,	"Seven octets" },
	{ 1,	"One octet" },
	{ 0,	NULL }
};
static const value_string profinet_mrrt_port_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"MRRT_CONFIGURED" },
	{ 2,	"MRRT_UP" },
	/* all other bits reserved */
	{ 0,	NULL }
};
static const value_string profinet_time_domain_number_vals[] = {
    { 0x0000, "Global Time" },
    { 0x0001, "Global Time Redundant" },
    { 0x0020, "Working Clock" },
    { 0x0021, "Working Clock Redundant" },
    { 0, NULL }
};

/* IEEE 802.1Qbg Subtypes */
static const value_string ieee_802_1qbg_subtypes[] = {
	{ 0x00,	"EVB" },
	{ 0x01,	"CDCP" },
	{ 0x02,	"VDP" },
	{ 0, NULL }
};

static const unit_name_string units_m = { " m", NULL };

static void
mdi_power_base(char *buf, uint32_t value) {
	snprintf(buf, ITEM_LABEL_LENGTH, "%u.%u. Watt", value/10, value%10);
}

static void
media_power_base(char *buf, uint32_t value) {
	snprintf(buf, ITEM_LABEL_LENGTH, "%u mW", value * 100);
}

// Get absolute 2's complement value
// Returns true if the value is negative (so if
// it returns false, there is no conversion).
//  bitSize: number of bits of the variable.
static bool
get2sComplementAbsoluteValue(uint64_t * value, unsigned bitSize){
	const uint64_t signMask = INT64_C(0x1) << (bitSize - 1);

	uint64_t signedMask = INT64_C(0x1) << bitSize;
	signedMask--;
	signedMask = ~signedMask;

	if(*value & signMask){
		*value |= signedMask; // sign propagation

		// Convert to absolute value
		*value = ~(*value);
		(*value)++;
		return true;
	}
	return false;
}

static uint64_t
getUint64MaskedValue(uint64_t value, unsigned bitSize){
	uint64_t mask = INT64_C(0x1) << bitSize;
	mask--;
	return value & mask;
}

static uint64_t
pow10_uint64(int exponent){
	uint64_t val = 1;

	while(exponent > 0){
		val *= 10;
		exponent--;
	}

	while(exponent < 0){
		val /= 10;
		exponent++;
	}
	return val;
}

// Decode uint fractional variable
static uint64_t
convertFractionalToFixedSizeDecimal(uint64_t value, unsigned fractionalBitSize, unsigned numberOfDigitToDisplay){
	const uint64_t resolution = INT64_C(0x1) << fractionalBitSize;
	// => 0x02000000 for 25-bits
	// => 0x00000100 for 8-bits

	const uint64_t fractionalPortionMask = resolution - 1;
	value &= fractionalPortionMask;

	// Maximum value for numberOfDigitToDisplay is :
	// log10(INT64_C(0xFFFFFFFFFFFFFFFF) / fractionalPortionMask);
	// => if result is stored in 32-bits, numberOfDigitToDisplay max = 9
	const uint64_t displayMultiplier = pow10_uint64(numberOfDigitToDisplay);
	value *= displayMultiplier;
	uint64_t moduloValue = value % resolution;
	value /= resolution;
    if(moduloValue >= (resolution/2)){
        value++; // rounded value
    }

	return value;
}


/* Calculate Latitude and Longitude string */
/*
	Parameters:
		option = 0 -> Latitude
		option = 1 -> Longitude
*/
static void
get_latitude_or_longitude(char *buf, int option, uint64_t unmasked_value)
{
	/* The latitude and longitude are 34 bit fixed point value consisting
	   of 9 bits of integer and 25 bits of fraction.
	   When option is equal to 0, positive numbers are represent a location
	   north of the equator and negative (2s complement) numbers are south of the equator.
	   When option is equal to 1, positive values are east of the prime
	   meridian and negative (2s complement) numbers are west of the prime meridian.
	   Longitude values outside the range of -180 to 180 decimal degrees or latitude values
	   outside the range of -90 to 90 degrees MUST be considered invalid.
	*/
	const unsigned variableBitSize = 34;
	const unsigned fractionalBitSize = 25;
	const uint64_t maxlatitude = (INT64_C(0x1) << fractionalBitSize) * INT64_C(90);   // 90 degrees
	const uint64_t maxlongitude = (INT64_C(0x1) << fractionalBitSize) * INT64_C(180); // 180 degrees

	uint64_t masked_value = getUint64MaskedValue(unmasked_value, variableBitSize); // get 34-bit value

	// Get absolute value of a 34-bit 2's variable
	// => value is 33-bit
	uint64_t absolute_value = masked_value;
	bool isNegative = get2sComplementAbsoluteValue(&absolute_value, variableBitSize);

	// Get unsigned integer 8-bit value
	uint32_t integerPortion = (uint32_t)(absolute_value >> fractionalBitSize);

	// Get fractional 25-bit value
	const unsigned numberOfDigitToDisplay = 4;
	uint64_t fixedSizeDecimal = convertFractionalToFixedSizeDecimal(absolute_value, fractionalBitSize, numberOfDigitToDisplay);

	const char *direction;
	const char *err_str = "";
	if (option == 0){
		// Latitude - north/south directions
		if (isNegative){
			direction = "South";
		} else {
			direction = "North";
		}
		if(absolute_value > maxlatitude){
			err_str = "[Error: value > 90 degrees] ";
		}
	} else {
		// Longitude - east/west directions
		if (isNegative){
			direction = "West";
		} else {
			direction = "East";
		}
		if(absolute_value > maxlongitude){
			err_str = "[Error: value > 180 degrees] ";
		}
	}

	const uint64_t fractionalMask = (INT64_C(0x1) << fractionalBitSize) - 1;

	// %04 correspond to numberOfDigitToDisplay
	snprintf(buf, ITEM_LABEL_LENGTH, "%s%u.%04" PRIu64 " degrees %s (0x%010" PRIX64 " - %u-bit integer part 0x%04" PRIX64 " / %u-bit fractional part 0x%08" PRIX64 ")",
	    err_str,
		integerPortion, fixedSizeDecimal, direction, masked_value,
		variableBitSize - fractionalBitSize, masked_value >> fractionalBitSize,
		fractionalBitSize, masked_value & fractionalMask
	);
}

static void
latitude_base(char *buf, uint64_t value) {
	get_latitude_or_longitude(buf, 0, value);
}

static void
longitude_base(char *buf, uint64_t value) {
	get_latitude_or_longitude(buf, 1, value);
}

static void
altitude_base(char *buf, uint32_t unmasked_value) {
	// RFC6225
	// Altitude: A 30-bit value defined by the AType field.
	// In some cases, the altitude of the location might not be provided.
	// An Altitude Type value of zero indicates that the altitude is not
	// given to the client.  In this case, the Altitude and Altitude
	// Uncertainty fields can contain any value and MUST be ignored.
	//
	// If the Altitude Type has a value of one, altitude is measured in
	// meters, in relation to the zero set by the vertical datum.  For AType
	// = 1, the altitude value is expressed as a 30-bit, fixed-point, two's
	// complement integer with 22 integer bits and 8 fractional bits.
	//
	// A value of two for Altitude Type indicates that the altitude value is
	// measured in floors.  Since altitude in meters may not be known within
	// a building, a floor indication may be more useful.  For AType = 2,
	// the altitude value is expressed as a 30-bit, fixed-point, two's
	// complement integer with 22 integer bits and 8 fractional bits.
	//
	// the altitude resolution (AltRes) value encodes the number of
	// high-order altitude bits that should be considered valid.
	// Values above 30 (decimal) are undefined and reserved.

	const unsigned variableBitSize = 30;
	const unsigned fractionalBitSize = 8;

	uint64_t masked_value = getUint64MaskedValue(unmasked_value, variableBitSize); // get 30-bit value

	// Get absolute value of a 30-bit 2's variable
	// => value is 29-bit
	uint64_t absolute_value = masked_value;
	bool isNegative = get2sComplementAbsoluteValue(&absolute_value, variableBitSize);

	// Get unsigned integer 8-bit value
	uint32_t integerPortion = (uint32_t)(absolute_value >> fractionalBitSize);

	// Get fractional 8-bit value
	const unsigned numberOfDigitToDisplay = 4;
	uint64_t fixedSizeDecimal = convertFractionalToFixedSizeDecimal(absolute_value, fractionalBitSize, numberOfDigitToDisplay);

	const char * sign;
	if (isNegative){
		sign = "-";
	} else {
		sign = "+";
	}


	const uint64_t fractionalMask = (INT64_C(0x1) << fractionalBitSize) - 1;

	// %04 correspond to numberOfDigitToDisplay
	snprintf(buf, ITEM_LABEL_LENGTH, "%s%u.%04" PRIu64 " (0x%08" PRIX64 " - %u-bit integer part 0x%06" PRIX64 " / %u-bit fractional part 0x%02" PRIX64 ")",
	    sign, integerPortion, fixedSizeDecimal, masked_value,
		variableBitSize - fractionalBitSize, masked_value >> fractionalBitSize,
		fractionalBitSize, masked_value & fractionalMask
	);
}

static void
latitude_or_longitude_resolution(char *buf, uint8_t value) {
	// formula, where x is the encoded integer value:
	//      Uncertainty = 2 ^ ( 8 - x )

	int32_t masked_value = value & 0x3F;
	double resolution = 1.0;
	int32_t i = 8 - masked_value;
	while(i > 0){
		resolution *= 2.0;
		i--;
	}
	while(i < 0){
		resolution /= 2.0;
		i++;
	}

	const char *err_str = "";
	if(masked_value > 34){
		err_str = "[Error: value > 34] ";
	} else if(masked_value < 2){
		err_str = "[Warning: value < 2] ";
	}

	snprintf(buf, ITEM_LABEL_LENGTH, "%s%lE degrees (%" PRIi32 ")", err_str, resolution, masked_value);
}

static void
altitude_resolution(char *buf, uint8_t value) {
	// The encoded altitude of 000000000000000010000110110011 decodes to
	// 33.69921875.  The encoded uncertainty of 15 gives a value of 64;
	// therefore, the final uncertainty is 33.69921875 +/- 64 (or the range
	// from -30.30078125 to 97.69921875).
	// The amount of altitude uncertainty can be determined by the following
	// formula, where x is the encoded integer value:
	//      Uncertainty = 2 ^ ( 21 - x )
	//                  = 2 ^ ( 21 - 15 ) = 2 ^ 6 = 64

	int32_t masked_value = value & 0x3F;
	double resolution = 1.0;
	int32_t i = 21 - masked_value;
	while(i > 0){
		resolution *= 2.0;
		i--;
	}
	while(i < 0){
		resolution /= 2.0;
		i++;
	}

	const char *err_str = "";
	if(masked_value > 30){
		err_str = "[Error: value > 34] ";
	} else if(masked_value < 2){
		err_str = "[Warning: value < 2] ";
	}

	snprintf(buf, ITEM_LABEL_LENGTH, "%s%lf (%" PRIi32 ")", err_str, resolution, masked_value);
}


/* Dissect Chassis Id TLV (Mandatory) */
static int32_t
dissect_lldp_chassis_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset,
	profinet_lldp_column_info *pn_lldp_column_info)
{
	uint8_t tlvsubType;
	uint16_t tempShort;
	uint32_t dataLen = 0;
	const char *strPtr=NULL;
        const char *idType=NULL;
	uint8_t addr_family = 0;

	proto_tree	*chassis_tree = NULL;
	proto_item	*tf = NULL, *lf = NULL;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tlvsubType = TLV_TYPE(tempShort);
	if (tlvsubType != CHASSIS_ID_TLV_TYPE)
	{
		proto_tree_add_expert_format(tree, pinfo, &ei_lldp_bad_type , tvb, offset, TLV_INFO_LEN(tempShort),
			"Invalid TLV type (0x%02X), expected ChassisID type (0x%02X)", tlvsubType, CHASSIS_ID_TLV_TYPE);

		return -1;
	}

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);
	/* Get tlv subtype */
	tlvsubType = tvb_get_uint8(tvb, (offset+2));

	/* Set chassis tree */
	chassis_tree = proto_tree_add_subtree_format(tree, tvb, offset, (dataLen + 2), ett_chassis_id, &tf, "Chassis Subtype = %s",
						     val_to_str_const(tlvsubType, chassis_id_subtypes, "Reserved" ));

	proto_tree_add_item(chassis_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	lf = proto_tree_add_item(chassis_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	if (dataLen < 2)
	{
		expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
			"Invalid Chassis ID Length (%u), expected > (2)", dataLen);

		return -1;
	}

	/* Get chassis id subtype */
	proto_tree_add_item(chassis_tree, hf_chassis_id_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (tlvsubType)
	{
	case 4:	/* MAC address */
	{
		if (dataLen != 7)
		{
			expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
				"Invalid Chassis ID Length (%u) for Type (%s), expected (7)", dataLen, val_to_str_const(tlvsubType, chassis_id_subtypes, ""));
			return -1;
		}

		idType="MA";
		strPtr = tvb_ether_to_str(pinfo->pool, tvb, offset);
		proto_tree_add_item(chassis_tree, hf_chassis_id_mac, tvb, offset, 6, ENC_NA);
		pn_lldp_column_info->chassis_id_mac = wmem_strdup(pinfo->pool, strPtr);
		offset += (dataLen - 1);
		break;
	}
	case 5:	/* Network address */
	{
		/* Get network address family */
		proto_tree_add_item(chassis_tree, hf_lldp_network_address_family, tvb, offset, 1, ENC_BIG_ENDIAN);
		addr_family = tvb_get_uint8(tvb,offset);

		offset++;

		idType="NA";

		/* Check for IPv4 or IPv6 */
		switch(addr_family){
		case AFNUM_INET:
			if (dataLen == 6){
				strPtr = tvb_ip_to_str(pinfo->pool, tvb, offset);
			}else{
				expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
					"Invalid Chassis ID Length (%u) for Type (%s, %s), expected (6)", dataLen, val_to_str_const(tlvsubType, chassis_id_subtypes, ""), val_to_str_const(addr_family, afn_vals, ""));
				return -1;
			}

			proto_tree_add_item(chassis_tree, hf_chassis_id_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);

			break;
		case AFNUM_INET6:
			if  (dataLen == 18){
				strPtr = tvb_ip6_to_str(pinfo->pool, tvb, offset);
			}else{
				expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
					"Invalid Chassis ID Length (%u) for Type (%s, %s), expected (18)", dataLen, val_to_str_const(tlvsubType, chassis_id_subtypes, ""), val_to_str_const(addr_family, afn_vals, ""));
				return -1;
			}

			proto_tree_add_item(chassis_tree, hf_chassis_id_ip6, tvb, offset, 16, ENC_NA);

			break;
		default:
			strPtr = tvb_bytes_to_str(pinfo->pool, tvb, offset, (dataLen-2));
			proto_tree_add_item(chassis_tree, hf_chassis_id, tvb, offset, (dataLen-2), ENC_NA);

			break;
		}

		offset += (dataLen - 2);
		break;
	}
	case 1: /* Chassis component */
	case 2:	/* Interface alias */
	case 3: /* Port component */
	case 6: /* Interface name */
	case 7:	/* Locally assigned */
	default:
	{
		if (dataLen > 256)
		{
			expert_add_info_format(pinfo, lf, &ei_lldp_bad_length_excess,
				"Invalid Chassis ID Length (%u) for Type (%s), expected < (256)", dataLen, val_to_str_const(tlvsubType, chassis_id_subtypes, ""));
			return -1;
		}

		switch(tlvsubType)
		{
		case 2: /* Interface alias */
			idType="IA";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 6: /* Interface name */
			idType="IN";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 7: /* Locally assigned */
			idType="LA";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen-1));
			pn_lldp_column_info->chassis_id_locally_assigned = wmem_strdup(pinfo->pool, strPtr);
			break;
		case 1: /* Chassis component */
			idType="CC";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 3: /* Port component */
			idType="PC";
			strPtr = tvb_bytes_to_str(pinfo->pool, tvb, offset, (dataLen-1));

			break;
		default:
			idType="Rs";
			strPtr = "Reserved";

			break;
		}

		proto_tree_add_item(chassis_tree, hf_chassis_id, tvb, offset, (dataLen-1), ENC_NA);

		offset += (dataLen - 1);
		break;
	}
	}

	if (column_info_selection == DEFAULT_COLUMN_INFO)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s/%s ", idType, strPtr);
	}
	proto_item_append_text(tf, ", Id: %s", strPtr);

	return offset;
}

/* Dissect Port Id TLV (Mandatory) */
static int32_t
dissect_lldp_port_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset,
	profinet_lldp_column_info *pn_lldp_column_info)
{
	uint8_t tlvsubType;
	uint16_t tempShort;
	uint32_t dataLen = 0;
	const char *strPtr=NULL;
	const char *idType=NULL;
	uint8_t addr_family = 0;

	proto_tree	*port_tree = NULL;
	proto_item	*tf = NULL, *lf = NULL;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tlvsubType = TLV_TYPE(tempShort);
	if (tlvsubType != PORT_ID_TLV_TYPE)
	{
		proto_tree_add_expert_format(tree, pinfo, &ei_lldp_bad_type , tvb, offset, TLV_INFO_LEN(tempShort),
			"Invalid Port ID (0x%02X), expected (0x%02X)", tlvsubType, PORT_ID_TLV_TYPE);

		return -1;
	}

	/* Get tlv length and subtype */
	dataLen = TLV_INFO_LEN(tempShort);
	tlvsubType = tvb_get_uint8(tvb, (offset+2));

	/* Set port tree */
	port_tree = proto_tree_add_subtree_format(tree, tvb, offset, (dataLen + 2), ett_port_id, &tf, "Port Subtype = %s",
		val_to_str_const(tlvsubType, port_id_subtypes, "Unknown" ));

	proto_tree_add_item(port_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	lf = proto_tree_add_item(port_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	if (dataLen < 2) {
		expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
			"Invalid Port ID Length (%u), expected > (2)", dataLen);

		return -1;
	}

	/* Get port id subtype */
	proto_tree_add_item(port_tree, hf_port_id_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (tlvsubType)
	{
	case 3: /* MAC address */
		if (dataLen != 7)
		{
			expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
				"Invalid Port ID Length (%u) for Type (%s), expected (7)", dataLen, val_to_str_const(tlvsubType, port_id_subtypes, ""));
			return -1;
		}

		idType = "MA";
		strPtr = tvb_ether_to_str(pinfo->pool, tvb, offset);
		proto_tree_add_item(port_tree, hf_port_id_mac, tvb, offset, 6, ENC_NA);

		offset += (dataLen - 1);
		break;
	case 4: /* Network address */
		/* Get network address family */
		addr_family = tvb_get_uint8(tvb,offset);
		proto_tree_add_item(port_tree, hf_lldp_network_address_family, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		idType = "NA";

		/* Check for IPv4 or IPv6 */
		switch(addr_family){
		case AFNUM_INET:
			if (dataLen == 6){
				strPtr = tvb_ip_to_str(pinfo->pool, tvb, offset);
			}else{
				expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
					"Invalid Port ID Length (%u) for Type (%s, %s), expected (6)", dataLen, val_to_str_const(tlvsubType, port_id_subtypes, ""), val_to_str_const(addr_family, afn_vals, ""));
				return -1;
			}

			proto_tree_add_item(port_tree, hf_port_id_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);

			break;
		case AFNUM_INET6:
			if  (dataLen == 18){
				strPtr = tvb_ip6_to_str(pinfo->pool, tvb, offset);
			}else{
				expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
					"Invalid Port ID Length (%u) for Type (%s, %s), expected (18)", dataLen, val_to_str_const(tlvsubType, port_id_subtypes, ""), val_to_str_const(addr_family, afn_vals, ""));
				return -1;
			}

			proto_tree_add_item(port_tree, hf_port_id_ip6, tvb, offset, 16, ENC_NA);

			break;
		default:
			strPtr = tvb_bytes_to_str(pinfo->pool, tvb, offset, (dataLen-2));
			proto_tree_add_item(port_tree, hf_port_id, tvb, offset, (dataLen-2), ENC_ASCII);

			break;
		}

		offset += (dataLen - 2);
		break;
	case 1: /* Interface alias */
	case 2: /* Port Component */
	case 5: /* Interface name */
	case 6: /* Agent circuit ID */
	case 7: /* Locally assigned */
	default:
		if (dataLen > 256)
		{
			expert_add_info_format(pinfo, lf, &ei_lldp_bad_length_excess,
				"Invalid Port ID Length (%u) for Type (%s), expected < (256)", dataLen, val_to_str_const(tlvsubType, port_id_subtypes, ""));
			return -1;
		}

		switch (tlvsubType)
		{
		case 1: /* Interface alias */
			idType = "IA";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 2: /* Port component */
			idType = "PC";
			strPtr = tvb_bytes_to_str(pinfo->pool, tvb, offset, (dataLen-1));
			break;
		case 5: /* Interface name */
			idType = "IN";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 6: /* Agent circuit ID */
			idType = "AC";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen - 1));
			break;
		case 7: /* Locally assigned */
			idType = "LA";
			strPtr = tvb_format_stringzpad(pinfo->pool, tvb, offset, (dataLen-1));
			pn_lldp_column_info->port_id_locally_assigned = wmem_strdup(pinfo->pool, strPtr);
			break;
		default:
			idType = "Rs";
			strPtr = "Reserved";
			break;
		}

		proto_tree_add_item(port_tree, hf_port_id, tvb, offset, (dataLen-1), ENC_ASCII);

		offset += (dataLen - 1);
		break;
	}
	if (column_info_selection == DEFAULT_COLUMN_INFO)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s/%s ", idType, strPtr);
	}
	proto_item_append_text(tf, ", Id: %s", strPtr);

	return offset;
}

/* Dissect Time To Live TLV (Mandatory) */
static int32_t
dissect_lldp_time_to_live(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint16_t *isShutdown)
{
	uint8_t tlvsubType;
	uint16_t tempShort;
	uint32_t dataLen = 0;

	proto_tree	*time_to_live_tree;
	proto_item	*ti;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tlvsubType = TLV_TYPE(tempShort);
	if (tlvsubType != TIME_TO_LIVE_TLV_TYPE)
		return -1;

	/* Get tlv length and seconds field */
	dataLen = TLV_INFO_LEN(tempShort);
	tempShort = tvb_get_ntohs(tvb, (offset+2));
	*isShutdown = !tempShort;

	/* LLDPDU types: IEEE 802.1AB-2016 9.1.2 */
	if (tempShort != 0) {
		time_to_live_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
			ett_time_to_live, NULL, "Time To Live = %u sec", tempShort);
		ti = proto_tree_add_none_format(time_to_live_tree, hf_pdu_type, tvb, offset, dataLen + 2, "Normal LLDPDU");
		proto_item_set_generated(ti);
	} else {
		time_to_live_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
			ett_time_to_live, NULL, "Discard all info for this MSAP (Time To Live = 0)");
		ti = proto_tree_add_none_format(time_to_live_tree, hf_pdu_type, tvb, offset, dataLen + 2, "Shutdown LLDPDU");
		proto_item_set_generated(ti);
	}

	proto_tree_add_item(time_to_live_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(time_to_live_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Display time to live information */
	proto_tree_add_item(time_to_live_tree, hf_time_to_live, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (column_info_selection == DEFAULT_COLUMN_INFO) {
		if (tempShort != 0) {
			col_append_fstr(pinfo->cinfo, COL_INFO, "%u ", tempShort);
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", "0 (Shutdown LLDPDU)");
		}
	}

	return offset;
}

/* Dissect End of LLDPDU TLV */
/* As of 802.1ab-2016 LLDP is defective by design.  The End of LLDPDU was changed from its
 * previously mandatory state to optional.  With nothing to indicate the length of the entire LLDPDU
 * and no marker to indicate the end of the LLDPDU there are now cases where it is not possible to
 * affirmatively determine that an LLDPDU has ended.  Depending on where a capture is collected,
 * additional data may follow the LLDPDU (FCS, diagnostic trailers, non-zero padding, etc...)
 */
static int32_t
dissect_lldp_end_of_lldpdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint8_t tlvType;
	uint16_t dataLen;
	uint16_t tempShort;

	proto_tree	*end_of_lldpdu_tree, *lf;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);
	tlvType = TLV_TYPE(tempShort);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	/* Set port tree */
	end_of_lldpdu_tree = proto_tree_add_subtree(tree, tvb, offset, (dataLen + 2), ett_end_of_lldpdu, NULL, "End of LLDPDU");

	proto_tree_add_item(end_of_lldpdu_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	lf = proto_tree_add_item(end_of_lldpdu_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	if (dataLen > 0)
	{
		/* Either a corrupt / bad End of LLDPDU, or the start of something after an LLDPDU
		 * without an End of LLDPDU TLV.
		 * Add EI pointing out possible invalid End of LLDP, but do not consume bytes.
		 * Any trailer, FCS, etc starting with 0x00 or 0x01 would be interpreted as an
		 * End of LLDPDU.  Chances are better that they belong to another dissector vs.
		 * being a malformed End of LLDPDU (or other TLV).
		 *
		 * It may be reasonable to add pref to consume the bytes anyway
		 */

		expert_add_info_format(pinfo, lf, &ei_lldp_bad_length_excess,
			"Invalid Length (%u) for Type (%s), expected (0)", dataLen, val_to_str_const(tlvType, tlv_types, ""));
		return -1;
	}

	offset += 2;
	return offset;
}

/* Dissect Port Description TLV */
static int32_t
dissect_lldp_port_desc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint16_t tempShort;
	uint32_t dataLen = 0;
	const char *strPtr;

	proto_tree	*port_desc_tree;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	strPtr = tvb_format_stringzpad(pinfo->pool, tvb, (offset+2), dataLen);

	/* Set port tree */
	port_desc_tree = proto_tree_add_subtree_format(tree, tvb, offset, (dataLen + 2),
							ett_port_description, NULL, "Port Description = %s", strPtr);

	proto_tree_add_item(port_desc_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(port_desc_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;
	/* Display port description information */
	proto_tree_add_item(port_desc_tree, hf_port_desc, tvb, offset, dataLen, ENC_ASCII);

	offset += dataLen;

	return offset;
}

/* Dissect System Name and description TLV */
static int32_t
dissect_lldp_system_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint16_t tempShort;
	uint32_t dataLen = 0;
	uint8_t tlvsubType;
	const char *strPtr;

	proto_tree	*system_subtree;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);
	tlvsubType = TLV_TYPE(tempShort);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	strPtr = tvb_format_stringzpad(pinfo->pool, tvb, (offset+2), dataLen);

	/* Set system name tree */
	if (tlvsubType == SYSTEM_NAME_TLV_TYPE) {
		system_subtree = proto_tree_add_subtree_format(tree, tvb, offset, (dataLen + 2),
										ett_system_name, NULL, "System Name = %s", strPtr);
		if (column_info_selection == DEFAULT_COLUMN_INFO)
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "SysN=%s ", strPtr);
		}
	} else {
		system_subtree = proto_tree_add_subtree_format(tree, tvb, offset, (dataLen + 2),
										ett_system_desc, NULL, "System Description = %s", strPtr);
		if (column_info_selection == DEFAULT_COLUMN_INFO)
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "SysD=%s ", strPtr);
		}
	}

	proto_tree_add_item(system_subtree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(system_subtree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset +=2;

	/* Display system name information */
	if (tlvsubType == SYSTEM_NAME_TLV_TYPE)
		proto_tree_add_item(system_subtree, hf_lldp_tlv_system_name, tvb, offset, dataLen, ENC_ASCII);
	else
		proto_tree_add_item(system_subtree, hf_lldp_tlv_system_desc, tvb, offset, dataLen, ENC_ASCII);

	offset += dataLen;

	return offset;
}

/* Dissect System Capabilities TLV */
static int32_t
dissect_lldp_system_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint16_t tempShort;
	uint32_t dataLen = 0;

	proto_tree	*system_capabilities_tree;
	proto_tree	*capabilities_summary_tree;
	proto_tree	*capabilities_enabled_tree;
	proto_item	*tf;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	/* Set system capabilities tree */
	system_capabilities_tree = proto_tree_add_subtree(tree, tvb, offset, (dataLen + 2), ett_system_cap, NULL, "Capabilities");

	proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;
	/* Display system capability information */
	tf = proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_system_cap, tvb, offset, 2, ENC_BIG_ENDIAN);
	capabilities_summary_tree = proto_item_add_subtree(tf, ett_system_cap_summary);

	/* Add capabilities to summary tree */
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_other, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_repeater, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_bridge, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_wlan_access_pt, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_router, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_telephone, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_docsis_cable_device, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_station_only, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_cvlan_component, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_svlan_component, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_tpmr_component, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;
	/* Get enabled summary */

	/* Display system capability information */
	tf = proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_enable_system_cap, tvb, offset, 2, ENC_BIG_ENDIAN);
	capabilities_enabled_tree = proto_item_add_subtree(tf, ett_system_cap_enabled);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_other, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_repeater, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_bridge, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_wlan_access_pt, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_router, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_telephone, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_docsis_cable_device, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_station_only, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_cvlan_component, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_svlan_component, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_tpmr_component, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	return offset;
}

/* Dissect Management Address TLV */
static int32_t
dissect_lldp_management_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint16_t tempShort;
	uint32_t dataLen = 0;
	uint8_t subtypeByte;
	uint8_t stringLen = 0;

	proto_tree	*system_mgm_addr;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	/* Set system capabilities tree */
	system_mgm_addr = proto_tree_add_subtree(tree, tvb, offset, (dataLen + 2), ett_management_address, NULL, "Management Address");

	proto_tree_add_item(system_mgm_addr, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(system_mgm_addr, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;

	/* Get management address string length */
	stringLen = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(system_mgm_addr, hf_mgn_address_len, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	/* Get management address subtype */
	subtypeByte = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(system_mgm_addr, hf_mgn_address_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	/* Get address */
	switch (subtypeByte)
	{
	/* XXX - Should we throw an exception if stringLen doesn't match our address length? */
	case 1:		/* IPv4 */
		proto_tree_add_item(system_mgm_addr, hf_mgn_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case 2:		/* IPv6 */
		proto_tree_add_item(system_mgm_addr, hf_mgn_addr_ipv6, tvb, offset, 16, ENC_NA);
		break;
	default:
		proto_tree_add_item(system_mgm_addr, hf_mgn_addr_hex, tvb, offset, (stringLen-1), ENC_NA);
		break;
	}

	offset += (stringLen-1);

	/* Get interface numbering subtype */
	proto_tree_add_item(system_mgm_addr, hf_mgn_interface_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	/* Get interface number */
	proto_tree_add_item(system_mgm_addr, hf_mgn_interface_number, tvb, offset, 4, ENC_BIG_ENDIAN);

	offset += 4;

	/* Get OID string length */
	stringLen = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(system_mgm_addr, hf_mgn_oid_len, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	if (stringLen > 0)
	{
		/* Get OID identifier */
		proto_tree_add_item(system_mgm_addr, hf_mgn_obj_id, tvb, offset, stringLen, ENC_NA);

		offset += stringLen;
	}

	return offset;
}

/* Dissect DCBX TLVs */
static void
dissect_dcbx_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;
	uint8_t priomaskByte, prioCounter, appCount = 0;
	uint16_t dataLen;
	uint16_t tempShort;

	proto_tree	*subtlv_tree = NULL;
	proto_tree	*apptlv_tree = NULL;

	proto_tree_add_item(tree, hf_dcbx_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	/* One org specific OUI holds many DCBx TLVs */
	while (tvb_reported_length_remaining(tvb, offset) && tree) {

		tempShort = tvb_get_ntohs(tvb, offset);

		/* Get TLV type & len. Actual TLV len = len + 2 */
		subType = TLV_TYPE(tempShort);
		dataLen = TLV_INFO_LEN(tempShort);

		/* Write out common header fields first */
		switch (subType)
		{
		case 0x1: /* Control */
			subtlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
					ett_org_spc_dcbx_cee_1, NULL, "%s TLV", val_to_str_const(subType, dcbx_subtypes, "Unknown"));
			break;
		case 0x2: /* Priority Groups */
			subtlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
					ett_org_spc_dcbx_cee_2, NULL, "%s TLV", val_to_str_const(subType, dcbx_subtypes, "Unknown"));
			break;
		case 0x3: /* PFC */
			subtlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
					ett_org_spc_dcbx_cee_3, NULL, "%s TLV", val_to_str_const(subType, dcbx_subtypes, "Unknown"));
			break;
		case 0x4: /* Application */
			subtlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
					ett_org_spc_dcbx_cee_4, NULL, "%s TLV", val_to_str_const(subType, dcbx_subtypes, "Unknown"));
			break;
		case 0x6: /* Logical Link Down */
			subtlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, dataLen + 2,
					ett_org_spc_dcbx_cin_6, NULL, "%s TLV", val_to_str_const(subType, dcbx_subtypes, "Unknown"));
			break;
		}
		proto_tree_add_item(subtlv_tree, hf_dcbx_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtlv_tree, hf_dcbx_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		proto_tree_add_item(subtlv_tree, hf_dcbx_tlv_oper_version, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(subtlv_tree, hf_dcbx_tlv_max_version, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		if (subType == 0x1) {
			/* Specific to Control TLV */
			proto_tree_add_item(subtlv_tree, hf_dcbx_control_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);

			offset +=4;

			proto_tree_add_item(subtlv_tree, hf_dcbx_control_ack, tvb, offset, 4, ENC_BIG_ENDIAN);

			offset +=4;
		} else {
			/* Common to all feature TLVs */
			proto_tree_add_item(subtlv_tree, hf_dcbx_feature_flag_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(subtlv_tree, hf_dcbx_feature_flag_willing, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(subtlv_tree, hf_dcbx_feature_flag_error, tvb, offset, 1, ENC_BIG_ENDIAN);

			offset++;

			/* Unused field, no connection to SubType used to identify TLVs */
			proto_tree_add_item(subtlv_tree, hf_dcbx_feature_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

			offset++;

			switch(subType)
			{
			case 0x2: /* Priority Groups */
			{
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_0, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_1, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_2, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_3, tvb, offset, 2, ENC_BIG_ENDIAN);

				offset +=2;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_4, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_5, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_6, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pgid_prio_7, tvb, offset, 2, ENC_BIG_ENDIAN);

				offset +=2;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_0, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_1, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_2, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_3, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_4, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_5, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_6, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_per_7, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pg_numtcs, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				break;
			}
			case 0x3: /* PFC */
			{
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio0, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio1, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio2, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio3, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio4, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio5, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio6, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_prio7, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_pfc_numtcs, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				break;
			}
			case 0x4: /* Application */
			{
				/* One App TLV can hold 4 byte header & multiple apps, each app takes 6 bytes */
				appCount = (dataLen - 4)/6;

				while(appCount--) {
					tempShort = tvb_get_ntohs(tvb, offset);

					apptlv_tree = proto_tree_add_subtree_format(subtlv_tree, tvb, offset, 6,
						ett_org_spc_dcbx_cee_app, NULL, "%s Application",
						val_to_str_const(tempShort, dcbx_app_types, "Unknown"));

					proto_tree_add_item(apptlv_tree, hf_dcbx_feature_app_proto, tvb, offset, 2, ENC_BIG_ENDIAN);

					offset += 2;

					proto_tree_add_item(apptlv_tree, hf_dcbx_feature_app_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(apptlv_tree, hf_dcbx_feature_app_selector, tvb, offset, 3, ENC_BIG_ENDIAN);

					offset += 3;

					priomaskByte = tvb_get_uint8(tvb, offset);

					for (prioCounter = 0; prioCounter < 8; prioCounter++)
						if(priomaskByte & (0x1 << prioCounter)) {
							proto_tree_add_uint(apptlv_tree, hf_dcbx_feature_app_prio, tvb, offset, 1, prioCounter);
							break;
						}

					offset++;
				}
				break;
			}
			case 0x6: /* Logical Link Down */
			{
				proto_tree_add_item(subtlv_tree, hf_dcbx_feature_flag_llink_type, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;

				break;
			}
			}
		}

	}

	return;
}

/* Dissect IEEE 802.1 TLVs */
static int
dissect_ieee_802_1_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;
	uint8_t tempByte;
	uint16_t dcbApp, appCount;

	proto_tree	*vlan_flags_tree = NULL;
	proto_tree	*mac_phy_flags = NULL;
	proto_tree	*apptlv_tree = NULL;
	proto_item	*tf = NULL;

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_ieee_802_1_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (subType)
	{
	case 0x01:	/* Port VLAN ID */
	{
		proto_tree_add_item(tree, hf_ieee_802_1_port_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		break;
	}
	case 0x02:	/* Port and Protocol VLAN ID */
	{
		/* Get flags */
		tf = proto_tree_add_item(tree, hf_ieee_802_1_port_and_vlan_id_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		vlan_flags_tree = proto_item_add_subtree(tf, ett_port_vlan_flags);

		proto_tree_add_item(vlan_flags_tree, hf_ieee_802_1_port_and_vlan_id_flag_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(vlan_flags_tree, hf_ieee_802_1_port_and_vlan_id_flag_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_802_1_port_proto_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		break;
	}
	case 0x03:	/* VLAN Name */
	{
		proto_tree_add_item(tree, hf_ieee_802_1_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;

		/* Get vlan name length */
		tempByte = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_ieee_802_1_vlan_name_length, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		if (tempByte > 0)
		{
			proto_tree_add_item(tree, hf_ieee_802_1_vlan_name, tvb, offset, tempByte, ENC_ASCII);

			offset += tempByte;
		}

		break;
	}
	case 0x04:	/* Protocol ID */
	{
		/* Get protocol id length */
		tempByte = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_ieee_802_1_proto_id_length, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		if (tempByte > 0)
		{
			/*
			 * Section D.2.4.3 "protocol identity" of IEEE
			 * 802.1Q-2018 says:
			 *
			 *   The protocol identity field shall contain
			 *   the first n octets of the protocol after
			 *   the layer 2 addresses (i.e., for example,
			 *   starting with the EtherType field) that the
			 *   sender would like to advertise.
			 *
			 * What comes "after the layer 2 addresses"
			 * depends on the network type.  For Ethernet,
			 * it's a type/length field, with, if it's a
			 * length field, an 802.2 LLC header, with,
			 * if that header specifies SNAP, a SNAP header
			 * following it.  For other network types, it's
			 * just going to be an 802.2 LLC header (presumably,
			 * if the layer 2 addresses aren't immediately
			 * before the 802.2 header, this doesn't include
			 * the fields between the last layer 2 address
			 * and the 802.2 header).
			 *
			 * We currently just show it as a blob of bytes.
			 */
			proto_tree_add_item(tree, hf_ieee_802_1_proto_id, tvb, offset, tempByte, ENC_NA);

			offset += tempByte;
		}

		break;
	}
	case 0x07:	/* Link Aggregation */
	{
		/* Get protocol id length */
		tf = proto_tree_add_item(tree, hf_ieee_802_1_aggregation_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		mac_phy_flags = proto_item_add_subtree(tf, ett_802_1_aggregation);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_1_aggregation_status_cap, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_1_aggregation_status_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_1_aggregation_status_porttype, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Get aggregated port id */
		proto_tree_add_item(tree, hf_ieee_802_1_aggregated_port_id, tvb, offset, 4, ENC_BIG_ENDIAN);

		offset+=4;
		break;
	}
	case 0x8:	/* Congestion Notification */
	{
		/* Per-Priority CNPV Indicators */
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio0, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio1, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio2, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio3, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio4, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio5, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio6, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_cnpv_prio7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Per-Priority Ready Indicators */
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio0, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio1, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio2, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio3, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio4, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio5, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio6, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021qau_ready_prio7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		break;
	}
	case 0x9:	/* ETS Configuration */
	{
		proto_tree_add_item(tree, hf_ieee_8021az_feature_flag_willing, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021az_feature_flag_cbs, tvb, offset, 1, ENC_BIG_ENDIAN);

		tempByte = (tvb_get_uint8(tvb, offset) & 0x7);
		/* 0 implies 8 traffic classes supported */
		proto_tree_add_uint_format_value(tree, hf_ieee_8021az_maxtcs, tvb, offset, 1, tempByte, "%u (0x%X)", tempByte ? tempByte : 8, tempByte);

		offset++;

		/* Priority Assignment Table */
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_0, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_2, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_3, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_4, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_5, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_6, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_7, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		/* TC Bandwidth Table */
		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_0, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_1, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_2, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_3, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_4, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_5, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_6, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* TSA Assignment Table */
		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class0, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class1, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class2, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class3, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class4, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class5, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class6, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		break;
	}
	case 0xA:	/* ETS Recommendation */
	{
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Priority Assignment Table */
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_0, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_2, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_3, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_4, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_5, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_6, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pgid_prio_7, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset +=2;

		/* TC Bandwidth Table */
		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_0, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_1, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_2, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_3, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_4, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_5, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_6, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pg_per_7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* TSA Assignment Table */
		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class0, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class1, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class2, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class3, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class4, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class5, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class6, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_ieee_8021az_tsa_class7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		break;
	}
	case 0xB:	/* PFC Configuration */
	{
		proto_tree_add_item(tree, hf_ieee_8021az_feature_flag_willing, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021az_feature_flag_mbc, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ieee_8021az_pfc_numtcs, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio0, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio1, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio2, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio3, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio4, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio5, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio6, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_dcbx_feature_pfc_prio7, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		break;
	}
	case 0xC:	/* Application Priority */
	{
		proto_tree_add_item(tree, hf_ieee_8021az_app_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		appCount = tvb_reported_length_remaining(tvb, offset)/3;

		while(appCount--) {
			dcbApp = tvb_get_ntohs(tvb, offset + 1);

			apptlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3,
						 ett_org_spc_ieee_dcbx_app, NULL, "%s Application",
						 val_to_str_const(dcbApp, dcbx_app_types, "Unknown"));

			proto_tree_add_item(apptlv_tree, hf_ieee_8021az_app_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(apptlv_tree, hf_ieee_8021az_app_selector, tvb, offset, 1, ENC_BIG_ENDIAN);

			offset++;

			proto_tree_add_item(apptlv_tree, hf_dcbx_feature_app_proto, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;
		}
		break;
	}
	}

	return offset;
}

/* Dissect IEEE 802.1Qbg TLVs */
static void
dissect_oui_default_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_unknown_subtype, tvb, 0, 1, ENC_BIG_ENDIAN);
	if (tvb_captured_length_remaining(tvb, 1) > 0) {
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, 1, -1, ENC_NA);
	}
}

static void
dissect_ieee_802_1qbg_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;

	proto_tree *evb_capabilities_subtree = NULL;

	proto_item *tf = NULL;
	subType = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_ieee_802_1qbg_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (subType) {
		case 0x00:
			/* Get EVB capabilities */
			tf = proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_support_caps, tvb, offset, 2, ENC_BIG_ENDIAN);
			evb_capabilities_subtree = proto_item_add_subtree(tf, ett_802_1qbg_capabilities_flags);

			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_std, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_rr, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_rte, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_ecp, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_vdp, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;

			tf = proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_configure_caps, tvb, offset, 2, ENC_BIG_ENDIAN);
			evb_capabilities_subtree = proto_item_add_subtree(tf, ett_802_1qbg_capabilities_flags);

			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_std, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_rr, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_rte, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_ecp, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_vdp, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;

			proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_supported_vsi, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;

			proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_configured_vsi, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;

			proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_retrans_timer, tvb, offset, 1, ENC_BIG_ENDIAN);

			break;
	}

	return;
}


/* Dissect extreme avaya ap tlv*/
static int
dissect_extreme_avaya_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint16_t dataLen)
{
	uint8_t subType;
	uint32_t i, loopCount;
	uint32_t offset = 0;

	/*
	Element TLV:
	___________________________________________________________________________________________________________________________
	| TLV Type | TLV Length | Avaya OUI | Subtype | HMAC-SHA Digest | Element Type | State  | Mgmt. VLAN | Rsvd    | System ID |
	----------------------------------------------------------------------------------------------------------------------------
	| 7 bits   | 9 bits     | 3 octets  | 1 octet | 32 octets       | 6 bits       | 6 bits | 12 bits    | 1 octet | 10 octets |
	----------------------------------------------------------------------------------------------------------------------------

	Assignment TLV:
	__________________________________________________________________________________________________________
	| TLV Type | TLV Length | Avaya OUI | Subtype | HMAC-SHA Digest | Assignment Status |  VLAN   | I-SID    |
	----------------------------------------------------------------------------------------------------------
	| 7 bits   | 9 bits     | 3 octets  | 1 octet | 32 octets       | 4 bits            | 12 bits | 3 octets |
	----------------------------------------------------------------------------------------------------------
	*/

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_ex_avaya_tlv_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	switch (subType)
	{
	case EX_AVAYA_SUBTYPE_ELEMENT_TLV:  /* Element TLV */
	{
		proto_tree_add_item(tree, hf_ex_avaya_hmac_shi, tvb, offset, 32, ENC_NA);
		offset+=32;
		proto_tree_add_item(tree, hf_ex_avaya_element_type, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ex_avaya_state, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ex_avaya_mgnt_vlan, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset+=3;
		proto_tree_add_item(tree, hf_ex_avaya_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		proto_tree_add_item(tree, hf_ex_avaya_system_id, tvb, offset, 10, ENC_NA);
		offset+=10;
		break;
	}
	case EX_AVAYA_SUBTYPE_ASSIGNMENT_TLV: /* Assignment TLV */
	{
		loopCount = (dataLen - 36) / 5;
		proto_tree_add_item(tree, hf_ex_avaya_hmac_shi, tvb, offset, 32, ENC_NA);
		offset+=32;
		for ( i=0; i < loopCount; i++)
		{
			proto_tree_add_item(tree, hf_ex_avaya_status, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_ex_avaya_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			proto_tree_add_item(tree, hf_ex_avaya_i_sid, tvb, offset, 3, ENC_BIG_ENDIAN);
			offset+=3;
		}
		break;
	}
	}
	return offset;
}

/* Dissect extreme avaya ap tlv*/
static int
dissect_extreme_avaya2_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t numbvlans, sysidlength;
	uint32_t offset = 0;

	/*
	Fabric TLV:
	_________________________________________________________________________________________________
	| TLV Type | TLV Length | Avaya OUI | Subtype | Num. BVLANs | BVLAN-ID*N | SysID Len | Sysid    |
	-------------------------------------------------------------------------------------------------
	| 7 bits   | 9 bits     | 3 octets  | 1 octet | 1 octet     | 2 octets*N | 1 octet   | octets*N |
	-------------------------------------------------------------------------------------------------
        */

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_ex_avaya2_tlv_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	switch (subType) {
	case EX_AVAYA2_SUBTYPE_ZTFv2_FC_TLV:  /* Zero Touch Fabric v2 Fabric Connect TLV */
		proto_tree_add_item(tree, hf_ex_avaya2_fabric_connect, tvb, offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item_ret_uint(tree, hf_ex_avaya2_fabric_numbvlans, tvb, offset, 1, ENC_NA, &numbvlans);
		offset++;
		while (numbvlans--) {
			proto_tree_add_item(tree, hf_ex_avaya2_fabric_bvlanid, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		proto_tree_add_item_ret_uint(tree, hf_ex_avaya2_fabric_sysidlength, tvb, offset, 1, ENC_NA, &sysidlength);
		offset++;
		proto_tree_add_item(tree, hf_ex_avaya2_fabric_sysid, tvb, offset, sysidlength, ENC_NA);
		offset += sysidlength;
		break;
	}
	return offset;
}

/* Dissect IEEE 802.3 TLVs */
static int
dissect_ieee_802_3_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;
	uint8_t tempByte;
	uint16_t tlvLen = tvb_reported_length(tvb)-offset;

	proto_tree	*mac_phy_flags = NULL;
	proto_tree	*autoneg_advertised_subtree = NULL;

	proto_item	*tf = NULL, *subitem;

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);

	subitem = proto_tree_add_item(tree, hf_ieee_802_3_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (subType)
	{
	case 0x01:	/* MAC/PHY Configuration/Status */
	{
		/* Get auto-negotiation info */
		tf = proto_tree_add_item(tree, hf_ieee_802_3_mac_phy_auto_neg_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_flags);

		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mac_phy_auto_neg_status_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mac_phy_auto_neg_status_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Get pmd auto-negotiation advertised capability */
		tf = proto_tree_add_item(tree, hf_ieee_802_3_pmd_auto_neg_advertised_caps, tvb, offset, 2, ENC_BIG_ENDIAN);
		autoneg_advertised_subtree = proto_item_add_subtree(tf, ett_802_3_autoneg_advertised);

		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_other, tvb, offset, 2, ENC_BIG_ENDIAN);

		autoneg_advertised_subtree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_802_3_autoneg_advertised, NULL, "Same in inverse (wrong) bitorder");

		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;

		/* Get operational MAU type */
		proto_tree_add_item(tree, hf_ieee_802_3_pmd_mau_type, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;

		break;
	}
	case 0x02:	/* MDI Power Support */
	{
		/* Get MDI power support info */
		tf = proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_support, tvb, offset, 1, ENC_BIG_ENDIAN);
		mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_power);

		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_port_class, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_power_support, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_power_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_pairs, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Get PSE power pair */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_pse_pair, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Get power class */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_class, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		if (tlvLen == 4)
			break;

		/* Get first byte */
		tempByte = tvb_get_uint8(tvb, offset);

		/* Determine power type */
		subType = ((tempByte & 0xC0) >> 6);
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_type, tvb, offset, 1, ENC_BIG_ENDIAN);

		tf = proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_source, tvb, offset, 1, ENC_BIG_ENDIAN);

		/* Determine power source subtype */
		switch (subType)
		{
		case 0:
		case 2:
		{
			subType = ((tempByte & 0x30) >> 4);
			proto_item_append_text(tf, " %s", val_to_str_const(subType, media_power_pse_device, "Reserved"));

			break;
		}
		case 1:
		case 3:
		{
			subType = ((tempByte & 0x30) >> 4);
			proto_item_append_text(tf, " %s", val_to_str_const(subType, media_power_pd_device, "Reserved"));

			break;
		}
		default:
		{
			proto_item_append_text(tf, " %s", "Unknown");

			break;
		}
		}

		/* Determine PD 4PID flag */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_pd4pid, tvb, offset, 1, ENC_BIG_ENDIAN);

		/* Determine power priority */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Power Value: 1 to 510 expected  */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_requested_power, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset+=2;

		/* Power Value: 1 to 510 expected */
		proto_tree_add_item(tree, hf_ieee_802_3_mdi_allocated_power, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset+=2;

		if (tlvLen == 26) { /* 802.3BT TLV Extensions */
			proto_tree_add_item(tree, hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_a, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			proto_tree_add_item(tree, hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_b, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			proto_tree_add_item(tree, hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_a, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			proto_tree_add_item(tree, hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_b, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			tf = proto_tree_add_item(tree, hf_ieee_802_3_bt_power_status, tvb, offset, 2, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_bt_power);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_pse_powering_status, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_pd_powered_status, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_pse_power_pairs_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_ds_pwr_class_ext_a, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_ds_pwr_class_ext_b, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_pwr_class_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			tf = proto_tree_add_item(tree, hf_ieee_802_3_bt_system_setup, tvb, offset, 1, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_bt_system_setup);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_power_type_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_power_pd_load, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset+=1;

			proto_tree_add_item(tree, hf_ieee_802_3_bt_pse_maximum_available_power_value, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;

			tf = proto_tree_add_item(tree, hf_ieee_802_3_bt_autoclass, tvb, offset, 1, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_bt_autoclass);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_pse_autoclass_support, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_autoclass_completed, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_autoclass_request, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_autoclass_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset+=1;

			tf = proto_tree_add_item(tree, hf_ieee_802_3_bt_power_down, tvb, offset, 3, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_bt_power_down);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_power_down_request, tvb, offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_bt_power_down_time, tvb, offset, 3, ENC_BIG_ENDIAN);
			offset+=3;
		}
		break;
	}
	case 0x03:	/* Link Aggregation */
	{
		/* Get aggregation status */
		expert_add_info(pinfo, subitem, &ei_lldp_tlv_deprecated);
		tf = proto_tree_add_item(tree, hf_ieee_802_3_aggregation_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_aggregation);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_aggregation_status_cap, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_aggregation_status_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Get aggregated port id */
		proto_tree_add_item(tree, hf_ieee_802_3_aggregated_port_id, tvb, offset, 4, ENC_BIG_ENDIAN);

		offset+=4;
		break;
	}
	case 0x04:	/* Maximum Frame Size */
	{
		/* Get maximum frame size */
		proto_tree_add_item(tree, hf_ieee_802_3_max_frame_size, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset+=2;
		break;
	}
	case 0x05:	/* Energy-Efficient Ethernet */
	{
		proto_tree_add_item(tree, hf_ieee_802_3_eee_transmit, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_ieee_802_3_eee_receive, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_ieee_802_3_eee_fallback_receive, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_ieee_802_3_eee_echo_transmit, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_ieee_802_3_eee_echo_receive, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		break;
	}
	case 0x07:	/* IEEE 802.3br Frame Preemption Protocol */
	{
		static int * const preemption_capabilities[] = {
			&hf_ieee_802_3br_aec_support,
			&hf_ieee_802_3br_aec_enable,
			&hf_ieee_802_3br_aec_active,
			&hf_ieee_802_3br_aec_addfragsize,
			&hf_ieee_802_3br_aec_reserved,
			NULL
		};

		/* Get Additional Ethernet Capabilities */
		proto_tree_add_bitmask(tree, tvb, offset, hf_ieee_802_3br_aec, ett_802_3br_capabilities_flags, preemption_capabilities, ENC_BIG_ENDIAN);
		offset+=2;
		break;
	}
	}

	if(tvb_reported_length_remaining(tvb, offset)) {
		proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length_excess, tvb, offset, -1);
	}
	return offset;
}

/* Dissect Media TLVs */
static void
dissect_media_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint16_t tlvLen = tvb_reported_length(tvb);
	uint8_t subType;
	uint32_t offset = 0;
	uint8_t tempByte;
	uint32_t LCI_Length;

	proto_tree	*media_flags = NULL;
	proto_item	*tf = NULL;
	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_media_tlv_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	tlvLen--;

	switch (subType)
	{
	case 1:		/* LLDP-MED Capabilities */
	{
		/* Get capabilities */
		if (tlvLen < 2)
		{
			proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
			return;
		}

		tf = proto_tree_add_item(tree, hf_media_tlv_subtype_caps, tvb, offset, 2, ENC_BIG_ENDIAN);
		media_flags = proto_item_add_subtree(tf, ett_media_capabilities);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_llpd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_network_policy, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_location_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_mdi_pse, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_mid_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_inventory, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;
		tlvLen -= 2;

		/* Get Class type */
		if (tlvLen < 1)
		{
			proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
			return;
		}

		proto_tree_add_item(tree, hf_media_tlv_subtype_class, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;
		tlvLen--;

		break;
	}
	case 2:		/* Network Policy */
	{
		/* Get application type */
		if (tlvLen < 1)
		{
			proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
			return;
		}

		proto_tree_add_item(tree, hf_media_application_type, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;
		tlvLen--;

		/* Get flags */
		if (tlvLen < 3)
		{
			proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
			return;
		}

		proto_tree_add_item(tree, hf_media_policy_flag, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_media_tag_flag, tvb, offset, 3, ENC_BIG_ENDIAN);

		/* Get vlan id */
		proto_tree_add_item(tree, hf_media_vlan_id, tvb, offset, 3, ENC_BIG_ENDIAN);


		/* Get L2 priority */

		proto_tree_add_item(tree, hf_media_l2_prio, tvb, offset, 3, ENC_BIG_ENDIAN);

		/* Get DSCP value */
		proto_tree_add_item(tree, hf_media_dscp, tvb, offset, 3, ENC_BIG_ENDIAN);

		break;
	}
	case 3:	/* Location Identification */
	{
		/* Get location data format */
		if (tlvLen < 1)
		{
			proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
			return;
		}

		tempByte = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_media_loc_data_format, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;
		tlvLen--;

		switch (tempByte)
		{
		case 1:	/* Coordinate-based LCI */
		{
			/*
			 * See RFC 6225 (obsoletes RFC 3825).
			 * XXX - should this be handled by the BOOTP
			 * dissector, and exported to us?
			 */
			if (tlvLen < 16)
			{
				proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
				return;
			}

			/* Get latitude resolution */
			proto_tree_add_item(tree, hf_media_loc_lat_resolution, tvb, offset, 1, ENC_BIG_ENDIAN);

			/* Get latitude */
			proto_tree_add_item(tree, hf_media_loc_lat, tvb, offset, 5, ENC_BIG_ENDIAN);

			offset += 5;

			/* Get longitude resolution */
			proto_tree_add_item(tree, hf_media_loc_long_resolution, tvb, offset, 1, ENC_BIG_ENDIAN);

			/* Get longitude */
			proto_tree_add_item(tree, hf_media_loc_long, tvb, offset, 5, ENC_BIG_ENDIAN);

			offset += 5;

			/* Altitude Type */
			proto_tree_add_item(tree, hf_media_loc_alt_type, tvb, offset, 1, ENC_BIG_ENDIAN);

			/* Get Altitude Resolution */
			proto_tree_add_item(tree, hf_media_loc_alt_resolution, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset++;

			/* Get Altitude */
			proto_tree_add_item(tree, hf_media_loc_alt, tvb, offset, 4, ENC_BIG_ENDIAN);

			offset += 4;

			/* Get Ver */
			proto_tree_add_item(tree, hf_media_loc_ver, tvb, offset, 1, ENC_BIG_ENDIAN);

			/* Get reserved */
			proto_tree_add_item(tree, hf_media_loc_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

			/* Get datum */
			proto_tree_add_item(tree, hf_media_loc_datum, tvb, offset, 1, ENC_BIG_ENDIAN);

			offset++;

			break;
		}
		case 2: /* Civic Address LCI */
		{
			/*
			 * See draft-ietf-geopriv-dhcp-civil-07.
			 * XXX - should this be handled by the BOOTP
			 * dissector, and exported to us?
			 */
			if (tlvLen < 1)
			{
				proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
				return;
			}

			/* Get LCI length */
			tempByte = tvb_get_uint8(tvb, offset);
			tlvLen--;
			if (tempByte > tlvLen)
			{
				proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length_excess , tvb, offset, tlvLen);

				return;
			}

			proto_tree_add_item(tree, hf_media_civic_lci_length, tvb, offset, 1 , ENC_BIG_ENDIAN);

			LCI_Length = (uint32_t)tempByte;

			offset++;

			/* Get what value */
			if (LCI_Length < 1)
			{
				proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
				return;
			}

			proto_tree_add_item(tree, hf_media_civic_what, tvb, offset, 1, ENC_BIG_ENDIAN);

			offset++;
			LCI_Length--;

			/* Get country code */
			if (LCI_Length < 2)
			{
				proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
				return;
			}

			proto_tree_add_item(tree, hf_media_civic_country, tvb, offset, 2, ENC_ASCII);

			offset += 2;
			LCI_Length -= 2;

			while (LCI_Length > 0)
			{
				/* Get CA Type */
				proto_tree_add_item(tree, hf_media_civic_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;
				LCI_Length--;

				/* Get CA Length */
				if (LCI_Length < 1)
				{
					proto_tree_add_expert(tree, pinfo, &ei_lldp_bad_length, tvb, offset, tlvLen);
					return;
				}
				tempByte = tvb_get_uint8(tvb, offset);

				proto_tree_add_item(tree, hf_media_civic_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;
				LCI_Length--;

				/* Make sure the CA value is within the specified length */
				if (tempByte > LCI_Length)
					return;

				if (tempByte > 0)
				{
					/* Get CA Value */
					proto_tree_add_item(tree, hf_media_civic_addr_value, tvb, offset, tempByte, ENC_ASCII);

					offset += tempByte;
					LCI_Length -= tempByte;
				}
			}

			break;
		}
		case 3: /* ECS ELIN */
		{
			if (tlvLen > 0)
			{
				proto_tree_add_item(tree, hf_media_ecs, tvb, offset, tlvLen, ENC_ASCII);
			}

			break;
		}
		}

		break;
	}
	case 4: /* Extended Power-via-MDI */
	{
		/* Get first byte */
		tempByte = tvb_get_uint8(tvb, offset);

		/* Determine power type */
		subType = ((tempByte & 0xC0) >> 6);
		proto_tree_add_item(tree, hf_media_power_type, tvb, offset, 1, ENC_BIG_ENDIAN);

		tf = proto_tree_add_item(tree, hf_media_power_source, tvb, offset, 1, ENC_BIG_ENDIAN);

		/* Determine power source */
		switch (subType)
		{
		case 0:
		{
			subType = ((tempByte & 0x30) >> 4);
			proto_item_append_text(tf, " %s", val_to_str_const(subType, media_power_pse_device, "Reserved"));

			break;
		}
		case 1:
		{
			subType = ((tempByte & 0x30) >> 4);
			proto_item_append_text(tf, " %s", val_to_str_const(subType, media_power_pd_device, "Reserved"));

			break;
		}
		default:
		{
			proto_item_append_text(tf, " %s", "Unknown");
			break;
		}
		}

		/* Determine power priority */
		proto_tree_add_item(tree, hf_media_power_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Power Value: 0 to 102.3 Watts (0.1 W increments) */
		proto_tree_add_item(tree, hf_media_power_value, tvb, offset, 2, ENC_BIG_ENDIAN);

		break;
	}
	case 5:	/* Hardware Revision */
	{
		/* Figure out the length of the hardware revision field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_hardware, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 6:	/* Firmware Revision */
	{
		/* Figure out the length of the firmware revision field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_firmware, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 7:	/* Software Revision */
	{
		/* Figure out the length of the software revision field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_software, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 8:	/* Serial Number */
	{
		/* Figure out the length of the serial number field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_sn, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 9:	/* Manufacturer Name */
	{
		/* Figure out the length of the manufacturer name field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_manufacturer, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 10:	/* Model Name */
	{
		/* Figure out the length of the model name field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_model, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	case 11:	/* Asset ID */
	{
		/* Figure out the length of the asset id field */
		if (tlvLen > 0)
		{
			proto_tree_add_item(tree, hf_media_asset, tvb, offset, tlvLen, ENC_ASCII|ENC_NA);
		}

		break;
	}
	}

	return;
}


static uint32_t
dissect_profinet_period(tvbuff_t *tvb, proto_tree *tree, uint32_t offset, const char *name, int hf_valid, int hf_value)
{
	uint32_t period;
	proto_tree	*period_tree;

	period = tvb_get_ntohl(tvb, offset);

	period_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_profinet_period, NULL, "%s: %s, %uns",
		name, (period & 0x80000000) ? "Valid" : "Invalid", period & 0x7FFFFFFF);

	proto_tree_add_uint(period_tree, hf_valid, tvb, offset, 4, period);
	proto_tree_add_uint(period_tree, hf_value, tvb, offset, 4, period);
	offset+=4;

	return offset;
}

static void
select_source_of_name_of_station
(packet_info *pinfo _U_, profinet_lldp_column_info *pn_lldp_column_info)
{
	if (pn_lldp_column_info->chassis_id_locally_assigned != NULL)
	{
		pn_lldp_column_info->is_nos_assigned = true;
		col_append_fstr(pinfo->cinfo, COL_INFO, "NoS = %s ", pn_lldp_column_info->chassis_id_locally_assigned);
	}
	else
	{
		if (pn_lldp_column_info->chassis_id_mac != NULL)
		{
			pn_lldp_column_info->is_nos_assigned = true;
			col_append_fstr(pinfo->cinfo, COL_INFO, "NoS = %s ", pn_lldp_column_info->chassis_id_mac);
		}
	}
}

static void
set_name_of_station_for_profinet_specialized_column_info
(packet_info *pinfo _U_, profinet_lldp_column_info *pn_lldp_column_info)
{
	const char *delimForProfinetv23 = ".";
	char* foundDot = NULL;
	char* tokenPortId = NULL;
	char* tokenNameOfStation = NULL;
	char* lldpPortIdCombinedWithNameOfStation = NULL;

	if (pn_lldp_column_info->is_nos_assigned != true)
	{
		if (pn_lldp_column_info->port_id_locally_assigned != NULL)
		{
			foundDot = strstr(pn_lldp_column_info->port_id_locally_assigned, delimForProfinetv23);
			if (foundDot != NULL)
			{
				pn_lldp_column_info->is_nos_assigned = true;
				pn_lldp_column_info->is_port_id_assigned = true;
				lldpPortIdCombinedWithNameOfStation = wmem_strdup(pinfo->pool, pn_lldp_column_info->port_id_locally_assigned);
				tokenPortId = strtok(lldpPortIdCombinedWithNameOfStation, delimForProfinetv23);
				tokenNameOfStation = strtok(NULL, delimForProfinetv23);
				col_append_fstr(pinfo->cinfo, COL_INFO, "NoS = %s ", tokenNameOfStation);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Port Id = %s ", tokenPortId);
			}
			else
			{
				select_source_of_name_of_station(pinfo, pn_lldp_column_info);
			}
		}
		else
		{
			select_source_of_name_of_station(pinfo, pn_lldp_column_info);
		}
	}
}

static void
set_port_id_for_profinet_specialized_column_info
(packet_info *pinfo _U_, profinet_lldp_column_info *pn_lldp_column_info)
{
	if (pn_lldp_column_info->is_port_id_assigned != true)
	{
	if (pn_lldp_column_info->port_id_locally_assigned != NULL)
		{
			pn_lldp_column_info->is_port_id_assigned = true;
			col_append_fstr(pinfo->cinfo, COL_INFO, "Port Id = %s ", pn_lldp_column_info->port_id_locally_assigned);
		}
	}
}

/* Dissect PROFINET TLVs */
static void
dissect_profinet_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, profinet_lldp_column_info *pn_lldp_column_info)
{
	uint8_t subType;
	uint32_t offset = 0;
	proto_item	*tf = NULL;
	uint32_t class3_PortStatus;
	uint32_t port_rx_delay_local;
	uint32_t port_rx_delay_remote;
	uint32_t port_tx_delay_local;
	uint32_t port_tx_delay_remote;
	uint32_t cable_delay_local;


	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(tree, hf_profinet_tlv_subtype, tvb, offset, 1, subType);
	offset++;

	if (column_info_selection == PROFINET_SPECIAL_COLUMN_INFO)
	{
		set_name_of_station_for_profinet_specialized_column_info(pinfo, pn_lldp_column_info);
		set_port_id_for_profinet_specialized_column_info(pinfo, pn_lldp_column_info);
	}

	switch (subType)
	{
	case 1:		/* LLDP_PNIO_DELAY */
	{
		port_rx_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_rx_delay_local, tvb, offset, 4, port_rx_delay_local);
		if(port_rx_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_rx_delay_remote = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_rx_delay_remote, tvb, offset, 4, port_rx_delay_remote);
		if(port_rx_delay_remote) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_tx_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_tx_delay_local, tvb, offset, 4, port_tx_delay_local);
		if(port_tx_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_tx_delay_remote = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_tx_delay_remote, tvb, offset, 4, port_tx_delay_remote);
		if(port_tx_delay_remote) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		cable_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_cable_delay_local, tvb, offset, 4, cable_delay_local);
		if(cable_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		/*offset+=4;*/
		break;
	}
	case 2:		/* LLDP_PNIO_PORTSTATUS */
	{
		proto_tree_add_item(tree, hf_profinet_class2_port_status, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		proto_tree_add_item_ret_uint(tree, hf_profinet_class3_port_status, tvb, offset, 2, ENC_BIG_ENDIAN, &class3_PortStatus);
		proto_tree_add_item(tree, hf_profinet_class3_port_status_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_profinet_class3_port_status_Fragmentation, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_profinet_class3_port_status_PreambleLength, tvb, offset, 2, ENC_BIG_ENDIAN);

		col_append_fstr(pinfo->cinfo, COL_INFO, "RTClass3 Port Status = %s", val_to_str(class3_PortStatus, profinet_port3_status_vals, "Unknown %d"));
		/*offset+=2;*/
		break;
	}
	/*case 3:*/	/* XXX - LLDP_PNIO_ALIAS */
	case 4:		/* LLDP_PNIO_MRPPORTSTATUS */
	{
		/* DomainUUID */
		proto_tree_add_item(tree, hf_profinet_mrp_domain_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;

		/* MRRT PortStatus */
		proto_tree_add_item(tree, hf_profinet_mrrt_port_status, tvb, offset, 2, ENC_BIG_ENDIAN);
		/*offset+=2;*/
		break;
	}
	case 5:		/* LLDP_PNIO_CHASSIS_MAC */
	{
		proto_tree_add_item(tree, hf_profinet_cm_mac, tvb, offset, 6, ENC_NA);
		/*offset += 6;*/
		break;
	}
	case 6:	/* LLDP_PNIO_PTCPSTATUS */
	{
		/* MasterSourceAddress */
		proto_tree_add_item(tree, hf_profinet_master_source_address, tvb, offset, 6, ENC_NA);
		offset += 6;
		/* SubdomainUUID */
		proto_tree_add_item(tree, hf_profinet_subdomain_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
		/* IRDataUUID */
		proto_tree_add_item(tree, hf_profinet_ir_data_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
		/* LengthOfPeriod */
		offset = dissect_profinet_period(tvb, tree, offset, "LengthOfPeriod",
			hf_profinet_length_of_period_valid, hf_profinet_length_of_period_length);
		/* RedPeriodBegin */
		offset = dissect_profinet_period(tvb, tree, offset, "RedPeriodBegin",
			hf_profinet_red_period_begin_valid, hf_profinet_red_period_begin_offset);
		/* OrangePeriodBegin */
		offset = dissect_profinet_period(tvb, tree, offset, "OrangePeriodBegin",
			hf_profinet_orange_period_begin_valid, hf_profinet_orange_period_begin_offset);
		/* GreenPeriodBegin */
		/*offset = */dissect_profinet_period(tvb, tree, offset, "GreenPeriodBegin",
			hf_profinet_green_period_begin_valid, hf_profinet_green_period_begin_offset);
		break;
	}
	case 9:		/* LLDP_PNIO_TSNDOMAIN */
	{
		/* DomainUUID */
		proto_tree_add_item(tree, hf_profinet_tsn_domain_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		/*offset += 16;*/
		break;
	}
	case 10:	/* LLDP_PNIO_TSNNMEManagementAddr */
	{
		uint8_t management_string_length = 0;
		management_string_length = tvb_get_uint8(tvb, offset);

		/* Management Address String Length */
		proto_tree_add_item(tree, hf_profinet_tsn_nme_management_addr_str_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		/* Management Address Subtype */
		proto_tree_add_item(tree, hf_profinet_tsn_nme_management_addr_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		management_string_length -= 1;

		/* Management Address */
		proto_tree_add_item(tree, hf_profinet_tsn_nme_management_addr, tvb, offset, management_string_length, ENC_NA);
		/*offset += management_string_length;*/
		break;
	}
	case 11:	/* LLDP_PNIO_TSNNMENameUUID */
	{
		/* TSNNMENameUUID */
		proto_tree_add_item(tree, hf_profinet_tsn_nme_name_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		/*offset += 16;*/
		break;
	}
	case 12:	/* LLDP_PNIO_TSNNMEParameterUUID */
	{
		/* NMEParameterUUID */
		proto_tree_add_item(tree, hf_profinet_tsn_nme_parameter_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		/*offset += 16;*/
		break;
	}
	case 13:	/* LLDP_PNIO_TSNTimeDomain */
	{
		/*TimeDomainNumber*/
		proto_tree_add_item(tree, hf_profinet_time_domain_number, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/*TimeDomainUUID*/
		proto_tree_add_item(tree, hf_profinet_time_domain_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;

		/*TimeDomainMasterIdentity*/
		proto_tree_add_item(tree, hf_profinet_time_domain_master_identity, tvb, offset, 8, ENC_NA);
		/*offset += 8;*/
		break;
	}
	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
	}
}

/* Dissect Cisco OUI TLVs */
static void
dissect_cisco_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;
	unsigned length = tvb_reported_length(tvb);

	proto_tree *upoe_data = NULL;
	proto_item *tf = NULL;
	proto_item *parent_item = proto_tree_get_parent(tree);

	if (tree == NULL) return;

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_cisco_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	length--;

	switch (subType)
	{
	/* UPOE */
	case 0x01:
		tf = proto_tree_add_item(tree, hf_cisco_upoe, tvb, offset, 1, ENC_BIG_ENDIAN);
		upoe_data = proto_item_add_subtree(tf, ett_cisco_upoe_tlv);
		proto_tree_add_item(upoe_data, hf_cisco_upoe_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(upoe_data, hf_cisco_upoe_altb_detection, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(upoe_data, hf_cisco_upoe_req_spare_pair, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(upoe_data, hf_cisco_upoe_pse_spare_pair_oper, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		length--;
		break;
	/* ACI */
	case 0xc9: // 201 port-state, uint8
		tf = proto_tree_add_item(tree, hf_cisco_aci_portstate, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset++;
		length--;
		break;
	case 0xca: // 202 node-role, uint8
		tf = proto_tree_add_item(tree, hf_cisco_aci_noderole, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset++;
		length--;
		break;
	case 0xcb: // 203 node-id, uint32
		tf = proto_tree_add_item(tree, hf_cisco_aci_nodeid, tvb, offset, length, ENC_BIG_ENDIAN);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 4;
		length -= 4;
		break;
	case 0xcc: // 204 spine-level, uint8
		tf = proto_tree_add_item(tree, hf_cisco_aci_spinelevel, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset++;
		length--;
		break;
	case 0xcd: // 205 pod-id, uint16
		tf = proto_tree_add_item(tree, hf_cisco_aci_podid, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 2;
		length -= 2;
		break;
	case 0xce: // 206 fabric-name, string
		tf = proto_tree_add_item(tree, hf_cisco_aci_fabricname, tvb, offset, length, ENC_ASCII);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
	case 0xcf: // 207 av (id, ip, uuid) (uint8, ipv4, string)
		proto_tree_add_item(tree, hf_cisco_aci_apiclist, tvb, offset, length, ENC_NA);
		while (length > 0) {
			tf = proto_tree_add_item(tree, hf_cisco_aci_apicid, tvb, offset, 1, ENC_NA);
			proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
			offset++;
			length--;
			proto_tree_add_item(tree, hf_cisco_aci_apicipv4, tvb, offset, 4, ENC_NA);
			offset += 4;
			length -= 4;
			proto_tree_add_item(tree, hf_cisco_aci_apicuuid, tvb, offset, 36, ENC_ASCII);
			offset += 36;
			length -= 36;
		}
		break;
	case 0xd0: // 208 node-ip, ipv4
		tf = proto_tree_add_item(tree, hf_cisco_aci_nodeip, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 4;
		length -= 4;
		break;
	case 0xd1: // 209 port-role, uint8
		tf = proto_tree_add_item(tree, hf_cisco_aci_portrole, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset++;
		length--;
		break;
	case 0xd2: // 210 fw-ver, string
		tf = proto_tree_add_item(tree, hf_cisco_aci_version, tvb, offset, length, ENC_ASCII);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
	case 0xd3: // 211 infra-vlan, uint16
		tf = proto_tree_add_item(tree, hf_cisco_aci_fabricvlan, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 2;
		length -= 2;
		break;
	case 0xd4: // 212 serial-number, string
		tf = proto_tree_add_item(tree, hf_cisco_aci_serialno, tvb, offset, length, ENC_ASCII);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
#if 0
	case 0xd5: // 213 unused
		break;
#endif
	case 0xd6: // 214 model, string
		tf = proto_tree_add_item(tree, hf_cisco_aci_model, tvb, offset, length, ENC_ASCII);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
	case 0xd7: // 215 name, string
		tf = proto_tree_add_item(tree, hf_cisco_aci_nodename, tvb, offset, length, ENC_ASCII);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
	case 0xd8: // 216 port-mode, uint16
		tf = proto_tree_add_item(tree, hf_cisco_aci_portmode, tvb, offset, length, ENC_BIG_ENDIAN);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 2;
		length -= 2;
		break;
	case 0xd9: // 217 authenticate-cookie, bytes
		tf = proto_tree_add_item(tree, hf_cisco_aci_authcookie, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += length;
		length -= length;
		break;
	case 0xda: // 218 standby-apic, uint8
		tf = proto_tree_add_item(tree, hf_cisco_aci_apicmode, tvb, offset, length, ENC_NA);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset++;
		length--;
		break;
	case 0xdb: // 219 fabric-id, uint16
		tf = proto_tree_add_item(tree, hf_cisco_aci_fabricid, tvb, offset, length, ENC_BIG_ENDIAN);
		proto_item_append_text(parent_item, ": %s", proto_item_get_display_repr(pinfo->pool, tf));
		offset += 2;
		length -= 2;
		break;
	default:
		if (length > 0) {
			proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, length, ENC_NA);
			offset += length;
			length -= length;
		}
		break;
	}
	if (length > 0) {
		proto_tree_add_item(tree, hf_subtype_content_remaining, tvb, offset, length, ENC_NA);
	}
}

/* Dissect OUI HytecGer-TLV's */
static void
dissect_hytec_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subtype, group, identifier;
	int32_t bit_offset, msg_len, expected_data_length, maximum_data_length, temp_gint32;
	proto_tree *hytec_data = NULL;
	proto_item *tf = NULL;
	proto_item *group_proto_item, *identifier_proto_item;
	float float_value = 0.0f;
	uint32_t offset = 0;

	subtype = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(tree, hf_hytec_tlv_subtype, tvb, offset, 1, subtype);
	offset++;

	/* get the group and identifier of the chosen subtype */
	bit_offset = (int32_t)(offset *8);
	group = tvb_get_bits8(tvb, bit_offset + HYTEC_GROUP_MASK_OFFSET, HYTEC_GROUP_MASK_SIZE);
	identifier = tvb_get_bits8(tvb, bit_offset + HYTEC_IDENTIFIER_MASK_OFFSET, HYTEC_IDENTIFIER_MASK_SIZE);

	group_proto_item = proto_tree_add_item(tree, hf_hytec_group, tvb, offset, 1, ENC_BIG_ENDIAN);
	identifier_proto_item = proto_tree_add_item(tree, hf_hytec_identifier, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_item_append_text(identifier_proto_item, " ("); /* a group dependent identifier description will be appended */

	offset++;
	msg_len = tvb_reported_length_remaining(tvb, offset);

	switch (subtype)
	{
	case HYTEC_SUBTYPE__TRANSCEIVER: /* Transceiver-Subtype */
		proto_item_append_text(group_proto_item, " (%s)", val_to_str_const(group, hytec_transceiver_groups, "Unknown" ));

		switch (group)
		{
		case HYTEC_TRANSG__TRANCEIVER_IDENTIFIER:
			proto_item_append_text(identifier_proto_item, "%s", val_to_str_const(identifier, hytec_tid, "Unknown"));

			switch (identifier)
			{
			case HYTEC_TID__VENDOR_PRODUCT_REVISION:
				maximum_data_length = 64;
				if(0 < msg_len && msg_len <= maximum_data_length)
					proto_tree_add_item(tree, hf_hytec_transceiver_vendor_product_revision, tvb, offset, msg_len, ENC_ASCII);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) is beyond valid range (1-%d)", val_to_str_const(identifier, hytec_tid, ""), msg_len, maximum_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			default: proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA); /* unknown identifier */
			} /* switch (identifier) */

			break;
		case HYTEC_TRANSG__TRANSCEIVER_BRIDGEABLE_DISTANCE:
			expected_data_length = 4;
			proto_item_append_text(identifier_proto_item, "%s", val_to_str_const(identifier, hytec_tbd, "Unknown"));

			switch (identifier)
			{
			case HYTEC_TBD__SINGLE_MODE:
				if(msg_len == expected_data_length)
				{
					proto_tree_add_item(tree, hf_hytec_single_mode, tvb, offset, msg_len, ENC_BIG_ENDIAN);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_tbd, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_TBD__MULTI_MODE_50:
				if(msg_len == expected_data_length)
				{
					proto_tree_add_item(tree, hf_hytec_multi_mode_50, tvb, offset, msg_len, ENC_BIG_ENDIAN);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_tbd, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_TBD__MULTI_MODE_62_5:
				if(msg_len == expected_data_length)
				{
					proto_tree_add_item(tree, hf_hytec_multi_mode_62_5, tvb, offset, msg_len, ENC_BIG_ENDIAN);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_tbd, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			default: proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA); /* unknown identifier */
			} /* switch (identifier) */
			break;
		case HYTEC_TRANSG__MEASUREMENT_DATA:
			expected_data_length = 4;
			proto_item_append_text(identifier_proto_item, "%s", val_to_str_const(identifier, hytec_md, "Unknown"));

			switch (identifier)
			{
			case HYTEC_MD__TX_CURRENT_OUTPUT_POWER:
				if(msg_len == expected_data_length)
				{
					temp_gint32 = tvb_get_ntohil(tvb, offset);
					float_value = (float) 0.1 * (float) temp_gint32;
					proto_tree_add_float(tree, hf_hytec_tx_current_output_power, tvb, offset, msg_len, float_value);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_md, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MD__RX_CURRENT_INPUT_POWER:
				if(msg_len == expected_data_length)
				{
					temp_gint32 = tvb_get_ntohil(tvb, offset);
					float_value = (float) 0.1 * (float) temp_gint32;
					proto_tree_add_float(tree, hf_hytec_rx_current_input_power, tvb, offset, msg_len, float_value);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_md, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MD__RX_INPUT_SNR:
				if(msg_len == expected_data_length)
				{
					temp_gint32 = tvb_get_ntohil(tvb, offset);
					if(temp_gint32 < 0) float_value = (float)-1.0 * (float)((~temp_gint32) >> 8);
					else float_value = (float) (temp_gint32 >> 8);
					float_value += (float)(temp_gint32 & 0xFF) * (float)0.00390625; /* 0.00390625 == 0.5 ^ 8 */
					proto_tree_add_float(tree, hf_hytec_rx_input_snr, tvb, offset, msg_len, float_value);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_md, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MD__LINELOSS:
				if(msg_len == expected_data_length)
				{
					temp_gint32 = tvb_get_ntohil(tvb, offset);
					if(temp_gint32 < 0) float_value = (float)-1.0 * (float)((~temp_gint32) >> 8);
					else float_value = (float) (temp_gint32 >> 8);
					float_value += (float)(temp_gint32 & 0xFF) * (float)0.00390625; /* 0.5 ^ 8 */
					proto_tree_add_float(tree, hf_hytec_lineloss, tvb, offset, msg_len, float_value);
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_md, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			default: proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA); /* unknown identifier */
			} /* switch (identifier) */
			break;
		default: /* unknown group */
			/* identifier considered also unknown */
			proto_item_append_text(identifier_proto_item, "Unknown");
			proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA);
		} /* switch (group) */
		break;
	case HYTEC_SUBTYPE__TRACE: /* Trace-Subtype */
		proto_item_append_text(group_proto_item, " (%s)", val_to_str_const(group, hytec_trace_groups, "Unknown"));

		switch (group)
		{
		case HYTEC_TRACEG__MAC_TRACE:
			proto_item_append_text(identifier_proto_item, "%s", val_to_str_const(identifier, hytec_mc, "Unknown"));

			switch (identifier)
			{
			case HYTEC_MC__MAC_TRACE_REQUEST:
				expected_data_length = 13;
				if(msg_len == expected_data_length)
				{
					tf = proto_tree_add_item(tree, hf_hytec_mac_trace_request, tvb, offset, -1, ENC_NA);
					hytec_data = proto_item_add_subtree(tf, ett_org_spc_hytec_trace_request);
					proto_tree_add_item(hytec_data, hf_hytec_trace_mac_address, tvb, offset, 6, ENC_NA);
					offset += 6;
					proto_tree_add_item(hytec_data, hf_hytec_request_mac_address, tvb, offset, 6, ENC_NA);
					offset += 6;
					proto_tree_add_item(hytec_data, hf_hytec_maximum_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
					/*offset += 1;*/
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__MAC_TRACE_REPLY:
				expected_data_length = 13;
				if(msg_len == expected_data_length)
				{
					tf = proto_tree_add_item(tree, hf_hytec_mac_trace_reply, tvb, offset, -1, ENC_NA);
					hytec_data = proto_item_add_subtree(tf, ett_org_spc_hytec_trace_reply);
					proto_tree_add_item(hytec_data, hf_hytec_trace_mac_address, tvb, offset, 6, ENC_NA);
					offset += 6;
					proto_tree_add_item(hytec_data, hf_hytec_answering_mac_address, tvb, offset, 6, ENC_NA);
					offset += 6;
					proto_tree_add_item(hytec_data, hf_hytec_actual_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
					/*offset += 1;*/
				}
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__NAME_OF_REPLYING_DEVICE:
				maximum_data_length = 64;
				if(0 < msg_len && msg_len <= maximum_data_length) proto_tree_add_item(tree, hf_hytec_name_of_replying_device, tvb, offset, msg_len, ENC_ASCII);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) is beyond valid range (1-%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, maximum_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__OUTGOING_PORT_NAME:
				maximum_data_length = 64;
				if(0 < msg_len && msg_len <= maximum_data_length) proto_tree_add_item(tree, hf_hytec_outgoing_port_name, tvb, offset, msg_len, ENC_ASCII);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) is beyond valid range (1-%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, maximum_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE:
				expected_data_length = 4;
				if(msg_len == expected_data_length) proto_tree_add_item(tree, hf_hytec_ipv4_address_of_replying_device, tvb, offset, msg_len, ENC_NA);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__END_OF_TRACE:
				expected_data_length = 1;
				if(msg_len == expected_data_length) proto_tree_add_item(tree, hf_hytec_end_of_trace, tvb, offset, msg_len, ENC_BIG_ENDIAN);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE:
				expected_data_length = 16;
				if(msg_len == expected_data_length) proto_tree_add_item(tree, hf_hytec_ipv6_address_of_replying_device, tvb, offset, msg_len, ENC_NA);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__INCOMING_PORT_NAME:
				maximum_data_length = 64;
				if(0 < msg_len && msg_len <= maximum_data_length) proto_tree_add_item(tree, hf_hytec_incoming_port_name, tvb, offset, msg_len, ENC_ASCII);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) is beyond valid range (1-%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, maximum_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			case HYTEC_MC__TRACE_IDENTIFIER:
				expected_data_length = 4;
				if(msg_len == expected_data_length) proto_tree_add_item(tree, hf_hytec_trace_identifier, tvb, offset, msg_len, ENC_BIG_ENDIAN);
				else
				{ /* unexpected length */
					expert_add_info_format(pinfo, tree, &ei_lldp_bad_length, "%s length (%d) != expected length (%d)", val_to_str_const(identifier, hytec_mc, ""), msg_len, expected_data_length);
					if(msg_len) proto_tree_add_item(tree, hf_hytec_invalid_object_data, tvb, offset, msg_len, ENC_STR_HEX);
				}
				break;
			default: proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA); /* unknown identifier */
			} /* switch (identifier) */
			break;
		default: /* unknown group */
			/* identifier considered also unknown */
			proto_item_append_text(identifier_proto_item, "Unknown");
			proto_tree_add_item(tree, hf_hytec_unknown_identifier_content, tvb, offset, -1, ENC_NA);
		} /* switch (group) */
		break;
	default: /* unknown subtype */
		proto_item_append_text(group_proto_item, " (Unknown)");
		proto_item_append_text(identifier_proto_item, "Unknown");
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
		break;
	} /* switch (subtype) */

	proto_item_append_text(identifier_proto_item, ")");
}

/* Dissect Avaya OUI TLVs */
static void
dissect_avaya_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint8_t subType;
	uint32_t offset = 0;

	proto_tree *avaya_data = NULL;
	proto_item *tf = NULL;

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_avaya_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	switch (subType)
	{
	case 0x01:	/* PoE Conservation Level Support */
	{
		proto_tree_add_item(tree, hf_avaya_poe, tvb, offset, 7, ENC_NA);
		break;
	}
	case 0x03:	/* Call Server IP Address */
	{
		proto_tree_add_item(tree, hf_avaya_call_server, tvb, offset, 4, ENC_NA);
		break;
	}
	case 0x04:	/* IP Phone Addresses */
	{
		tf = proto_tree_add_item(tree, hf_avaya_ipphone, tvb, offset, 12, ENC_NA);
		avaya_data = proto_item_add_subtree(tf, ett_avaya_ipphone_tlv);
		proto_tree_add_item(avaya_data, hf_avaya_ipphone_ip, tvb, offset, 4, ENC_NA);
		proto_tree_add_item(avaya_data, hf_avaya_ipphone_mask, tvb, offset+4, 4, ENC_NA);
		proto_tree_add_item(avaya_data, hf_avaya_ipphone_gateway, tvb, offset+8, 4, ENC_NA);
		break;
	}
	case 0x05:	/* CNA Server IP Address */
	{
		proto_tree_add_item(tree, hf_avaya_cna_server, tvb, offset, 4, ENC_NA);
		break;
	}
	case 0x06:	/* File Server */
	{
		proto_tree_add_item(tree, hf_avaya_file_server, tvb, offset, 4, ENC_NA);
		break;
	}
	case 0x07:	/* 802.1Q Framing */
	{
		proto_tree_add_item(tree, hf_avaya_dot1q, tvb, offset, 1, ENC_NA);
		break;
	}
	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
		break;
	}
}

/* Dissect IANA OUI TLVs */
static void
dissect_iana_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint16_t msg_len;
	uint8_t subType;
	uint32_t offset = 0;

	/* Get subtype */
	subType = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_iana_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	msg_len=tvb_reported_length_remaining(tvb, offset);
	switch (subType)
	{
	case 0x01: /* MUDURL */
		if ( msg_len > 0 )
			proto_tree_add_item(tree, hf_iana_mudurl, tvb, offset, msg_len, ENC_ASCII);
		break;

	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
		break;
	}
}

static void
dissect_onos_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	uint16_t msg_len;
	uint32_t subType;
	uint32_t offset = 0;

	proto_tree_add_item_ret_uint(tree, hf_onos_subtype, tvb, offset, 1, ENC_BIG_ENDIAN, &subType);
	offset++;

	msg_len=tvb_reported_length_remaining(tvb, offset);
	switch (subType)
	{
	case ONOS_CHASSIS_TLV_TYPE:
		proto_tree_add_item(tree, hf_onos_chassis, tvb, offset, msg_len, ENC_ASCII);
		break;
	case ONOS_PORT_TLV_TYPE:
		proto_tree_add_item(tree, hf_onos_port, tvb, offset, msg_len, ENC_ASCII);
		break;
	case ONOS_TTL_TLV_TYPE:
		proto_tree_add_item(tree, hf_onos_ttl, tvb, offset, msg_len, ENC_NA);
		break;
	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
		break;
	}
}


/* Dissect Organizational Specific TLV */
static int32_t
dissect_organizational_specific_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, profinet_lldp_column_info *pn_lldp_column_info)
{
	uint16_t dataLen;
	uint16_t tempShort;
	int     tempTree;
	uint32_t oui, tLength = tvb_reported_length(tvb);
	uint8_t subType;
	tvbuff_t *vendor_tvb;
	const char *ouiStr;
	const char *subTypeStr;

	proto_tree	*org_tlv_tree = NULL;
	proto_item	*lf = NULL;
	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);
	/* Get OUI value */
	oui = tvb_get_ntoh24(tvb, (offset+2));
	subType = tvb_get_uint8(tvb, (offset+5));

	/* check for registered dissectors for the OUI  If none found continue, else call dissector */
	if( dissector_try_uint(oui_unique_code_table, oui, tvb, pinfo, tree) ) {
		return tLength;
	}
	/* Look in manuf database for OUI */
	ouiStr = uint_get_manuf_name_if_known(oui);
	if(ouiStr==NULL) ouiStr="Unknown";

	/* Set a default value */
	tempTree = ett_org_spc_ProfinetSubTypes_1;
	switch(oui)
	{
	case OUI_DCBX:
		subTypeStr = val_to_str(subType, dcbx_protocol_types, "Unknown subtype (0x%x)");
		switch(subType)
		{
		case 1: tempTree = ett_org_spc_dcbx_cin;
			break;
		case 2: tempTree = ett_org_spc_dcbx_cee;
			break;
		}
		break;
	case OUI_IEEE_802_1:
		subTypeStr = val_to_str(subType, ieee_802_1_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 0x1:	tempTree = ett_org_spc_ieee_802_1_1;
			break;
		case 0x2:	tempTree = ett_org_spc_ieee_802_1_2;
			break;
		case 0x3:	tempTree = ett_org_spc_ieee_802_1_3;
			break;
		case 0x4:	tempTree = ett_org_spc_ieee_802_1_4;
			break;
		case 0x8:	tempTree = ett_org_spc_ieee_802_1_8;
			break;
		case 0x9:	tempTree = ett_org_spc_ieee_802_1_9;
			break;
		case 0xa:	tempTree = ett_org_spc_ieee_802_1_a;
			break;
		case 0xb:	tempTree = ett_org_spc_ieee_802_1_b;
			break;
		case 0xc:	tempTree = ett_org_spc_ieee_802_1_c;
			break;
		}
		break;
	case OUI_IEEE_802_3:
		subTypeStr = val_to_str(subType, ieee_802_3_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_ieee_802_3_1;
			break;
		case 2:	tempTree = ett_org_spc_ieee_802_3_2;
			break;
		case 3:	tempTree = ett_org_spc_ieee_802_3_3;
			break;
		case 4:	tempTree = ett_org_spc_ieee_802_3_4;
			break;
		case 5:	tempTree = ett_org_spc_ieee_802_3_5;
			break;
		case 7:	tempTree = ett_org_spc_ieee_802_3_7;
			break;
		}
		break;
	case OUI_MEDIA_ENDPOINT:
		subTypeStr = val_to_str(subType, media_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_media_1;
			break;
		case 2:	tempTree = ett_org_spc_media_2;
			break;
		case 3:	tempTree = ett_org_spc_media_3;
			break;
		case 4:	tempTree = ett_org_spc_media_4;
			break;
		case 5:	tempTree = ett_org_spc_media_5;
			break;
		case 6:	tempTree = ett_org_spc_media_6;
			break;
		case 7:	tempTree = ett_org_spc_media_7;
			break;
		case 8:	tempTree = ett_org_spc_media_8;
			break;
		case 9:	tempTree = ett_org_spc_media_9;
			break;
		case 10:	tempTree = ett_org_spc_media_10;
			break;
		case 11:	tempTree = ett_org_spc_media_11;
			break;
		}
		break;
	case OUI_PROFINET:
		subTypeStr = val_to_str(subType, profinet_subtypes, "Reserved (0x%x)");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_ProfinetSubTypes_1;
			break;
		case 2:	tempTree = ett_org_spc_ProfinetSubTypes_2;
			break;
		case 3:	tempTree = ett_org_spc_ProfinetSubTypes_3;
			break;
		case 4:	tempTree = ett_org_spc_ProfinetSubTypes_4;
			break;
		case 5:	tempTree = ett_org_spc_ProfinetSubTypes_5;
			break;
		case 6:	tempTree = ett_org_spc_ProfinetSubTypes_6;
			break;
		}
		break;
	case OUI_CISCO_2:
		subTypeStr = val_to_str(subType, cisco_subtypes, "Unknown subtype (0x%x)");
		break;
	case OUI_IEEE_802_1QBG:
		subTypeStr = val_to_str(subType, ieee_802_1qbg_subtypes, "Unknown subtype 0x%x");
		break;
	case OUI_AVAYA_EXTREME:
		subTypeStr = val_to_str(subType, ex_avaya_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case EX_AVAYA_SUBTYPE_ELEMENT_TLV: tempTree = ett_ex_avayaSubTypes_11;
			break;
		case EX_AVAYA_SUBTYPE_ASSIGNMENT_TLV: tempTree = ett_ex_avayaSubTypes_12;
			break;
		}
		break;
	case OUI_AVAYA_EXTREME2:
		subTypeStr = val_to_str(subType, ex_avaya2_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case EX_AVAYA2_SUBTYPE_ZTFv2_FC_TLV: tempTree = ett_ex_avaya2SubTypes_4;
			break;
		}
		break;
	case OUI_HYTEC_GER:
		subTypeStr = val_to_str(subType, hytec_subtypes, "Unknown subtype (0x%x)");
		switch(subType)
		{
			case HYTEC_SUBTYPE__TRANSCEIVER: tempTree = ett_org_spc_hytec_subtype_transceiver;
			break;
			case HYTEC_SUBTYPE__TRACE: tempTree = ett_org_spc_hytec_subtype_trace;
			break;
		}
		break;
	case OUI_AVAYA:
		subTypeStr = val_to_str(subType, avaya_subtypes, "Unknown subtype (0x%x)");
		break;
	case OUI_IANA:
		subTypeStr = val_to_str(subType, iana_subtypes, "Unknown subtype (0x%x)");
		break;
	case OUI_ONOS:
		subTypeStr = val_to_str(subType, onos_subtypes, "Unknown subtype (0x%x)");
		break;
	case OUI_ODVA:
		subTypeStr = val_to_str(subType, lldp_cip_subtypes, "Unknown subtype (0x%x)");
		break;
	default:
		subTypeStr = wmem_strdup_printf(pinfo->pool, "Unknown (%d)",subType);
		break;
	}

	org_tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, tLength, tempTree, NULL, "%s - %s", ouiStr, subTypeStr);
	proto_tree_add_item(org_tlv_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);

	lf = proto_tree_add_item(org_tlv_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	if (dataLen < 4)
	{
		expert_add_info_format(pinfo, lf, &ei_lldp_bad_length,
			"TLV length (%u) too short, must be >=4)", dataLen);
		return tLength;
	}

	/* Display organizational unique id */
	proto_tree_add_uint(org_tlv_tree, hf_org_spc_oui, tvb, offset + 2, 3, oui);

	/* Try to make sure we don't overrun the sub-tlvs */
	vendor_tvb = tvb_new_subset_length(tvb, offset + 5, dataLen - 3);

	switch (oui)
	{
	case OUI_DCBX:
		dissect_dcbx_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_IEEE_802_1:
		dissect_ieee_802_1_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_IEEE_802_3:
		dissect_ieee_802_3_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_MEDIA_ENDPOINT:
		dissect_media_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_PROFINET:
		dissect_profinet_tlv(vendor_tvb, pinfo, org_tlv_tree, pn_lldp_column_info);
		break;
	case OUI_CISCO_2:
		dissect_cisco_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_IEEE_802_1QBG:
		dissect_ieee_802_1qbg_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_HYTEC_GER:
		dissect_hytec_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_AVAYA:
		dissect_avaya_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_IANA:
		dissect_iana_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_AVAYA_EXTREME:
		dissect_extreme_avaya_tlv(vendor_tvb, pinfo, org_tlv_tree, dataLen );
		break;
	case OUI_AVAYA_EXTREME2:
		dissect_extreme_avaya2_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_ONOS:
		dissect_onos_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	case OUI_ODVA:
		dissect_lldp_cip_tlv(vendor_tvb, pinfo, org_tlv_tree);
		break;
	default:
		dissect_oui_default_tlv(vendor_tvb, pinfo, org_tlv_tree);
	}

	return offset + tvb_reported_length(tvb);
}

/* Dissect Unknown TLV */
static int32_t
dissect_lldp_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint32_t offset)
{
	uint16_t dataLen;
	uint16_t tempShort;

	proto_tree	*unknown_tlv_tree;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);

	unknown_tlv_tree = proto_tree_add_subtree(tree, tvb, offset, (dataLen + 2), ett_unknown_tlv, NULL, "Unknown TLV");

	proto_tree_add_item(unknown_tlv_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(unknown_tlv_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

	offset += 2;
	/* Adjust for unknown data */
	offset += dataLen;

	return offset;
}


/* Dissect LLDP packets */
static int
dissect_lldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *lldp_tree = NULL;
	tvbuff_t *new_tvb = NULL;
	uint32_t offset = 0;
	uint16_t isShutdown;
	int32_t rtnValue = 0;
	uint16_t tempShort;
	uint8_t tlvType;
	uint32_t tvbLen;
	profinet_lldp_column_info *pn_lldp_column_info = NULL;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLDP");

	/* Clear the information column on summary display */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_lldp, tvb, offset, -1, ENC_NA);
	lldp_tree = proto_item_add_subtree(ti, ett_lldp);

	// Maybe add an explicit field for the type of the destination mac address?

	// IEEE 802.1AB-2016, Table 7-2—Support for MAC addresses in different systems
	// Address                                   | C-VLAN Bridge | S-VLAN  Bridge | TPMR Bridge   | End station
        // ------------------------------------------+---------------+----------------+---------------+-------------
	// 01-80-C2-00-00-0E Nearest bridge          | Mandatory     | Mandatory      | Mandatory     | Mandatory
	// 01-80-C2-00-00-03 Nearest non-TPMR bridge | Mandatory     | Mandatory      | Not permitted | Recommended
	// 01-80-C2-00-00-00 Nearest Customer Bridge | Mandatory     | Not permitted  | Not permitted | Recommended
	// Any other group MAC address               | Permitted     | Permitted      | Permitted     | Permitted
	// Any individual MAC address                | Permitted     | Permitted      | Permitted     | Permitted

	/* Get chassis id tlv */
	tempShort = tvb_get_ntohs(tvb, offset);
	new_tvb = tvb_new_subset_length(tvb, offset, TLV_INFO_LEN(tempShort)+2);

	/* allocation */
	pn_lldp_column_info = wmem_new0(pinfo->pool, profinet_lldp_column_info);

	rtnValue = dissect_lldp_chassis_id(new_tvb, pinfo, lldp_tree, 0, pn_lldp_column_info);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Chassis ID TLV");
		return tvb_captured_length(tvb);
	}

	offset += rtnValue;

	/* Get port id tlv */
	tempShort = tvb_get_ntohs(tvb, offset);
	new_tvb = tvb_new_subset_length(tvb, offset, TLV_INFO_LEN(tempShort)+2);

	rtnValue = dissect_lldp_port_id(new_tvb, pinfo, lldp_tree, 0, pn_lldp_column_info);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Port ID TLV");
		return tvb_captured_length(tvb);
	}

	offset += rtnValue;

	/* Get time to live tlv */
	tempShort = tvb_get_ntohs(tvb, offset);
	new_tvb = tvb_new_subset_length(tvb, offset, TLV_INFO_LEN(tempShort)+2);

	rtnValue = dissect_lldp_time_to_live(new_tvb, pinfo, lldp_tree, 0, &isShutdown);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Time-to-Live TLV");
		return tvb_captured_length(tvb);
	}

	offset += rtnValue;

	tvbLen = tvb_captured_length(tvb);
	/* Dissect optional tlv info that contained in data packets */
	while (offset < tvbLen)
	{
		tempShort = tvb_get_ntohs(tvb, offset);
		tlvType = TLV_TYPE(tempShort);
		/* pass single TLV to dissectors, Zero offset (point to front of tlv) */
		new_tvb = tvb_new_subset_length(tvb, offset, TLV_INFO_LEN(tempShort)+2);
		switch (tlvType)
		{
		case CHASSIS_ID_TLV_TYPE:
			dissect_lldp_chassis_id(new_tvb, pinfo, lldp_tree, 0, pn_lldp_column_info);
			rtnValue = -1;	/* Duplicate chassis id tlv */
			if (column_info_selection == DEFAULT_COLUMN_INFO)
			{
				col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Chassis ID TLV");
			}
			break;
		case PORT_ID_TLV_TYPE:
			dissect_lldp_port_id(new_tvb, pinfo, lldp_tree, 0, pn_lldp_column_info);
			rtnValue = -1;	/* Duplicate port id tlv */
			if (column_info_selection == DEFAULT_COLUMN_INFO)
			{
				col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Port ID TLV");
			}
			break;
		case TIME_TO_LIVE_TLV_TYPE:
			dissect_lldp_time_to_live(new_tvb, pinfo, lldp_tree, 0, &isShutdown);
			rtnValue = -1;	/* Duplicate time-to-live tlv */
			if (column_info_selection == DEFAULT_COLUMN_INFO)
			{
				col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Time-To-Live TLV");
			}
			break;
		case END_OF_LLDPDU_TLV_TYPE:
			rtnValue = dissect_lldp_end_of_lldpdu(new_tvb, pinfo, lldp_tree, 0);
			break;
		case PORT_DESCRIPTION_TLV_TYPE:
			rtnValue = dissect_lldp_port_desc(new_tvb, pinfo, lldp_tree, 0);
			break;
		case SYSTEM_NAME_TLV_TYPE:
		case SYSTEM_DESCRIPTION_TLV_TYPE:
			rtnValue = dissect_lldp_system_name(new_tvb, pinfo, lldp_tree, 0);
			break;
		case SYSTEM_CAPABILITIES_TLV_TYPE:
			rtnValue = dissect_lldp_system_capabilities(new_tvb, pinfo, lldp_tree, 0);
			break;
		case MANAGEMENT_ADDR_TLV_TYPE:
			rtnValue = dissect_lldp_management_address(new_tvb, pinfo, lldp_tree, 0);
			break;
		case ORGANIZATION_SPECIFIC_TLV_TYPE:
			rtnValue = dissect_organizational_specific_tlv(new_tvb, pinfo, lldp_tree, 0, pn_lldp_column_info);
			break;
		default:
			if (!assume_unrecognized_tlv
			|| tempShort > tvb_reported_length_remaining(tvb, offset)) {
				/* Probably not an LLDP LTV */
				rtnValue = -1;
			}
			else {
				rtnValue = dissect_lldp_unknown_tlv(new_tvb, pinfo, lldp_tree, 0);
			}
			break;
		}

		// Shutdown PDU: Verify that only ChassisID, PortID, TTL and optionally END TLVs are present
		if (isShutdown && tlvType != END_OF_LLDPDU_TLV_TYPE)
		{
			proto_tree_add_expert_format(tree, pinfo, &ei_lldp_shutdown_excess_tlv , tvb, offset, TLV_INFO_LEN(tempShort),
				"TLV type 0x%02X not allowed in Shutdown PDU", tlvType);
		}

		if (rtnValue < 0) {
			break;
		}
		else
			offset += rtnValue;

		/* Terminate the LLDP dissector after reaching the END_OF_LLDPDU */
		if (tlvType == END_OF_LLDPDU_TLV_TYPE) {
			break;
		}
	}

	set_actual_length(tvb, offset);
	proto_item_set_len(ti, offset);
	return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_lldp(void)
{
	module_t *lldp_module;
	expert_module_t *expert_lldp;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_lldp_tlv_type,
			{ "TLV Type", "lldp.tlv.type", FT_UINT16, BASE_DEC,
			VALS(tlv_types), TLV_TYPE_MASK, NULL, HFILL }
		},
		{ &hf_lldp_tlv_len,
			{ "TLV Length", "lldp.tlv.len", FT_UINT16, BASE_DEC,
			NULL, TLV_INFO_LEN_MASK, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap,
			{ "Capabilities", "lldp.tlv.system_cap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_other,
			{ "Other", "lldp.tlv.system_cap.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_OTHER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_repeater,
			{ "Repeater", "lldp.tlv.system_cap.repeater", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_REPEATER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_bridge,
			{ "Bridge", "lldp.tlv.system_cap.bridge", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_BRIDGE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_wlan_access_pt,
			{ "WLAN access point", "lldp.tlv.system_cap.wlan_access_pt", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_WLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_router,
			{ "Router", "lldp.tlv.system_cap.router", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_ROUTER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_telephone,
			{ "Telephone", "lldp.tlv.system_cap.telephone", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TELEPHONE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_docsis_cable_device,
			{ "DOCSIS cable device", "lldp.tlv.system_cap.docsis_cable_device", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_DOCSIS, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_station_only,
			{ "Station only", "lldp.tlv.system_cap.station_only", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_STATION, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_cvlan_component,
			{ "C-VLAN component", "lldp.tlv.system_cap.cvlan", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_CVLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_svlan_component,
			{ "S-VLAN component", "lldp.tlv.system_cap.svlan", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_SVLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_tpmr_component,
			{ "TPMR component", "lldp.tlv.system_cap.tpmr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TPMR, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_name,
			{ "System Name", "lldp.tlv.system.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_desc,
			{ "System Description", "lldp.tlv.system.desc", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap,
			{ "Enabled Capabilities", "lldp.tlv.enable_system_cap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_other,
			{ "Other", "lldp.tlv.enable_system_cap.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_OTHER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_repeater,
			{ "Repeater", "lldp.tlv.enable_system_cap.repeater", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_REPEATER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_bridge,
			{ "Bridge", "lldp.tlv.enable_system_cap.bridge", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_BRIDGE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_wlan_access_pt,
			{ "WLAN access point", "lldp.tlv.enable_system_cap.wlan_access_pt", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_WLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_router,
			{ "Router", "lldp.tlv.enable_system_cap.router", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_ROUTER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_telephone,
			{ "Telephone", "lldp.tlv.enable_system_cap.telephone", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TELEPHONE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_docsis_cable_device,
			{ "DOCSIS cable device", "lldp.tlv.enable_system_cap.docsis_cable_device", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_DOCSIS, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_station_only,
			{ "Station only", "lldp.tlv.enable_system_cap.station_only", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_STATION, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_cvlan_component,
			{ "C-VLAN component", "lldp.tlv.enable_system_cap.cvlan", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_CVLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_svlan_component,
			{ "S-VLAN component", "lldp.tlv.enable_system_cap.svlan", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_SVLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_tpmr_component,
			{ "TPMR component", "lldp.tlv.enable_system_cap.tpmr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TPMR, NULL, HFILL }
		},
		{ &hf_chassis_id_subtype,
			{ "Chassis Id Subtype", "lldp.chassis.subtype", FT_UINT8, BASE_DEC,
			VALS(chassis_id_subtypes), 0, NULL, HFILL }
		},
		{ &hf_chassis_id,
			{ "Chassis Id", "lldp.chassis.id", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_mac,
			{ "Chassis Id", "lldp.chassis.id.mac", FT_ETHER, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_ip4,
			{ "Chassis Id", "lldp.chassis.id.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_ip6,
			{ "Chassis Id", "lldp.chassis.id.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_id_subtype,
			{ "Port Id Subtype", "lldp.port.subtype", FT_UINT8, BASE_DEC,
			VALS(port_id_subtypes), 0, NULL, HFILL }
		},
		{ &hf_port_id,
			{ "Port Id", "lldp.port.id", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_desc,
			{ "Port Description", "lldp.port.desc", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_id_mac,
			{ "Port Id", "lldp.port.id.mac", FT_ETHER, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_network_address_family,
			{ "Network Address family", "lldp.network_address.subtype", FT_UINT8, BASE_DEC,
			VALS(afn_vals), 0, NULL, HFILL }
		},
		{ &hf_port_id_ip4,
			{ "Port Id", "lldp.port.id.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_id_ip6,
			{ "Port Id", "lldp.port.id.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_time_to_live,
			{ "Seconds", "lldp.time_to_live", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_pdu_type,
			{ "PDU Type", "lldp.pdu_type", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_mgn_address_len,
			{ "Address String Length", "lldp.mgn.address.len", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_address_subtype,
			{ "Address Subtype", "lldp.mgn.address.subtype", FT_UINT8, BASE_DEC,
			VALS(afn_vals), 0, "Undefined", HFILL }
		},
		{ &hf_mgn_addr_ipv4,
			{ "Management Address", "lldp.mgn.addr.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_addr_ipv6,
			{ "Management Address", "lldp.mgn.addr.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_addr_hex,
			{ "Management Address", "lldp.mgn.addr.hex", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_interface_subtype,
			{ "Interface Subtype", "lldp.mgn.interface.subtype", FT_UINT8, BASE_DEC,
			VALS(interface_subtype_values), 0, "Undefined", HFILL }
		},
		{ &hf_mgn_interface_number,
			{ "Interface Number", "lldp.mgn.interface.number", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_oid_len,
			{ "OID String Length", "lldp.mgn.obj.len", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_obj_id,
			{ "Object Identifier", "lldp.mgn.obj.id", FT_OID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_org_spc_oui,
			{ "Organization Unique Code", "lldp.orgtlv.oui", FT_UINT24, BASE_OUI,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dcbx_type,
			{ "DCBx Protocol", "lldp.dcbx.proto", FT_UINT8, BASE_HEX,
			VALS(dcbx_protocol_types), 0x0, NULL, HFILL }
		},
		{ &hf_dcbx_tlv_type,
			{ "DCBx TLV Type", "lldp.dcbx.type", FT_UINT16, BASE_DEC,
			VALS(dcbx_subtypes), TLV_TYPE_MASK, NULL, HFILL }
		},
		{ &hf_dcbx_tlv_len,
			{ "DCBx TLV Length", "lldp.dcbx.len", FT_UINT16, BASE_DEC,
			NULL, TLV_INFO_LEN_MASK, NULL, HFILL }
		},
		{ &hf_dcbx_tlv_oper_version,
			{ "Operating Version", "lldp.dcbx.version", FT_UINT8, BASE_HEX,
			VALS(dcbx_protocol_types), 0x0, "Unknown", HFILL }
		},
		{ &hf_dcbx_tlv_max_version,
			{ "Max Version", "lldp.dcbx.max_version", FT_UINT8, BASE_HEX,
			VALS(dcbx_protocol_types), 0x0, "Unknown", HFILL }
		},
		{ &hf_dcbx_control_sequence,
			{ "Sequence No", "lldp.dcbx.control.seq", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_control_ack,
			{ "Ack No", "lldp.dcbx.control.ack", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_flag_enabled,
			{ "Feature", "lldp.dcbx.feature.enabled", FT_BOOLEAN , 8,
			TFS(&tfs_enabled_disabled), 0x80, NULL, HFILL }
		},
		{ &hf_dcbx_feature_flag_willing,
			{ "Willing", "lldp.dcbx.feature.willing", FT_BOOLEAN , 8,
			TFS(&tfs_yes_no), 0x40, NULL, HFILL }
		},
		{ &hf_dcbx_feature_flag_error,
			{ "Error", "lldp.dcbx.feature.error", FT_BOOLEAN , 8,
			TFS(&tfs_set_notset), 0x20, NULL, HFILL }
		},
		{ &hf_dcbx_feature_subtype,
			{ "Subtype", "lldp.dcbx.feature.subtype", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_reserved,
			{ "Reserved", "lldp.dcbx.feature.pg.reserved", FT_UINT8, BASE_HEX,
			NULL, 0xFE, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_0,
			{ "PGID for Prio 0", "lldp.dcbx.feature.pg.pgid_prio0", FT_UINT16, BASE_DEC,
			NULL, 0xF000, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_1,
			{ "PGID for Prio 1", "lldp.dcbx.feature.pg.pgid_prio1", FT_UINT16, BASE_DEC,
			NULL, 0x0F00, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_2,
			{ "PGID for Prio 2", "lldp.dcbx.feature.pg.pgid_prio2", FT_UINT16, BASE_DEC,
			NULL, 0x00F0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_3,
			{ "PGID for Prio 3", "lldp.dcbx.feature.pg.pgid_prio3", FT_UINT16, BASE_DEC,
			NULL, 0x000F, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_4,
			{ "PGID for Prio 4", "lldp.dcbx.feature.pg.pgid_prio4", FT_UINT16, BASE_DEC,
			NULL, 0xF000, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_5,
			{ "PGID for Prio 5", "lldp.dcbx.feature.pg.pgid_prio5", FT_UINT16, BASE_DEC,
			NULL, 0x0F00, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_6,
			{ "PGID for Prio 6", "lldp.dcbx.feature.pg.pgid_prio6", FT_UINT16, BASE_DEC,
			NULL, 0x00F0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pgid_prio_7,
			{ "PGID for Prio 7", "lldp.dcbx.feature.pg.pgid_prio7", FT_UINT16, BASE_DEC,
			NULL, 0x000F, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_0,
			{ "Bandwidth for PGID 0", "lldp.dcbx.feature.pg.per0", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_1,
			{ "Bandwidth for PGID 1", "lldp.dcbx.feature.pg.per1", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_2,
			{ "Bandwidth for PGID 2", "lldp.dcbx.feature.pg.per2", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_3,
			{ "Bandwidth for PGID 3", "lldp.dcbx.feature.pg.per3", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_4,
			{ "Bandwidth for PGID 4", "lldp.dcbx.feature.pg.per4", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_5,
			{ "Bandwidth for PGID 5", "lldp.dcbx.feature.pg.per5", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_6,
			{ "Bandwidth for PGID 6", "lldp.dcbx.feature.pg.per6", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_per_7,
			{ "Bandwidth for PGID 7", "lldp.dcbx.feature.pg.per7", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pg_numtcs,
			{ "Number of Traffic Classes Supported", "lldp.dcbx.feature.pg.numtcs", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio0,
			{ "PFC for Priority 0", "lldp.dcbx.feature.pfc.prio0", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x1, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio1,
			{ "PFC for Priority 1", "lldp.dcbx.feature.pfc.prio1", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x2, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio2,
			{ "PFC for Priority 2", "lldp.dcbx.feature.pfc.prio2", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x4, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio3,
			{ "PFC for Priority 3", "lldp.dcbx.feature.pfc.prio3", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x8, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio4,
			{ "PFC for Priority 4", "lldp.dcbx.feature.pfc.prio4", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio5,
			{ "PFC for Priority 5", "lldp.dcbx.feature.pfc.prio5", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio6,
			{ "PFC for Priority 6", "lldp.dcbx.feature.pfc.prio6", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_prio7,
			{ "PFC for Priority 7", "lldp.dcbx.feature.pfc.prio7", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x80, NULL, HFILL }
		},
		{ &hf_dcbx_feature_pfc_numtcs,
			{ "Number of Traffic Classes Supported", "lldp.dcbx.feature.pfc.numtcs", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_app_proto,
			{ "Application Protocol Id", "lldp.dcbx.feature.app.proto", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_app_selector,
			{ "Selector Field", "lldp.dcbx.feature.app.sf", FT_UINT24, BASE_DEC,
			VALS(dcbx_app_selector), 0x3 << 16, NULL, HFILL }
		},
		{ &hf_dcbx_feature_app_oui,
			{ "Application OUI", "lldp.dcbx.feature.app.oui", FT_UINT24, BASE_HEX,
			NULL, ~(0x3 << 16), NULL, HFILL }
		},
		{ &hf_dcbx_feature_app_prio,
			{ "Application Priority", "lldp.dcbx.feature.app.prio", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dcbx_feature_flag_llink_type,
			{ "Logical Link Down Type", "lldp.dcbx.feature.llink.type", FT_UINT8, BASE_HEX,
			VALS(dcbx_llink_types), 0x80, NULL, HFILL }
		},
		{ &hf_ieee_802_1_subtype,
			{ "IEEE 802.1 Subtype", "lldp.ieee.802_1.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_1_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag,
			{ "Flags", "lldp.ieee.802_1.port_and_vlan_id_flag", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag_supported,
			{ "Port and Protocol VLAN", "lldp.ieee.802_1.port_and_vlan_id_flag.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag_enabled,
			{ "Port and Protocol VLAN", "lldp.ieee.802_1.port_and_vlan_id_flag.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_vlan_id,
			{ "Port VLAN Identifier", "lldp.ieee.802_1.port_vlan.id", FT_UINT16, BASE_DEC_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_proto_vlan_id,
			{ "Port and Protocol VLAN Identifier", "lldp.ieee.802_1.port_proto_vlan.id", FT_UINT16, BASE_DEC_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_vlan_id,
			{ "VLAN Identifier", "lldp.ieee.802_1.vlan.id", FT_UINT16, BASE_DEC_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_vlan_name_length,
			{ "VLAN Name Length", "lldp.ieee.802_1.vlan.name_len", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_vlan_name,
			{ "VLAN Name", "lldp.ieee.802_1.vlan.name", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_proto_id_length,
			{ "Protocol Identity Length", "lldp.ieee.802_1.proto.id_length", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_proto_id,
			{ "Protocol Identity", "lldp.ieee.802_1.proto.id", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_aggregation_status,
			{ "Aggregation Status", "lldp.ieee.802_1.aggregation_status", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_aggregation_status_cap,
			{ "Aggregation Capability", "lldp.ieee.802_1.aggregation_status.cap", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_1_aggregation_status_enabled,
			{ "Aggregation Status", "lldp.ieee.802_1.aggregation_status.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_1_aggregation_status_porttype,
			{ "Aggregation Status", "lldp.ieee.802_1.aggregation_status.porttype", FT_UINT8, BASE_DEC,
			VALS(porttype_values), 0x0c, NULL, HFILL }
		},
		{ &hf_ieee_802_1_aggregated_port_id,
			{ "Aggregated Port Id", "lldp.ieee.802_1.aggregated_port_id", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio0,
			{ "Priority 0 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio0", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio1,
			{ "Priority 1 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio1", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio2,
			{ "Priority 2 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio2", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio3,
			{ "Priority 3 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio3", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio4,
			{ "Priority 4 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio4", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio5,
			{ "Priority 5 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio5", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio6,
			{ "Priority 6 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio6", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_cnpv_prio7,
			{ "Priority 7 CNPV Capability", "lldp.ieee.802_1qau.cnpv.prio7", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x80, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio0,
			{ "Priority 0 Ready Indicator", "lldp.ieee.802_1qau.ready.prio0", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio1,
			{ "Priority 1 Ready Indicator", "lldp.ieee.802_1qau.ready.prio1", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio2,
			{ "Priority 2 Ready Indicator", "lldp.ieee.802_1qau.ready.prio2", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio3,
			{ "Priority 3 Ready Indicator", "lldp.ieee.802_1qau.ready.prio3", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x08, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio4,
			{ "Priority 4 Ready Indicator", "lldp.ieee.802_1qau.ready.prio4", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x10, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio5,
			{ "Priority 5 Ready Indicator", "lldp.ieee.802_1qau.ready.prio5", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x20, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio6,
			{ "Priority 6 Ready Indicator", "lldp.ieee.802_1qau.ready.prio6", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x40, NULL, HFILL }
		},
		{ &hf_ieee_8021qau_ready_prio7,
			{ "Priority 7 Ready Indicator", "lldp.ieee.802_1qau.ready.prio7", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), 0x80, NULL, HFILL }
		},
		{ &hf_ieee_8021az_feature_flag_willing,
			{ "Willing", "lldp.dcbx.ieee.willing", FT_BOOLEAN , 8,
			TFS(&tfs_yes_no), 0x80, NULL, HFILL }
		},
		{ &hf_ieee_8021az_feature_flag_cbs,
			{ "Credit-Based Shaper", "lldp.dcbx.ieee.ets.cbs", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL }
		},
		{ &hf_ieee_8021az_maxtcs,
			{ "Maximum Number of Traffic Classes", "lldp.dcbx.ieee.ets.maxtcs", FT_UINT8, BASE_DEC,
			NULL, 0x7, NULL, HFILL }
		},
		{ &hf_ieee_8021az_tsa_class0,
			{ "TSA for Traffic Class 0", "lldp.dcbx.ieee.ets.tsa0", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class1,
			{ "TSA for Traffic Class 1", "lldp.dcbx.ieee.ets.tsa1", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class2,
			{ "TSA for Traffic Class 2", "lldp.dcbx.ieee.ets.tsa2", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class3,
			{ "TSA for Traffic Class 3", "lldp.dcbx.ieee.ets.tsa3", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class4,
			{ "TSA for Traffic Class 4", "lldp.dcbx.ieee.ets.tsa4", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class5,
			{ "TSA for Traffic Class 5", "lldp.dcbx.ieee.ets.tsa5", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class6,
			{ "TSA for Traffic Class 6", "lldp.dcbx.ieee.ets.tsa6", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_tsa_class7,
			{ "TSA for Traffic Class 7", "lldp.dcbx.ieee.ets.tsa7", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_tsa), 0, "Reserved", HFILL }
		},
		{ &hf_ieee_8021az_feature_flag_mbc,
			{ "MACsec Bypass Capability", "lldp.dcbx.ieee.pfc.mbc", FT_BOOLEAN, 8,
			TFS(&tfs_capable_not_capable), 0x40, NULL, HFILL }
		},
		{ &hf_ieee_8021az_pfc_numtcs,
			{ "Max PFC Enabled Traffic Classes", "lldp.dcbx.ieee.pfc.numtcs", FT_UINT8, BASE_DEC,
			NULL, 0xF, NULL, HFILL }
		},
		{ &hf_ieee_8021az_app_reserved,
			{ "Reserved", "lldp.dcbx.ieee.app.reserved", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_8021az_app_prio,
			{ "Application Priority", "lldp.dcbx.ieee.app.prio", FT_UINT8, BASE_DEC,
			NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_ieee_8021az_app_selector,
			{ "Application Selector", "lldp.dcbx.iee.app.sf", FT_UINT8, BASE_DEC,
			VALS(dcbx_ieee_8021az_sf), 0x7, NULL, HFILL }
		},
		{ &hf_ieee_802_3_subtype,
			{ "IEEE 802.3 Subtype", "lldp.ieee.802_3.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_3_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status,
			{ "Auto-Negotiation Support/Status", "lldp.ieee.802_3.mac_phy_auto_neg_status", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status_supported,
			{ "Auto-Negotiation", "lldp.ieee.802_3.mac_phy_auto_neg_status.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status_enabled,
			{ "Auto-Negotiation", "lldp.ieee.802_3.mac_phy_auto_neg_status.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps,
			{ "PMD Auto-Negotiation Advertised Capability", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd,
			{ "1000BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_TFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t,
			{ "1000BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd,
			{ "1000BASE-X (-LX, -SX, -CX full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_XFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x,
			{ "1000BASE-X (-LX, -SX, -CX half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_X, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause,
			{ "Asymmetric and Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_BPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause,
			{ "Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_SPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause,
			{ "Asymmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_APAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause,
			{ "PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_PAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd,
			{ "100BASE-T2 (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T2FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2,
			{ "100BASE-T2 (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T2, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd,
			{ "100BASE-TX (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_TXFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx,
			{ "100BASE-TX (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_TX, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4,
			{ "100BASE-T4", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T4, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd,
			{ "10BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_10BASET_FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t,
			{ "10BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_10BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_other,
			{ "Other or unknown", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_OTHER, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd,
			{ "1000BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_TFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t,
			{ "1000BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd,
			{ "1000BASE-X (-LX, -SX, -CX full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_XFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x,
			{ "1000BASE-X (-LX, -SX, -CX half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_X, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause,
			{ "Asymmetric and Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_BPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause,
			{ "Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_SPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause,
			{ "Asymmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_APAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause,
			{ "PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_PAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd,
			{ "100BASE-T2 (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T2FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2,
			{ "100BASE-T2 (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T2, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd,
			{ "100BASE-TX (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_TXFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx,
			{ "100BASE-TX (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_TX, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4,
			{ "100BASE-T4", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T4, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd,
			{ "10BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_10BASET_FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t,
			{ "10BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_10BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other,
			{ "Other or unknown", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_OTHER, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_mau_type,
			{ "Operational MAU Type", "lldp.ieee.802_3.pmd_mau_type", FT_UINT16, BASE_HEX,
			VALS(operational_mau_type_values), 0x0, "Unknown", HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support,
			{ "MDI Power Support", "lldp.ieee.802_3.mdi_power_support", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_port_class,
			{ "Port Class", "lldp.ieee.802_3.mdi_power_support.port_class", FT_BOOLEAN, 8,
			TFS(&tfs_ieee_802_3_pse_pd), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_power_support,
			{ "PSE MDI Power", "lldp.ieee.802_3.mdi_power_support.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_power_enabled,
			{ "PSE MDI Power", "lldp.ieee.802_3.mdi_power_support.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_pairs,
			{ "PSE Pairs Control Ability", "lldp.ieee.802_3.mdi_power_support.pse_pairs", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x08, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_pse_pair,
			{ "PSE Power Pair", "lldp.ieee.802_3.mdi_pse_pair", FT_UINT8, BASE_DEC,
			VALS(power_pair_802_3), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_class,
			{ "Power Class", "lldp.ieee.802_3.mdi_power_class", FT_UINT8, BASE_DEC,
			VALS(power_class_802_3), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_type,
			{ "Power Type", "lldp.ieee.802_3.mdi_power_type", FT_UINT8, BASE_DEC,
			VALS(power_type_802_3), 0xC0, "Unknown", HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_source,
			{ "Power Source", "lldp.ieee.802_3.mdi_power_source", FT_UINT8, BASE_DEC,
			NULL, 0x30, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_priority,
			{ "Power Priority", "lldp.ieee.802_3.mdi_power_priority", FT_UINT8, BASE_DEC,
			VALS(media_power_priority), 0x03, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_pd4pid,
			{ "PD 4PID", "lldp.ieee.802_3.mdi_power_pd4pid", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x4, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_requested_power,
			{ "PD Requested Power Value", "lldp.ieee.802_3.mdi_pde_requested", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_allocated_power,
			{ "PSE Allocated Power Value", "lldp.ieee.802_3.mdi_pse_allocated", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_a,
			{ "DS PD Requested Power Value Mode A", "lldp.ieee.802_3.bt_ds_pd_requested_power_value_mode_a", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pd_requested_power_value_mode_b,
			{ "DS PD Requested Power Value Mode B", "lldp.ieee.802_3.bt_ds_pd_requested_power_value_mode_b", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_a,
			{ "DS PSE Allocated Power Value Alt A", "lldp.ieee.802_3.bt_ds_pse_allocated_power_value_alt_a", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pse_allocated_power_value_alt_b,
			{ "DS PSE Allocated Power Value Alt B", "lldp.ieee.802_3.bt_ds_pse_allocated_power_value_alt_b", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_status,
			{ "Power Status", "lldp.ieee.802_3.bt_power_status", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pse_powering_status,
			{ "PSE Powering Status", "lldp.ieee.802_3.bt_pse_powering_status", FT_UINT16, BASE_DEC,
			VALS(pse_powering_status_802_3_bt), 0xC000, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pd_powered_status,
			{ "PD Powered Status", "lldp.ieee.802_3.bt_pd_powered_status", FT_UINT16, BASE_DEC,
			VALS(pd_powered_status_802_3_bt), 0x3000, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pse_power_pairs_ext,
			{ "PSE Power Pairs ext", "lldp.ieee.802_3.bt_pse_power_pairs_ext", FT_UINT16, BASE_DEC,
			VALS(power_pairs_ext_802_3_bt), 0x0C00, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pwr_class_ext_a,
			{ "DS Pwr Class Ext A", "lldp.ieee.802_3.bt_ds_pwr_class_ext_a", FT_UINT16, BASE_DEC,
			VALS(power_type_ext_mode_ab_802_3_bt), 0x0380, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_ds_pwr_class_ext_b,
			{ "DS Pwr Class Ext B", "lldp.ieee.802_3.bt_ds_pwr_class_ext_b", FT_UINT16, BASE_DEC,
			VALS(power_type_ext_mode_ab_802_3_bt), 0x0070, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pwr_class_ext,
			{ "Pwr Class Ext", "lldp.ieee.802_3.bt_pwr_class_ext_", FT_UINT16, BASE_DEC,
			VALS(power_class_ext_802_3_bt), 0x000F, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_system_setup,
			{ "System Setup", "lldp.ieee.802_3.bt_system_setup", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_type_ext,
			{ "Power Type Ext", "lldp.ieee.802_3.bt_power_type_ext", FT_UINT8, BASE_DEC,
			VALS(power_type_ext_802_3_bt), 0x0E, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_pd_load,
			{ "PD Load", "lldp.ieee.802_3.bt_power.pd_load", FT_BOOLEAN, 8,
			TFS(&tfs_ieee_802_3_pd_load), 0x1, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pse_maximum_available_power_value,
			{ "PSE Maximum Available Power Value", "lldp.ieee.802_3.bt_pse_maximum_available_power_value", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(mdi_power_base), 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_autoclass,
			{ "Autoclass", "lldp.ieee.802_3.bt_autoclass", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_pse_autoclass_support,
			{ "PSE Autoclass support", "lldp.ieee.802_3.bt_pse_autoclass_support", FT_UINT8, BASE_DEC,
			NULL, 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_autoclass_completed,
			{ "Autoclass Completed", "lldp.ieee.802_3.bt_autoclass_completed", FT_UINT8, BASE_DEC,
			NULL, 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_autoclass_request,
			{ "Autoclass Request", "lldp.ieee.802_3.bt_autoclass_request", FT_UINT8, BASE_DEC,
			NULL, 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_autoclass_reserved,
			{ "Autoclass Reserved", "lldp.ieee.802_3.bt_autoclass_reserved", FT_UINT8, BASE_HEX,
			NULL, 0xF8, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_down,
			{ "Power down", "lldp.ieee.802_3.bt_power_down", FT_UINT24, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_down_request,
			{ "Power down request", "lldp.ieee.802_3.bt_power_down_request", FT_UINT24, BASE_DEC,
			NULL, 0xFC0000, NULL, HFILL }
		},
		{ &hf_ieee_802_3_bt_power_down_time,
			{ "Power down time", "lldp.ieee.802_3.bt_power_down_time", FT_UINT24, BASE_DEC,
			NULL, 0x03FFFF, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status,
			{ "Aggregation Status", "lldp.ieee.802_3.aggregation_status", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status_cap,
			{ "Aggregation Capability", "lldp.ieee.802_3.aggregation_status.cap", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status_enabled,
			{ "Aggregation Status", "lldp.ieee.802_3.aggregation_status.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregated_port_id,
			{ "Aggregated Port Id", "lldp.ieee.802_3.aggregated_port_id", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_max_frame_size,
			{ "Maximum Frame Size", "lldp.ieee.802_3.max_frame_size", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_eee_transmit,
			{ "Transmit", "lldp.ieee.802_3.eee.transmit", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_eee_receive,
			{ "Receive", "lldp.ieee.802_3.eee.receive", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_eee_fallback_receive,
			{ "Fallback Receive", "lldp.ieee.802_3.eee.fallback_receive", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_eee_echo_transmit,
			{ "Echo Transmit", "lldp.ieee.802_3.eee.echo_transmit", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_eee_echo_receive,
			{ "Echo Receive", "lldp.ieee.802_3.eee.echo_receive", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_subtype,
			{ "IEEE 802.1Qbg Subtype", "lldp.ieee.802_1qbg.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_1qbg_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps,
			{ "Supported capabilities", "lldp.ieee.802_1qbg.evb_support_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_std,
			{ "Standard bridging (STD)", "lldp.ieee.802_1qbg.evb_support_caps.std", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_STD, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_rr,
			{ "Reflective relay (RR)", "lldp.ieee.802_1qbg.evb_support_caps.rr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RR, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_rte,
			{ "Retransmission timer exponent (RTE)", "lldp.ieee.802_1qbg.evb_support_caps.rte", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RTE, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_ecp,
			{ "Edge control protocol (ECP)", "lldp.ieee.802_1qbg.evb_support_caps.ecp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_ECP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_vdp,
			{ "VSI discovery protocol (VDP)", "lldp.ieee.802_1qbg.evb_support_caps.vdp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_VDP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps,
			{ "Configured capabilities", "lldp.ieee.802_1qbg.evb_configure_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_std,
			{ "Standard bridging (STD)", "lldp.ieee.802_1qbg.evb_configure_caps.std", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_STD, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_rr,
			{ "Reflective relay (RR)", "lldp.ieee.802_1qbg.evb_configure_caps.rr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RR, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_rte,
			{ "Retransmission timer exponent (RTE)", "lldp.ieee.802_1qbg.evb_configure_caps.rte", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RTE, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_ecp,
			{ "Edge control protocol (ECP)", "lldp.ieee.802_1qbg.evb_configure_caps.ecp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_ECP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_vdp,
			{ "VSI discovery protocol (VDP)", "lldp.ieee.802_1qbg.evb_configure_caps.vdp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_VDP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_supported_vsi,
			{ "Supported No of VSIs", "lldp.ieee.802_1qbg.evb_supported_vsi", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configured_vsi,
			{ "Configured No of VSIs", "lldp.ieee.802_1qbg.evb_configured_vsi", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_retrans_timer,
			{ "Retransmission timer exponent", "lldp.ieee.802_1qbg.evb_retrans_timer", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec,
			{ "Additional Ethernet Capabilities", "lldp.ieee.802_3br.eac", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec_support,
			{ "Preemption capabilities support", "lldp.ieee.802_3br.aec.support", FT_BOOLEAN, 16,
			TFS(&tfs_supported_not_supported), IEEE_802_3BR_AEC_SUPPORT, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec_enable,
			{ "Preemption capabilities enable", "lldp.ieee.802_3br.aec.enable", FT_BOOLEAN, 16,
			TFS(&tfs_enabled_disabled), IEEE_802_3BR_AEC_ENABLE, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec_active,
			{ "Preemption capabilities active", "lldp.ieee.802_3br.aec.active", FT_BOOLEAN, 16,
			TFS(&tfs_active_inactive), IEEE_802_3BR_AEC_ACTIVE, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec_addfragsize,
			{ "Additional Fragment Size", "lldp.ieee.802_3br.aec.addfragsize", FT_UINT16, BASE_DEC,
			NULL, IEEE_802_3BR_AEC_ADDFRAGSIZE, NULL, HFILL }
		},
		{ &hf_ieee_802_3br_aec_reserved,
			{ "Reserved", "lldp.ieee.802_3br.aec.reserved", FT_UINT16, BASE_HEX,
			NULL, IEEE_802_3BR_AEC_RESERVED, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype,
			{ "Media Subtype",	"lldp.media.subtype", FT_UINT8, BASE_HEX,
			VALS(media_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps,
			{ "Capabilities", "lldp.media.subtype.caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_llpd,
			{ "LLDP-MED Capabilities", "lldp.media.subtype.caps.llpd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_LLDP, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_network_policy,
			{ "Network Policy", "lldp.media.subtype.caps.network_policy", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_NETWORK_POLICY, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_location_id,
			{ "Location Identification", "lldp.media.subtype.caps.location_id", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_LOCATION_ID, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_mdi_pse,
			{ "Extended Power via MDI-PSE", "lldp.media.subtype.caps.mdi_pse", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_MDI_PSE, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_mid_pd,
			{ "Extended Power via MDI-PD", "lldp.media.subtype.caps.mid_pd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_MDI_PD, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_inventory,
			{ "Inventory", "lldp.media.subtype.caps.inventory", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_INVENTORY, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_class,
			{ "Class Type", "lldp.media.subtype.class", FT_UINT8, BASE_DEC,
			VALS(media_class_values), 0x0, "Unknown", HFILL }
		},
		{ &hf_media_application_type,
			{ "Application Type", "lldp.media.app_type", FT_UINT8, BASE_DEC,
			VALS(media_application_type), 0x0, "Unknown", HFILL }
		},
		{ &hf_media_policy_flag,
			{ "Policy", "lldp.media.policy_flag", FT_BOOLEAN, 24,
			TFS(&tfs_unknown_defined), 0x800000, NULL, HFILL }
		},
		{ &hf_media_tag_flag,
			{ "Tagged", "lldp.media.tag_flag", FT_BOOLEAN, 24,
			TFS(&tfs_yes_no), 0x400000, NULL, HFILL }
		},
		{ &hf_media_vlan_id,
			{ "VLAN Id", "lldp.media.vlan_id", FT_UINT24, BASE_DEC,
			NULL, 0x1FFE00, NULL, HFILL }
		},
		{ &hf_media_l2_prio,
			{ "L2 Priority", "lldp.media.l2_prio", FT_UINT24, BASE_DEC,
			NULL, 0x0001C0, NULL, HFILL }
		},
		{ &hf_media_dscp,
			{ "DSCP Priority", "lldp.media.dscp", FT_UINT24, BASE_DEC,
			NULL, 0x00003F, NULL, HFILL }
		},
		{ &hf_media_loc_data_format,
			{ "Location Data Format", "lldp.media.loc.data_format", FT_UINT8, BASE_DEC,
			VALS(location_data_format), 0x0, NULL, HFILL }
		},
		{ &hf_media_loc_lat_resolution,
			{ "Latitude Resolution", "lldp.media.loc.lat_resolution", FT_UINT8, BASE_CUSTOM,
			CF_FUNC(latitude_or_longitude_resolution), 0xFC, NULL, HFILL }
		},
		{ &hf_media_loc_lat,
			{ "Latitude", "lldp.media.loc.latitude", FT_UINT40, BASE_CUSTOM,
			CF_FUNC(latitude_base), 0x0, NULL, HFILL }
		},
		{ &hf_media_loc_long_resolution,
			{ "Longitude Resolution", "lldp.media.loc.long_resolution", FT_UINT8, BASE_CUSTOM,
			CF_FUNC(latitude_or_longitude_resolution), 0xFC, NULL, HFILL }
		},
		{ &hf_media_loc_long,
			{ "Longitude", "lldp.media.loc.longitude", FT_UINT40, BASE_CUSTOM,
			CF_FUNC(longitude_base), 0x0, NULL, HFILL }
		},
		{ &hf_media_loc_alt_type,
			{ "Altitude Type", "lldp.media.loc.alt_type", FT_UINT8, BASE_DEC,
			VALS(altitude_type), 0xF0, "Unknown", HFILL }
		},
		{ &hf_media_loc_alt_resolution,
			{ "Altitude Resolution", "lldp.media.loc.alt_resolution", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(altitude_resolution), 0x0FC0, NULL, HFILL }
		},
		{ &hf_media_loc_alt,
			{ "Altitude", "lldp.media.loc.altitude", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(altitude_base), 0x0, NULL, HFILL }
		},
		{ &hf_media_loc_ver,
			{ "Ver", "lldp.media.loc.ver", FT_UINT8, BASE_DEC,
			NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_media_loc_reserved,
			{ "Reserved", "lldp.media.loc.reserved", FT_UINT8, BASE_DEC,
			NULL, 0x38, NULL, HFILL }
		},
		{ &hf_media_loc_datum,
			{ "Datum", "lldp.media.loc.datum", FT_UINT8, BASE_DEC,
			VALS(datum_type_values), 0x07, NULL, HFILL }
		},
		{ &hf_media_civic_lci_length,
			{ "LCI Length", "lldp.media.civic.length", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_civic_what,
			{ "What", "lldp.media.civic.what", FT_UINT8, BASE_DEC,
			VALS(civic_address_what_values), 0x0, "Unknown", HFILL }
		},
		{ &hf_media_civic_country,
			{ "Country", "lldp.media.civic.country", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_civic_addr_type,
			{ "CA Type", "lldp.media.civic.type", FT_UINT8, BASE_DEC,
			VALS(civic_address_type_values), 0x0, "Unknown", HFILL }
		},
		{ &hf_media_civic_addr_len,
			{ "CA Length", "lldp.media.civic.addr_length", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_civic_addr_value,
			{ "CA Value", "lldp.media.civic.value", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_ecs,
			{ "ELIN", "lldp.media.ecs", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_power_type,
			{ "Power Type", "lldp.media.power.type", FT_UINT8, BASE_DEC,
			VALS(media_power_type), 0xC0, "Unknown", HFILL }
		},
		{ &hf_media_power_source,
			{ "Power Source", "lldp.media.power.source", FT_UINT8, BASE_DEC,
			NULL, 0x30, NULL, HFILL }
		},
		{ &hf_media_power_priority,
			{ "Power Priority", "lldp.media.power.prio", FT_UINT8, BASE_DEC,
			VALS(media_power_priority), 0x0F, "Reserved", HFILL }
		},
		{ &hf_media_power_value,
			{ "Power Value", "lldp.media.power.value", FT_UINT16, BASE_CUSTOM,
			CF_FUNC(media_power_base), 0x0, NULL, HFILL }
		},
		{ &hf_media_hardware,
			{ "Hardware Revision", "lldp.media.hardware", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_firmware,
			{ "Firmware Revision", "lldp.media.firmware", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_software,
			{ "Software Revision", "lldp.media.software", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_sn,
			{ "Serial Number", "lldp.media.sn", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_manufacturer,
			{ "Manufacturer Name", "lldp.media.manufacturer", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_model,
			{ "Model Name", "lldp.media.model", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_asset,
			{ "Asset ID", "lldp.media.asset", FT_STRINGZPAD, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tlv_subtype,
			{ "Subtype",	"lldp.profinet.subtype", FT_UINT8, BASE_HEX,
			VALS(profinet_subtypes), 0x0, "PROFINET Subtype", HFILL }
		},
		{ &hf_profinet_port_rx_delay_local,
			{ "Port RX Delay Local",	"lldp.profinet.port_rx_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_rx_delay_remote,
			{ "Port RX Delay Remote",	"lldp.profinet.port_rx_delay_remote", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_tx_delay_local,
			{ "Port TX Delay Local",	"lldp.profinet.port_tx_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_tx_delay_remote,
			{ "Port TX Delay Remote",	"lldp.profinet.port_tx_delay_remote", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_cable_delay_local,
			{ "Port Cable Delay Local",	"lldp.profinet.cable_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_class2_port_status,
			{ "RTClass2 Port Status",	"lldp.profinet.rtc2_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_port2_status_vals), 0x0, NULL, HFILL }
		},
		{ &hf_profinet_class3_port_status,
			{ "RTClass3 Port Status",	"lldp.profinet.rtc3_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_port3_status_vals), 0x07, NULL, HFILL }
		},
		/* class3_port state got some new BITs */
		{ &hf_profinet_class3_port_status_Fragmentation,
			{ "RTClass3_PortStatus.Fragmentation",	"lldp.profinet.rtc3_port_status.fragmentation", FT_BOOLEAN, 16,
			TFS(&tfs_on_off), 0x1000, NULL, HFILL }
		},
		{ &hf_profinet_class3_port_status_reserved,
			{ "RTClass3_PortStatus.reserved",	"lldp.profinet.rtc3_port_status.reserved", FT_UINT16, BASE_HEX,
			  NULL, 0x0FF8, "reserved", HFILL }
		},
		{ &hf_profinet_class3_port_status_PreambleLength,
			{ "RTClass3_PortStatus.PreambleLength",	"lldp.profinet.rtc3_port_status.preambleLength", FT_UINT16, BASE_HEX,
			VALS(profinet_port3_status_PreambleLength), 0x2000, NULL, HFILL }
		},
		{ &hf_profinet_mrp_domain_uuid,
			{ "MRP DomainUUID", "lldp.profinet.mrp_domain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_domain_uuid,
			{ "TSN DomainUUID", "lldp.profinet.tsn_domain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_nme_management_addr,
			{ "TSN NME Management Address",	"lldp.profinet.tsn_nme_management_addr", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_nme_management_addr_str_length,
			{ "TSN NME Management Address String Length", "lldp.profinet.tsn_nme_management_addr_str_length", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_nme_management_addr_subtype,
			{ "TSN NME Management Address Subtype",	"lldp.profinet.tsn_nme_management_addr_subtype", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_nme_name_uuid,
			{ "TSN NME Name UUID", "lldp.profinet.tsn_nme_name_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_tsn_nme_parameter_uuid,
			{ "TSN NME Parameter UUID", "lldp.profinet.tsn_nme_parameter_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_time_domain_number,
			{ "Time Domain Number",	"lldp.profinet.time_domain_number", FT_UINT16, BASE_HEX,
			VALS(profinet_time_domain_number_vals), 0x0, NULL, HFILL }
		},
		{ &hf_profinet_time_domain_uuid,
			{ "Time Domain UUID", "lldp.profinet.time_domain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_time_domain_master_identity,
			{ "Time Domain Master Identity", "lldp.profinet.time_domain_master_identity", FT_BYTES, BASE_NONE,
			0x0, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_mrrt_port_status,
			{ "MRRT PortStatus",	"lldp.profinet.mrrt_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_mrrt_port_status_vals), 0x0, NULL, HFILL }
		},
		{ &hf_profinet_cm_mac,
			{ "CMMacAdd",	"lldp.profinet.cm_mac_add", FT_ETHER, BASE_NONE,
			NULL, 0x0, "CMResponderMacAdd or CMInitiatorMacAdd", HFILL }
		},
		{ &hf_profinet_master_source_address,
			{ "MasterSourceAddress",	"lldp.profinet.master_source_address", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_subdomain_uuid,
			{ "SubdomainUUID",	"lldp.profinet.subdomain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_ir_data_uuid,
			{ "IRDataUUID",	"lldp.profinet.ir_data_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_length_of_period_valid,
			{ "LengthOfPeriod.Valid",	"lldp.profinet.length_of_period_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Length field is valid/invalid", HFILL }
		},
		{ &hf_profinet_length_of_period_length,
			{ "LengthOfPeriod.Length",	"lldp.profinet.length_of_period_length", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "Duration of a cycle in nanoseconds", HFILL }
		},
		{ &hf_profinet_red_period_begin_valid,
			{ "RedPeriodBegin.Valid",	"lldp.profinet.red_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_red_period_begin_offset,
			{ "RedPeriodBegin.Offset",	"lldp.profinet.red_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "RT_CLASS_3 period, offset to cycle begin in nanoseconds", HFILL }
		},
		{ &hf_profinet_orange_period_begin_valid,
			{ "OrangePeriodBegin.Valid",	"lldp.profinet.orange_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_orange_period_begin_offset,
			{ "OrangePeriodBegin.Offset","lldp.profinet.orange_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "RT_CLASS_2 period, offset to cycle begin in nanoseconds", HFILL }
		},
		{ &hf_profinet_green_period_begin_valid,
			{ "GreenPeriodBegin.Valid",	"lldp.profinet.green_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_green_period_begin_offset,
			{ "GreenPeriodBegin.Offset",	"lldp.profinet.green_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "Unrestricted period, offset to cycle begin in nanoseconds", HFILL }
		},
	/* Cisco generic */
		{ &hf_cisco_subtype,
			{ "Cisco Subtype",	"lldp.cisco.subtype", FT_UINT8, BASE_HEX,
			VALS(cisco_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_upoe,
			{ "UPOE Capabilities", "lldp.cisco.upoe", FT_UINT8, BASE_HEX,
			NULL, 0x0, "PSE/PD Capabilities", HFILL }
		},
		{ &hf_cisco_upoe_supported,
			{ "UPOE Supported", "lldp.cisco.upoe.supported", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x01, "UPOE (4-pair POE) Supported", HFILL }
		},
		{ &hf_cisco_upoe_altb_detection,
			{ "ALT-B Detection required", "lldp.cisco.upoe.altb_detection_required", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x02, "ALT-B pair Detection/Classification Required", HFILL }
		},
		{ &hf_cisco_upoe_req_spare_pair,
			{ "PD Request Spare Pair PoE", "lldp.cisco.upoe.pd_altb_desired", FT_BOOLEAN, 8,
			TFS(&tfs_desired_not_desired), 0x04, "PD ALT-B Pair Desired", HFILL }
		},
		{ &hf_cisco_upoe_pse_spare_pair_oper,
			{ "PSE Spare Pair PoE", "lldp.cisco.upoe.pse_altb_oper", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x08, "PSE ALT-B Pair Operational State", HFILL }
		},
	/* Cisco ACI */
		{ &hf_cisco_aci_portstate,
			{ "Port State", "lldp.cisco.portstate", FT_UINT8, BASE_NONE,
			VALS(cisco_portstate_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_noderole,
			{ "Node Role", "lldp.cisco.noderole", FT_UINT8, BASE_DEC,
			VALS(cisco_noderole_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_nodeid,
			{ "Node ID", "lldp.cisco.nodeid", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_spinelevel,
			{ "Spine Level", "lldp.cisco.spinelevel", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_podid,
			{ "Pod ID", "lldp.cisco.podid", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_fabricname,
			{ "Fabric Name", "lldp.cisco.fabricname", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_apiclist,
			{ "Appliance Vector", "lldp.cisco.apiclist", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_apicid,
			{ "APIC ID", "lldp.cisco.apicid", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_apicipv4,
			{ "APIC IPv4", "lldp.cisco.apicipv4", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_apicuuid,
			{ "APIC UUID", "lldp.cisco.apicuuid", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_nodeip,
			{ "Node IP", "lldp.cisco.nodeip", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_portrole,
			{ "Port Role", "lldp.cisco.portrole", FT_UINT8, BASE_NONE,
			VALS(cisco_portrole_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_version,
			{ "Version", "lldp.cisco.version", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_fabricvlan,
			{ "Fabric VLAN", "lldp.cisco.fabricvlan", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_serialno,
			{ "Serial No", "lldp.cisco.serialno", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_model,
			{ "Model", "lldp.cisco.model", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_nodename,
			{ "Node Name", "lldp.cisco.nodename", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_portmode,
			{ "Port Mode", "lldp.cisco.portmode", FT_UINT8, BASE_NONE,
			VALS(cisco_portmode_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_authcookie,
			{ "Authentication Cookie", "lldp.cisco.authcookie", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_apicmode,
			{ "APIC Mode", "lldp.cisco.apicmode", FT_UINT8, BASE_DEC,
			VALS(cisco_apicmode_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_aci_fabricid,
			{ "Fabric ID", "lldp.cisco.fabricd", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
	/* Hytec */
		{ &hf_hytec_tlv_subtype,
			{ "Hytec Subtype",	"lldp.hytec.tlv_subtype", FT_UINT8, BASE_DEC,
			VALS(hytec_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_hytec_group,
			{ "Group", "lldp.hytec.group", FT_UINT8, BASE_DEC,
			NULL, HYTEC_GROUP_MASK, NULL, HFILL }
		},
		{ &hf_hytec_identifier,
			{ "Identifier", "lldp.hytec.identifier", FT_UINT8, BASE_DEC,
			NULL, HYTEC_IDENTIFIER_MASK, NULL, HFILL }
		},
		{ &hf_hytec_transceiver_vendor_product_revision,
			{ HYTEC_TID__VENDOR_PRODUCT_REVISION_STR, "lldp.hytec.transceiver_vendor_product_revision", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_hytec_single_mode,
			{ HYTEC_TBD__SINGLE_MODE_STR, "lldp.hytec.single_mode", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			&units_m, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_multi_mode_50,
			{ HYTEC_TBD__MULTI_MODE_50_STR, "lldp.hytec.multi_mode_50", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			&units_m, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_multi_mode_62_5,
			{ HYTEC_TBD__MULTI_MODE_62_5_STR, "lldp.hytec.multi_mode_62_5", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
			&units_m, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_tx_current_output_power,
			{ HYTEC_MD__TX_CURRENT_OUTPUT_POWER_STR, "lldp.hytec.tx_current_output_power", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
			&units_microwatts, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_rx_current_input_power,
			{ HYTEC_MD__RX_CURRENT_INPUT_POWER_STR, "lldp.hytec.rx_current_input_power", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
			&units_microwatts, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_rx_input_snr,
			{ HYTEC_MD__RX_INPUT_SNR_STR, "lldp.hytec.rx_input_snr", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
			&units_decibels, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_lineloss,
			{ HYTEC_MD__LINELOSS_STR, "lldp.hytec.lineloss", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
			&units_decibels, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_mac_trace_request,
			{ HYTEC_MC__MAC_TRACE_REQUEST_STR, "lldp.hytec.mac_trace_request", FT_NONE, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_trace_mac_address,
			{ "Trace MAC address", "lldp.hytec.trace_mac_address", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_request_mac_address,
			{ "Requester's MAC address", "lldp.hytec.requesters_mac_address", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_maximum_depth,
			{ "Maximum depth", "lldp.hytec.maximum_depth", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_mac_trace_reply,
			{ HYTEC_MC__MAC_TRACE_REPLY_STR, "lldp.hytec.mac_trace_reply", FT_NONE, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_answering_mac_address,
			{ "Answering MAC address", "lldp.hytec.answering_mac_address", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_actual_depth,
			{ "Actual depth", "lldp.hytec.actual_depth", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_name_of_replying_device,
			{ HYTEC_MC__NAME_OF_REPLYING_DEVICE_STR, "lldp.hytec.name_of_replying_device", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_outgoing_port_name,
			{ HYTEC_MC__OUTGOING_PORT_NAME_STR, "lldp.hytec.outgoing_port_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_ipv4_address_of_replying_device,
			{ HYTEC_MC__IPV4_ADDRESS_OF_REPLYING_DEVICE_STR, "lldp.hytec.ipv4_address_of_replying_device", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_end_of_trace,
			{ HYTEC_MC__END_OF_TRACE_STR, "lldp.hytec.end_of_trace", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_ipv6_address_of_replying_device,
			{ HYTEC_MC__IPV6_ADDRESS_OF_REPLYING_DEVICE_STR, "lldp.hytec.ipv6_address_of_replying_device", FT_IPv6, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_incoming_port_name,
			{ HYTEC_MC__INCOMING_PORT_NAME_STR, "lldp.hytec.incoming_port_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_trace_identifier,
			{ HYTEC_MC__TRACE_IDENTIFIER_STR, "lldp.hytec.trace_identifier", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL}
		},
		{ &hf_hytec_invalid_object_data,
			{ "Invalid object data", "lldp.hytec.invalid_object_data", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_hytec_unknown_identifier_content,
			{ "Unknown Identifier Content","lldp.hytec.unknown_identifier_content", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_subtype,
			{ "Avaya Subtype", "lldp.avaya.subtype", FT_UINT8, BASE_HEX,
			VALS(avaya_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_avaya_poe,
			{ "PoE Conservation Level Support", "lldp.avaya.poe", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_call_server,
			{ "Call Server IP Address", "lldp.avaya.callserver", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_cna_server,
			{ "CNA Server IP Address", "lldp.avaya.cnaserver", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_file_server,
			{ "File Server", "lldp.avaya.fileserver", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_dot1q,
			{ "802.1Q Framing", "lldp.avaya.dot1q", FT_UINT8, BASE_HEX,
			VALS(avaya_dot1q_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_avaya_ipphone,
			{ "IP Phone Addresses", "lldp.avaya.ipphone", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_ipphone_ip,
			{ "IP Address", "lldp.avaya.ipphone.ip", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_ipphone_mask,
			{ "Subnet Mask", "lldp.avaya.ipphone.mask", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_avaya_ipphone_gateway,
			{ "Gateway IP", "lldp.avaya.ipphone.gateway", FT_IPv4, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_iana_subtype,
			{ "IANA Subtype", "lldp.iana.subtype", FT_UINT8, BASE_HEX,
			  VALS(iana_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_iana_mudurl,
			{ "Manufacturer Usage Description URL", "lldp.iana.mudurl", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_onos_subtype,
			{ "ONOS Subtype", "lldp.onos.subtype", FT_UINT8, BASE_HEX,
			  VALS(onos_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_onos_chassis,
			{ "Chassis", "lldp.onos.chassis", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_onos_port,
			{ "Port", "lldp.onos.port", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_onos_ttl,
			{ "ttl", "lldp.onos.ttl", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_unknown_subtype,
			{ "Unknown Subtype","lldp.unknown_subtype", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_unknown_subtype_content,
			{ "Unknown Subtype Content","lldp.unknown_subtype.content", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_subtype_content_remaining,
			{ "Subtype Unknown Trailing Bytes","lldp.subtype.content_remaining", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya_tlv_subtype,
			{ "Subtype", "lldp.extreme_avaya_ap.subtype", FT_UINT8, BASE_DEC,
			VALS(ex_avaya_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya_hmac_shi,
			{ "HMAC-SHA Digest", "lldp.extreme_avaya_ap.hmac_sha_digest", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya_element_type,
			{ "Element Type", "lldp.extreme_avaya_ap.element_type", FT_UINT24, BASE_DEC,
			NULL, 0xfc0000, NULL, HFILL }
		},
		{ &hf_ex_avaya_state,
			{ "State", "lldp.extreme_avaya_ap.state", FT_UINT24, BASE_DEC,
			NULL, 0x03f000, NULL, HFILL }
		},
		{ &hf_ex_avaya_mgnt_vlan,
			{ "Mgmt VLAN", "lldp.extreme_avaya_ap.mgnt_vlan", FT_UINT24, BASE_DEC,
			NULL, 0x000fff, NULL, HFILL }
		},
		{ &hf_ex_avaya_vlan,
			{ "VLAN", "lldp.extreme_avaya_ap.vlan", FT_UINT16, BASE_DEC,
			NULL, 0x0fff, NULL, HFILL }
		},
		{ &hf_ex_avaya_rsvd,
			{ "Reserved", "lldp.extreme_avaya_ap.rsvd", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya_system_id,
			{ "System ID", "lldp.extreme_avaya_ap.system_id", FT_BYTES, SEP_COLON,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya_status,
			{ "Assignment Status", "lldp.extreme_avaya_ap.status", FT_UINT16, BASE_DEC,
			NULL, 0xf000, NULL, HFILL }
		},
		{ &hf_ex_avaya_i_sid,
			{ "I-SID", "lldp.extreme_avaya_ap.i_sid", FT_UINT24, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya2_tlv_subtype,
			{ "Subtype", "lldp.extreme_avaya.fabric.subtype", FT_UINT8, BASE_DEC,
			VALS(ex_avaya2_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya2_fabric_connect,
			{ "FC Capability", "lldp.extreme_avaya.fabric.fabric_connect", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_enabled_disabled), 0x0, "Fabric Connect aka auto-sense", HFILL }
		},
		{ &hf_ex_avaya2_fabric_numbvlans,
			{ "Number B-VLANs", "lldp.extreme_avaya.fabric.numbvlans", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya2_fabric_bvlanid,
			{ "B-VLAN ID", "lldp.extreme_avaya.fabric.bvlanid", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya2_fabric_sysidlength,
			{ "SysID Length", "lldp.extreme_avaya.fabric.sysidlength", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ex_avaya2_fabric_sysid,
			{ "System ID", "lldp.extreme_avaya.fabric.sysid", FT_SYSTEM_ID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_lldp,
		&ett_chassis_id,
		&ett_port_id,
		&ett_time_to_live,
		&ett_end_of_lldpdu,
		&ett_port_description,
		&ett_system_name,
		&ett_system_desc,
		&ett_system_cap,
		&ett_system_cap_summary,
		&ett_system_cap_enabled,
		&ett_management_address,
		&ett_unknown_tlv,
		&ett_org_spc_tlv,
		&ett_org_spc_def,
		&ett_org_spc_dcbx_cin,
		&ett_org_spc_dcbx_cee,
		&ett_org_spc_dcbx_cee_1,
		&ett_org_spc_dcbx_cee_2,
		&ett_org_spc_dcbx_cee_3,
		&ett_org_spc_dcbx_cee_4,
		&ett_org_spc_dcbx_cin_6,
		&ett_org_spc_dcbx_cee_app,
		&ett_org_spc_ieee_802_1_1,
		&ett_org_spc_ieee_802_1_2,
		&ett_org_spc_ieee_802_1_3,
		&ett_org_spc_ieee_802_1_4,
		&ett_org_spc_ieee_802_1_8,
		&ett_org_spc_ieee_802_1_9,
		&ett_org_spc_ieee_802_1_a,
		&ett_org_spc_ieee_802_1_b,
		&ett_org_spc_ieee_802_1_c,
		&ett_org_spc_ieee_dcbx_app,
		&ett_org_spc_ieee_802_3_1,
		&ett_org_spc_ieee_802_3_2,
		&ett_org_spc_ieee_802_3_3,
		&ett_org_spc_ieee_802_3_4,
		&ett_org_spc_ieee_802_3_5,
		&ett_org_spc_ieee_802_3_7,
		&ett_org_spc_media_1,
		&ett_org_spc_media_2,
		&ett_org_spc_media_3,
		&ett_org_spc_media_4,
		&ett_org_spc_media_5,
		&ett_org_spc_media_6,
		&ett_org_spc_media_7,
		&ett_org_spc_media_8,
		&ett_org_spc_media_9,
		&ett_org_spc_media_10,
		&ett_org_spc_media_11,
		&ett_org_spc_ProfinetSubTypes_1,
		&ett_org_spc_ProfinetSubTypes_2,
		&ett_org_spc_ProfinetSubTypes_3,
		&ett_org_spc_ProfinetSubTypes_4,
		&ett_org_spc_ProfinetSubTypes_5,
		&ett_org_spc_ProfinetSubTypes_6,
		&ett_port_vlan_flags,
		&ett_802_3_flags,
		&ett_802_3_autoneg_advertised,
		&ett_802_3_power,
		&ett_802_3_bt_power,
		&ett_802_3_bt_system_setup,
		&ett_802_3_bt_autoclass,
		&ett_802_3_bt_power_down,
		&ett_802_3_aggregation,
		&ett_802_1_aggregation,
		&ett_802_1qbg_capabilities_flags,
		&ett_802_3br_capabilities_flags,
		&ett_media_capabilities,
		&ett_profinet_period,
		&ett_cisco_upoe_tlv,
		&ett_avaya_ipphone_tlv,
		&ett_org_spc_hytec_subtype_transceiver,
		&ett_org_spc_hytec_subtype_trace,
		&ett_org_spc_hytec_trace_request,
		&ett_org_spc_hytec_trace_reply,
		&ett_ex_avayaSubTypes_11,
		&ett_ex_avayaSubTypes_12,
		&ett_ex_avaya2SubTypes_4
	};

	static ei_register_info ei[] = {
		{ &ei_lldp_bad_length, { "lldp.incorrect_length", PI_MALFORMED, PI_WARN, "Invalid length, too short", EXPFILL }},
		{ &ei_lldp_bad_length_excess, { "lldp.excess_length", PI_MALFORMED, PI_WARN, "Invalid length, greater than expected", EXPFILL }},
		{ &ei_lldp_shutdown_excess_tlv, { "lldp.excess_tlv", PI_MALFORMED, PI_WARN, "Excess TLV in Shutdown PDU", EXPFILL }},
		{ &ei_lldp_bad_type, { "lldp.bad_type", PI_MALFORMED, PI_WARN, "Incorrect type", EXPFILL }},
		{ &ei_lldp_tlv_deprecated, { "lldp.tlv_deprecated", PI_PROTOCOL, PI_WARN, "TLV has been deprecated", EXPFILL }},
	};

	static const enum_val_t column_info_options[] = {
		{ "default_column_info", "Default Column Info", DEFAULT_COLUMN_INFO },
		{ "profinet_special_column_info", "PROFINET Special Column Info", PROFINET_SPECIAL_COLUMN_INFO },
		{ NULL, NULL, 0 }
	};

	/* Register the protocol name and description */
	proto_lldp = proto_register_protocol("Link Layer Discovery Protocol", "LLDP", "lldp");
	lldp_handle = register_dissector("lldp", dissect_lldp, proto_lldp);

	/* Register preferences */
	lldp_module = prefs_register_protocol(proto_lldp, NULL);

	prefs_register_enum_preference(lldp_module,
		"column_info_selection",
		"Select Column Info Display Style",
		"Which Information will be showed at Column Information is decided by the selection",
		&column_info_selection,
		column_info_options,
		false);

	prefs_register_bool_preference(lldp_module,
		"assume_unrecognized_tlv",
		"Assume unrecognized TLV",
		"If checked, assume an unrecognized TLV type should be consumed and treated as an LLDP TLV.  Otherwise, end LLDP dissection.",
		&assume_unrecognized_tlv);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_lldp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	oui_unique_code_table = register_dissector_table("lldp.orgtlv.oui", "LLDP OUI", proto_lldp, FT_UINT24, BASE_HEX );

	expert_lldp = expert_register_protocol(proto_lldp);
	expert_register_field_array(expert_lldp, ei, array_length(ei));
}

void
proto_reg_handoff_lldp(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_LLDP, lldp_handle);
	dissector_add_uint("ethertype", ETHERTYPE_ONOS, lldp_handle);
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
