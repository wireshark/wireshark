/* packet-wifi-nan.c
 *
 * Wi-Fi Neighbour Awareness Networking (NAN)
 *
 * Copyright 2019 Samsung Electronics
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-ieee80211.h"

#include <wsutil/str_util.h>

void proto_reg_handoff_nan(void);
void proto_register_nan(void);

static dissector_handle_t nan_act_handle;
static dissector_handle_t nan_disco_handle;
static dissector_handle_t nan_beacon_handle;

static dissector_table_t ie_handle_table;

#define WFA_ACTION_OUI_TYPE 0x18
#define WFA_NAN_IE_OUI_TYPE 0x13
#define WFA_SERVICE_DISCOVERY_SUBTYPE 0x13

#define NAN_MASTER_IND_LENGTH 2
#define NAN_CLUSTER_LENGTH 13
#define NAN_SDA_MIN_LENGTH 9
#define NAN_SDEA_MIN_LENGTH 3
#define NAN_CONNECTION_CAP_LENGTH 2
#define NAN_WLAN_INFRA_MIN_LENGTH 15
#define NAN_P2P_OP_MIN_LENGTH 9
#define NAN_IBSS_MIN_LENGTH 14
#define NAN_MESH_MIN_LENGTH 8
#define NAN_RANGING_MIN_LENGTH 8
#define NAN_CLUSTER_DISC_LENGTH 22
#define NAN_DEVICE_CAP_LENGTH 9
#define NAN_NDP_MIN_LENGTH 11
#define NAN_NDPE_MIN_LENGTH 11
#define NAN_AVAILABILITY_MIN_LENGTH 8
#define NAN_NDC_MIN_LENGTH 11
#define NAN_NDL_MIN_LENGTH 4
#define NAN_NDL_QOS_LENGTH 3
#define NAN_UNALIGNED_SCH_MIN_LENGTH 16
#define NAN_RANGING_SETUP_MIN_LENGTH 4
#define NAN_EXTENDED_WLAN_INFRA_LENGTH 20
#define NAN_EXTENDED_P2P_OP_LENGTH 14
#define NAN_EXTENDED_IBSS_LENGTH 19
#define NAN_EXTENDED_MESH_MIN_LENGTH 13
#define NAN_CIPHER_SUITE_INFO_MIN_LENGTH 3
#define NAN_SECURITY_CONTEXT_INFO_MIN_LENGTH 4
#define NAN_PUBLIC_AVAIL_MIN_LENGTH 4
#define NAN_VENDOR_SPECIFIC_MIN_LENGTH 3
#define NAN_DEVICE_CAPABILITY_EXTENSION_MIN_LENGTH 2
#define NAN_IDENTITY_RESOLUTION_MIN_LEN 1
#define NAN_PAIRING_BOOTSTRAPPING_LEN 5

#define NAN_UNALIGNED_SCH_BAND_ID_EXIST 0
#define NAN_UNALIGNED_SCH_CHANNEL_ENTRY_EXIST 1
#define NAN_UNALIGNED_SCH_CHANNEL_ENTRY_W_AUX_EXIST 2

static int proto_nan;

static expert_field ei_nan_elem_len_invalid;
static expert_field ei_nan_unknown_attr_id;
static expert_field ei_nan_unknown_op_class;
static expert_field ei_nan_unknown_beacon_type;
static expert_field ei_nan_invalid_channel_num_for_op_class;
static expert_field ei_nan_invalid_channel_count;

static int ett_nan;
static int ett_attributes;
static int ett_map_control;
static int ett_type_status;
static int ett_time_bitmap_ctrl;
static int ett_non_nan_op_channel;
static int ett_non_nan_beacon;
static int ett_cluster_anchor_master_info;
static int ett_sda_service_ctr;
static int ett_sda_srf_ctr;
static int ett_sdea_ctr;
static int ett_sdea_range_limit;
static int ett_sdea_service_info;
static int ett_connection_cap_field;
static int ett_further_av_map_entry_ctrl;
static int ett_device_cap_map_id;
static int ett_device_cap_committed_dw;
static int ett_device_cap_supported_bands;
static int ett_device_cap_op_mode;
static int ett_device_cap_antennas;
static int ett_device_cap_capabilities;
static int ett_ndp_control;
static int ett_ndpe_tlv;
static int ett_availability_ctr;
static int ett_availability_entry;
static int ett_availability_entry_ctr;
static int ett_availability_entry_entries;
static int ett_availability_entry_entries_channel;
static int ett_ndc_ctr;
static int ett_ndc_entries;
static int ett_device_ndc_map_id;
static int ett_ndl_control;
static int ett_ndl_schedule_entries;
static int ett_unaligned_sch_ctrl;
static int ett_unaligned_sch_ulw_overwrite;
static int ett_unaligned_sch_ulw_ctrl;
static int ett_ranging_setup_ftm_params;
static int ett_ranging_setup_ctrl;
static int ett_ranging_setup_schedule_entries;
static int ett_ranging_info_location_info_availability;
static int ett_p2p_device_role;
static int ett_cipher_suite_info_list;
static int ett_security_context_identifiers;
static int ett_public_availability_sch_entries;
static int ett_ie_tree;
static int ett_availability_op_class;
static int ett_device_capability_extension;
static int ett_nan_pairing_bootstrapping_type_status;
static int ett_nan_pairing_bootstrapping_method;
static int ett_nan_cipher_suite_capabilities;

static int hf_nan_attribute_type;
static int hf_nan_attribute_len;
static int hf_nan_action_subtype;
static int hf_nan_instance_id;
static int hf_nan_service_id;
static int hf_nan_map_id;
static int hf_nan_oui;
static int hf_nan_type_status;
static int hf_nan_reason_code;
static int hf_nan_status_1;
static int hf_nan_status_2;
static int hf_nan_bss_id;
static int hf_nan_availability_intervals_bitmap;
static int hf_nan_mac_address;
static int hf_nan_publish_id;
static int hf_nan_dialog_tokens;
static int hf_nan_time_bitmap;
static int hf_nan_time_bitmap_len;
static int hf_nan_time_bitmap_ctrl;
static int hf_nan_time_bitmap_ctrl_bit_duration;
static int hf_nan_time_bitmap_ctrl_period;
static int hf_nan_time_bitmap_ctrl_start_offset;
static int hf_nan_map_ctrl_map_id;
static int hf_nan_map_ctrl_availability_interval_duration;
static int hf_nan_map_ctrl_repeat;
static int hf_nan_map_ctrl_field;
static int hf_nan_non_op_channel_global_op_class;
static int hf_nan_non_op_channel_channel;
static int hf_nan_non_op_channel_center_freq;
static int hf_nan_non_beacon_tbtt_offset;
static int hf_nan_non_beacon_interval;
static int hf_nan_attr_master_preference;
static int hf_nan_attr_master_random_factor;
static int hf_nan_attr_cluster_anchor_master_rank;
static int hf_nan_attr_cluster_hop_count;
static int hf_nan_attr_cluster_beacon_transmission_time;
static int hf_nan_attr_sda_requestor_instance_id;
static int hf_nan_attr_sda_sc;
static int hf_nan_attr_sda_sc_type;
static int hf_nan_attr_sda_sc_matching_filter;
static int hf_nan_attr_sda_sc_service_response;
static int hf_nan_attr_sda_sc_service_info;
static int hf_nan_attr_sda_sc_discovery_range;
static int hf_nan_attr_sda_sc_binding_bitmap;
static int hf_nan_attr_sda_binding_bitmap;
static int hf_nan_attr_sda_matching_filter_len;
static int hf_nan_attr_sda_matching_filter_val;
static int hf_nan_attr_sda_service_response_filter_len;
static int hf_nan_attr_sda_srf_ctr;
static int hf_nan_attr_sda_srf_ctr_type;
static int hf_nan_attr_sda_srf_ctr_include;
static int hf_nan_attr_sda_srf_ctr_bloom_filter_index;
static int hf_nan_attr_sda_srf_address_set;
static int hf_nan_attr_sda_service_info_len;
static int hf_nan_attr_sda_service_info;
static int hf_nan_attr_sdea_ctr;
static int hf_nan_attr_sdea_ctr_fsd;
static int hf_nan_attr_sdea_ctr_fsd_w_gas;
static int hf_nan_attr_sdea_ctr_data_path;
static int hf_nan_attr_sdea_ctr_data_path_type;
static int hf_nan_attr_sdea_ctr_reserved_multicast_type;
static int hf_nan_attr_sdea_ctr_qos;
static int hf_nan_attr_sdea_ctr_security;
static int hf_nan_attr_sdea_ctr_ranging;
static int hf_nan_attr_sdea_ctr_range_limit;
static int hf_nan_attr_sdea_ctr_service_update_indicator;
static int hf_nan_attr_sdea_ingress_range_limit;
static int hf_nan_attr_sdea_egress_range_limit;
static int hf_nan_attr_sdea_service_update_indicator;
static int hf_nan_attr_sdea_service_info_length;
static int hf_nan_attr_sdea_service_info_protocol_type;
static int hf_nan_attr_sdea_service_info_specific;
static int hf_nan_attr_connection_cap_bitmap;
static int hf_nan_attr_connection_cap_wifi_direct;
static int hf_nan_attr_connection_cap_p2ps;
static int hf_nan_attr_connection_cap_tdls;
static int hf_nan_attr_connection_cap_wlan_infra;
static int hf_nan_attr_connection_cap_ibss;
static int hf_nan_attr_connection_cap_mesh;
static int hf_nan_attr_wlan_infra_device_role;
static int hf_nan_attr_p2p_device_role_device;
static int hf_nan_attr_p2p_device_role_group_owner;
static int hf_nan_attr_p2p_device_role_client;
static int hf_nan_attr_p2p_device_role;
static int hf_nan_attr_mesh_id;
static int hf_nan_attr_further_av_map_entry_av_interval_duration;
static int hf_nan_attr_further_av_map_op_class;
static int hf_nan_attr_further_av_map_channel_num;
static int hf_nan_attr_further_av_map_entry_ctrl;
static int hf_nan_attr_further_av_map_id;
static int hf_nan_attr_country_code;
static int hf_nan_attr_ranging_protocol;
static int hf_nan_attr_cluster_disc_id;
static int hf_nan_attr_cluster_disc_time_offset;
static int hf_nan_attr_cluster_disc_anchor_master_rank;
static int hf_nan_attr_device_cap_map_id_apply_to;
static int hf_nan_attr_device_cap_map_id_associated_maps;
static int hf_nan_attr_device_cap_committed_dw;
static int hf_nan_attr_device_cap_committed_dw_24ghz;
static int hf_nan_attr_device_cap_committed_dw_5ghz;
static int hf_nan_attr_device_cap_committed_dw_24ghz_overwrite;
static int hf_nan_attr_device_cap_committed_dw_5ghz_overwrite;
static int hf_nan_attr_device_cap_supported_bands;
static int hf_nan_attr_device_cap_supported_bands_reserved_tv_whitespaces;
static int hf_nan_attr_device_cap_supported_bands_sub_1ghz;
static int hf_nan_attr_device_cap_supported_bands_24ghz;
static int hf_nan_attr_device_cap_supported_bands_reserved_36ghz;
static int hf_nan_attr_device_cap_supported_bands_5ghz;
static int hf_nan_attr_device_cap_supported_bands_reserved_60ghz;
static int hf_nan_attr_device_cap_supported_bands_reserved_45ghz;
static int hf_nan_attr_device_cap_supported_bands_6ghz;
static int hf_nan_attr_device_cap_op_mode;
static int hf_nan_attr_device_cap_op_mode_phy_vht;
static int hf_nan_attr_device_cap_op_mode_phy_he;
static int hf_nan_attr_device_cap_op_mode_phy_he_vht8080;
static int hf_nan_attr_device_cap_op_mode_phy_he_vht160;
static int hf_nan_attr_device_cap_op_mode_reserved_paging_ndl;
static int hf_nan_attr_device_cap_antennas;
static int hf_nan_attr_device_cap_antennas_tx;
static int hf_nan_attr_device_cap_antennas_rx;
static int hf_nan_attr_device_cap_max_channel_switch_time;
static int hf_nan_attr_device_cap_capabilities;
static int hf_nan_attr_device_cap_capabilities_dfs_master;
static int hf_nan_attr_device_cap_capabilities_extended_key_id;
static int hf_nan_attr_device_cap_capabilities_simul_ndp_reception;
static int hf_nan_attr_device_cap_capabilities_ndpe_attr_support;
static int hf_nan_attr_device_cap_capabilities_s3_capable;
static int hf_nan_attr_ndp_type;
static int hf_nan_attr_ndp_initiator;
static int hf_nan_attr_ndp_id;
static int hf_nan_attr_ndp_ctrl_confirm;
static int hf_nan_attr_ndp_ctrl_security_pres;
static int hf_nan_attr_ndp_ctrl_publish_id_pres;
static int hf_nan_attr_ndp_ctrl_responder_ndi_pres;
static int hf_nan_attr_ndp_ctrl_sepcific_info_pres;
static int hf_nan_attr_ndpe_ctrl_confirm;
static int hf_nan_attr_ndpe_ctrl_security_pres;
static int hf_nan_attr_ndpe_ctrl_publish_id_pres;
static int hf_nan_attr_ndpe_ctrl_responder_ndi_pres;
static int hf_nan_attr_ndpe_ctrl_gtk_requried;
static int hf_nan_attr_ndp_control;
static int hf_nan_attr_ndpe_control;
static int hf_nan_attr_ndp_responder_ndi;
static int hf_nan_attr_ndp_specific_info;
static int hf_nan_attr_ndpe_tlv_type;
static int hf_nan_attr_ndpe_tlv_len;
static int hf_nan_attr_ndpe_tlv_ipv6_interface_identifier;
static int hf_nan_attr_availability_sequence_id;
static int hf_nan_attr_availability_ctr;
static int hf_nan_attr_availability_map_id;
static int hf_nan_attr_availability_committed_changed;
static int hf_nan_attr_availability_potential_changed;
static int hf_nan_attr_availability_public_availability_changed;
static int hf_nan_attr_availability_ndc_changed;
static int hf_nan_attr_availability_reserved_multicast_schedule_changed;
static int hf_nan_attr_availability_reserved_multicast_schedule_change_changed;
static int hf_nan_attr_availability_entry_len;
static int hf_nan_attr_availability_entry_ctr;
static int hf_nan_attr_availability_entry_ctr_type;
static int hf_nan_attr_availability_entry_ctr_pref;
static int hf_nan_attr_availability_entry_ctr_utilization;
static int hf_nan_attr_availability_entry_ctr_rx_nss;
static int hf_nan_attr_availability_entry_ctr_time_bitmap;
static int hf_nan_attr_availability_entry_entries_type;
static int hf_nan_attr_availability_entry_entries_non_contiguous_bw;
static int hf_nan_attr_availability_entry_entries_num_entries;
static int hf_nan_attr_availability_entry_entries_band;
static int hf_nan_attr_availability_entry_entries_channel_op_class;
static int hf_nan_attr_availability_entry_entries_channel_bitmap;
static int hf_nan_attr_availability_entry_entries_primary_channel_bitmap;
static int hf_nan_attr_availability_entry_entries_aux_channel_bitmap;
static int hf_nan_attr_availability_entry_entries_channel_set;
static int hf_nan_attr_availability_entry_entries_start_channel_number;
static int hf_nan_attr_availability_entry_entries_number_of_ch_included;
static int hf_nan_attr_availability_entry_entries_start_freq;
static int hf_nan_attr_availability_entry_entries_bandwidth;
static int hf_nan_attr_ndc_id;
static int hf_nan_attr_ndc_ctrl;
static int hf_nan_attr_ndc_ctrl_selected;
static int hf_nan_attr_ndc_map_id_related_sch;
static int hf_nan_attr_ndl_type;
static int hf_nan_attr_ndl_control;
static int hf_nan_attr_ndl_ctrl_peer_id;
static int hf_nan_attr_ndl_ctrl_immutable_schedule_pres;
static int hf_nan_attr_ndl_ctrl_ndc_pres;
static int hf_nan_attr_ndl_ctrl_qos;
static int hf_nan_attr_ndl_ctrl_type;
static int hf_nan_attr_ndl_ctrl_setup_reason;
static int hf_nan_attr_ndl_ctrl_max_idle_pres;
static int hf_nan_attr_ndl_reserved_peer_id;
static int hf_nan_attr_ndl_max_idle;
static int hf_nan_attr_ndlqos_min_time_slots;
static int hf_nan_attr_ndlqos_max_latency;
static int hf_nan_attr_unaligned_sch_ctrl;
static int hf_nan_attr_unaligned_sch_ctrl_schedule_id;
static int hf_nan_attr_unaligned_sch_ctrl_seq_id;
static int hf_nan_attr_unaligned_sch_starting_time;
static int hf_nan_attr_unaligned_sch_duration;
static int hf_nan_attr_unaligned_sch_period;
static int hf_nan_attr_unaligned_sch_count_down;
static int hf_nan_attr_unaligned_sch_ulw_overwrite;
static int hf_nan_attr_unaligned_sch_ulw_overwrite_all;
static int hf_nan_attr_unaligned_sch_ulw_overwrite_map_id;
static int hf_nan_attr_unaligned_sch_ulw_ctrl;
static int hf_nan_attr_unaligned_sch_ulw_ctrl_type;
static int hf_nan_attr_unaligned_sch_ulw_ctrl_channel_av;
static int hf_nan_attr_unaligned_sch_ulw_ctrl_rxnss;
static int hf_nan_attr_ranging_info_location_info_avail;
static int hf_nan_attr_ranging_info_location_info_avail_lci;
static int hf_nan_attr_ranging_info_location_info_avail_geospatial;
static int hf_nan_attr_ranging_info_location_info_avail_civic_location;
static int hf_nan_attr_ranging_info_location_info_avail_last_movement_pres;
static int hf_nan_attr_ranging_info_last_movement_indication;
static int hf_nan_attr_ranging_setup_type;
static int hf_nan_attr_ranging_setup_ctrl;
static int hf_nan_attr_ranging_setup_ctrl_report_req;
static int hf_nan_attr_ranging_setup_ctrl_ftm_params;
static int hf_nan_attr_ranging_setup_ctrl_entry_list;
static int hf_nan_attr_ranging_setup_ftm_params;
static int hf_nan_attr_ranging_setup_ftm_max_per_burst;
static int hf_nan_attr_ranging_setup_ftm_min_delta;
static int hf_nan_attr_ranging_setup_ftm_max_burst_duration;
static int hf_nan_attr_ranging_setup_ftm_format_bw;
static int hf_nan_attr_ftm_range_report;
static int hf_nan_attr_cipher_suite_capabilities;
static int hf_nan_attr_cipher_suite_capabilities_ndtksa_nmtksa_replay_counters;
static int hf_nan_attr_cipher_suite_capabilities_gtksa_igtksa_bigtksa_support;
static int hf_nan_attr_cipher_suite_capabilities_gtksa_replay_counters;
static int hf_nan_attr_cipher_suite_capabilities_igtksa_bigtksa_cipher;
static int hf_nan_attr_cipher_suite_id;
static int hf_nan_attr_security_context_identifier;
static int hf_nan_attr_security_context_identifier_len;
static int hf_nan_attr_security_context_identifier_type;
static int hf_nan_attr_shared_key_rsna_descriptor;
static int hf_nan_attr_vendor_specific_body;
static int hf_nan_attr_container_element_id;
static int hf_nan_attr_container_element_len;
/* Device Capability Extension attribute, Capability Info field */
static int hf_nan_attr_device_capability_extension;
static int hf_nan_attr_device_capability_extension_6g_regulatory_info_presented;
static int hf_nan_attr_device_capability_extension_6g_regulatory_info;
static int hf_nan_attr_device_capability_extension_6g_regulatory_info_reserved;
static int hf_nan_attr_device_capability_extension_paring_setup_enabled;
static int hf_nan_attr_device_capability_extension_npk_nik_cache_enabled;
/* NAN Identity Resolution attribute */
static int hf_nan_attr_identity_cipher_version;
static int hf_nan_attr_identity_resolution_nonce;
static int hf_nan_attr_identity_resolution_tag;

/* NAN Pairing Bootstrapping attribute */
static int hf_nan_attr_pairing_bootstrapping_dialog_token;
static int hf_nan_attr_pairing_bootstrapping_type_status;
static int hf_nan_attr_pairing_bootstrapping_type;
static int hf_nan_attr_pairing_bootstrapping_status;
static int hf_nan_attr_pairing_bootstrapping_resaon_code;
static int hf_nan_attr_pairing_bootstrapping_comeback_after;
static int hf_nan_attr_pairing_bootstrapping_comeback_cookie_len;
static int hf_nan_attr_pairing_bootstrapping_comeback_cookie;
static int hf_nan_attr_pairing_bootstrapping_methods;
static int hf_nan_attr_pairing_bootstrapping_method_opportunistic_bootstrapping;
static int hf_nan_attr_pairing_bootstrapping_method_pin_code_display;
static int hf_nan_attr_pairing_bootstrapping_method_passphrase_display;
static int hf_nan_attr_pairing_bootstrapping_method_qr_code_display;
static int hf_nan_attr_pairing_bootstrapping_method_nfc_tag;
static int hf_nan_attr_pairing_bootstrapping_method_keypad_pin_code_only;
static int hf_nan_attr_pairing_bootstrapping_method_keypad_passphrase;
static int hf_nan_attr_pairing_bootstrapping_method_qr_code_scan;
static int hf_nan_attr_pairing_bootstrapping_method_nfc_reader;
static int hf_nan_attr_pairing_bootstrapping_method_reserved;
static int hf_nan_attr_pairing_bootstrapping_method_service_managed_bootstrapping;
static int hf_nan_attr_pairing_bootstrapping_method_bootstrapping_handshakes_skipped;

static int hf_nan_attr_reserved;

enum {
    NAN_ATTR_MASTER_INDICATION = 0x00,
    NAN_ATTR_CLUSTER = 0x01,
    NAN_ATTR_SERVICE_ID_LIST = 0x02,
    NAN_ATTR_SERVICE_DESCRIPTOR = 0x03,
    NAN_ATTR_CONNECTION_CAPABILITY = 0x04,
    NAN_ATTR_WLAN_INFRA = 0x05,
    NAN_ATTR_P2P_OPERATION = 0x06,
    NAN_ATTR_IBSS = 0x07,
    NAN_ATTR_MESH = 0x08,
    NAN_ATTR_FURTHER_SERVICE_DISCOVERY = 0x09,
    NAN_ATTR_FURTHER_AVAILABILITY_MAP = 0x0A,
    NAN_ATTR_COUNTRY_CODE = 0x0B,
    NAN_ATTR_RANGING = 0x0C,
    NAN_ATTR_CLUSTER_DISCOVERY = 0x0D,
    NAN_ATTR_SERVICE_DESCRIPTOR_EXTENSION = 0x0E,
    NAN_ATTR_DEVICE_CAPABILITY = 0x0F,
    NAN_ATTR_NDP = 0x10,
    NAN_ATTR_RESERVED_NMSG = 0x11,
    NAN_ATTR_AVAILABILITY = 0x12,
    NAN_ATTR_NDC = 0x13,
    NAN_ATTR_NDL = 0x14,
    NAN_ATTR_NDL_QOS = 0x15,
    NAN_ATTR_RESERVED_MULTICAST_SCHEDULE = 0x16,
    NAN_ATTR_UNALIGNED_SCHEDULE = 0x17,
    NAN_ATTR_RESERVED_UNICAST_PAGING = 0x18,
    NAN_ATTR_RESERVED_MULTICAST_PAGING = 0x19,
    NAN_ATTR_RANGING_INFORMATION = 0x1A,
    NAN_ATTR_RANGING_SETUP = 0x1B,
    NAN_ATTR_FTM_RANGING_REPORT = 0x1C,
    NAN_ATTR_ELEMENT_CONTAINER = 0x1D,
    NAN_ATTR_EXTENDED_WLAN_INFRA = 0x1E,
    NAN_ATTR_EXTENDED_P2P_OPERATION = 0x1F,
    NAN_ATTR_EXTENDED_IBSS = 0x20,
    NAN_ATTR_EXTENDED_MESH = 0x21,
    NAN_ATTR_CIPHER_SUITE_INFO = 0x22,
    NAN_ATTR_SECURITY_CONTEXT_INFO = 0x23,
    NAN_ATTR_SHARED_KEY_DESCRIPTOR = 0x24,
    NAN_ATTR_RESERVED_MULTICAST_SCHEDULE_CHANGE = 0x25,
    NAN_ATTR_RESERVED_MULTICAST_SCHEDULE_OWNER_CHANGE = 0x26,
    NAN_ATTR_PUBLIC_AVAILABILITY = 0x27,
    NAN_ATTR_SUBSCRIBE_SERVICE_ID_LIST = 0x28,
    NAN_ATTR_NDP_EXTENSION = 0x29,
    NAN_ATTR_DEVICE_CAPABILITY_EXTENSION = 0x2a,
    NAN_ATTR_IDENTITY_RESOLUTION = 0x2b,
    NAN_ATTR_PAIRING_BOOTSTRAPPING = 0x2c,
    NAN_ATTR_VENDOR_SPECIFIC = 0xDD
};

static const value_string attribute_types[] = {
    { NAN_ATTR_MASTER_INDICATION, "Master Indication Attribute" },
    { NAN_ATTR_CLUSTER, "Cluster Attribute" },
    { NAN_ATTR_SERVICE_ID_LIST, "Service ID List Attribute" },
    { NAN_ATTR_SERVICE_DESCRIPTOR, "Service Descriptor Attribute" },
    { NAN_ATTR_CONNECTION_CAPABILITY, "NAN Connection Capability Attribute" },
    { NAN_ATTR_WLAN_INFRA, "WLAN Infrastructure Attribute" },
    { NAN_ATTR_P2P_OPERATION, "P2P Operation Attribute" },
    { NAN_ATTR_IBSS, "IBSS Attribute" },
    { NAN_ATTR_MESH, "Mesh Attribute" },
    { NAN_ATTR_FURTHER_SERVICE_DISCOVERY, "Further NAN Service Discovery Attribute" },
    { NAN_ATTR_FURTHER_AVAILABILITY_MAP, "Further Availability Map Attribute" },
    { NAN_ATTR_COUNTRY_CODE, "Country Code Attribute" },
    { NAN_ATTR_RANGING, "Ranging Attribute" },
    { NAN_ATTR_CLUSTER_DISCOVERY, "Cluster Discovery Attribute" },
    { NAN_ATTR_SERVICE_DESCRIPTOR_EXTENSION, "Service Descriptor Extension Attribute" },
    { NAN_ATTR_DEVICE_CAPABILITY, "Device Capability" },
    { NAN_ATTR_NDP, "NDP Attribute" },
    { NAN_ATTR_RESERVED_NMSG, "Reserved (NMSG)" },
    { NAN_ATTR_AVAILABILITY, "NAN Availability" },
    { NAN_ATTR_NDC, "NDC Attribute" },
    { NAN_ATTR_NDL, "NDL Attribute" },
    { NAN_ATTR_NDL_QOS, "NDL QoS Attribute" },
    { NAN_ATTR_RESERVED_MULTICAST_SCHEDULE, "Reserved (Multicast Schedule)" },
    { NAN_ATTR_UNALIGNED_SCHEDULE, "Unaligned Schedule Attribute" },
    { NAN_ATTR_RESERVED_UNICAST_PAGING, "Reserved (Unicast Paging)" },
    { NAN_ATTR_RESERVED_MULTICAST_PAGING, "Reserved (Multicast Paging)" },
    { NAN_ATTR_RANGING_INFORMATION, "Ranging Information Attribute" },
    { NAN_ATTR_RANGING_SETUP, "Ranging Setup Attribute" },
    { NAN_ATTR_FTM_RANGING_REPORT, "FTM Ranging Report Attribute" },
    { NAN_ATTR_ELEMENT_CONTAINER, "Element Container Attribute" },
    { NAN_ATTR_EXTENDED_WLAN_INFRA, "Extended WLAN Infrastructure Attribute" },
    { NAN_ATTR_EXTENDED_P2P_OPERATION, "Extended P2P Operation Attribute" },
    { NAN_ATTR_EXTENDED_IBSS, "Extended IBSS Attribute" },
    { NAN_ATTR_EXTENDED_MESH, "Extended Mesh Attribute" },
    { NAN_ATTR_CIPHER_SUITE_INFO, "Cipher Suite Info Attribute" },
    { NAN_ATTR_SECURITY_CONTEXT_INFO, "Security Context Info Attribute" },
    { NAN_ATTR_SHARED_KEY_DESCRIPTOR, "Shared-Key Descriptor Attribute" },
    { NAN_ATTR_RESERVED_MULTICAST_SCHEDULE_CHANGE, "Reserved (Multicast Schedule Change)" },
    { NAN_ATTR_RESERVED_MULTICAST_SCHEDULE_OWNER_CHANGE, "Reserved (Multicast Schedule Owner Change)" },
    { NAN_ATTR_PUBLIC_AVAILABILITY, "Public Availability Attribute" },
    { NAN_ATTR_SUBSCRIBE_SERVICE_ID_LIST, "Subscribe Service ID List Attribute" },
    { NAN_ATTR_NDP_EXTENSION, "NDP Extension Attribute" },
    { NAN_ATTR_DEVICE_CAPABILITY_EXTENSION, "Device Capability Extension"},
    { NAN_ATTR_IDENTITY_RESOLUTION, "NAN Identity Resolution"},
    { NAN_ATTR_PAIRING_BOOTSTRAPPING, "NAN Pairing Bootstrapping"},
    { NAN_ATTR_VENDOR_SPECIFIC, "Vendor Specific Attribute" },
    { 0, NULL }
};

// Bitmask fields shared by multiple attributes
static int* const map_control_fields[] = {
    &hf_nan_map_ctrl_map_id,
    &hf_nan_map_ctrl_availability_interval_duration,
    &hf_nan_map_ctrl_repeat,
    NULL
};

static int* const time_bitmap_ctr_fields[] = {
    &hf_nan_time_bitmap_ctrl_bit_duration,
    &hf_nan_time_bitmap_ctrl_period,
    &hf_nan_time_bitmap_ctrl_start_offset,
    NULL
};

static const true_false_string srf_type_flags = {
    "Address Set is a Bloom filter",
    "Address Set is a sequence of MAC Addresses"
};

static const true_false_string srf_include_flags = {
    "Only STAs Present in Address Set shall send a response",
    "STAs present in Address Set shall not send responses"
};

static const true_false_string sdea_ctr_data_path_type_flags = {
    "Reserved",
    "Unicast NDP required (Reserved if NDP is not required)"
};

static const true_false_string sdea_ctr_reserved_multicast_type_flags = {
    "Many to many (Reserved if NDP is not required)",
    "One to many (Reserved if NDP is not required)"
};

static const true_false_string device_cap_map_id_apply_to_flags = {
    "Only specified map",
    "All maps"
};

static const true_false_string device_cap_op_mode_phy_flags_vht = {
    "VHT",
    "HT"
};

static const true_false_string device_cap_op_mode_phy_flags_he = {
    "HE",
    "HE Not Supported"
};

static const true_false_string availability_entry_entries_type_flags = {
    "Operating Classes and channel entries",
    "Indicated bands"
};

static const true_false_string ndc_ctr_selected_flags = {
    "Selected NDC for a NDL Schedule",
    "NDC included for the peer's information"
};

static const value_string map_ctrl_availability_interval_duration[] = {
    { 0, "16 TU" },
    { 1, "32 TU" },
    { 2, "64 TU" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string service_ctr_type[] = {
    { 0, "Publish" },
    { 1, "Subscribe" },
    { 2, "Follow up" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const range_string service_info_protocol_type[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "Bonjour" },
    { 2, 2, "Generic" },
    { 3, 255, "Reserved" },
    { 0, 0, NULL }
};

static const value_string availability_entry_type[] = {
    { 0, "Reserved" },
    { 1, "Committed" },
    { 2, "Potential" },
    { 3, "Committed + Potential" },
    { 4, "Conditional" },
    { 5, "Reserved" },
    { 6, "Potential + Conditional" },
    { 7, "Reserved" },
    { 0, NULL }
};

static const range_string availability_entry_time_bitmap_ctr_bit_duration_type[] = {
    { 0, 0, "16 TU" },
    { 1, 1, "32 TU" },
    { 2, 2, "64 TU" },
    { 3, 3, "128 TU" },
    { 4, 7, "Reserved" },
    { 0, 0, NULL }
};

static const value_string availability_entry_time_bitmap_ctr_period_type[] = {
    { 1, "128 TU" },
    { 2, "256 TU" },
    { 3, "512 TU" },
    { 4, "1024 TU" },
    { 5, "2048 TU" },
    { 6, "4096 TU" },
    { 7, "8192 TU" },
    { 0, NULL }
};

static const range_string availability_entry_entries_band_type[] = {
    { 0, 0, "Reserved (for TV white spaces)" },
    { 1, 1, "Sub-1 GHz" },
    { 2, 2, "2.4 GHz" },
    { 3, 3, "Reserved (for 3.6 GHz)" },
    { 4, 4, "4.9 and 5 GHz" },
    { 5, 5, "Reserved (for 60 GHz)" },
    { 6, 6, "Reserved (for 45 GHz)" },
    { 7, 7, "6 Ghz" },
    { 8, 255, "Reserved" },
    { 0, 0, NULL }
};

static const range_string ndp_type_values[] = {
    { 0, 0, "Request" },
    { 1, 1, "Response" },
    { 2, 2, "Confirm" },
    { 3, 3, "Security Install" },
    { 4, 4, "Terminate" },
    { 5, 15, "Reserved" },
    { 0, 0, NULL }
};

static const range_string ndpe_tlv_type_values[] = {
    { 0, 0, "IPv6 Link Local" },
    { 1, 1, "Service Info" },
    { 2, 255, "Reserved" },
    { 0, 0, NULL }
};

static const range_string ndl_type_values[] = {
    { 0, 0, "Request" },
    { 1, 1, "Response" },
    { 2, 2, "Confirm" },
    { 3, 15, "Reserved" },
    { 0, 0, NULL }
};

static const range_string ranging_setup_type_values[] = {
    { 0, 0, "Request" },
    { 1, 1, "Response" },
    { 2, 2, "Termination" },
    { 3, 15, "Reserved" },
    { 0, 0, NULL }
};

static const range_string status_type1_values[] = {
    { 0, 0, "Continue" },
    { 1, 1, "Accepted" },
    { 2, 2, "Rejected" },
    { 3, 15, "Reserved" },
    { 0, 0, NULL }
};

static const range_string status_type2_values[] = {
    { 0, 0, "Accepted" },
    { 1, 1, "Rejected" },
    { 2, 15, "Reserved" },
    { 0, 0, NULL }
};

static const range_string reason_code_values[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "UNSPECIFIED_REASON" },
    { 2, 2, "RESOURCE_LIMITATION" },
    { 3, 3, "INVALID_PARAMETERS" },
    { 4, 4, "FTM_PARAMETERS_INCAPABLE" },
    { 5, 5, "NO_MOVEMENT" },
    { 6, 6, "INVALID_AVAILABILITY" },
    { 7, 7, "IMMUTABLE_UNACCEPTABLE" },
    { 8, 8, "SECURITY_POLICY" },
    { 9, 9, "QoS_UNACCEPTABLE" },
    { 10, 10, "NDP_REJECTED" },
    { 11, 11, "NDL_UNACCEPTABLE" },
    { 12, 12, "Ranging Schedule unacceptable" },
    { 13, 255, "Reserved" },
    { 0, 0, NULL }
};

static const range_string action_frame_type_values[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "Ranging Request" },
    { 2, 2, "Ranging Response" },
    { 3, 3, "Ranging Termination" },
    { 4, 4, "Ranging Report" },
    { 5, 5, "Data Path Request" },
    { 6, 6, "Data Path Response" },
    { 7, 7, "Data Path Confirm" },
    { 8, 8, "Data Path Key Installment" },
    { 9, 9, "Data Path Termination" },
    { 10, 10, "Schedule Request" },
    { 11, 11, "Schedule Response" },
    { 12, 12, "Schedule Confirm" },
    { 13, 13, "Schedule Update Notification" },
    { 14, 255, "Reserved" },
    { 0, 0, NULL }
};

static const value_string ndl_type_string[] = {
    { 0, "S-NDL" },
    { 1, "Reserved (P-NDL)" },
    { 0, NULL }
};

static const value_string ndl_setup_reason[] = {
    { 0, "NDP" },
    { 1, "FSD using GAS" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string unaligned_sch_ulw_type[] = {
    { 0, "Followed by a Band ID field" },
    { 1, "Followed by a Channel Entry field without Auxiliary Channel" },
    { 2, "Followed by a Channel Entry field with Auxiliary Channel" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const range_string security_context_iden_type[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "ND-PMKID" },
    { 2, 255, "Reserved" },
    { 0, 0, NULL }
};

static const value_string device_role[] = {
    { 0, "AP" },
    { 1, "Non-AP STA associated with AP" },
    { 2, "Non-AP STA listening to AP" },
    { 0, NULL }
};

static const range_string furth_av_map_id[] = {
    {0, 15, "Identify Further Availability attribute"},
    {16, 255, "Reserved"},
    {0, 0, NULL}
};

static const value_string device_capability_extension_6g_regulatoty_info[] = {
    { 0, "Indoor AP" },
    { 1, "Standard Power AP" },
    { 2, "Very Low Power AP" },
    { 3, "Indoor Enabled AP" },
    { 4, "Indoor Standard Power AP" },
    { 0, NULL }
};

static const range_string nan_identity_resolution_cipher_version[] = {
    {0, 0, "128-bit NIK, 64-bit Nonce, 64-bit Tag, HMAC-SHA-256"},
    {1, 255, "Reserved"},
    {0, 0, NULL }
};

static const value_string nan_pairing_bootstrapping_pairing_bootstrapping_type[] = {
    { 0, "Advertise" },
    { 1, "Request" },
    { 2, "Response" },
    { 0, NULL } /* Reserved for other value */
};

static const value_string nan_pairing_bootstrapping_pairing_bootstrapping_status[] = {
    { 0, "Accepted" },
    { 1, "Rejected" },
    { 2, "Comeback" },
    { 0, NULL } /* Reserved for other value */
};

static const value_string cipher_suite_capabilities_nd_nm_tksa_replay_counters[] = {
    { 0, "4 ND-TKSA and NM-TKSA (if applicable) replay counters" },
    { 1, "16 ND-TKSA and NM-TKSA (if applicable) replay counters" },
    { 0, NULL }
};

static const value_string cipher_suite_capabilities_group_and_integrity_sa_support[] = {
    { 0, "GTKSA, IGTKSA, BIGTKSA are not supported" },
    { 1, "GTKSA and IGTKSA are supported, and BIGTKSA is not supported" },
    { 2, "GTKSA, IGTKSA, and BIGTKSA are supported" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string cipher_suite_capabilities_gtksa_replay_counters[] = {
    { 0, "4 GTKSA replay counters" },
    { 1, "16 GTKSA replay counters" },
    { 0, NULL }
};

static const value_string cipher_suite_capabilities_integrity_sa_ciphers[] = {
    { 0, "NCS-BIP-128 (BIP-CMAC-128)" },
    { 1, "NCS-BIP_256 (BIP-GMAC-256)" },
    { 0, NULL }
};

#define PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN (64)

typedef struct _range_channel_set {
    uint32_t   value_min;
    uint32_t   value_max;
    const int channel_set[PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN];
} range_channel_set;

static const int *
rval_to_channel_set(const uint32_t val, const range_channel_set* ra)
{
    int i = 0;
    if (ra)
    {
        while (*ra[i].channel_set) /* no such thing as channel 0 - end of list */
        {
            if ((val >= ra[i].value_min) && (val <= ra[i].value_max))
            {
                return ra[i].channel_set;
            }
            i++;
        }
    }
    return NULL;
}

static unsigned int channel_number_valid(const uint8_t channel_number, const int *const channel_set)
{
    for (unsigned int i = 0; i < PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN; i++)
    {
        if (channel_set[i] == channel_number)
        {
            return i;
        }
    }

    return PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN;
}

// TODO: this table corresponds to the 802.11 global operating classes.
//   it's probably in the 802.11 dissector somewhere and ideally this
//   should be used instead...
static const range_channel_set op_class_channel[] = {
    {1, 80, {-1}},
    {81, 81, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {82, 82, {14}},
    {83, 83, {1, 2, 3, 4, 5, 6, 7, 8, 9}},
    {84, 84, {5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {85, 85, {-3}},
    {86, 86, {-3}},
    {87, 87, {-3}},
    {88, 93, {-1}},
    {94, 94, {133, 137}},
    {95, 95, {136, 138}},
    {96, 96, {131, 132, 133, 134, 135, 136, 137, 138}},
    {97, 100, {-1}},
    {101, 101, {21, 25}},
    {102, 102, {11, 13, 15, 17, 19}},
    {103, 103, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
    {104, 104, {184, 192}},
    {105, 105, {188, 196}},
    {106, 106, {191, 195}},
    {107, 107, {189, 191, 193, 195, 197}},
    {108, 108, {188, 189, 190, 191, 192, 193, 194, 195, 196, 197}},
    {109, 109, {184, 188, 192, 196}},
    {110, 110, {183, 184, 185, 186, 187, 188, 189}},
    {111, 111, {182, 183, 184, 185, 186, 187, 188, 189}},
    {112, 112, {8, 12, 16}},
    {113, 113, {7, 8, 9, 10, 11}},
    {114, 114, {6, 7, 8, 9, 10, 11}},
    {115, 115, {36, 40, 44, 48}},
    {116, 116, {36, 44}},
    {117, 117, {40, 48}},
    {118, 118, {52, 56, 60, 64}},
    {119, 119, {52, 60}},
    {120, 120, {56, 64}},
    {121, 121, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}},
    {122, 122, {100, 108, 116, 124, 132, 140}},
    {123, 123, {103, 112, 120, 128, 136, 144}},
    {124, 124, {149, 153, 157, 161}},
    {125, 125, {149, 153, 157, 161,165, 169}},
    {126, 126, {149, 157}},
    {127, 127, {153, 161}},
    {128, 128, {42, 58, 106, 122, 138, 155}},
    {129, 129, {50, 114}},
    {130, 130, {42, 58, 106, 122, 138, 155}},
    {131, 131, {1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233}},
    {132, 132, {3, 11, 19, 27, 35, 43, 51, 59, 67, 75, 83, 91, 99, 107, 115, 123, 131, 139, 147, 155, 163, 171, 179, 187, 195, 203, 211, 219, 227}},
    {133, 133, {7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215}},
    {134, 134, {15, 47, 79, 111, 143, 175, 207}},
    {135, 135, {7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215}},
    {137, 137, {31, 63, 95, 127, 159, 191}},
    {138, 179, {-1}},
    {137, 179, {-1}},
    {180, 180, {1, 2, 3, 4, 5, 6}},
    {181, 191, {-1}},
    {192, 254, {-2}},
    {255, 255, {-1}},
    {0, 0, {0}}, /* no such thing as channel 1 - end of list */
};

static const range_string op_channel_spacing[] = {
    {1, 80, "Reserved"},
    {81, 82, "25"},
    {83, 84, "40"},
    {85, 85, "6, 7, 8"},
    {86, 86, "12, 14, 16"},
    {87, 87, "24, 28, 32"},
    {88, 93, "Reserved"},
    {94, 94, "20"},
    {95, 95, "10"},
    {96, 96, "5"},
    {97, 100, "Reserved"},
    {101, 101, "20"},
    {102, 102, "10"},
    {103, 103, "5"},
    {104, 105, "40"},
    {106, 106, "20"},
    {107, 107, "10"},
    {108, 108, "5"},
    {109, 109, "20"},
    {110, 110, "10"},
    {111, 111, "5"},
    {112, 112, "20"},
    {113, 113, "10"},
    {114, 114, "5"},
    {115, 115, "20"},
    {116, 117, "40"},
    {118, 118, "20"},
    {119, 120, "40"},
    {121, 121, "20"},
    {122, 123, "40"},
    {124, 125, "20"},
    {126, 127, "40"},
    {128, 128, "80"},
    {129, 129, "160"},
    {130, 130, "80"},
    {131, 131, "20"},
    {132, 132, "40"},
    {133, 133, "80"},
    {134, 134, "160"},
    {135, 135, "80"},
    {136, 136, "20"},
    {137, 137, "320"},
    {138, 179, "Reserved"},
    {180, 180, "2160"},
    {181, 191, "Reserved"},
    {255, 255, "Reserved"},
    {0, 0, NULL}
};

static const range_string op_starting_freq[] = {
    {1, 80, "Reserved"},
    {81, 81, "2.407"},
    {82, 82, "2.414"},
    {83, 83, "2.407"},
    {84, 84, "2.407"},
    {88, 93, "Reserved"},
    {94, 95, "3"},
    {96, 96, "3.0025"},
    {97, 100, "Reserved"},
    {101, 101, "4.85"},
    {102, 102, "4.89"},
    {103, 103, "4.9375"},
    {104, 104, "4"},
    {105, 107, "4"},
    {108, 108, "4.0025"},
    {109, 110, "4"},
    {111, 111, "4.0025"},
    {112, 113, "5"},
    {114, 114, "5.0025"},
    {115, 130, "5"},
    {131, 135, "5.950"},
    {136, 136, "5.925"},
    {137, 137, "5.950"},
    {138, 179, "Reserved"},
    {180, 180, "56.16"},
    {181, 191, "Reserved"},
    {255, 255, "Reserved"},
    {0, 0, NULL}
};

static void
dissect_attr_master_indication(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_MASTER_IND_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    proto_tree_add_item(attr_tree, hf_nan_attr_master_preference, tvb,
        offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(attr_tree, hf_nan_attr_master_random_factor, tvb,
        offset + 4, 1, ENC_BIG_ENDIAN);
}

static void
dissect_attr_cluster(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_CLUSTER_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    proto_tree* anchor_master_tree = proto_tree_add_subtree(attr_tree, tvb, offset + 3, 13,
        ett_cluster_anchor_master_info, NULL, "Anchor Master Information");
    proto_tree_add_item(anchor_master_tree, hf_nan_attr_cluster_anchor_master_rank, tvb,
        offset + 3, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(anchor_master_tree, hf_nan_attr_cluster_hop_count, tvb,
        offset + 11, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(anchor_master_tree, hf_nan_attr_cluster_beacon_transmission_time, tvb,
        offset + 12, 4, ENC_BIG_ENDIAN);
}

static void
dissect_attr_service_id_list(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len % 6 != 0 || attr_len == 0)
    {
        expert_add_info_format(pinfo, attr_tree, &ei_nan_elem_len_invalid, "Invalid Service ID length");
        return;
    }

    int num_service_ids = attr_len / 6;
    offset += 3;
    for (int i = 1; i <= num_service_ids; ++i)
    {
        proto_tree_add_item(attr_tree, hf_nan_service_id, tvb, offset, 6, ENC_NA);
        offset += 6;
    }
}

static void
dissect_attr_sda(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_SDA_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    proto_tree_add_item(attr_tree, hf_nan_service_id, tvb,
        offset + 3, 6, ENC_NA);
    proto_tree_add_item(attr_tree, hf_nan_instance_id, tvb,
        offset + 9, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(attr_tree, hf_nan_attr_sda_requestor_instance_id, tvb,
        offset + 10, 1, ENC_BIG_ENDIAN);
    offset += 11;

    static int* const service_ctr_fields[] = {
        &hf_nan_attr_sda_sc_type,
        &hf_nan_attr_sda_sc_matching_filter,
        &hf_nan_attr_sda_sc_service_response,
        &hf_nan_attr_sda_sc_service_info,
        &hf_nan_attr_sda_sc_discovery_range,
        &hf_nan_attr_sda_sc_binding_bitmap,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, offset, hf_nan_attr_sda_sc,
        ett_sda_service_ctr, service_ctr_fields, ENC_LITTLE_ENDIAN);

    uint8_t service_ctr_byte = tvb_get_uint8(tvb, offset);
    offset += 1;

    const uint8_t BITMASK_TYPE_SUBSCRIBE = 0x01;
    const uint8_t BITMASK_TYPE_FOLLOW_UP = 0x02;
    const uint8_t BITMASK_MATCHING_FILTER_PRESENT = 0x04;
    const uint8_t BITMASK_SERVICE_RESPONSE_FILTER_PRESENT = 0x08;
    const uint8_t BITMASK_SERVICE_INFO_PRESENT = 0x10;
    const uint8_t BITMASK_BITMAP_PRESENT = 0x40;

    if (service_ctr_byte & BITMASK_TYPE_SUBSCRIBE)
    {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "SDF Subscribe, ");
    }
    else if (service_ctr_byte & BITMASK_TYPE_FOLLOW_UP)
    {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "SDF Follow up, ");
    }
    else
    {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "SDF Publish, ");
    }

    if (service_ctr_byte & BITMASK_BITMAP_PRESENT)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_sda_binding_bitmap, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    if (service_ctr_byte & BITMASK_MATCHING_FILTER_PRESENT)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_sda_matching_filter_len, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        int mf_len = tvb_get_uint8(tvb, offset);
        int dissected_mf_len = 0;
        offset += 1;
        while (dissected_mf_len < mf_len)
        {
            int filter_len = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(attr_tree, hf_nan_attr_sda_matching_filter_val, tvb,
                offset + 1, filter_len, ENC_NA);
            offset += filter_len + 1;
            dissected_mf_len += filter_len + 1;
        }
    }

    if (service_ctr_byte & BITMASK_SERVICE_RESPONSE_FILTER_PRESENT)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_sda_service_response_filter_len, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        int srf_len = tvb_get_uint8(tvb, offset);

        static int* const srf_ctr_fields[] = {
            &hf_nan_attr_sda_srf_ctr_type,
            &hf_nan_attr_sda_srf_ctr_include,
            &hf_nan_attr_sda_srf_ctr_bloom_filter_index,
            NULL
        };

        proto_tree_add_bitmask(attr_tree, tvb, offset + 1, hf_nan_attr_sda_srf_ctr,
            ett_sda_service_ctr, srf_ctr_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(attr_tree, hf_nan_attr_sda_srf_address_set, tvb,
            offset + 2, srf_len - 1, ENC_NA);
        offset += srf_len + 1;
    }

    if (service_ctr_byte & BITMASK_SERVICE_INFO_PRESENT)
    {
        uint32_t service_info_len;

        /* XXX - use FT_UINT_BYTES? */
        proto_tree_add_item_ret_uint(attr_tree, hf_nan_attr_sda_service_info_len, tvb,
            offset, 1, ENC_BIG_ENDIAN, &service_info_len);
        proto_tree_add_item(attr_tree, hf_nan_attr_sda_service_info, tvb,
            offset + 1, service_info_len, ENC_NA);
        // offset += service_info_len + 1;
    }
}

static void
dissect_attr_sdea(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_SDEA_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    proto_tree_add_item(attr_tree, hf_nan_instance_id, tvb,
        offset + 3, 1, ENC_LITTLE_ENDIAN);
    offset += 4;
    uint16_t dissected_len = 1;

    static int* const sdea_ctr_fields[] = {
        &hf_nan_attr_sdea_ctr_fsd,
        &hf_nan_attr_sdea_ctr_fsd_w_gas,
        &hf_nan_attr_sdea_ctr_data_path,
        &hf_nan_attr_sdea_ctr_data_path_type,
        &hf_nan_attr_sdea_ctr_reserved_multicast_type,
        &hf_nan_attr_sdea_ctr_qos,
        &hf_nan_attr_sdea_ctr_security,
        &hf_nan_attr_sdea_ctr_ranging,
        &hf_nan_attr_sdea_ctr_range_limit,
        &hf_nan_attr_sdea_ctr_service_update_indicator,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, offset, hf_nan_attr_sdea_ctr, ett_sdea_ctr,
        sdea_ctr_fields, ENC_LITTLE_ENDIAN);

    uint16_t sdea_ctr_byte = tvb_get_letohs(tvb, offset);
    offset += 2;
    dissected_len += 2;

    if (sdea_ctr_byte & 0x100)
    {
        proto_tree* range_lim_tree = proto_tree_add_subtree(attr_tree, tvb, offset, 4,
            ett_sdea_range_limit, NULL, "Range Limit");
        proto_tree_add_item(range_lim_tree, hf_nan_attr_sdea_ingress_range_limit, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(range_lim_tree, hf_nan_attr_sdea_egress_range_limit, tvb,
            offset + 2, 2, ENC_LITTLE_ENDIAN);
        offset += 4;
        dissected_len += 4;
    }

    if (sdea_ctr_byte & 0x200)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_sdea_service_update_indicator, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        dissected_len += 1;
    }

    // If Service Info field is present
    if (dissected_len < attr_len)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_sdea_service_info_length, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree* service_info_tree = proto_tree_add_subtree(attr_tree, tvb, offset + 2,
            attr_len - dissected_len - 2, ett_sdea_service_info, NULL, "Service Info");
        proto_tree_add_item(service_info_tree, hf_nan_oui, tvb,
            offset + 2, 3, ENC_NA);
        proto_tree_add_item(service_info_tree, hf_nan_attr_sdea_service_info_protocol_type, tvb,
            offset + 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(service_info_tree, hf_nan_attr_sdea_service_info_specific, tvb,
            offset + 6, attr_len - dissected_len - 6, ENC_NA);
    }
}

static void
dissect_attr_connection_capability(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_CONNECTION_CAP_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const connection_cap_bitmap_fields[] = {
        &hf_nan_attr_connection_cap_wifi_direct,
        &hf_nan_attr_connection_cap_p2ps,
        &hf_nan_attr_connection_cap_tdls,
        &hf_nan_attr_connection_cap_wlan_infra,
        &hf_nan_attr_connection_cap_ibss,
        &hf_nan_attr_connection_cap_mesh,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, offset + 3, hf_nan_attr_connection_cap_bitmap,
        ett_connection_cap_field, connection_cap_bitmap_fields, ENC_LITTLE_ENDIAN);
}

static void
dissect_attr_wlan_infra(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_WLAN_INFRA_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_bss_id, tvb, sub_offset, 6, ENC_LITTLE_ENDIAN);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    int bitmap_length = attr_len - 14;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, bitmap_length, ENC_NA);
    sub_offset += bitmap_length;
    proto_tree_add_item(attr_tree, hf_nan_attr_wlan_infra_device_role, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_attr_p2p_operation(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_P2P_OP_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    static int* const p2p_bitmap_fields[] = {
        &hf_nan_attr_p2p_device_role_device,
        &hf_nan_attr_p2p_device_role_group_owner,
        &hf_nan_attr_p2p_device_role_client,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_p2p_device_role,
        ett_p2p_device_role, p2p_bitmap_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_ibss(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_IBSS_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_bss_id, tvb, sub_offset, 6, ENC_LITTLE_ENDIAN);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_mesh(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_MESH_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;

    uint8_t duration = tvb_get_bits8(tvb, sub_offset * 8 + 5, 2);
    unsigned bitmap_length;
    switch (duration) {
    case 0:
        bitmap_length = 4;
        break;
    case 1:
        bitmap_length = 2;
        break;
    case 2:
        bitmap_length = 1;
        break;
    default:
        bitmap_length = 0;
    }

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, bitmap_length, ENC_NA);
    sub_offset += bitmap_length;
    proto_tree_add_item(attr_tree, hf_nan_attr_mesh_id, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_further_service_discovery(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len)
{
    unsigned sub_offset = offset + 3;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    int bitmap_length = attr_len - 1;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, bitmap_length, ENC_NA);
}

static void
dissect_attr_further_availability_map(proto_tree* attr_tree, tvbuff_t* tvb, int offset)
{
    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_attr_further_av_map_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    static int* const availability_entry_control_fields[] = {
        &hf_nan_attr_further_av_map_entry_av_interval_duration,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_further_av_map_entry_ctrl,
        ett_further_av_map_entry_ctrl, availability_entry_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_attr_further_av_map_op_class, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_attr_further_av_map_channel_num, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_country_code(proto_tree* attr_tree, tvbuff_t* tvb, int offset)
{
    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_attr_country_code, tvb, sub_offset, 2, ENC_ASCII);
}

static void
dissect_attr_ranging(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_RANGING_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_ctrl_field,
        ett_map_control, map_control_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_attr_ranging_protocol, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_availability_intervals_bitmap, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_cluter_discovery(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_CLUSTER_DISC_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_attr_cluster_disc_id, tvb, sub_offset, 6, ENC_LITTLE_ENDIAN);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_attr_cluster_disc_time_offset, tvb, sub_offset, 8, ENC_LITTLE_ENDIAN);
    sub_offset += 8;
    proto_tree_add_item(attr_tree, hf_nan_attr_cluster_disc_anchor_master_rank, tvb, sub_offset, 8, ENC_LITTLE_ENDIAN);
}

static void
dissect_attr_device_capability(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_DEVICE_CAP_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const device_cap_map_id_fields[] = {
        &hf_nan_attr_device_cap_map_id_apply_to,
        &hf_nan_attr_device_cap_map_id_associated_maps,
        NULL
    };
    static int* const device_cap_committed_dw_fields[] = {
        &hf_nan_attr_device_cap_committed_dw_24ghz,
        &hf_nan_attr_device_cap_committed_dw_5ghz,
        &hf_nan_attr_device_cap_committed_dw_24ghz_overwrite,
        &hf_nan_attr_device_cap_committed_dw_5ghz_overwrite,
        NULL
    };
    static int* const device_cap_supported_bands_fields[] = {
        &hf_nan_attr_device_cap_supported_bands_reserved_tv_whitespaces,
        &hf_nan_attr_device_cap_supported_bands_sub_1ghz,
        &hf_nan_attr_device_cap_supported_bands_24ghz,
        &hf_nan_attr_device_cap_supported_bands_reserved_36ghz,
        &hf_nan_attr_device_cap_supported_bands_5ghz,
        &hf_nan_attr_device_cap_supported_bands_reserved_60ghz,
        &hf_nan_attr_device_cap_supported_bands_reserved_45ghz,
        &hf_nan_attr_device_cap_supported_bands_6ghz,
        NULL
    };
    static int* const device_cap_op_mode_fields[] = {
        &hf_nan_attr_device_cap_op_mode_phy_vht,
        &hf_nan_attr_device_cap_op_mode_phy_he_vht8080,
        &hf_nan_attr_device_cap_op_mode_phy_he_vht160,
        &hf_nan_attr_device_cap_op_mode_reserved_paging_ndl,
        &hf_nan_attr_device_cap_op_mode_phy_he,
        NULL
    };
    static int* const device_cap_antennas_fields[] = {
        &hf_nan_attr_device_cap_antennas_tx,
        &hf_nan_attr_device_cap_antennas_rx,
        NULL
    };
    static int* const device_cap_capabilities_fields[] = {
        &hf_nan_attr_device_cap_capabilities_dfs_master,
        &hf_nan_attr_device_cap_capabilities_extended_key_id,
        &hf_nan_attr_device_cap_capabilities_simul_ndp_reception,
        &hf_nan_attr_device_cap_capabilities_ndpe_attr_support,
        &hf_nan_attr_device_cap_capabilities_s3_capable,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, offset + 3, hf_nan_map_id,
        ett_device_cap_map_id, device_cap_map_id_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 4, hf_nan_attr_device_cap_committed_dw,
        ett_device_cap_committed_dw, device_cap_committed_dw_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 6, hf_nan_attr_device_cap_supported_bands,
        ett_device_cap_supported_bands, device_cap_supported_bands_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 7, hf_nan_attr_device_cap_op_mode,
        ett_device_cap_op_mode, device_cap_op_mode_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 8, hf_nan_attr_device_cap_antennas,
        ett_device_cap_antennas, device_cap_antennas_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(attr_tree, hf_nan_attr_device_cap_max_channel_switch_time, tvb,
        offset + 9, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 11, hf_nan_attr_device_cap_capabilities,
        ett_device_cap_capabilities, device_cap_capabilities_fields, ENC_LITTLE_ENDIAN);
}

static void
dissect_attr_ndp(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_NDP_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_dialog_tokens, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    static int* const ndp_type_status_fields[] = {
        &hf_nan_attr_ndp_type,
        &hf_nan_status_1,
        NULL
    };
    static int* const ndp_control_fields[] = {
        &hf_nan_attr_ndp_ctrl_confirm,
        &hf_nan_attr_ndp_ctrl_security_pres,
        &hf_nan_attr_ndp_ctrl_publish_id_pres,
        &hf_nan_attr_ndp_ctrl_responder_ndi_pres,
        &hf_nan_attr_ndp_ctrl_sepcific_info_pres,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_type_status,
        ett_type_status, ndp_type_status_fields, ENC_LITTLE_ENDIAN);

    uint8_t bits_type = tvb_get_bits8(tvb, sub_offset * 8 + 4, 4);
    uint8_t bit_offset = (sub_offset * 8) + 4;
    uint8_t bits_status = tvb_get_bits8(tvb, bit_offset, 4);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_reason_code, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_attr_ndp_initiator, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_attr_ndp_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_ndp_control,
        ett_ndp_control, ndp_control_fields, ENC_LITTLE_ENDIAN);

    uint8_t bits_ndp_info = tvb_get_bits8(tvb, (sub_offset * 8) + 2, 1);
    uint8_t bits_publish_id = tvb_get_bits8(tvb, (sub_offset * 8) + 4, 1);
    sub_offset++;

    if (bits_publish_id == 1 && bits_type == 0)
    {
        proto_tree_add_item(attr_tree, hf_nan_publish_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
    }
    if (bits_type == 1 && (bits_status == 0 || bits_status == 1))
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ndp_responder_ndi, tvb, sub_offset, 6, ENC_NA);
        sub_offset += 6;
    }
    if (bits_ndp_info)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ndp_specific_info, tvb, sub_offset, -1, ENC_NA);
    }
}

static void
dissect_attr_ndpe(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_NDPE_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const ndp_type_status_fields[] = {
        &hf_nan_attr_ndp_type,
        &hf_nan_status_1,
        NULL
    };
    static int* const ndpe_control_fields[] = {
        &hf_nan_attr_ndpe_ctrl_confirm,
        &hf_nan_attr_ndpe_ctrl_security_pres,
        &hf_nan_attr_ndpe_ctrl_publish_id_pres,
        &hf_nan_attr_ndpe_ctrl_responder_ndi_pres,
        &hf_nan_attr_ndpe_ctrl_gtk_requried,
        NULL
    };

    int dissected_len = 0;
    proto_tree_add_item(attr_tree, hf_nan_dialog_tokens, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 4, hf_nan_type_status,
        ett_type_status, ndp_type_status_fields, ENC_LITTLE_ENDIAN);

    offset += 4;
    dissected_len += 4;
    uint8_t bits_type = tvb_get_bits8(tvb, offset * 8 + 4, 4);
    uint32_t bit_offset = (offset * 8) + 4;
    uint8_t bits_status = tvb_get_bits8(tvb, bit_offset, 4);

    proto_tree_add_item(attr_tree, hf_nan_reason_code, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(attr_tree, hf_nan_attr_ndp_initiator, tvb, offset + 2, 6, ENC_NA);
    proto_tree_add_item(attr_tree, hf_nan_attr_ndp_id, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 9, hf_nan_attr_ndpe_control,
        ett_ndp_control, ndpe_control_fields, ENC_LITTLE_ENDIAN);
    offset += 9;
    dissected_len += 9;

    uint8_t bits_publish_id = tvb_get_bits8(tvb, (offset * 8) + 4, 1);
    offset++;
    dissected_len++;

    if (bits_publish_id == 1 && bits_type == 0)
    {
        proto_tree_add_item(attr_tree, hf_nan_publish_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        dissected_len++;
    }
    if (bits_type == 1 && (bits_status == 0 || bits_status == 1))
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ndp_responder_ndi, tvb, offset, 6, ENC_NA);
        offset += 6;
        dissected_len += 6;
    }

    while (dissected_len < attr_len)
    {
        uint8_t tlv_type = tvb_get_uint8(tvb, offset);
        uint16_t tlv_len = tvb_get_letohs(tvb, offset + 1);
        proto_tree* tlv_tree = proto_tree_add_subtree(attr_tree, tvb, offset, tlv_len + 3,
            ett_ndpe_tlv, NULL, "TLV entry");
        proto_tree_add_item(tlv_tree, hf_nan_attr_ndpe_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_tree, hf_nan_attr_ndpe_tlv_len, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);

        switch (tlv_type)
        {
        case 0:
            proto_tree_add_item(tlv_tree, hf_nan_attr_ndpe_tlv_ipv6_interface_identifier, tvb, offset + 3, 8, ENC_NA);
            offset += 11;
            dissected_len += 11;
            break;
        case 1:
            proto_tree_add_item(tlv_tree, hf_nan_oui, tvb, offset + 3, 3, ENC_NA);
            proto_tree_add_item(tlv_tree, hf_nan_attr_vendor_specific_body, tvb, offset + 6, tlv_len - 3, ENC_NA);
            offset += tlv_len + 3;
            dissected_len += tlv_len + 3;
            break;
        default:
            proto_tree_add_item(tlv_tree, hf_nan_attr_vendor_specific_body, tvb, offset + 3, tlv_len, ENC_NA);
            offset += tlv_len + 3;
            dissected_len += tlv_len + 3;
            break;
        }
    }
}

static void
dissect_attr_availability(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_AVAILABILITY_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const availability_ctr_fields[] = {
        &hf_nan_attr_availability_map_id,
        &hf_nan_attr_availability_committed_changed,
        &hf_nan_attr_availability_potential_changed,
        &hf_nan_attr_availability_public_availability_changed,
        &hf_nan_attr_availability_ndc_changed,
        &hf_nan_attr_availability_reserved_multicast_schedule_changed,
        &hf_nan_attr_availability_reserved_multicast_schedule_change_changed,
        NULL
    };
    static int* const availability_entry_ctr_fields[] = {
        &hf_nan_attr_availability_entry_ctr_type,
        &hf_nan_attr_availability_entry_ctr_pref,
        &hf_nan_attr_availability_entry_ctr_utilization,
        &hf_nan_attr_availability_entry_ctr_rx_nss,
        &hf_nan_attr_availability_entry_ctr_time_bitmap,
        NULL
    };

    proto_tree_add_item(attr_tree, hf_nan_attr_availability_sequence_id, tvb,
        offset + 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 4, hf_nan_attr_availability_ctr,
        ett_device_cap_capabilities, availability_ctr_fields, ENC_LITTLE_ENDIAN);
    offset += 6;

    int dissected_len = 3;
    while (dissected_len < attr_len)
    {
        uint16_t entry_len = tvb_get_letohs(tvb, offset);
        uint8_t entry_type = tvb_get_bits8(tvb, offset * 8 + 21, 3);
        uint8_t hdr_len = 2;
        uint32_t time_bitmap_len = 0;
        uint64_t avail_entry;
        const char* entry_type_msg = val_to_str(entry_type, availability_entry_type,
            "Unknown type (%u)");
        char* info_msg = wmem_strconcat(pinfo->pool, "Availability Type : ", entry_type_msg, NULL);
        proto_tree* entry_tree = proto_tree_add_subtree(attr_tree, tvb, offset, entry_len + 2,
            ett_availability_entry, NULL, info_msg);
        proto_tree_add_item(entry_tree, hf_nan_attr_availability_entry_len, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask_ret_uint64(entry_tree, tvb, offset + 2, hf_nan_attr_availability_entry_ctr,
            ett_availability_entry_ctr, availability_entry_ctr_fields, ENC_LITTLE_ENDIAN, &avail_entry);
        offset += 4;

        bool time_bitmap_present = avail_entry & (1 << 12);
        if (time_bitmap_present)
        {
            proto_tree_add_bitmask(entry_tree, tvb, offset,
                hf_nan_time_bitmap_ctrl, ett_time_bitmap_ctrl,
                time_bitmap_ctr_fields, ENC_LITTLE_ENDIAN);
            proto_tree_add_item_ret_uint(entry_tree, hf_nan_time_bitmap_len, tvb,
                offset + 2, 1, ENC_LITTLE_ENDIAN, &time_bitmap_len);
            proto_tree_add_item(entry_tree, hf_nan_time_bitmap, tvb,
                offset + 3, time_bitmap_len, ENC_NA);
            hdr_len = 5;
            offset += 3 + time_bitmap_len;
        }

        int entries_len = entry_len - hdr_len - time_bitmap_len;
        proto_tree* entries_tree = proto_tree_add_subtree(entry_tree, tvb, offset, entries_len,
            ett_availability_entry_entries, NULL, "Band/Channel Entries");

        uint64_t entries_type, non_contiguous_bw, num_entries;
        proto_tree_add_bits_ret_val(entries_tree, hf_nan_attr_availability_entry_entries_type, tvb,
            offset * 8, 1, &entries_type, ENC_LITTLE_ENDIAN);
        proto_tree_add_bits_ret_val(entries_tree,
            hf_nan_attr_availability_entry_entries_non_contiguous_bw, tvb, offset * 8 + 1, 1,
            &non_contiguous_bw, ENC_LITTLE_ENDIAN);
        proto_tree_add_bits_ret_val(entries_tree, hf_nan_attr_availability_entry_entries_num_entries,
            tvb, offset * 8 + 4, 4, &num_entries, ENC_LITTLE_ENDIAN);

        offset += 1;
        for (uint8_t i = 0; i < num_entries; i++)
        {
            switch (entries_type) {
            case 0:
            {
                proto_tree_add_item(entries_tree, hf_nan_attr_availability_entry_entries_band, tvb,
                    offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                break;
            }
            case 1:
            {
                int channel_entry_len = (non_contiguous_bw == 0) ? 4 : 6;
                proto_tree* channel_tree = proto_tree_add_subtree(entries_tree, tvb, offset,
                    channel_entry_len, ett_availability_entry_entries_channel, NULL, "Channel Entry");
                uint8_t op_class = tvb_get_uint8(tvb, offset);
                uint16_t bitmap = tvb_get_uint16(tvb, offset + 1, ENC_LITTLE_ENDIAN);
                proto_tree* op_class_tree = proto_tree_add_subtree(channel_tree, tvb, offset, 1, ett_availability_op_class, NULL, "Operating Class");
                proto_tree_add_item(op_class_tree, hf_nan_attr_availability_entry_entries_start_freq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(op_class_tree, hf_nan_attr_availability_entry_entries_bandwidth, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                wmem_strbuf_t* str;
                str = wmem_strbuf_new(pinfo->pool, "");
                if (op_class < 131)
                {
                    for(unsigned i_bitmap = 0; i_bitmap < 16; ++i_bitmap)
                    {
                        if (bitmap & (1u << i_bitmap))
                        {

                            const int *channel_set = rval_to_channel_set(op_class, op_class_channel);
                            if (channel_set == NULL)
                            {
                                expert_add_info(pinfo, channel_tree, &ei_nan_unknown_op_class);
                                break;
                            }
                            int channel = channel_set[i_bitmap];

                            switch (channel)
                            {
                            // TODO: replace these magic numbers (or use 802.11 dissector for this)
                            case -3:
                                wmem_strbuf_append_printf(str, "%s", "Derived from regulation ");
                                break;
                            case -2:
                                wmem_strbuf_append_printf(str, "%s", "Vendor Specific ");
                                break;
                            case -1:
                                wmem_strbuf_append_printf(str, "%s", "Reserved ");
                                break;
                            default:
                                wmem_strbuf_append_printf(str, "%d ", channel);
                            }
                        }
                    }

                    proto_tree_add_string(channel_tree, hf_nan_attr_availability_entry_entries_channel_set, tvb, offset + 1, 2, wmem_strbuf_finalize(str));
                }
                else
                {
                    /* This is the new and standard rules for mapping channels for 6G channels introduced in NAN R4.
                     * Some vendors may have already implemetned a different approach to support NAN 6G before
                     * the introduction of standard 6G NAN operation. And hence, in this case, the availability
                     * may not be correct. */
                    uint8_t start_ch_number = bitmap & 0xff;
                    uint8_t number_of_chs = (bitmap & 0xff00) >> 8;

                    const int *channel_set_higher_op_class = rval_to_channel_set(op_class, op_class_channel);
                    if (channel_set_higher_op_class)
                    {
                        unsigned int start_ch_number_idx = channel_number_valid(start_ch_number, channel_set_higher_op_class);
                        if (start_ch_number_idx == PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN)
                        {
                            /* The given channel number does not belong to this operating class */
                            expert_add_info(pinfo, channel_tree, &ei_nan_invalid_channel_num_for_op_class);
                        }

                        if (!number_of_chs || number_of_chs > PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN)
                        {
                            /* Number of channel should at least be one and should not exceed the maximum */
                            expert_add_info(pinfo, channel_tree, &ei_nan_invalid_channel_count);
                        }

                        uint8_t number_of_chs_max =
                            (number_of_chs + start_ch_number_idx < PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN) ?
                            (number_of_chs + start_ch_number_idx) : PACKET_WIFI_NAN_MAX_CHANNEL_SET_LEN;
                        for (uint8_t num_ch = start_ch_number_idx; num_ch < number_of_chs_max; num_ch++)
                        {
                            wmem_strbuf_append_printf(str, "%d ", channel_set_higher_op_class[num_ch]);
                        }
                    }
                    else
                    {
                        expert_add_info(pinfo, channel_tree, &ei_nan_unknown_op_class);
                    }
                    proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_start_channel_number, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_number_of_ch_included, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

                    proto_tree_add_string(channel_tree, hf_nan_attr_availability_entry_entries_channel_set, tvb, offset + 1, 2, wmem_strbuf_finalize(str));
                }
                proto_tree_add_item(channel_tree,
                    hf_nan_attr_availability_entry_entries_primary_channel_bitmap, tvb,
                    offset + 3, 1, ENC_LITTLE_ENDIAN);

                if (non_contiguous_bw == 1)
                {
                    proto_tree_add_item(channel_tree,
                        hf_nan_attr_availability_entry_entries_aux_channel_bitmap, tvb,
                        offset + 4, 2, ENC_LITTLE_ENDIAN);
                }
                offset += channel_entry_len;
                break;
            }
            }
        }
        dissected_len += entry_len + 2;
    }
}

static void
dissect_attr_ndc(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_NDC_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const ndc_ctr_fields[] = {
        &hf_nan_attr_ndc_ctrl_selected,
        NULL
    };

    static int* const ndc_map_id_fields[] = {
        &hf_nan_attr_ndc_map_id_related_sch,
        NULL
    };

    proto_tree_add_item(attr_tree, hf_nan_attr_ndc_id, tvb, offset + 3, 6, ENC_NA);
    proto_tree_add_bitmask(attr_tree, tvb, offset + 9, hf_nan_attr_ndc_ctrl,
        ett_ndc_ctr, ndc_ctr_fields, ENC_LITTLE_ENDIAN);

    offset += 10;
    int dissected_len = 7;
    while (dissected_len < attr_len)
    {
        uint8_t time_bitmap_len = tvb_get_uint8(tvb, offset + 3);
        proto_tree* entry_tree = proto_tree_add_subtree(attr_tree, tvb, offset,
            time_bitmap_len + 4, ett_ndc_entries, NULL, "Schedule Entry");
        proto_tree_add_bitmask(entry_tree, tvb, offset, hf_nan_map_id,
            ett_device_ndc_map_id, ndc_map_id_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(entry_tree, tvb, offset + 1,
            hf_nan_time_bitmap_ctrl, ett_time_bitmap_ctrl,
            time_bitmap_ctr_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(entry_tree, hf_nan_time_bitmap_len, tvb,
            offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(entry_tree, hf_nan_time_bitmap, tvb,
            offset + 4, time_bitmap_len, ENC_NA);

        offset += time_bitmap_len + 4;
        dissected_len += time_bitmap_len + 4;
    }
}

static void
dissect_attr_ndl(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_NDL_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;
    proto_tree_add_item(attr_tree, hf_nan_dialog_tokens, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    static int* const ndl_type_status_fields[] = {
        &hf_nan_attr_ndl_type,
        &hf_nan_status_1,
        NULL
    };
    static int* const ndl_control_fields[] = {
        &hf_nan_attr_ndl_ctrl_peer_id,
        &hf_nan_attr_ndl_ctrl_immutable_schedule_pres,
        &hf_nan_attr_ndl_ctrl_ndc_pres,
        &hf_nan_attr_ndl_ctrl_qos,
        &hf_nan_attr_ndl_ctrl_max_idle_pres,
        &hf_nan_attr_ndl_ctrl_type,
        &hf_nan_attr_ndl_ctrl_setup_reason,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_type_status,
        ett_type_status, ndl_type_status_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_reason_code, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_ndl_control,
        ett_ndl_control, ndl_control_fields, ENC_LITTLE_ENDIAN);

    uint8_t peer_id_pres = tvb_get_bits8(tvb, sub_offset * 8 + 7, 1);
    uint8_t immutable_sched_pres = tvb_get_bits8(tvb, sub_offset * 8 + 6, 1);
    uint8_t idle_per = tvb_get_bits8(tvb, sub_offset * 8 + 3, 1);
    sub_offset++;
    dissected_len += 4;

    if (peer_id_pres)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ndl_reserved_peer_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        dissected_len++;
    }
    if (idle_per)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ndl_max_idle, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
        sub_offset += 2;
        dissected_len += 2;
    }
    if (immutable_sched_pres)
    {
        char* info_msg = "Immutable Schedule entry list";
        proto_tree* sub_attr_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, attr_len - dissected_len,
            ett_ndl_schedule_entries, NULL, info_msg);
        while (dissected_len < attr_len)
        {
            proto_tree_add_item(sub_attr_tree, hf_nan_map_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
            sub_offset++;
            proto_tree_add_bitmask(sub_attr_tree, tvb, sub_offset, hf_nan_time_bitmap_ctrl, ett_time_bitmap_ctrl,
                time_bitmap_ctr_fields, ENC_LITTLE_ENDIAN);
            sub_offset += 2;
            unsigned field_length = tvb_get_uint8(tvb, sub_offset);
            proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap_len, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
            sub_offset++;
            proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap, tvb, sub_offset, field_length, ENC_NA);
            sub_offset += field_length;
            dissected_len += field_length + 4;
        }
    }
}

static void
dissect_attr_ndl_qos(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_NDL_QOS_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_attr_ndlqos_min_time_slots, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_attr_ndlqos_max_latency, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
}

static void
dissect_attr_unaligned_schedule(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_UNALIGNED_SCH_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;
    static int* const control_fields[] = {
        &hf_nan_attr_unaligned_sch_ctrl_schedule_id,
        &hf_nan_attr_unaligned_sch_ctrl_seq_id,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_unaligned_sch_ctrl,
        ett_unaligned_sch_ctrl, control_fields, ENC_LITTLE_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(attr_tree, hf_nan_attr_unaligned_sch_starting_time, tvb, sub_offset, 4, ENC_LITTLE_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(attr_tree, hf_nan_attr_unaligned_sch_duration, tvb, sub_offset, 4, ENC_LITTLE_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(attr_tree, hf_nan_attr_unaligned_sch_period, tvb, sub_offset, 4, ENC_LITTLE_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(attr_tree, hf_nan_attr_unaligned_sch_count_down, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    static int* const ulw_overwrite_fields[] = {
        &hf_nan_attr_unaligned_sch_ulw_overwrite_all,
        &hf_nan_attr_unaligned_sch_ulw_overwrite_map_id,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_unaligned_sch_ulw_overwrite,
        ett_unaligned_sch_ulw_overwrite, ulw_overwrite_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    dissected_len += 16;

    // ULW Control and Band ID or Channel Entry present
    if (dissected_len < attr_len)
    {
        static int* const ulw_control_fields[] = {
            &hf_nan_attr_unaligned_sch_ulw_ctrl_type,
            &hf_nan_attr_unaligned_sch_ulw_ctrl_channel_av,
            &hf_nan_attr_unaligned_sch_ulw_ctrl_rxnss,
            NULL
        };

        proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_unaligned_sch_ulw_ctrl,
            ett_unaligned_sch_ulw_ctrl, ulw_control_fields, ENC_LITTLE_ENDIAN);
        uint8_t entry_type = tvb_get_bits8(tvb, sub_offset * 8 + 6, 2);
        sub_offset++;

        switch (entry_type)
        {
        case NAN_UNALIGNED_SCH_BAND_ID_EXIST:
            proto_tree_add_item(attr_tree, hf_nan_attr_availability_entry_entries_band,
                tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
            sub_offset++;
            break;
        case NAN_UNALIGNED_SCH_CHANNEL_ENTRY_EXIST:
        {
            proto_tree* channel_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
                ett_availability_entry_entries_channel, NULL, "Channel Entry");
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_channel_op_class,
                tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
            sub_offset++;
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_channel_bitmap,
                tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
            sub_offset += 2;
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_primary_channel_bitmap,
                tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
            break;
        }
        case NAN_UNALIGNED_SCH_CHANNEL_ENTRY_W_AUX_EXIST:
        {
            proto_tree* channel_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
                ett_availability_entry_entries_channel, NULL, "Channel Entry");
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_channel_op_class,
                tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
            sub_offset++;
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_channel_bitmap,
                tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
            sub_offset += 2;
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_primary_channel_bitmap,
                tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
            sub_offset++;
            proto_tree_add_item(channel_tree, hf_nan_attr_availability_entry_entries_aux_channel_bitmap,
                tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
        }
    }
}

static void
dissect_attr_ranging_info(proto_tree* attr_tree, tvbuff_t* tvb, int offset)
{
    unsigned sub_offset = offset + 3;
    static int* const location_info_availability_fields[] = {
        &hf_nan_attr_ranging_info_location_info_avail_lci,
        &hf_nan_attr_ranging_info_location_info_avail_geospatial,
        &hf_nan_attr_ranging_info_location_info_avail_civic_location,
        &hf_nan_attr_ranging_info_location_info_avail_last_movement_pres,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_ranging_info_location_info_avail,
        ett_ranging_info_location_info_availability, location_info_availability_fields, ENC_LITTLE_ENDIAN);
    bool loc_exists = tvb_get_bits8(tvb, sub_offset * 8 + 4, 1);
    sub_offset++;
    if (loc_exists)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_ranging_info_last_movement_indication, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_attr_ranging_setup(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_RANGING_SETUP_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;
    proto_tree_add_item(attr_tree, hf_nan_dialog_tokens, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    static int* const ranging_setup_type_status_fields[] = {
        &hf_nan_attr_ranging_setup_type,
        &hf_nan_status_2,
        NULL
    };
    static int* const ranging_setup_ctrl_fields[] = {
        &hf_nan_attr_ranging_setup_ctrl_report_req,
        &hf_nan_attr_ranging_setup_ctrl_ftm_params,
        &hf_nan_attr_ranging_setup_ctrl_entry_list,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_type_status,
        ett_type_status, ranging_setup_type_status_fields, ENC_LITTLE_ENDIAN);
    sub_offset++;
    proto_tree_add_item(attr_tree, hf_nan_reason_code, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_ranging_setup_ctrl,
        ett_ranging_setup_ctrl, ranging_setup_ctrl_fields, ENC_LITTLE_ENDIAN);
    uint8_t ftm_check = tvb_get_bits8(tvb, sub_offset * 8 + 6, 1);
    uint8_t ranging_entry_check = tvb_get_bits8(tvb, sub_offset * 8 + 5, 1);
    sub_offset++;
    dissected_len += 4;

    if (ftm_check)
    {
        static int* const ranging_setup_ftm_param_fields[] = {
            &hf_nan_attr_ranging_setup_ftm_max_burst_duration,
            &hf_nan_attr_ranging_setup_ftm_min_delta,
            &hf_nan_attr_ranging_setup_ftm_max_per_burst,
            &hf_nan_attr_ranging_setup_ftm_format_bw,
            NULL
        };

        proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_ranging_setup_ftm_params,
            ett_ranging_setup_ftm_params, ranging_setup_ftm_param_fields, ENC_LITTLE_ENDIAN);
        sub_offset += 3;
        dissected_len += 3;
    }
    if (ranging_entry_check)
    {
        char* info_msg = "Ranging Schedule Entry List";
        proto_tree* sub_attr_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, attr_len - dissected_len,
            ett_ranging_setup_schedule_entries, NULL, info_msg);

        while (dissected_len < attr_len)
        {
            proto_tree_add_item(sub_attr_tree, hf_nan_map_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
            sub_offset++;
            proto_tree_add_bitmask(sub_attr_tree, tvb, sub_offset, hf_nan_time_bitmap_ctrl, ett_time_bitmap_ctrl,
                time_bitmap_ctr_fields, ENC_LITTLE_ENDIAN);
            sub_offset += 2;
            unsigned field_length = tvb_get_uint8(tvb, sub_offset);
            proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap_len, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
            sub_offset++;
            proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap, tvb, sub_offset, field_length, ENC_NA);
            sub_offset += field_length;
            dissected_len += field_length + 4;
        }
    }
}

static void
dissect_attr_ftm_report(proto_tree* attr_tree, tvbuff_t* tvb, int offset)
{
    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_attr_ftm_range_report, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_element_container(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    unsigned sub_offset = offset + 3;

    // Some header fields and trees are reused.
    static int* const container_map_id_fields[] = {
        &hf_nan_attr_device_cap_map_id_apply_to,
        &hf_nan_attr_device_cap_map_id_associated_maps,
        NULL
    };
    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_map_id,
        ett_device_cap_map_id, container_map_id_fields, ENC_LITTLE_ENDIAN);
    sub_offset += 1;
    unsigned dissected_length = 1;
    proto_tree* sub_tree;
    while (dissected_length < attr_len)
    {
        unsigned element_id = tvb_get_uint8(tvb, sub_offset);
        unsigned element_len = tvb_get_uint8(tvb, sub_offset + 1);
        const char* msg = val_to_str(element_id, ie_tag_num_vals, "Unknown element ID (%u)");

        sub_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, element_len + 2, ett_ie_tree, NULL, msg);
        proto_tree_add_item(sub_tree, hf_nan_attr_container_element_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_item(sub_tree, hf_nan_attr_container_element_len, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;

        ieee80211_tagged_field_data_t field_data = { 0 };
        tvbuff_t* ie_tvb = tvb_new_subset_length(tvb, sub_offset, element_len);
        field_data.item_tag = sub_tree;
        dissector_try_uint_new(ie_handle_table, element_id, ie_tvb, pinfo, sub_tree, true, &field_data);
        sub_offset += element_len;
        dissected_length += element_len + 2;
    }
}

static void
dissect_attr_extended_wlan_infra(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_EXTENDED_WLAN_INFRA_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_bss_id, tvb, sub_offset, 6, ENC_LITTLE_ENDIAN);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_attr_wlan_infra_device_role, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset += 1;

    char* info_msg = "Non-NAN Operating Channel Information";
    proto_tree* sub_attr_tree_op = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 3,
        ett_non_nan_op_channel, NULL, info_msg);
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_global_op_class, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_channel, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_center_freq, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    char* info_msg_beacon = "Non-NAN Beacon Information";
    proto_tree* sub_attr_tree_beacon = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
        ett_non_nan_beacon, NULL, info_msg_beacon);
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_tbtt_offset, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_interval, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    // sub_offset += 2;
}

static void
dissect_attr_extended_p2p_operation(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_EXTENDED_P2P_OP_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    static int* const ext_p2p_bitmap_fields[] = {
        &hf_nan_attr_p2p_device_role_device,
        &hf_nan_attr_p2p_device_role_group_owner,
        &hf_nan_attr_p2p_device_role_client,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, sub_offset, hf_nan_attr_p2p_device_role,
        ett_p2p_device_role, ext_p2p_bitmap_fields, ENC_LITTLE_ENDIAN);
    sub_offset += 1;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;

    char* info_msg = "Non-NAN Operating Channel Information";
    proto_tree* sub_attr_tree_op = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 3,
        ett_non_nan_op_channel, NULL, info_msg);
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_global_op_class, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_channel, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_center_freq, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    char* info_msg_beacon = "Non-NAN Beacon Information";
    proto_tree* sub_attr_tree_beacon = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
        ett_non_nan_beacon, NULL, info_msg_beacon);
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_tbtt_offset, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_interval, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    // sub_offset += 2;
}

static void
dissect_attr_extended_ibss(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len != NAN_EXTENDED_IBSS_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_bss_id, tvb, sub_offset, 6, ENC_LITTLE_ENDIAN);
    sub_offset += 6;
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;

    char* info_msg = "Non-NAN Operating Channel Information";
    proto_tree* sub_attr_tree_op = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 3,
        ett_non_nan_op_channel, NULL, info_msg);
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_global_op_class, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_channel, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_center_freq, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    char* info_msg_beacon = "Non-NAN Beacon Information";
    proto_tree* sub_attr_tree_beacon = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
        ett_non_nan_beacon, NULL, info_msg_beacon);
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_tbtt_offset, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_interval, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    // sub_offset += 2;
}

static void
dissect_attr_extended_mesh(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_EXTENDED_MESH_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned length = tvb_get_uint16(tvb, sub_offset - 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(attr_tree, hf_nan_mac_address, tvb, sub_offset, 6, ENC_NA);
    sub_offset += 6;

    char* info_msg = "Non-NAN Operating Channel Information";
    proto_tree* sub_attr_tree_op = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 3,
        ett_non_nan_op_channel, NULL, info_msg);
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_global_op_class, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_channel, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;
    proto_tree_add_item(sub_attr_tree_op, hf_nan_non_op_channel_center_freq, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset++;

    char* info_msg_beacon = "Non-NAN Beacon Information";
    proto_tree* sub_attr_tree_beacon = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 4,
        ett_non_nan_beacon, NULL, info_msg_beacon);
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_tbtt_offset, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_attr_tree_beacon, hf_nan_non_beacon_interval, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
    sub_offset += 2;

    proto_tree_add_item(attr_tree, hf_nan_attr_mesh_id, tvb, sub_offset, length - sub_offset + 3, ENC_NA);
}

static void
dissect_attr_cipher_suite_info(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_CIPHER_SUITE_INFO_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;

    proto_tree* caps_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, 1, ett_nan_cipher_suite_capabilities, NULL, "Capabilities");
    proto_tree_add_item(caps_tree, hf_nan_attr_cipher_suite_capabilities_ndtksa_nmtksa_replay_counters, tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(caps_tree, hf_nan_attr_cipher_suite_capabilities_gtksa_igtksa_bigtksa_support, tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(caps_tree, hf_nan_attr_cipher_suite_capabilities_gtksa_replay_counters, tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(caps_tree, hf_nan_attr_cipher_suite_capabilities_igtksa_bigtksa_cipher, tvb, sub_offset, 1, ENC_LITTLE_ENDIAN);

    sub_offset++;
    dissected_len++;

    char* info_msg = "Cipher Suite List";
    proto_tree* sub_attr_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, attr_len - dissected_len,
        ett_cipher_suite_info_list, NULL, info_msg);

    while (dissected_len < attr_len)
    {
        proto_tree_add_item(sub_attr_tree, hf_nan_attr_cipher_suite_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_item(sub_attr_tree, hf_nan_publish_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        dissected_len += 2;
    }
}

static void
dissect_attr_security_context_info(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_CIPHER_SUITE_INFO_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;

    while (dissected_len < attr_len)
    {
        unsigned field_length = tvb_get_uint16(tvb, sub_offset, ENC_LITTLE_ENDIAN);
        proto_item* sub_attr_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, field_length + 4,
            ett_attributes, NULL, "Security Context Identifier");
        proto_tree_add_item(sub_attr_tree, hf_nan_attr_security_context_identifier_len, tvb, sub_offset, 2, ENC_LITTLE_ENDIAN);
        sub_offset += 2;
        proto_tree_add_item(sub_attr_tree, hf_nan_attr_security_context_identifier_type, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_item(sub_attr_tree, hf_nan_publish_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_item(sub_attr_tree, hf_nan_attr_security_context_identifier, tvb, sub_offset, field_length, ENC_NA);
        sub_offset += field_length;
        dissected_len += field_length + 4;
    }
}

static void
dissect_attr_shared_key_descriptor(proto_tree* attr_tree, tvbuff_t* tvb, int offset)
{
    unsigned sub_offset = offset + 3;
    proto_tree_add_item(attr_tree, hf_nan_publish_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset += 1;
    proto_tree_add_item(attr_tree, hf_nan_attr_shared_key_rsna_descriptor, tvb, sub_offset, -1, ENC_NA);
}

static void
dissect_attr_public_availability(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_PUBLIC_AVAIL_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    unsigned dissected_len = 0;

    proto_tree* sub_attr_tree = proto_tree_add_subtree(attr_tree, tvb, sub_offset, attr_len,
        ett_public_availability_sch_entries, NULL, "Public Availability Schedule Entry List");
    while (dissected_len < attr_len)
    {
        proto_tree_add_item(sub_attr_tree, hf_nan_map_id, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_bitmask(sub_attr_tree, tvb, sub_offset, hf_nan_time_bitmap_ctrl, ett_time_bitmap_ctrl,
            time_bitmap_ctr_fields, ENC_LITTLE_ENDIAN);
        sub_offset += 2;
        unsigned field_length = tvb_get_uint8(tvb, sub_offset);
        proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap_len, tvb, sub_offset, 1, ENC_BIG_ENDIAN);
        sub_offset++;
        proto_tree_add_item(sub_attr_tree, hf_nan_time_bitmap, tvb, sub_offset, field_length, ENC_NA);
        sub_offset += field_length;
        dissected_len += field_length + 4;
    }
}

static void
dissect_attr_vendor_specific(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_VENDOR_SPECIFIC_MIN_LENGTH)
    {
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    unsigned sub_offset = offset + 3;
    tvbuff_t* ie_tvb = tvb_new_subset_length(tvb, sub_offset, -1);
    ieee80211_tagged_field_data_t field_data = { 0 };
    field_data.item_tag = attr_tree;
    dissector_try_uint_new(ie_handle_table, TAG_VENDOR_SPECIFIC_IE, ie_tvb, pinfo, attr_tree, true, &field_data);
}

static void
dissect_attr_device_capability_extension(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_DEVICE_CAPABILITY_EXTENSION_MIN_LENGTH)
    {
        /* At least has 9 bits defined in NAN-R4 spec  */
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    static int* const capability_info_fields[] = {
        &hf_nan_attr_device_capability_extension_6g_regulatory_info_presented,
        &hf_nan_attr_device_capability_extension_6g_regulatory_info,
        &hf_nan_attr_device_capability_extension_6g_regulatory_info_reserved,
        &hf_nan_attr_device_capability_extension_paring_setup_enabled,
        &hf_nan_attr_device_capability_extension_npk_nik_cache_enabled,
        NULL
    };

    proto_tree_add_bitmask(attr_tree, tvb, offset + 3, hf_nan_attr_device_capability_extension,
        ett_device_capability_extension, capability_info_fields, ENC_LITTLE_ENDIAN);
}

static void
dissect_attr_nan_identity_resolution(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_IDENTITY_RESOLUTION_MIN_LEN)
    {
        /* At least 1 byte: Cipher version  */
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }

    proto_tree_add_item(attr_tree, hf_nan_attr_identity_cipher_version, tvb,
            offset + 3, 1, ENC_LITTLE_ENDIAN);

    uint8_t cipher_version = tvb_get_uint8(tvb, offset + 3);
    switch (cipher_version)
    {
    case 0:
        proto_tree_add_item(attr_tree, hf_nan_attr_identity_resolution_nonce, tvb,
            offset + 4, 8, ENC_NA);
        proto_tree_add_item(attr_tree, hf_nan_attr_identity_resolution_tag, tvb,
            offset + 12, 8, ENC_NA);
        break;
    default:
        proto_tree_add_item(attr_tree, hf_nan_attr_reserved, tvb,
            offset + 3, attr_len - 1, ENC_NA);
    }
}

static void
dissect_attr_nan_pairing_bootstrapping(proto_tree* attr_tree, tvbuff_t* tvb, int offset, uint16_t attr_len, packet_info* pinfo)
{
    if (attr_len < NAN_PAIRING_BOOTSTRAPPING_LEN)
    {
        /* At least 5 bytes: Dialog Token(1) + Type and Status(1) + Reason Code(1) + Pairing Bootstrapping Method(2) */
        expert_add_info(pinfo, attr_tree, &ei_nan_elem_len_invalid);
        return;
    }
    int npba_local_offset = offset + 3;

    /* Dialog Token */
    proto_tree_add_item(attr_tree, hf_nan_attr_pairing_bootstrapping_dialog_token, tvb,
            npba_local_offset, 1, ENC_LITTLE_ENDIAN);
    npba_local_offset += 1;

    /* Type and Status */
    uint8_t type_status = tvb_get_uint8(tvb, npba_local_offset);
    uint8_t type = type_status & 0x0f;
    uint8_t status = (type_status & 0xf0) >> 4;

    static int* const type_and_status_fields[] = {
        &hf_nan_attr_pairing_bootstrapping_type,
        &hf_nan_attr_pairing_bootstrapping_status,
        NULL
    };
    proto_tree_add_bitmask(attr_tree, tvb, npba_local_offset, hf_nan_attr_pairing_bootstrapping_type_status,
        ett_nan_pairing_bootstrapping_type_status, type_and_status_fields, ENC_LITTLE_ENDIAN);
    npba_local_offset += 1;

    /* Resaon code
     * Indicate the reject reason when Type = 2 (Response) and Status = 1 (Rejected); otherwise, reserved */
    if ((type == 2) && (status == 1))
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_pairing_bootstrapping_resaon_code, tvb,
            npba_local_offset, 1, ENC_LITTLE_ENDIAN);
    }
    else
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_reserved, tvb,
            npba_local_offset, 1, ENC_NA);
    }
    npba_local_offset += 1;

    /* Comeback, if any. Presetned if,
     * a) type is 2 and status is 2, or
     * b) type is 1 and status is 2, and cookie is requried (based on attribute length)
     */
    bool comeback_presented = (attr_len > NAN_PAIRING_BOOTSTRAPPING_LEN);

    bool comeback_after_presented = comeback_presented && ((type == 2) && (status == 2));

    if (comeback_after_presented)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_pairing_bootstrapping_comeback_after, tvb,
            npba_local_offset, 2, ENC_LITTLE_ENDIAN);
        npba_local_offset += 2;
    }

    if (comeback_presented)
    {
        uint8_t cookie_len = tvb_get_uint8(tvb, npba_local_offset);
        proto_tree_add_item(attr_tree, hf_nan_attr_pairing_bootstrapping_comeback_cookie_len, tvb,
            npba_local_offset, 1, ENC_LITTLE_ENDIAN);
        npba_local_offset += 1;

        if (cookie_len)
        {
            proto_tree_add_item(attr_tree, hf_nan_attr_pairing_bootstrapping_comeback_cookie, tvb,
                npba_local_offset, cookie_len, ENC_NA);
            npba_local_offset += cookie_len;
        }
    }

    /* Pairing Bootstrapping Method */
    static int* const pairing_bootstrapping_method[] = {
        &hf_nan_attr_pairing_bootstrapping_method_opportunistic_bootstrapping,
        &hf_nan_attr_pairing_bootstrapping_method_pin_code_display,
        &hf_nan_attr_pairing_bootstrapping_method_passphrase_display,
        &hf_nan_attr_pairing_bootstrapping_method_qr_code_display,
        &hf_nan_attr_pairing_bootstrapping_method_nfc_tag,
        &hf_nan_attr_pairing_bootstrapping_method_keypad_pin_code_only,
        &hf_nan_attr_pairing_bootstrapping_method_keypad_passphrase,
        &hf_nan_attr_pairing_bootstrapping_method_qr_code_scan,
        &hf_nan_attr_pairing_bootstrapping_method_nfc_reader,
        &hf_nan_attr_pairing_bootstrapping_method_reserved,
        &hf_nan_attr_pairing_bootstrapping_method_service_managed_bootstrapping,
        &hf_nan_attr_pairing_bootstrapping_method_bootstrapping_handshakes_skipped,
        NULL
    };
    if (type == 2 && status)
    {
        proto_tree_add_item(attr_tree, hf_nan_attr_reserved, tvb,
            npba_local_offset, 2, ENC_NA);
    }
    else
    {
        proto_tree_add_bitmask(attr_tree, tvb, npba_local_offset, hf_nan_attr_pairing_bootstrapping_methods,
            ett_nan_pairing_bootstrapping_method, pairing_bootstrapping_method, ENC_LITTLE_ENDIAN);
    }
}

static void
find_attribute_field(proto_tree* nan_tree, tvbuff_t* tvb, unsigned tvb_len, unsigned* offset, packet_info* pinfo)
{
    if ((tvb_len - *offset) < 3)
    {
        proto_tree_add_expert_format(nan_tree, pinfo, &ei_nan_elem_len_invalid, tvb, *offset, -1,
            "Insufficient remaining packet bytes for NAN attribute");
        *offset = tvb_len;
        return;
    }

    int attr_id = tvb_get_uint8(tvb, *offset);
    uint16_t attr_len = tvb_get_letohs(tvb, *offset + 1);

    if ((*offset + 3 + attr_len) > tvb_len)
    {
        proto_tree_add_expert_format(nan_tree, pinfo, &ei_nan_elem_len_invalid, tvb, *offset, -1,
            "Attribute length (%u) exceeds remaining packet length. Attribute id: %u", attr_len, attr_id);
        *offset = tvb_len;
        return;
    }

    proto_tree* attr_tree = proto_tree_add_subtree(nan_tree, tvb, *offset, attr_len + 3,
        ett_attributes, NULL, val_to_str(attr_id, attribute_types, "Unknown attribute ID (%u)"));

    proto_tree_add_item(attr_tree, hf_nan_attribute_type, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(attr_tree, hf_nan_attribute_len, tvb, *offset + 1, 2, ENC_LITTLE_ENDIAN);

    switch (attr_id) {
    case NAN_ATTR_SERVICE_DESCRIPTOR:
        dissect_attr_sda(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_MASTER_INDICATION:
        dissect_attr_master_indication(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_CLUSTER:
        dissect_attr_cluster(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_CIPHER_SUITE_INFO:
        dissect_attr_cipher_suite_info(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_SECURITY_CONTEXT_INFO:
        dissect_attr_security_context_info(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_SHARED_KEY_DESCRIPTOR:
        dissect_attr_shared_key_descriptor(attr_tree, tvb, *offset);
        break;
    case NAN_ATTR_PUBLIC_AVAILABILITY:
        dissect_attr_public_availability(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_ELEMENT_CONTAINER:
        dissect_attr_element_container(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_FTM_RANGING_REPORT:
        dissect_attr_ftm_report(attr_tree, tvb, *offset);
        break;
    case NAN_ATTR_RANGING_SETUP:
        dissect_attr_ranging_setup(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_RANGING_INFORMATION:
        dissect_attr_ranging_info(attr_tree, tvb, *offset);
        break;
    case NAN_ATTR_UNALIGNED_SCHEDULE:
        dissect_attr_unaligned_schedule(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_NDL_QOS:
        dissect_attr_ndl_qos(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_EXTENDED_WLAN_INFRA:
        dissect_attr_extended_wlan_infra(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_EXTENDED_P2P_OPERATION:
        dissect_attr_extended_p2p_operation(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_EXTENDED_IBSS:
        dissect_attr_extended_ibss(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_EXTENDED_MESH:
        dissect_attr_extended_mesh(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_CONNECTION_CAPABILITY:
        dissect_attr_connection_capability(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_CLUSTER_DISCOVERY:
        dissect_attr_cluter_discovery(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_RANGING:
        dissect_attr_ranging(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_COUNTRY_CODE:
        dissect_attr_country_code(attr_tree, tvb, *offset);
        break;
    case NAN_ATTR_FURTHER_AVAILABILITY_MAP:
        dissect_attr_further_availability_map(attr_tree, tvb, *offset);
        break;
    case NAN_ATTR_FURTHER_SERVICE_DISCOVERY:
        dissect_attr_further_service_discovery(attr_tree, tvb, *offset, attr_len);
        break;
    case NAN_ATTR_MESH:
        dissect_attr_mesh(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_IBSS:
        dissect_attr_ibss(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_P2P_OPERATION:
        dissect_attr_p2p_operation(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_WLAN_INFRA:
        dissect_attr_wlan_infra(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_NDP:
        dissect_attr_ndp(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_NDP_EXTENSION:
        dissect_attr_ndpe(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_SERVICE_DESCRIPTOR_EXTENSION:
        dissect_attr_sdea(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_DEVICE_CAPABILITY:
        dissect_attr_device_capability(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_AVAILABILITY:
        dissect_attr_availability(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_NDC:
        dissect_attr_ndc(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_SERVICE_ID_LIST:
    case NAN_ATTR_SUBSCRIBE_SERVICE_ID_LIST:
        dissect_attr_service_id_list(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_VENDOR_SPECIFIC:
        dissect_attr_vendor_specific(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_NDL:
        dissect_attr_ndl(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_DEVICE_CAPABILITY_EXTENSION:
        dissect_attr_device_capability_extension(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_IDENTITY_RESOLUTION:
        dissect_attr_nan_identity_resolution(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    case NAN_ATTR_PAIRING_BOOTSTRAPPING:
        dissect_attr_nan_pairing_bootstrapping(attr_tree, tvb, *offset, attr_len, pinfo);
        break;
    default:
        expert_add_info(pinfo, attr_tree, &ei_nan_unknown_attr_id);
    }

    *offset += attr_len + 3;
}

static int
dissect_nan_beacon(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NAN");

    //
    // Workaround to identify NAN Discovery vs Synchronization beacon frames.
    //
    // We have to determine the beacon interval, but there is, unfortunately,
    // no mechanism by which a subdissector can request that an arbitrary
    // field value be provided to it by the calling dissector, so we can't
    // just ask for "wlan.fixed.beacon".
    //
    // Fortunately, we are currently putting the Discovery vs. Sync information
    // only in the Info column, and the beacon interval is put at the end
    // of the Info column, as "BI={interval}", by the 802.11 dissector, so
    // we can just fetch the Info column string and, if it's present, extract
    // that value.
    //
    // An interval of 100, meaning .1024 seconds, means it's a Discovery
    // beacon, and an interval of 512, meaning .524288 seconds, means
    // it's a Sync beacon.
    //
    const char* info_text = col_get_text(pinfo->cinfo, COL_INFO);
    if (info_text != NULL && g_str_has_suffix(info_text, "100"))
    {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "Discovery ");
    }
    else if (info_text != NULL && g_str_has_suffix(info_text, "512"))
    {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "Sync ");
    }
    else
    {
        expert_add_info(pinfo, tree, &ei_nan_unknown_beacon_type);
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "[Unknown] ");
    }

    proto_item* ti = proto_tree_add_item(tree, proto_nan, tvb, 0, -1, ENC_NA);
    proto_tree* nan_tree = proto_item_add_subtree(ti, ett_nan);

    unsigned tvb_len = tvb_reported_length(tvb);
    while (offset < tvb_len)
    {
        find_attribute_field(nan_tree, tvb, tvb_len, &offset, pinfo);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_nan_action(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NAN");

    proto_tree* upper_tree = proto_tree_get_parent_tree(tree);
    proto_item* ti = proto_tree_add_item(upper_tree, proto_nan, tvb, 0, -1, ENC_NA);
    proto_tree* nan_tree = proto_item_add_subtree(ti, ett_nan);

    uint8_t subtype = tvb_get_uint8(tvb, offset);
    const char* subtype_text = rval_to_str(subtype, action_frame_type_values, "Unknown type (%u)");
    proto_item_set_text(ti, "%s", subtype_text);
    proto_tree_add_item(nan_tree, hf_nan_action_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s", subtype_text);
    offset++;

    unsigned tvb_len = tvb_reported_length(tvb);
    while (offset < tvb_len)
    {
        find_attribute_field(nan_tree, tvb, tvb_len, &offset, pinfo);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_nan_service_discovery(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    unsigned offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NAN");
    proto_item* ti = proto_tree_add_item(tree, proto_nan, tvb, 0, -1, ENC_NA);
    proto_tree* nan_tree = proto_item_add_subtree(ti, ett_nan);

    unsigned tvb_len = tvb_reported_length(tvb);
    while (offset < tvb_len)
    {
        find_attribute_field(nan_tree, tvb, tvb_len, &offset, pinfo);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_nan(void)
{
    static hf_register_info hf[] = {
        { &hf_nan_attribute_type,
            {
            "Attribute Type",
            "wifi_nan.attribute.type",
            FT_UINT8, BASE_DEC, VALS(attribute_types), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attribute_len,
            {
            "Attribute Length",
            "wifi_nan.attribute.len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_action_subtype,
            {
            "Subtype",
            "wifi_nan.action.subtype",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(action_frame_type_values), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_instance_id,
            {
            "Instance ID",
            "wifi_nan.instance_id",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_service_id,
            {
            "Service ID",
            "wifi_nan.service_id",
            FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_map_id,
            {
            "Map ID",
            "wifi_nan.map_id",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_oui,
            {
            "OUI",
            "wifi_nan.oui",
            FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_type_status,
            {
            "Type and Status",
            "wifi_nan.type_status",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_reason_code,
            {
            "Reason Code",
            "wifi_nan.reason_code",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(reason_code_values), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_status_1,
             {
             "Status",
             "wifi_nan.status",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(status_type1_values), 0xF0, NULL, HFILL
             }
        },
        { &hf_nan_status_2,
             {
             "Status",
             "wifi_nan.status",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(status_type2_values), 0xF0, NULL, HFILL
             }
        },
        { &hf_nan_bss_id,
            {
            "BSS ID",
            "wifi_nan.bss_id",
            FT_UINT48, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_availability_intervals_bitmap,
             {
             "Availability Intervals Bitmap",
             "wifi_nan.availability_intervals_bitmap",
             FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_mac_address,
            {
            "MAC Address",
            "wifi_nan.mac_address",
            FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_publish_id,
            {
            "Publish ID",
            "wifi_nan.publish_id",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_dialog_tokens,
            {
            "Dialog Token",
            "wifi_nan.dialog_token",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap,
            {
            "Time Bitmap",
            "wifi_nan.time_bitmap",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap_len,
            {
            "Time Bitmap Length",
            "wifi_nan.time_bitmap.len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap_ctrl,
            {
            "Time Bitmap Control",
            "wifi_nan.time_bitmap.ctrl",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap_ctrl_bit_duration,
            {
            "Bit Duration",
            "wifi_nan.time_bitmap.ctrl.bit_duration",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(availability_entry_time_bitmap_ctr_bit_duration_type),
            0x0007, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap_ctrl_period,
            {
            "Period",
            "wifi_nan.time_bitmap.ctrl.period",
            FT_UINT16, BASE_DEC, VALS(availability_entry_time_bitmap_ctr_period_type),
            0x0038, NULL, HFILL
            }
        },
        { &hf_nan_time_bitmap_ctrl_start_offset,
            {
            "Start Offset",
            "wifi_nan.time_bitmap.ctrl.start_offset",
            FT_UINT16, BASE_DEC, NULL, 0x7FC0, NULL, HFILL
            }
        },
        { &hf_nan_map_ctrl_map_id,
             {
             "Map ID",
             "wifi_nan.map_ctrl.map_id",
             FT_UINT8, BASE_HEX_DEC, NULL, 0xF, NULL, HFILL
             }
        },
        { &hf_nan_map_ctrl_availability_interval_duration,
             {
             "Availability Interval Duration",
             "wifi_nan.map_ctrl.interval_duration",
             FT_UINT8, BASE_DEC, VALS(map_ctrl_availability_interval_duration), 0x30, NULL, HFILL
             }
        },
        { &hf_nan_map_ctrl_repeat,
             {
             "Repeat",
             "wifi_nan.map_ctrl.repeat",
             FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL
             }
        },
        { &hf_nan_map_ctrl_field,
             {
             "Map Control",
             "wifi_nan.map_ctrl",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_non_op_channel_global_op_class,
            {
            "Global Operation Class",
            "wifi_nan.non_op_channel.global_op_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_non_op_channel_channel,
            {
            "Channel",
            "wifi_nan.non_op_channel.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_non_op_channel_center_freq,
            {
            "Channel Center Frequency",
            "wifi_nan.non_op_channel.center_freq",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_non_beacon_tbtt_offset,
            {
            "TBTT Offset",
            "wifi_nan.non_beacon.tbtt_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_non_beacon_interval,
            {
            "Beacon Interval",
            "wifi_nan.non_beacon.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_master_preference,
            {
            "Master Preference",
            "wifi_nan.master_indication.preference",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_master_random_factor,
            {
            "Random Factor",
            "wifi_nan.master_indication.random_factor",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_cluster_anchor_master_rank,
            {
            "Anchor Master Rank",
            "wifi_nan.cluster.anchor_master_rank",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_cluster_hop_count,
            {
            "Hop Count to Anchor Master",
            "wifi_nan.cluster.hop_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_cluster_beacon_transmission_time,
            {
            "Anchor Master Beacon Transmission Time",
            "wifi_nan.cluster.beacon_transmission_time",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_requestor_instance_id,
            {
            "Requestor Instance ID",
            "wifi_nan.sda.requestor_instance_id",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc,
            {
            "Service Control",
            "wifi_nan.sda.sc",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_type,
            {
            "Service Control Type",
            "wifi_nan.sda.sc.type",
            FT_UINT8, BASE_HEX, VALS(service_ctr_type), 0x03, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_matching_filter,
            {
            "Matching Filter Present",
            "wifi_nan.sda.sc.matching_filter",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_service_response,
            {
            "Service Response Filter Present",
            "wifi_nan.sda.sc.service_response",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_service_info,
            {
            "Service Info Present",
            "wifi_nan.sda.sc.service_info",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_discovery_range,
            {
            "Discovery Range Limited",
            "wifi_nan.sda.sc.discovery_range",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_sc_binding_bitmap,
            {
            "Binding Bitmap Present",
            "wifi_nan.sda.sc.binding_bitmap",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_binding_bitmap,
            {
            "Binding Bitmap",
            "wifi_nan.sda.binding_bitmap",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_matching_filter_len,
            {
            "Matching Filter Length",
            "wifi_nan.sda.matching_filter_len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_matching_filter_val,
            {
            "Matching Filter Value",
            "wifi_nan.sda.matching_filter_val",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_service_response_filter_len,
            {
            "Service Response Filter Length",
            "wifi_nan.sda.service_response_filter_len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_srf_ctr,
            {
            "SRF Control",
            "wifi_nan.sda.srf_ctr",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_srf_ctr_type,
            {
            "SRF Type",
            "wifi_nan.sda.srf_type",
            FT_BOOLEAN, 8, TFS(&srf_type_flags), 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_srf_ctr_include,
            {
            "Include",
            "wifi_nan.sda.srf_include",
            FT_BOOLEAN, 8, TFS(&srf_include_flags), 0x02, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_srf_ctr_bloom_filter_index,
            {
            "Bloom Filter Index",
            "wifi_nan.sda.srf_bloom_filter_index",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x0C, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_srf_address_set,
            {
            "Address Set",
            "wifi_nan.sda.srf_address_set",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_service_info_len,
            {
            "Service Info Length",
            "wifi_nan.sda.service_info_len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sda_service_info,
            {
            "Service Info",
            "wifi_nan.sda.service_info",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr,
            {
            "SDEA Control",
            "wifi_nan.sdea.ctr",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_fsd,
            {
            "FSD Required",
            "wifi_nan.sdea.ctr_fsd",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_fsd_w_gas,
            {
            "FSD with GAS",
            "wifi_nan.sdea.ctr_fsd_w_gas",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_data_path,
            {
            "Data Path Required",
            "wifi_nan.sdea.ctr_data_path",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_data_path_type,
            {
            "Data Path Type",
            "wifi_nan.sdea.ctr_data_path_type",
            FT_BOOLEAN, 16, TFS(&sdea_ctr_data_path_type_flags), 0x0008, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_reserved_multicast_type,
            {
            "Reserved (Multicast Type)",
            "wifi_nan.sdea.ctr_reserved_multicast_type",
            FT_BOOLEAN, 16, TFS(&sdea_ctr_reserved_multicast_type_flags), 0x0010, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_qos,
            {
            "QoS Required",
            "wifi_nan.sdea.ctr_qos",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_security,
            {
            "Security Required",
            "wifi_nan.sdea.ctr_security",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_ranging,
            {
            "Ranging Required",
            "wifi_nan.sdea.ctr_ranging",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_range_limit,
            {
            "Range Limit Present",
            "wifi_nan.sdea.ctr_range_limit",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ctr_service_update_indicator,
            {
            "Service Update Indicator Present",
            "wifi_nan.sdea.ctr_service_update_indicator",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_ingress_range_limit,
            {
            "Ingress Range Limit",
            "wifi_nan.sdea.range_limit_ingress",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_egress_range_limit,
            {
            "Egress Range Limit",
            "wifi_nan.sdea.range_limit_egress",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_service_update_indicator,
            {
            "Service Update Indicator",
            "wifi_nan.sdea.service_update_indicator",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_service_info_length,
            {
            "Service Info Length",
            "wifi_nan.sdea.service_info_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_service_info_protocol_type,
            {
            "Service Protocol Type",
            "wifi_nan.sdea.service_info_protocol_type",
            FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(service_info_protocol_type), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_sdea_service_info_specific,
            {
            "Service Specific info",
            "wifi_nan.sdea.service_info_specific",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_connection_cap_bitmap,
             {
             "Connection Capability Bitmap",
             "wifi_nan.connection_cap.bitmap",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_wifi_direct,
             {
             "Wifi Direct",
             "wifi_nan.connection_cap.wifi_direct",
             FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_p2ps,
             {
             "P2Ps",
             "wifi_nan.connection_cap.p2ps",
             FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_tdls,
             {
             "TDLS",
             "wifi_nan.connection_cap.tdls",
             FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_wlan_infra,
             {
             "WLAN Infrastructure",
             "wifi_nan.connection_cap.wlan_infra",
             FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_ibss,
             {
             "IBSS",
             "wifi_nan.connection_cap.ibss",
             FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL
             }
        },
        { &hf_nan_attr_connection_cap_mesh,
             {
             "Mesh",
             "wifi_nan.connection_cap.mesh",
             FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL
             }
        },
        { &hf_nan_attr_wlan_infra_device_role,
            {
            "Device Role",
            "wifi_nan.wlan_infra.device_role",
            FT_UINT8, BASE_DEC, VALS(device_role), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_p2p_device_role_device,
             {
             "P2P Device",
             "wifi_nan.p2p.device",
             FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_p2p_device_role_group_owner,
             {
             "P2P Group Owner",
             "wifi_nan.p2p.group_owner",
             FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL
             }
        },
        { &hf_nan_attr_p2p_device_role_client,
             {
             "P2P Client",
             "wifi_nan.p2p.client",
             FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
             }
        },
        { &hf_nan_attr_p2p_device_role,
             {
             "P2P Device Role",
             "wifi_nan.p2p.device_role",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_mesh_id,
            {
            "Mesh ID",
            "wifi_nan.mesh.id",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_further_av_map_id,
            {
            "Map ID",
            "wifi_nan.furth.av.map.id",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(furth_av_map_id), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_further_av_map_entry_av_interval_duration,
            {
            "Availability Interval Duration",
            "wifi_nan.further_av_map.entry.av_interval_duration",
            FT_UINT8, BASE_DEC, VALS(map_ctrl_availability_interval_duration), 0x03, NULL, HFILL
            }
        },
        { &hf_nan_attr_further_av_map_op_class,
             {
             "Operating Class",
             "wifi_nan.further_av_map.entry.op_class",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_further_av_map_channel_num,
             {
             "Channel Number",
             "wifi_nan.further_av_map.entry.channel_number",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_further_av_map_entry_ctrl,
             {
             "Entry Control Fields",
             "wifi_nan.further_av_map.entry.ctrl",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_country_code,
             {
             "Condensed Country String",
             "wifi_nan.country_code",
             FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_protocol,
             {
             "Ranging Protocol",
             "wifi_nan.ranging.protocol",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_cluster_disc_id,
             {
             "Cluster ID",
             "wifi_nan.cluster_disc.id",
             FT_UINT48, BASE_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_cluster_disc_time_offset,
             {
             "Cluster Time Offset",
             "wifi_nan.cluster_disc.time_offset",
             FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_cluster_disc_anchor_master_rank,
             {
             "Anchor Master Rank",
             "wifi_nan.cluster_disc.anchor_master_rank",
             FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_device_cap_map_id_apply_to,
            {
            "Apply to",
            "wifi_nan.device_cap.map_id_apply_to",
            FT_BOOLEAN, 8, TFS(&device_cap_map_id_apply_to_flags), 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_map_id_associated_maps,
            {
            "Map ID",
            "wifi_nan.device_cap.map_id_associated_maps",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x1E, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_committed_dw,
            {
            "Committed DW Info",
            "wifi_nan.device_cap.committed_dw_info",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_committed_dw_24ghz,
            {
            "2.4 GHz DW",
            "wifi_nan.device_cap.committed_dw_info.24ghz",
            FT_UINT16, BASE_DEC, NULL, 0x0007, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_committed_dw_5ghz,
            {
            "5 GHz DW",
            "wifi_nan.device_cap.committed_dw_info.5ghz",
            FT_UINT16, BASE_DEC, NULL, 0x0038, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_committed_dw_24ghz_overwrite,
            {
            "2.4 GHz DW Overwrite",
            "wifi_nan.device_cap.committed_dw_info.24ghz_overwrite",
            FT_UINT16, BASE_DEC, NULL, 0x03C0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_committed_dw_5ghz_overwrite,
            {
            "5 GHz DW Overwrite",
            "wifi_nan.device_cap.committed_dw_info.5ghz_overwrite",
            FT_UINT16, BASE_DEC, NULL, 0x3C00, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands,
            {
            "Supported Bands",
            "wifi_nan.device_cap.supported_bands",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_reserved_tv_whitespaces,
            {
            "Reserved (for TV white spaces)",
            "wifi_nan.device_cap.supported_bands.tv_whitespaces",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_sub_1ghz,
            {
            "Sub-1 GHz",
            "wifi_nan.device_cap.supported_bands.sub_1ghz",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_24ghz,
            {
            "2.4 GHz",
            "wifi_nan.device_cap.supported_bands.24ghz",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_reserved_36ghz,
            {
            "Reserved (for 3.6 GHz)",
            "wifi_nan.device_cap.supported_bands.reserved_36ghz",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_5ghz,
            {
            "4.9 and 5 GHz",
            "wifi_nan.device_cap.supported_bands.5ghz",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_reserved_60ghz,
            {
            "Reserved (for 60 GHz)",
            "wifi_nan.device_cap.supported_bands.reserved_60ghz",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_reserved_45ghz,
            {
            "Reserved (for 45 GHz)",
            "wifi_nan.device_cap.supported_bands.reserved_45ghz",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_supported_bands_6ghz,
            {
            "6GHz",
            "wifi_nan.device_cap.supported_bands.6ghz",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode,
            {
            "Operation Mode",
            "wifi_nan.device_cap.op_mode",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode_phy_vht,
            {
            "PHY Mode (VHT/HT)",
            "wifi_nan.device_cap.op_mode.phy.vht",
            FT_BOOLEAN, 8, TFS(&device_cap_op_mode_phy_flags_vht), 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode_phy_he,
            {
            "PHY Mode (HE)",
            "wifi_nan.device_cap.op_mode.phy.he",
            FT_BOOLEAN, 8, TFS(&device_cap_op_mode_phy_flags_he), 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode_phy_he_vht8080,
            {
            "HE/VHT 80+80",
            "wifi_nan.device_cap.op_mode.vht8080",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode_phy_he_vht160,
            {
            "HE/VHT 160",
            "wifi_nan.device_cap.op_mode.vht160",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_op_mode_reserved_paging_ndl,
            {
            "Reserved (Paging NDL Support)",
            "wifi_nan.device_cap.op_mode.reserved_paging_ndl",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_antennas,
            {
            "Antennas",
            "wifi_nan.device_cap.antennas",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_antennas_tx,
            {
            "Number of TX antennas",
            "wifi_nan.device_cap.antennas.tx",
            FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_antennas_rx,
            {
            "Number of RX antennas",
            "wifi_nan.device_cap.antennas.rx",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_max_channel_switch_time,
            {
            "Max Channel Switch Time (us)",
            "wifi_nan.device_cap.max_channel_switch_time",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities,
            {
            "Capabilities",
            "wifi_nan.device_cap.capabilities",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities_dfs_master,
            {
            "DFS Master",
            "wifi_nan.device_cap.capabilities.dfs_master",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities_extended_key_id,
            {
            "Extended key ID",
            "wifi_nan.device_cap.capabilities.extended_key_id",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities_simul_ndp_reception,
            {
            "Simultaneous NDP data reception",
            "wifi_nan.device_cap.capabilities.simul_ndp_reception",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities_ndpe_attr_support,
            {
            "NDPE attribute support",
            "wifi_nan.device_cap.capabilities.ndpe_attr_support",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_cap_capabilities_s3_capable,
            {
            "S3 Capable",
            "wifi_nan.device_cap.capabilities.s3_capable",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndp_type,
             {
             "Type",
             "wifi_nan.ndp.type",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(ndp_type_values), 0xF, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_initiator,
            {
            "Initiator NDI",
            "wifi_nan.ndp.initiator_ndi",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndp_id,
             {
             "NDP ID",
             "wifi_nan.ndp.id",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_ctrl_confirm,
             {
             "Confirm Required",
             "wifi_nan.ndp.ctrl.confirm",
             FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_ctrl_security_pres,
             {
             "Security Present",
             "wifi_nan.ndp.ctrl.security_pres",
             FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_ctrl_publish_id_pres,
             {
             "Publish ID Present",
             "wifi_nan.ndp.ctrl.publish_id_pres",
             FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_ctrl_responder_ndi_pres,
             {
             "Responder NDI Present",
             "wifi_nan.ndp.ctrl.responder_ndi_pres",
             FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_ctrl_sepcific_info_pres,
             {
             "NDP Specific Info Present",
             "wifi_nan.ndp.ctrl.specific_info_pres",
             FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_ctrl_confirm,
             {
             "Confirm Required",
             "wifi_nan.ndpe.ctrl.confirm",
             FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_ctrl_security_pres,
             {
             "Security Present",
             "wifi_nan.ndpe.ctrl.security_pres",
             FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_ctrl_publish_id_pres,
             {
             "Publish ID Present",
             "wifi_nan.ndpe.ctrl.publish_id_pres",
             FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_ctrl_responder_ndi_pres,
             {
             "Responder NDI Present",
             "wifi_nan.ndpe.ctrl.responder_ndi_pres",
             FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_ctrl_gtk_requried,
             {
             "GTK Required",
             "wifi_nan.ndpe.ctrl.gtk_required",
             FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_control,
             {
             "NDP Control",
             "wifi_nan.ndp.ctrl",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_control,
             {
             "NDPE Control",
             "wifi_nan.ndpe.ctrl",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_responder_ndi,
             {
             "Responder NDI",
             "wifi_nan.ndp.responder.ndi",
             FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndp_specific_info,
             {
             "NDP Specific Info",
             "wifi_nan.ndp.specific_info",
             FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_tlv_type,
             {
             "Type",
             "wifi_nan.ndpe.tlv.type",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(ndpe_tlv_type_values), 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_tlv_len,
             {
             "Length",
             "wifi_nan.ndpe.tlv.len",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndpe_tlv_ipv6_interface_identifier,
             {
             "Interface Identifier",
             "wifi_nan.ndpe.tlv.ipv6_interface_identifier",
             FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_availability_sequence_id,
            {
            "Sequence ID",
            "wifi_nan.availability.sequence_id",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_ctr,
            {
            "Attribute Control",
            "wifi_nan.availability.ctr",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_map_id,
            {
            "Map ID",
            "wifi_nan.availability.map_id",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x000F, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_committed_changed,
            {
            "Committed Changed",
            "wifi_nan.availability.committed_changed",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_potential_changed,
            {
            "Potential Changed",
            "wifi_nan.availability.potential_changed",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_public_availability_changed,
            {
            "Public Availability Attribute Changed",
            "wifi_nan.availability.public_availability_changed",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_ndc_changed,
            {
            "NDC Attribute Changed",
            "wifi_nan.availability.ndc_changed",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_reserved_multicast_schedule_changed,
            {
            "Reserved (Multicast Schedule Attribute Changed)",
            "wifi_nan.availability.reserved_multicast_schedule_changed",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_reserved_multicast_schedule_change_changed,
            {
            "Reserved (Multicast Schedule Change Attribute Change Changed)",
            "wifi_nan.availability.reserved_multicast_schedule_change_changed",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_len,
            {
            "Length",
            "wifi_nan.availability.entry.len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr,
            {
            "Entry Control",
            "wifi_nan.availability.entry.ctr",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr_type,
            {
            "Availability Type",
            "wifi_nan.availability.entry.ctr.type",
            FT_UINT16, BASE_HEX, VALS(availability_entry_type), 0x0007, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr_pref,
            {
            "Usage Preference",
            "wifi_nan.availability.entry.ctr.pref",
            FT_UINT16, BASE_DEC, NULL, 0x0018, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr_utilization,
            {
            "Utilization",
            "wifi_nan.availability.entry.ctr.utilization",
            FT_UINT16, BASE_DEC, NULL, 0x00E0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr_rx_nss,
            {
            "Rx Nss",
            "wifi_nan.availability.entry.ctr.rx_nss",
            FT_UINT16, BASE_DEC, NULL, 0x0F00, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_ctr_time_bitmap,
            {
            "Time Bitmap Present",
            "wifi_nan.availability.entry.ctr.time_bitmap",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_type,
            {
            "Type",
            "wifi_nan.availability.entry.entries.type",
            FT_BOOLEAN, BASE_NONE, TFS(&availability_entry_entries_type_flags), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_non_contiguous_bw,
            {
            "Non-contiguous Bandwidth",
            "wifi_nan.availability.entry.entries.non_contiguous_bw",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_num_entries,
            {
            "Number of Entries",
            "wifi_nan.availability.entry.entries.num_entries",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_band,
            {
            "Band Entry",
            "wifi_nan.availability.entry.entries.band",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(availability_entry_entries_band_type), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_channel_op_class,
            {
            "Operating Class",
            "wifi_nan.availability.entry.entries.channel.op_class",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_channel_bitmap,
            {
            "Channel Bitmap",
            "wifi_nan.availability.entry.entries.channel.bitmap",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_primary_channel_bitmap,
            {
            "Primary Channel Bitmap",
            "wifi_nan.availability.entry.entries.channel.primary_bitmap",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_aux_channel_bitmap,
            {
            "Auxiliary Channel Bitmap",
            "wifi_nan.availability.entry.entries.channel.aux_bitmap",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_channel_set,
            {
            "Channel Bitmap - Channel Set",
            "wifi_nan.ava.chan.set",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_start_channel_number,
            {
            "Start Channel Number",
            "wifi_nan.availability.entry.entries.channel.start_channel_number",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_number_of_ch_included,
            {
            "Number of Channels Included",
            "wifi_nan.availability.entry.entries.channel.num_of_channel",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_start_freq,
            {
            "Starting Frequency",
            "wifi_nan.av.entry.start.freq",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(op_starting_freq), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_availability_entry_entries_bandwidth,
            {
            "Bandwidth",
            "wifi_nan.av.entry.bandwidth",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(op_channel_spacing), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndc_id,
            {
            "NDC ID",
            "wifi_nan.ndc.id",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndc_ctrl,
            {
            "Control",
            "wifi_nan.ndc.ctrl",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndc_ctrl_selected,
            {
            "Selected NDC",
            "wifi_nan.ndc.ctrl.selected",
            FT_BOOLEAN, 8, TFS(&ndc_ctr_selected_flags), 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndc_map_id_related_sch,
            {
            "NAN Availability associated with schedule time bitmap",
            "wifi_nan.ndc.map.id.rel",
            FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_type,
             {
             "Type",
             "wifi_nan.ndl.type",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(ndl_type_values), 0xF, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndl_control,
             {
             "NDL Control",
             "wifi_nan.ndl.ctrl",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ndl_ctrl_peer_id,
            {
            "NDL Peer ID Present",
            "wifi_nan.ndl.ctrl.peer_id",
            FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_immutable_schedule_pres,
            {
            "Immutable Schedule Present",
            "wifi_nan.ndl.ctrl.immutable_schedule_pres",
            FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_ndc_pres,
            {
            "NDC Attribute Present",
            "wifi_nan.ndl.ctrl.ndc_pres",
            FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_qos,
            {
            "NDL QoS Present",
            "wifi_nan.ndl.ctrl.qos_pres",
            FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_max_idle_pres,
            {
            "Max Idle period Present",
            "wifi_nan.ndl.ctrl.max_idle_period_pres",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_type,
            {
            "NDL Type",
            "wifi_nan.ndl.ctrl.type",
            FT_UINT8, BASE_DEC, VALS(ndl_type_string), 0x20, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_ctrl_setup_reason,
            {
            "NDL Setup Reason",
            "wifi_nan.ndl.ctrl.setup_reason",
            FT_UINT8, BASE_DEC, VALS(ndl_setup_reason), 0xC0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_reserved_peer_id,
            {
            "Reserved (NDL Peer ID)",
            "wifi_nan.ndl.peer_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndl_max_idle,
            {
            "Max Idle Period",
            "wifi_nan.ndl.max.idle",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndlqos_min_time_slots,
            {
            "Minimum Time Slots",
            "wifi_nan.ndl_qos.min_time_slots",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ndlqos_max_latency,
            {
            "Maximum Latency",
            "wifi_nan.ndl_qos.max_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_ctrl,
             {
             "Attribute Control",
             "wifi_nan.unaligned_schedule.ctrl",
             FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ctrl_schedule_id,
            {
            "Schedule ID",
            "wifi_nan.unaligned_schedule.ctrl.schedule_id",
            FT_UINT16, BASE_HEX_DEC, NULL, 0xF, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_ctrl_seq_id,
            {
            "Sequence ID",
            "wifi_nan.unaligned_schedule.ctrl.sequence_id",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0F00, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_starting_time,
            {
            "Starting Time",
            "wifi_nan.unaligned_schedule.starting_time",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_duration,
            {
            "Duration",
            "wifi_nan.unaligned_schedule.duration",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_period,
            {
            "Period",
            "wifi_nan.unaligned_schedule.period",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_count_down,
            {
            "Count Down",
            "wifi_nan.unaligned_schedule.count_down",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_unaligned_sch_ulw_overwrite,
             {
             "ULW Overwrite",
             "wifi_nan.unaligned_schedule.ulw_overwrite",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_overwrite_all,
             {
             "Overwrite All",
             "wifi_nan.unaligned_schedule.ulw_overwrite.overwrite_all",
             FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_overwrite_map_id,
             {
             "Map ID",
             "wifi_nan.unaligned_schedule.ulw_overwrite.map_id",
             FT_UINT8, BASE_HEX_DEC, NULL, 0x1E, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_ctrl,
             {
             "ULW Control Field",
             "wifi_nan.attribute.ulw.ctrl",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_ctrl_type,
             {
             "Type",
             "wifi_nan.unaligned_schedule.ulw_ctrl.type",
             FT_UINT8, BASE_DEC_HEX, VALS(unaligned_sch_ulw_type), 0x3, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_ctrl_channel_av,
             {
             "Channel Availability",
             "wifi_nan.unaligned_schedule.ulw_ctrl.channel_availability",
             FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL
             }
        },
        { &hf_nan_attr_unaligned_sch_ulw_ctrl_rxnss,
             {
             "Rx Nss",
             "wifi_nan.unaligned_schedule.ulw_ctrl.rx_nss",
             FT_UINT8, BASE_HEX, NULL, 0x78, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_info_location_info_avail,
            {
            "Location Info Availability",
            "wifi_nan.ranging_info.location_info_availability",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_info_location_info_avail_lci,
             {
             "LCI Local Coordinates",
             "wifi_nan.ranging_info.location_info_availability.local_coord",
             FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_info_location_info_avail_geospatial,
             {
             "Geospatial LCI WGS84",
             "wifi_nan.ranging_info.location_info_availability.geospatial",
             FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_info_location_info_avail_civic_location,
             {
             "Civic Location",
             "wifi_nan.ranging_info.location_info_availability.civic_location",
             FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_info_location_info_avail_last_movement_pres,
             {
             "Last Movement Indication",
             "wifi_nan.ranging_info.location_info_availability.last_movement_indication",
             FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_info_last_movement_indication,
            {
            "Last Movement Indication",
            "wifi_nan.ranging_info.last_movement_indication",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_type,
             {
             "Type",
             "wifi_nan.ranging_setup.type",
             FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(ranging_setup_type_values), 0xF, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_setup_ctrl,
            {
            "Ranging Control",
            "wifi_nan.ranging_setup.ctrl",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_ctrl_report_req,
            {
            "Ranging Report Required",
            "wifi_nan.ranging_setup.ctrl.report_required",
            FT_BOOLEAN, 3, NULL, 0x1, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_ctrl_ftm_params,
            {
            "FTM Parameters Present",
            "wifi_nan.ranging_setup.ctrl.ftm_params",
            FT_BOOLEAN, 3, NULL, 0x2, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_ctrl_entry_list,
            {
            "Ranging Schedule Entry List Present",
            "wifi_nan.ranging_setup.ctrl.sch_entry_pres",
            FT_BOOLEAN, 3, NULL, 0x4, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_ftm_params,
            {
            "FTM Parameters",
            "wifi_nan.ranging_setup.ftm",
            FT_UINT24, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_ranging_setup_ftm_max_burst_duration,
             {
             "Max Burst Duration",
             "wifi_nan.ranging_setup.ftm.max_burst_duration",
             FT_UINT24, BASE_HEX_DEC, NULL, 0xF, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_setup_ftm_min_delta,
             {
             "Min Delta FTM",
             "wifi_nan.ranging_setup.ftm.min_delta_ftm",
             FT_UINT24, BASE_HEX_DEC, NULL, 0x03F0, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_setup_ftm_max_per_burst,
             {
             "Max FTMs per Burst",
             "wifi_nan.ranging_setup.ftm.max_ftms_per_burst",
             FT_UINT24, BASE_HEX_DEC, NULL, 0x7C00, NULL, HFILL
             }
        },
        { &hf_nan_attr_ranging_setup_ftm_format_bw,
             {
             "FTM Format and Bandwidth",
             "wifi_nan.ranging_setup.ftm.format_bw",
             FT_UINT24, BASE_HEX_DEC, NULL, 0x1F8000, NULL, HFILL
             }
        },
        { &hf_nan_attr_ftm_range_report,
             {
             "FTM Range Report",
             "wifi_nan.ftm.range_report",
             FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_cipher_suite_capabilities,
            {
            "Capabilities",
            "wifi_nan.cipher_suite.capabilities",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_cipher_suite_capabilities_ndtksa_nmtksa_replay_counters,
            {
            "ND-TKSA and NM-TKSA Replay Counters",
            "wifi_nan.cipher_suite.capabilities.replay_counters.ndtksa",
            FT_UINT8, BASE_HEX, VALS(cipher_suite_capabilities_nd_nm_tksa_replay_counters), 0x01, NULL, HFILL
            }
        },
        { &hf_nan_attr_cipher_suite_capabilities_gtksa_igtksa_bigtksa_support,
            {
            "GTKSA, IGTKSA, and BIGTKSA Support",
            "wifi_nan.cipher_suite.capabilities.group_key_support",
            FT_UINT8, BASE_HEX, VALS(cipher_suite_capabilities_group_and_integrity_sa_support), 0x06, NULL, HFILL
            }
        },
        { &hf_nan_attr_cipher_suite_capabilities_gtksa_replay_counters,
            {
            "GTKSA Replay Counters",
            "wifi_nan.cipher_suite.capabilities.replay_counters.gtksa",
            FT_UINT8, BASE_HEX, VALS(cipher_suite_capabilities_gtksa_replay_counters), 0x08, NULL, HFILL
            }
        },
        { &hf_nan_attr_cipher_suite_capabilities_igtksa_bigtksa_cipher,
            {
            "IGTKSA and BIGTKSA Cipher",
            "wifi_nan.cipher_suite.capabilities.integrity_key_cipher",
            FT_UINT8, BASE_HEX, VALS(cipher_suite_capabilities_integrity_sa_ciphers), 0x10, NULL, HFILL
            }
        },
        { &hf_nan_attr_cipher_suite_id,
            {
            "Cipher Suite ID",
            "wifi_nan.cipher_suite.id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_security_context_identifier,
            {
            "Security Context Identifier",
            "wifi_nan.security_context.identifier",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_security_context_identifier_len,
            {
            "Security Context Identifier Length",
            "wifi_nan.security_context.identifier_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_security_context_identifier_type,
            {
            "Security Context Identifier Type",
            "wifi_nan.security_context.identifier_type",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(security_context_iden_type), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_shared_key_rsna_descriptor,
             {
             "IEEE 802.11 RSNA Key Descriptor",
             "wifi_nan.shared_key.rsna_key_descriptor",
             FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
             }
        },
        { &hf_nan_attr_vendor_specific_body,
            {
            "Body",
            "wifi_nan.vendor_specific.body",
            FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_container_element_id,
            {
            "Element Id",
            "wifi_nan.container.element.id",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_container_element_len,
            {
            "Element Length",
            "wifi_nan.container.element.len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension,
            {
                "Capability Extension",
                "wifi_nan.device_capability_extension.capability_info",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension_6g_regulatory_info_presented,
            {
                "6GHz Regulatory Info Presented",
                "wifi_nan.device_capability_extension.6g_regulatory_presented",
                FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension_6g_regulatory_info,
            {
                "6GHz Regulatory Info",
                "wifi_nan.device_capability_extension.6g_regulatory",
                FT_UINT16, BASE_HEX_DEC, VALS(device_capability_extension_6g_regulatoty_info), 0x000e, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension_6g_regulatory_info_reserved,
            {
                "Reserved for 6GHz Regulatory Info",
                "wifi_nan.device_capability_extension.6g_regulatory_reserved",
                FT_UINT16, BASE_HEX_DEC, NULL, 0x00f0, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension_paring_setup_enabled,
            {
                "Paring Enable",
                "wifi_nan.device_capability_extension.paring_enable",
                FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL
            }
        },
        { &hf_nan_attr_device_capability_extension_npk_nik_cache_enabled,
            {
                "NPK/NIK Caching Enable",
                "wifi_nan.device_capability_extension.npk_nik_caching_enable",
                FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL
            }
        },
        { &hf_nan_attr_identity_cipher_version,
            {
                "Cipher Version",
                "wifi_nan.identity_resolution.cipher_version",
                FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(nan_identity_resolution_cipher_version), 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_identity_resolution_nonce,
            {
                "Nonce",
                "wifi_nan.identity_resolution.nonce",
                FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_identity_resolution_tag,
            {
                "Tag",
                "wifi_nan.identity_resolution.tag",
                FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_reserved,
            {
                "Reserved",
                "wifi_nan.reserved",
                FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_dialog_token,
            {
                "Dialog Token",
                "wifi_nan.nan_pairing_bootstrapping.dialog_token",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_type_status,
            {
                "Type and Status",
                "wifi_nan.nan_pairing_bootstrapping.type_status",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_type,
            {
                "Type",
                "wifi_nan.nan_pairing_bootstrapping.type",
                FT_UINT8, BASE_HEX_DEC, VALS(nan_pairing_bootstrapping_pairing_bootstrapping_type), 0x0f, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_status,
            {
                "Status",
                "wifi_nan.nan_pairing_bootstrapping.status",
                FT_UINT8, BASE_HEX_DEC, VALS(nan_pairing_bootstrapping_pairing_bootstrapping_status), 0xf0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_comeback_after,
            {
                "Comeback after (TU)",
                "wifi_nan.nan_pairing_bootstrapping.comeback_after",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_comeback_cookie_len,
            {
                "Cookie Length",
                "wifi_nan.nan_pairing_bootstrapping.cookie_len",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_comeback_cookie,
            {
                "Cookie",
                "wifi_nan.nan_pairing_bootstrapping.cookie",
                FT_BYTES, SEP_DASH, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_methods,
            {
                "Bootstrapping Methods",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_opportunistic_bootstrapping,
            {
                "Opportunistic Bootstrapping",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.opportunistic",
                FT_UINT16, BASE_HEX, NULL, 0x0001, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_pin_code_display,
            {
                "Pin Code (Display)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.pin_code_display",
                FT_UINT16, BASE_HEX, NULL, 0x0002, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_passphrase_display,
            {
                "Passphrase (Display)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.passphrase_display",
                FT_UINT16, BASE_HEX, NULL, 0x0004, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_qr_code_display,
            {
                "QR Code (Display)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.qr_code_display",
                FT_UINT16, BASE_HEX, NULL, 0x0008, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_nfc_tag,
            {
                "NFC Tag",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.nfc_tag",
                FT_UINT16, BASE_HEX, NULL, 0x0010, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_keypad_pin_code_only,
            {
                "Pin Code Only (Keypad)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.pin_code_keypad",
                FT_UINT16, BASE_HEX, NULL, 0x0020, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_keypad_passphrase,
            {
                "Passphrase (Keypad)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.passphrase_keypad",
                FT_UINT16, BASE_HEX, NULL, 0x0040, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_qr_code_scan,
            {
                "QR Code (Scan)",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.qr_code_scan",
                FT_UINT16, BASE_HEX, NULL, 0x0080, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_nfc_reader,
            {
                "NFC Reader",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.nfc_reader",
                FT_UINT16, BASE_HEX, NULL, 0x0100, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_reserved,
            {
                "Reserved",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x3e00, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_service_managed_bootstrapping,
            {
                "Service Managed",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.service_managed",
                FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL
            }
        },
        { &hf_nan_attr_pairing_bootstrapping_method_bootstrapping_handshakes_skipped,
            {
                "Bootstrapping Handshakes Skipped",
                "wifi_nan.nan_pairing_bootstrapping.bootstrapping_methods.bootstrapping_handshakes_skipped",
                FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL
            }
        },
    };

    static int* ett[] = {
        &ett_nan,
        &ett_attributes,
        &ett_type_status,
        &ett_map_control,
        &ett_time_bitmap_ctrl,
        &ett_non_nan_op_channel,
        &ett_non_nan_beacon,
        &ett_cluster_anchor_master_info,
        &ett_sda_service_ctr,
        &ett_sda_srf_ctr,
        &ett_sdea_ctr,
        &ett_sdea_range_limit,
        &ett_sdea_service_info,
        &ett_connection_cap_field,
        &ett_further_av_map_entry_ctrl,
        &ett_p2p_device_role,
        &ett_device_cap_map_id,
        &ett_device_cap_committed_dw,
        &ett_device_cap_supported_bands,
        &ett_device_cap_op_mode,
        &ett_device_cap_antennas,
        &ett_device_cap_capabilities,
        &ett_ndp_control,
        &ett_ndpe_tlv,
        &ett_availability_ctr,
        &ett_availability_entry,
        &ett_availability_entry_ctr,
        &ett_availability_entry_entries,
        &ett_availability_entry_entries_channel,
        &ett_availability_op_class,
        &ett_ndc_ctr,
        &ett_ndc_entries,
        &ett_device_ndc_map_id,
        &ett_ndl_control,
        &ett_ndl_schedule_entries,
        &ett_unaligned_sch_ctrl,
        &ett_unaligned_sch_ulw_overwrite,
        &ett_unaligned_sch_ulw_ctrl,
        &ett_ranging_info_location_info_availability,
        &ett_ranging_setup_ctrl,
        &ett_ranging_setup_ftm_params,
        &ett_ranging_setup_schedule_entries,
        &ett_cipher_suite_info_list,
        &ett_security_context_identifiers,
        &ett_public_availability_sch_entries,
        &ett_ie_tree,
        &ett_device_capability_extension,
        &ett_nan_pairing_bootstrapping_type_status,
        &ett_nan_pairing_bootstrapping_method,
        &ett_nan_cipher_suite_capabilities
    };

    static ei_register_info ei[] = {
        { &ei_nan_elem_len_invalid,
            {
            "wifi_nan.expert.elem_len_invalid",
            PI_MALFORMED, PI_ERROR,
            "Element length invalid",
            EXPFILL
            }
        },
        { &ei_nan_unknown_attr_id,
            {
            "wifi_nan.expert.unknown_attr_id",
            PI_PROTOCOL, PI_ERROR,
            "Unknown attribute ID",
            EXPFILL
            }
        },
        { &ei_nan_unknown_op_class,
            {
            "wifi_nan.expert.unknown_op_class",
            PI_PROTOCOL, PI_COMMENT,
            "Unknown Operating Class - Channel Set unavailable",
            EXPFILL
            }
        },
        { &ei_nan_unknown_beacon_type,
            {
            "wifi_nan.expert.unknown_beacon_type",
            PI_PROTOCOL, PI_WARN,
            "Unknown beacon type - Beacon type detection error",
            EXPFILL
            }
        },
        { &ei_nan_invalid_channel_num_for_op_class,
            {
            "wifi_nan.expert.invalid_ch_num",
            PI_PROTOCOL, PI_WARN,
            "Invalid Channel number for given operation class",
            EXPFILL
            }
        },
        { &ei_nan_invalid_channel_count,
            {
            "wifi_nan.expert.invalid_ch_count",
            PI_PROTOCOL, PI_WARN,
            "Invalid Channel count",
            EXPFILL
            }
        },
    };

    proto_nan = proto_register_protocol("Wi-Fi Neighbor Awareness Networking (NAN)", "Wi-Fi NAN", "wifi_nan");

    proto_register_field_array(proto_nan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nan_act_handle = register_dissector("nan.action", dissect_nan_action, proto_nan);
    nan_disco_handle = register_dissector("nan.service_discovery", dissect_nan_service_discovery, proto_nan);
    nan_beacon_handle = register_dissector("nan.beacon", dissect_nan_beacon, proto_nan);

    expert_module_t* expert_nan = expert_register_protocol(proto_nan);
    expert_register_field_array(expert_nan, ei, array_length(ei));

    ie_handle_table = find_dissector_table("wlan.tag.number");
}

void
proto_reg_handoff_nan(void)
{
    dissector_add_uint("wlan.pa.wifi_alliance.subtype", WFA_ACTION_OUI_TYPE, nan_act_handle);
    dissector_add_uint("wlan.pa.wifi_alliance.subtype", WFA_SERVICE_DISCOVERY_SUBTYPE, nan_disco_handle);
    dissector_add_uint("wlan.ie.wifi_alliance.subtype", WFA_NAN_IE_OUI_TYPE, nan_beacon_handle);
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
