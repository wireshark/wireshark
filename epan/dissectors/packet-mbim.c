/* packet-mbim.c
 * Routines for MBIM dissection
 * Copyright 2013-2016, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Dissector based on MBIM specification 1.0 Errata-1 and MBIM extended version 2.0
 * http://www.usb.org/developers/devclass_docs/MBIM10Errata1_073013.zip
 * http://compliance.usb.org/mbim/
 * http://www.usb.org/developers/docs/devclass_docs/MBIMMultiflow10.zip
 *
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/host-shutdown-device-service
 *
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-provisioned-context-operations
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-network-blacklist-operations
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-lte-attach-operations
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-multi-sim-operations
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-protocol-configuration-options-pco-operations
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-modem-reset-operations
 *
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-sar-platform-support
 *
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-low-level-uicc-access
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-uicc-application-and-file-system-access
 *
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-5g-data-class-support
 * https://download.microsoft.com/download/8/3/a/83a64106-a1f4-4a03-811f-4dbef2e3bf7a/MBIM extensions for 5G.docx
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/ipproto.h>

#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-usb.h"
#include "packet-mbim.h"

void proto_register_mbim(void);
void proto_reg_handoff_mbim(void);

/* Initialize the protocol and registered fields */
static int proto_mbim = -1;
static int hf_mbim_control = -1;
static int hf_mbim_header_message_type = -1;
static int hf_mbim_header_message_length = -1;
static int hf_mbim_header_transaction_id = -1;
static int hf_mbim_fragment_total = -1;
static int hf_mbim_fragment_current = -1;
static int hf_mbim_max_ctrl_transfer = -1;
static int hf_mbim_device_service_id = -1;
static int hf_mbim_uuid_basic_connect_cid = -1;
static int hf_mbim_uuid_sms_cid = -1;
static int hf_mbim_uuid_ussd_cid = -1;
static int hf_mbim_uuid_phonebook_cid = -1;
static int hf_mbim_uuid_stk_cid = -1;
static int hf_mbim_uuid_auth_cid = -1;
static int hf_mbim_uuid_dss_cid = -1;
static int hf_mbim_uuid_multicarrier_cid = -1;
static int hf_mbim_uuid_ms_hostshutdown_cid = -1;
static int hf_mbim_uuid_msfwid_cid = -1;
static int hf_mbim_uuid_qmi_cid = -1;
static int hf_mbim_uuid_intel_fwusvc_cid = -1;
static int hf_mbim_uuid_intel_dptf_cid = -1;
static int hf_mbim_uuid_intel_sar_cid = -1;
static int hf_mbim_uuid_intel_act_cid = -1;
static int hf_mbim_uuid_intel_trcsvc_cid = -1;
static int hf_mbim_uuid_intel_nrtc_cid = -1;
static int hf_mbim_uuid_intel_usb_profile_cid = -1;
static int hf_mbim_uuid_intel_ciq_cid = -1;
static int hf_mbim_uuid_atds_cid = -1;
static int hf_mbim_uuid_multiflow_cid = -1;
static int hf_mbim_uuid_basic_connect_extensions_cid = -1;
static int hf_mbim_uuid_ms_sarcontrol_cid = -1;
static int hf_mbim_uuid_ms_uicc_low_level_cid = -1;
static int hf_mbim_cid = -1;
static int hf_mbim_command_type = -1;
static int hf_mbim_info_buffer_len = -1;
static int hf_mbim_info_buffer = -1;
static int hf_mbim_error_status_code = -1;
static int hf_mbim_status = -1;
static int hf_mbim_tlv_ie_type = -1;
static int hf_mbim_tlv_ie_reserved = -1;
static int hf_mbim_tlv_ie_padding_length = -1;
static int hf_mbim_tlv_ie_data_length = -1;
static int hf_mbim_tlv_ie_unnamed_data = -1;
static int hf_mbim_tlv_ie_data_wchar_str = -1;
static int hf_mbim_tlv_ie_data_int32 = -1;
static int hf_mbim_tlv_ie_data_guid = -1;
static int hf_mbim_tlv_ie_padding = -1;
static int hf_mbim_ms_ursp_tc_length = -1;
static int hf_mbim_ms_ursp_precedence = -1;
static int hf_mbim_ms_ursp_tc_type = -1;
static int hf_mbim_ms_ursp_tc_os_id = -1;
static int hf_mbim_ms_ursp_tc_dnn = -1;
static int hf_mbim_ms_ursp_tc_fqdn = -1;
static int hf_mbim_ms_ursp_tc_ipv4 = -1;
static int hf_mbim_ms_ursp_tc_ipv4_mask = -1;
static int hf_mbim_ms_ursp_tc_ipv6 = -1;
static int hf_mbim_ms_ursp_tc_ipv6_prefix_length = -1;
static int hf_mbim_ms_ursp_tc_proto_id = -1;
static int hf_mbim_ms_ursp_tc_port = -1;
static int hf_mbim_ms_ursp_tc_port_range_low = -1;
static int hf_mbim_ms_ursp_tc_port_range_high = -1;
static int hf_mbim_ms_ursp_tc_app_id = -1;
static int hf_mbim_ms_ursp_tc_byte_value = -1;
static int hf_mbim_ms_ursp_tc_capability = -1;
static int hf_mbim_ms_ursp_tc_connection_capability_flag_ims = -1;
static int hf_mbim_ms_ursp_tc_connection_capability_flag_mms = -1;
static int hf_mbim_ms_ursp_tc_connection_capability_flag_supl = -1;
static int hf_mbim_ms_ursp_tc_connection_capability_flag_internet = -1;
static int hf_mbim_ms_snssai_length = -1;
static int hf_mbim_ms_snssai_slice_service_type = -1;
static int hf_mbim_ms_snssai_slice_differentiator = -1;
static int hf_mbim_ms_snssai_mapped_slice_service_type = -1;
static int hf_mbim_ms_snssai_mapped_slice_differentiator = -1;
static int hf_mbim_ms_rej_snssai_cause = -1;
static int hf_mbim_ms_pre_dflt_nssai_info_access_type = -1;
static int hf_mbim_device_caps_info_device_type = -1;
static int hf_mbim_device_caps_info_cellular_class = -1;
static int hf_mbim_device_caps_info_voice_class = -1;
static int hf_mbim_device_caps_info_sim_class = -1;
static int hf_mbim_device_caps_info_sim_class_logical = -1;
static int hf_mbim_device_caps_info_sim_class_removable = -1;
static int hf_mbim_device_caps_info_data_class = -1;
static int hf_mbim_data_class_gprs = -1;
static int hf_mbim_data_class_edge = -1;
static int hf_mbim_data_class_umts = -1;
static int hf_mbim_data_class_hsdpa = -1;
static int hf_mbim_data_class_hsupa = -1;
static int hf_mbim_data_class_lte = -1;
static int hf_mbim_data_class_5g = -1;
static int hf_mbim_data_class_reserved_gsm = -1;
static int hf_mbim_data_class_1xrtt = -1;
static int hf_mbim_data_class_1xevdo = -1;
static int hf_mbim_data_class_1xevdoreva = -1;
static int hf_mbim_data_class_1xevdv = -1;
static int hf_mbim_data_class_3xrtt = -1;
static int hf_mbim_data_class_1xevdorevb = -1;
static int hf_mbim_data_class_umb = -1;
static int hf_mbim_data_class_reserved_cdma = -1;
static int hf_mbim_data_class_custom = -1;
static int hf_mbim_device_caps_info_sms_caps = -1;
static int hf_mbim_device_caps_info_sms_caps_pdu_receive = -1;
static int hf_mbim_device_caps_info_sms_caps_pdu_send = -1;
static int hf_mbim_device_caps_info_sms_caps_text_receive = -1;
static int hf_mbim_device_caps_info_sms_caps_text_send = -1;
static int hf_mbim_device_caps_info_control_caps = -1;
static int hf_mbim_device_caps_info_control_caps_reg_manual = -1;
static int hf_mbim_device_caps_info_control_caps_hw_radio_switch = -1;
static int hf_mbim_device_caps_info_control_caps_cdma_mobile_ip = -1;
static int hf_mbim_device_caps_info_control_caps_cdma_simple_ip = -1;
static int hf_mbim_device_caps_info_control_caps_multi_carrier = -1;
static int hf_mbim_device_caps_info_control_caps_esim = -1;
static int hf_mbim_device_caps_info_control_caps_ue_policy_route_selection = -1;
static int hf_mbim_device_caps_info_control_caps_sim_hot_swap_capable = -1;
static int hf_mbim_device_caps_info_control_caps_use_ursp_rule_on_epc_capable = -1;
static int hf_mbim_device_caps_info_data_subclass = -1;
static int hf_mbim_data_subclass_5gendc = -1;
static int hf_mbim_data_subclass_5gnr = -1;
static int hf_mbim_data_subclass_5gnedc = -1;
static int hf_mbim_data_subclass_5gelte = -1;
static int hf_mbim_data_subclass_5gngendc = -1;
static int hf_mbim_device_caps_info_max_sessions = -1;
static int hf_mbim_device_caps_info_wcdma_band_class = -1;
static int hf_mbim_device_caps_info_custom_data_class_offset = -1;
static int hf_mbim_device_caps_info_custom_data_class_size = -1;
static int hf_mbim_device_caps_info_device_id_offset = -1;
static int hf_mbim_device_caps_info_device_id_size = -1;
static int hf_mbim_device_caps_info_fw_info_offset = -1;
static int hf_mbim_device_caps_info_fw_info_size = -1;
static int hf_mbim_device_caps_info_hw_info_offset = -1;
static int hf_mbim_device_caps_info_hw_info_size = -1;
static int hf_mbim_device_caps_info_custom_data_class = -1;
static int hf_mbim_device_caps_info_device_id = -1;
static int hf_mbim_device_caps_info_fw_info = -1;
static int hf_mbim_device_caps_info_hw_info = -1;
static int hf_mbim_device_caps_info_v2_executor_index = -1;
static int hf_mbim_subscr_ready_status_ready_state = -1;
static int hf_mbim_subscr_ready_status_flags = -1;
static int hf_mbim_subscr_ready_status_flag_esim = -1;
static int hf_mbim_subscr_ready_status_flag_sim_removability_known = -1;
static int hf_mbim_subscr_ready_status_flag_sim_removable = -1;
static int hf_mbim_subscr_ready_status_flag_sim_slot_active = -1;
static int hf_mbim_subscr_ready_status_susbcr_id_offset = -1;
static int hf_mbim_subscr_ready_status_susbcr_id_size = -1;
static int hf_mbim_subscr_ready_status_sim_icc_id_offset = -1;
static int hf_mbim_subscr_ready_status_sim_icc_id_size = -1;
static int hf_mbim_subscr_ready_status_ready_info = -1;
static int hf_mbim_subscr_ready_status_elem_count = -1;
static int hf_mbim_subscr_ready_status_tel_nb_offset = -1;
static int hf_mbim_subscr_ready_status_tel_nb_size = -1;
static int hf_mbim_subscr_ready_status_susbcr_id = -1;
static int hf_mbim_subscr_ready_status_sim_icc_id = -1;
static int hf_mbim_subscr_ready_status_tel_nb = -1;
static int hf_mbim_radio_state_set = -1;
static int hf_mbim_radio_state_hw_radio_state = -1;
static int hf_mbim_radio_state_sw_radio_state = -1;
static int hf_mbim_set_pin_pin_type = -1;
static int hf_mbim_set_pin_pin_pin_operation = -1;
static int hf_mbim_set_pin_pin_pin_offset = -1;
static int hf_mbim_set_pin_pin_pin_size = -1;
static int hf_mbim_set_pin_new_pin_offset = -1;
static int hf_mbim_set_pin_new_pin_size = -1;
static int hf_mbim_set_pin_pin = -1;
static int hf_mbim_set_pin_new_pin = -1;
static int hf_mbim_pin_info_pin_type = -1;
static int hf_mbim_pin_info_pin_state = -1;
static int hf_mbim_pin_info_remaining_attempts = -1;
static int hf_mbim_pin_list_pin_mode = -1;
static int hf_mbim_pin_list_pin_format = -1;
static int hf_mbim_pin_list_pin_length_min = -1;
static int hf_mbim_pin_list_pin_length_max = -1;
static int hf_mbim_provider_state = -1;
static int hf_mbim_provider_state_home = -1;
static int hf_mbim_provider_state_forbidden = -1;
static int hf_mbim_provider_state_preferred = -1;
static int hf_mbim_provider_state_visible = -1;
static int hf_mbim_provider_state_registered = -1;
static int hf_mbim_provider_state_preferred_multicarrier = -1;
static int hf_mbim_provider_provider_id_offset = -1;
static int hf_mbim_provider_provider_id_size = -1;
static int hf_mbim_provider_provider_name_offset = -1;
static int hf_mbim_provider_provider_name_size = -1;
static int hf_mbim_provider_cellular_class = -1;
static int hf_mbim_provider_rssi = -1;
static int hf_mbim_provider_error_rate = -1;
static int hf_mbim_provider_provider_id = -1;
static int hf_mbim_provider_provider_name = -1;
static int hf_mbim_providers_elem_count = -1;
static int hf_mbim_providers_provider_offset = -1;
static int hf_mbim_providers_provider_size = -1;
static int hf_mbim_visible_providers_req_action = -1;
static int hf_mbim_set_register_state_provider_id_offset = -1;
static int hf_mbim_set_register_state_provider_id_size = -1;
static int hf_mbim_set_register_state_register_action = -1;
static int hf_mbim_register_state_data_class = -1;
static int hf_mbim_set_register_state_provider_id = -1;
static int hf_mbim_registration_state_info_nw_error = -1;
static int hf_mbim_registration_state_info_register_state = -1;
static int hf_mbim_registration_state_info_register_mode = -1;
static int hf_mbim_registration_state_info_available_data_classes = -1;
static int hf_mbim_registration_state_info_current_cellular_class = -1;
static int hf_mbim_registration_state_info_provider_id_offset = -1;
static int hf_mbim_registration_state_info_provider_id_size = -1;
static int hf_mbim_registration_state_info_provider_name_offset = -1;
static int hf_mbim_registration_state_info_provider_name_size = -1;
static int hf_mbim_registration_state_info_roaming_text_offset = -1;
static int hf_mbim_registration_state_info_roaming_text_size = -1;
static int hf_mbim_registration_state_info_registration_flags = -1;
static int hf_mbim_registration_state_info_registration_flags_manual_selection_not_available = -1;
static int hf_mbim_registration_state_info_registration_flags_packet_service_auto_attach = -1;
static int hf_mbim_registration_state_info_preferred_data_class = -1;
static int hf_mbim_registration_state_info_provider_id = -1;
static int hf_mbim_registration_state_info_provider_name = -1;
static int hf_mbim_registration_state_info_roaming_text = -1;
static int hf_mbim_set_packet_service_action = -1;
static int hf_mbim_ms_plmn_mcc = -1;
static int hf_mbim_ms_plmn_mnc = -1;
static int hf_mbim_ms_tai_tac = -1;
static int hf_mbim_ms_tai_list_type = -1;
static int hf_mbim_ms_tai_list_single_plmn_tac_element = -1;
static int hf_mbim_ms_tai_list_multi_plmn_tai_element = -1;
static int hf_mbim_packet_service_info_nw_error = -1;
static int hf_mbim_packet_service_info_packet_service_state = -1;
static int hf_mbim_packet_service_info_highest_available_data_class = -1;
static int hf_mbim_packet_service_info_current_data_class = -1;
static int hf_mbim_packet_service_info_uplink_speed = -1;
static int hf_mbim_packet_service_info_downlink_speed = -1;
static int hf_mbim_packet_service_info_frequency_range = -1;
static int hf_mbim_packet_service_info_data_subclass = -1;
static int hf_mbim_set_signal_state_signal_strength_interval = -1;
static int hf_mbim_set_signal_state_rssi_threshold = -1;
static int hf_mbim_set_signal_state_error_rate_threshold = -1;
static int hf_mbim_signal_state_element_rsrp = -1;
static int hf_mbim_signal_state_element_snr = -1;
static int hf_mbim_signal_state_element_rsrp_threshold = -1;
static int hf_mbim_signal_state_element_snr_threshold = -1;
static int hf_mbim_signal_state_element_system_type = -1;
static int hf_mbim_signal_state_info_rssi = -1;
static int hf_mbim_signal_state_info_error_rate = -1;
static int hf_mbim_signal_state_info_signal_strength_interval = -1;
static int hf_mbim_signal_state_info_rssi_threshold = -1;
static int hf_mbim_signal_state_info_error_rate_threshold = -1;
static int hf_mbim_signal_state_info_rsrp_snr_offset = -1;
static int hf_mbim_signal_state_info_rsrp_snr_size = -1;
static int hf_mbim_signal_state_info_elem_count = -1;
static int hf_mbim_context_type = -1;
static int hf_mbim_set_connect_session_id = -1;
static int hf_mbim_set_connect_activation_command = -1;
static int hf_mbim_set_connect_activation_option = -1;
static int hf_mbim_set_connect_access_string_offset = -1;
static int hf_mbim_set_connect_access_string_size = -1;
static int hf_mbim_set_connect_user_name_offset = -1;
static int hf_mbim_set_connect_user_name_size = -1;
static int hf_mbim_set_connect_password_offset = -1;
static int hf_mbim_set_connect_password_size = -1;
static int hf_mbim_set_connect_compression = -1;
static int hf_mbim_set_connect_auth_protocol = -1;
static int hf_mbim_set_connect_ip_type = -1;
static int hf_mbim_set_connect_access_string = -1;
static int hf_mbim_set_connect_user_name = -1;
static int hf_mbim_set_connect_password = -1;
static int hf_mbim_set_connect_media_preference = -1;
static int hf_mbim_connect_info_session_id = -1;
static int hf_mbim_connect_info_activation_state = -1;
static int hf_mbim_connect_info_voice_call_state = -1;
static int hf_mbim_connect_info_ip_type = -1;
static int hf_mbim_connect_info_nw_error = -1;
static int hf_mbim_connect_info_access_media = -1;
static int hf_mbim_context_context_id = -1;
static int hf_mbim_context_access_string_offset = -1;
static int hf_mbim_context_access_string_size = -1;
static int hf_mbim_context_user_name_offset = -1;
static int hf_mbim_context_user_name_size = -1;
static int hf_mbim_context_password_offset = -1;
static int hf_mbim_context_password_size = -1;
static int hf_mbim_context_compression = -1;
static int hf_mbim_context_auth_protocol = -1;
static int hf_mbim_context_provider_id_offset = -1;
static int hf_mbim_context_provider_id_size = -1;
static int hf_mbim_context_provider_id = -1;
static int hf_mbim_context_access_string = -1;
static int hf_mbim_context_user_name = -1;
static int hf_mbim_context_password = -1;
static int hf_mbim_provisioned_contexts_info_elem_count = -1;
static int hf_mbim_provisioned_contexts_info_provisioned_context_offset = -1;
static int hf_mbim_provisioned_contexts_info_provisioned_context_size = -1;
static int hf_mbim_set_service_activation_data_buffer = -1;
static int hf_mbim_service_activation_info_nw_error = -1;
static int hf_mbim_service_activation_info_data_buffer = -1;
static int hf_mbim_ipv4_element_on_link_prefix_length = -1;
static int hf_mbim_ipv4_element_ipv4_address = -1;
static int hf_mbim_ipv6_element_on_link_prefix_length = -1;
static int hf_mbim_ipv6_element_ipv6_address = -1;
static int hf_mbim_ip_configuration_info_session_id = -1;
static int hf_mbim_ip_configuration_info_ipv4_configuration_available = -1;
static int hf_mbim_ip_configuration_info_ipv4_configuration_available_address = -1;
static int hf_mbim_ip_configuration_info_ipv4_configuration_available_gateway = -1;
static int hf_mbim_ip_configuration_info_ipv4_configuration_available_dns = -1;
static int hf_mbim_ip_configuration_info_ipv4_configuration_available_mtu = -1;
static int hf_mbim_ip_configuration_info_ipv6_configuration_available = -1;
static int hf_mbim_ip_configuration_info_ipv6_configuration_available_address = -1;
static int hf_mbim_ip_configuration_info_ipv6_configuration_available_gateway = -1;
static int hf_mbim_ip_configuration_info_ipv6_configuration_available_dns = -1;
static int hf_mbim_ip_configuration_info_ipv6_configuration_available_mtu = -1;
static int hf_mbim_ip_configuration_info_ipv4_address_count = -1;
static int hf_mbim_ip_configuration_info_ipv4_address_offset = -1;
static int hf_mbim_ip_configuration_info_ipv6_address_count = -1;
static int hf_mbim_ip_configuration_info_ipv6_address_offset = -1;
static int hf_mbim_ip_configuration_info_ipv4_gateway_offset = -1;
static int hf_mbim_ip_configuration_info_ipv6_gateway_offset = -1;
static int hf_mbim_ip_configuration_info_ipv4_dns_count = -1;
static int hf_mbim_ip_configuration_info_ipv4_dns_offset = -1;
static int hf_mbim_ip_configuration_info_ipv6_dns_count = -1;
static int hf_mbim_ip_configuration_info_ipv6_dns_offset = -1;
static int hf_mbim_ip_configuration_info_ipv4_mtu = -1;
static int hf_mbim_ip_configuration_info_ipv6_mtu = -1;
static int hf_mbim_ip_configuration_info_ipv4_gateway = -1;
static int hf_mbim_ip_configuration_info_ipv6_gateway = -1;
static int hf_mbim_ip_configuration_info_ipv4_dns = -1;
static int hf_mbim_ip_configuration_info_ipv6_dns = -1;
static int hf_mbim_device_service_element_device_service_id = -1;
static int hf_mbim_device_service_element_dss_payload = -1;
static int hf_mbim_device_service_element_dss_payload_host_device = -1;
static int hf_mbim_device_service_element_dss_payload_device_host = -1;
static int hf_mbim_device_service_element_max_dss_instances = -1;
static int hf_mbim_device_service_element_cid_count = -1;
static int hf_mbim_device_service_element_cid = -1;
static int hf_mbim_device_services_info_device_services_count = -1;
static int hf_mbim_device_services_info_max_dss_sessions = -1;
static int hf_mbim_device_services_info_device_services_offset = -1;
static int hf_mbim_device_services_info_device_services_size = -1;
static int hf_mbim_event_entry_device_service_id = -1;
static int hf_mbim_event_entry_cid_count = -1;
static int hf_mbim_event_entry_cid = -1;
static int hf_mbim_device_service_subscribe_element_count = -1;
static int hf_mbim_device_service_subscribe_device_service_offset = -1;
static int hf_mbim_device_service_subscribe_device_service_size = -1;
static int hf_mbim_packet_statistics_info_in_discards = -1;
static int hf_mbim_packet_statistics_info_in_errors = -1;
static int hf_mbim_packet_statistics_info_in_octets = -1;
static int hf_mbim_packet_statistics_info_in_packets = -1;
static int hf_mbim_packet_statistics_info_out_octets = -1;
static int hf_mbim_packet_statistics_info_out_packets = -1;
static int hf_mbim_packet_statistics_info_out_errors = -1;
static int hf_mbim_packet_statistics_info_out_discards = -1;
static int hf_mbim_network_idle_hint_state = -1;
static int hf_mbim_emergency_mode_info_emergency_mode = -1;
static int hf_mbim_single_packet_filter_filter_size = -1;
static int hf_mbim_single_packet_filter_packet_filter_offset = -1;
static int hf_mbim_single_packet_filter_packet_mask_offset = -1;
static int hf_mbim_single_packet_filter_filter_id = -1;
static int hf_mbim_single_packet_filter_packet_filter = -1;
static int hf_mbim_single_packet_filter_packet_mask = -1;
static int hf_mbim_packet_filters_session_id = -1;
static int hf_mbim_packet_filters_packet_filters_count = -1;
static int hf_mbim_packet_filters_packet_filters_packet_filter_offset = -1;
static int hf_mbim_packet_filters_packet_filters_packet_filter_size = -1;
static int hf_mbim_set_sms_configuration_format = -1;
static int hf_mbim_set_sms_configuration_sc_address_offset = -1;
static int hf_mbim_set_sms_configuration_sc_address_size = -1;
static int hf_mbim_set_sms_configuration_sc_address = -1;
static int hf_mbim_sms_configuration_info_sms_storage_state = -1;
static int hf_mbim_sms_configuration_info_format = -1;
static int hf_mbim_sms_configuration_info_max_messages = -1;
static int hf_mbim_sms_configuration_info_cdma_short_message_size = -1;
static int hf_mbim_sms_configuration_info_sc_address_offset = -1;
static int hf_mbim_sms_configuration_info_sc_address_size = -1;
static int hf_mbim_sms_configuration_info_sc_address = -1;
static int hf_mbim_sms_pdu_record_message_index = -1;
static int hf_mbim_sms_pdu_record_message_status = -1;
static int hf_mbim_sms_pdu_record_pdu_data_offset = -1;
static int hf_mbim_sms_pdu_record_pdu_data_size = -1;
static int hf_mbim_sms_pdu_record_pdu_data = -1;
static int hf_mbim_sms_pdu_record_pdu_data_sc_address_size = -1;
static int hf_mbim_sms_cdma_record_message_index = -1;
static int hf_mbim_sms_cdma_record_message_status = -1;
static int hf_mbim_sms_cdma_record_address_offset = -1;
static int hf_mbim_sms_cdma_record_address_size = -1;
static int hf_mbim_sms_cdma_record_timestamp_offset = -1;
static int hf_mbim_sms_cdma_record_timestamp_size = -1;
static int hf_mbim_sms_cdma_record_encoding_id = -1;
static int hf_mbim_sms_cdma_record_language_id = -1;
static int hf_mbim_sms_cdma_record_encoded_message_offset = -1;
static int hf_mbim_sms_cdma_record_size_in_bytes = -1;
static int hf_mbim_sms_cdma_record_size_in_characters = -1;
static int hf_mbim_sms_cdma_record_address = -1;
static int hf_mbim_sms_cdma_record_timestamp = -1;
static int hf_mbim_sms_cdma_record_encoded_message = -1;
static int hf_mbim_sms_cdma_record_encoded_message_text = -1;
static int hf_mbim_sms_read_req_format = -1;
static int hf_mbim_sms_read_req_flag = -1;
static int hf_mbim_sms_read_req_message_index = -1;
static int hf_mbim_sms_read_info_format = -1;
static int hf_mbim_sms_read_info_element_count = -1;
static int hf_mbim_sms_read_info_sms_offset = -1;
static int hf_mbim_sms_read_info_sms_size = -1;
static int hf_mbim_sms_send_pdu_pdu_data_offset = -1;
static int hf_mbim_sms_send_pdu_pdu_data_size = -1;
static int hf_mbim_sms_send_pdu_pdu_data = -1;
static int hf_mbim_sms_send_pdu_pdu_data_sc_address_size = -1;
static int hf_mbim_sms_send_cdma_encoding_id = -1;
static int hf_mbim_sms_send_cdma_language_id = -1;
static int hf_mbim_sms_send_cdma_address_offset = -1;
static int hf_mbim_sms_send_cdma_address_size = -1;
static int hf_mbim_sms_send_cdma_encoded_message_offset = -1;
static int hf_mbim_sms_send_cdma_size_in_bytes = -1;
static int hf_mbim_sms_send_cdma_size_in_characters = -1;
static int hf_mbim_sms_send_cdma_address = -1;
static int hf_mbim_sms_send_cdma_encoded_message = -1;
static int hf_mbim_sms_send_cdma_encoded_message_text = -1;
static int hf_mbim_set_sms_send_format = -1;
static int hf_mbim_sms_send_info_message_reference = -1;
static int hf_mbim_set_sms_delete_flag = -1;
static int hf_mbim_set_sms_delete_message_index = -1;
static int hf_mbim_sms_status_info_flags = -1;
static int hf_mbim_sms_status_info_flags_message_store_full = -1;
static int hf_mbim_sms_status_info_flags_new_message = -1;
static int hf_mbim_sms_status_info_message_index = -1;
static int hf_mbim_set_ussd_ussd_action = -1;
static int hf_mbim_set_ussd_ussd_data_coding_scheme = -1;
static int hf_mbim_set_ussd_ussd_payload_offset = -1;
static int hf_mbim_set_ussd_ussd_payload_length = -1;
static int hf_mbim_set_ussd_ussd_payload = -1;
static int hf_mbim_set_ussd_ussd_payload_text = -1;
static int hf_mbim_ussd_info_ussd_response = -1;
static int hf_mbim_ussd_info_ussd_session_state = -1;
static int hf_mbim_ussd_info_ussd_data_coding_scheme = -1;
static int hf_mbim_ussd_info_ussd_payload_offset = -1;
static int hf_mbim_ussd_info_ussd_payload_length = -1;
static int hf_mbim_ussd_info_ussd_payload = -1;
static int hf_mbim_ussd_info_ussd_payload_text = -1;
static int hf_mbim_phonebook_configuration_info_phonebook_state = -1;
static int hf_mbim_phonebook_configuration_info_total_nb_of_entries = -1;
static int hf_mbim_phonebook_configuration_info_used_entries = -1;
static int hf_mbim_phonebook_configuration_info_max_number_length = -1;
static int hf_mbim_phonebook_configuration_info_max_name_length = -1;
static int hf_mbim_phonebook_entry_entry_index = -1;
static int hf_mbim_phonebook_entry_number_offset = -1;
static int hf_mbim_phonebook_entry_number_length = -1;
static int hf_mbim_phonebook_entry_name_offset = -1;
static int hf_mbim_phonebook_entry_name_length = -1;
static int hf_mbim_phonebook_entry_number = -1;
static int hf_mbim_phonebook_entry_name = -1;
static int hf_mbim_phonebook_read_req_filter_flag = -1;
static int hf_mbim_phonebook_read_req_filter_message_index = -1;
static int hf_mbim_phonebook_read_info_element_count = -1;
static int hf_mbim_phonebook_read_info_phonebook_offset = -1;
static int hf_mbim_phonebook_read_info_phonebook_size = -1;
static int hf_mbim_set_phonebook_delete_filter_flag = -1;
static int hf_mbim_set_phonebook_delete_filter_message_index = -1;
static int hf_mbim_set_phonebook_write_save_flag = -1;
static int hf_mbim_set_phonebook_write_save_index = -1;
static int hf_mbim_set_phonebook_write_number_offset = -1;
static int hf_mbim_set_phonebook_write_number_length = -1;
static int hf_mbim_set_phonebook_write_name_offset = -1;
static int hf_mbim_set_phonebook_write_name_length = -1;
static int hf_mbim_set_phonebook_write_number = -1;
static int hf_mbim_set_phonebook_write_name = -1;
static int hf_mbim_set_stk_pac_pac_host_control = -1;
static int hf_mbim_set_stk_pac_pac_host_control_refresh = -1;
static int hf_mbim_set_stk_pac_pac_host_control_more_time = -1;
static int hf_mbim_set_stk_pac_pac_host_control_poll_interval = -1;
static int hf_mbim_set_stk_pac_pac_host_control_polling_off = -1;
static int hf_mbim_set_stk_pac_pac_host_control_set_up_evt_list = -1;
static int hf_mbim_set_stk_pac_pac_host_control_set_up_call = -1;
static int hf_mbim_set_stk_pac_pac_host_control_send_ss = -1;
static int hf_mbim_set_stk_pac_pac_host_control_send_ussd = -1;
static int hf_mbim_set_stk_pac_pac_host_control_send_short_msg = -1;
static int hf_mbim_set_stk_pac_pac_host_control_send_dtmf = -1;
static int hf_mbim_set_stk_pac_pac_host_control_launch_browser = -1;
static int hf_mbim_set_stk_pac_pac_host_control_geo_loc_req = -1;
static int hf_mbim_set_stk_pac_pac_host_control_play_tone = -1;
static int hf_mbim_set_stk_pac_pac_host_control_display_text = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_inkey = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_input = -1;
static int hf_mbim_set_stk_pac_pac_host_control_select_item = -1;
static int hf_mbim_set_stk_pac_pac_host_control_set_up_menu = -1;
static int hf_mbim_set_stk_pac_pac_host_control_prov_local_info = -1;
static int hf_mbim_set_stk_pac_pac_host_control_timer_management = -1;
static int hf_mbim_set_stk_pac_pac_host_control_set_up_idle_mode_text = -1;
static int hf_mbim_set_stk_pac_pac_host_control_perform_card_apdu = -1;
static int hf_mbim_set_stk_pac_pac_host_control_power_on_card = -1;
static int hf_mbim_set_stk_pac_pac_host_control_power_off_card = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_reader_status = -1;
static int hf_mbim_set_stk_pac_pac_host_control_run_at_cmd = -1;
static int hf_mbim_set_stk_pac_pac_host_control_lang_notif = -1;
static int hf_mbim_set_stk_pac_pac_host_control_open_channel = -1;
static int hf_mbim_set_stk_pac_pac_host_control_close_channel = -1;
static int hf_mbim_set_stk_pac_pac_host_control_receive_data = -1;
static int hf_mbim_set_stk_pac_pac_host_control_send_data = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_channel_status = -1;
static int hf_mbim_set_stk_pac_pac_host_control_service_search = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_service_info = -1;
static int hf_mbim_set_stk_pac_pac_host_control_declare_service = -1;
static int hf_mbim_set_stk_pac_pac_host_control_set_frames = -1;
static int hf_mbim_set_stk_pac_pac_host_control_get_frames_status = -1;
static int hf_mbim_set_stk_pac_pac_host_control_retrieve_multimedia_msg = -1;
static int hf_mbim_set_stk_pac_pac_host_control_submit_multimedia_msg = -1;
static int hf_mbim_set_stk_pac_pac_host_control_display_multimedia_msg = -1;
static int hf_mbim_set_stk_pac_pac_host_control_activate = -1;
static int hf_mbim_set_stk_pac_pac_host_control_contactless_state_changed = -1;
static int hf_mbim_set_stk_pac_pac_host_control_cmd_container = -1;
static int hf_mbim_set_stk_pac_pac_host_control_encapsulated_session_ctrl = -1;
static int hf_mbim_set_stk_pac_pac_host_control_end_proact_session = -1;
static int hf_mbim_stk_pac_info_pac_support = -1;
static int hf_mbim_stk_pac_info_pac_support_refresh = -1;
static int hf_mbim_stk_pac_info_pac_support_more_time = -1;
static int hf_mbim_stk_pac_info_pac_support_poll_interval = -1;
static int hf_mbim_stk_pac_info_pac_support_polling_off = -1;
static int hf_mbim_stk_pac_info_pac_support_set_up_evt_list = -1;
static int hf_mbim_stk_pac_info_pac_support_set_up_call = -1;
static int hf_mbim_stk_pac_info_pac_support_send_ss = -1;
static int hf_mbim_stk_pac_info_pac_support_send_ussd = -1;
static int hf_mbim_stk_pac_info_pac_support_send_short_msg = -1;
static int hf_mbim_stk_pac_info_pac_support_send_dtmf = -1;
static int hf_mbim_stk_pac_info_pac_support_launch_browser = -1;
static int hf_mbim_stk_pac_info_pac_support_geo_loc_req = -1;
static int hf_mbim_stk_pac_info_pac_support_play_tone = -1;
static int hf_mbim_stk_pac_info_pac_support_display_text = -1;
static int hf_mbim_stk_pac_info_pac_support_get_inkey = -1;
static int hf_mbim_stk_pac_info_pac_support_get_input = -1;
static int hf_mbim_stk_pac_info_pac_support_select_item = -1;
static int hf_mbim_stk_pac_info_pac_support_set_up_menu = -1;
static int hf_mbim_stk_pac_info_pac_support_prov_local_info = -1;
static int hf_mbim_stk_pac_info_pac_support_timer_management = -1;
static int hf_mbim_stk_pac_info_pac_support_set_up_idle_mode_text = -1;
static int hf_mbim_stk_pac_info_pac_support_perform_card_apdu = -1;
static int hf_mbim_stk_pac_info_pac_support_power_on_card = -1;
static int hf_mbim_stk_pac_info_pac_support_power_off_card = -1;
static int hf_mbim_stk_pac_info_pac_support_get_reader_status = -1;
static int hf_mbim_stk_pac_info_pac_support_run_at_cmd = -1;
static int hf_mbim_stk_pac_info_pac_support_lang_notif = -1;
static int hf_mbim_stk_pac_info_pac_support_open_channel = -1;
static int hf_mbim_stk_pac_info_pac_support_close_channel = -1;
static int hf_mbim_stk_pac_info_pac_support_receive_data = -1;
static int hf_mbim_stk_pac_info_pac_support_send_data = -1;
static int hf_mbim_stk_pac_info_pac_support_get_channel_status = -1;
static int hf_mbim_stk_pac_info_pac_support_service_search = -1;
static int hf_mbim_stk_pac_info_pac_support_get_service_info = -1;
static int hf_mbim_stk_pac_info_pac_support_declare_service = -1;
static int hf_mbim_stk_pac_info_pac_support_set_frames = -1;
static int hf_mbim_stk_pac_info_pac_support_get_frames_status = -1;
static int hf_mbim_stk_pac_info_pac_support_retrieve_multimedia_msg = -1;
static int hf_mbim_stk_pac_info_pac_support_submit_multimedia_msg = -1;
static int hf_mbim_stk_pac_info_pac_support_display_multimedia_msg = -1;
static int hf_mbim_stk_pac_info_pac_support_activate = -1;
static int hf_mbim_stk_pac_info_pac_support_contactless_state_changed = -1;
static int hf_mbim_stk_pac_info_pac_support_cmd_container = -1;
static int hf_mbim_stk_pac_info_pac_support_encapsulated_session_ctrl = -1;
static int hf_mbim_stk_pac_info_pac_support_end_proact_session = -1;
static int hf_mbim_stk_pac_pac_type = -1;
static int hf_mbim_stk_pac_pac = -1;
static int hf_mbim_set_stk_terminal_response_response_length = -1;
static int hf_mbim_set_stk_terminal_response_data_buffer = -1;
static int hf_mbim_stk_terminal_response_info_result_data_string_offset = -1;
static int hf_mbim_stk_terminal_response_info_result_data_string_length = -1;
static int hf_mbim_stk_terminal_response_info_status_word = -1;
static int hf_mbim_stk_terminal_response_info_result_data_string = -1;
static int hf_mbim_set_stk_envelope_data_buffer = -1;
static int hf_mbim_stk_envelope_info_envelope_support = -1;
static int hf_mbim_aka_auth_req_rand = -1;
static int hf_mbim_aka_auth_req_autn = -1;
static int hf_mbim_aka_auth_info_res = -1;
static int hf_mbim_aka_auth_info_res_length = -1;
static int hf_mbim_aka_auth_info_ik = -1;
static int hf_mbim_aka_auth_info_ck = -1;
static int hf_mbim_aka_auth_info_auts = -1;
static int hf_mbim_akap_auth_req_rand = -1;
static int hf_mbim_akap_auth_req_autn = -1;
static int hf_mbim_akap_auth_req_network_name_offset = -1;
static int hf_mbim_akap_auth_req_network_name_length = -1;
static int hf_mbim_akap_auth_req_network_name = -1;
static int hf_mbim_akap_auth_info_res = -1;
static int hf_mbim_akap_auth_info_res_length = -1;
static int hf_mbim_akap_auth_info_ik = -1;
static int hf_mbim_akap_auth_info_ck = -1;
static int hf_mbim_akap_auth_info_auts = -1;
static int hf_mbim_sim_auth_req_rand1 = -1;
static int hf_mbim_sim_auth_req_rand2 = -1;
static int hf_mbim_sim_auth_req_rand3 = -1;
static int hf_mbim_sim_auth_req_n = -1;
static int hf_mbim_sim_auth_info_sres1 = -1;
static int hf_mbim_sim_auth_info_kc1 = -1;
static int hf_mbim_sim_auth_info_sres2 = -1;
static int hf_mbim_sim_auth_info_kc2 = -1;
static int hf_mbim_sim_auth_info_sres3 = -1;
static int hf_mbim_sim_auth_info_kc3 = -1;
static int hf_mbim_sim_auth_info_n = -1;
static int hf_mbim_set_dss_connect_device_service_id = -1;
static int hf_mbim_set_dss_connect_dss_session_id = -1;
static int hf_mbim_set_dss_connect_dss_link_state = -1;
static int hf_mbim_multicarrier_capabilities_info_capabilities = -1;
static int hf_mbim_multicarrier_capabilities_info_capabilities_static_scan = -1;
static int hf_mbim_multicarrier_capabilities_info_capabilities_fw_requires_reboot = -1;
static int hf_mbim_location_info_country = -1;
static int hf_mbim_multicarrier_current_cid_list_req_uuid = -1;
static int hf_mbim_multicarrier_current_cid_list_info_cid_count = -1;
static int hf_mbim_multicarrier_current_cid_list_info_cid = -1;
static int hf_mbim_msfwid_firmwareid_info_firmware_id = -1;
static int hf_mbim_qmi_buffer = -1;
static int hf_mbim_thermal_config_enable = -1;
static int hf_mbim_thermal_config_temp_sensor_id = -1;
static int hf_mbim_thermal_config_alarm_id = -1;
static int hf_mbim_thermal_config_threshold_value = -1;
static int hf_mbim_thermal_config_hyst_value = -1;
static int hf_mbim_thermal_config_sampling_period = -1;
static int hf_mbim_query_thermal_state_temp_sensor_id = -1;
static int hf_mbim_thermal_state_info_current_temp_value = -1;
static int hf_mbim_thermal_state_info_enable = -1;
static int hf_mbim_thermal_state_info_temp_sensor_id = -1;
static int hf_mbim_thermal_state_info_alarm_id = -1;
static int hf_mbim_thermal_state_info_threshold_value = -1;
static int hf_mbim_thermal_state_info_hyst_value = -1;
static int hf_mbim_thermal_state_info_sampling_period = -1;
static int hf_mbim_sar_config_sar_status = -1;
static int hf_mbim_sar_config_level = -1;
static int hf_mbim_ms_sar_config_sar_mode = -1;
static int hf_mbim_ms_sar_config_sar_backoff_status = -1;
static int hf_mbim_ms_sar_config_sar_wifi_Integration = -1;
static int hf_mbim_ms_sar_config_element_count = -1;
static int hf_mbim_ms_sar_config_element_offset = -1;
static int hf_mbim_ms_sar_config_element_size = -1;
static int hf_mbim_ms_sar_config_state_sar_antenna_index = -1;
static int hf_mbim_ms_sar_config_state_sar_backoff_index = -1;
static int hf_mbim_ms_transmission_status_channel_notification = -1;
static int hf_mbim_ms_transmission_status_transmission_status = -1;
static int hf_mbim_ms_transmission_status_hysteresis_timer = -1;
static int hf_mbim_adpclk_activate_state = -1;
static int hf_mbim_adpclk_freq_info_elem_count = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_offset = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_size = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_center_freq = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_freq_spread = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_noise_power = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_rssi = -1;
static int hf_mbim_adpclk_freq_info_adpclk_freq_value_connect_status = -1;
static int hf_mbim_trace_config_config = -1;
static int hf_mbim_nrtc_app_info_period = -1;
static int hf_mbim_nrtc_app_info_duration = -1;
static int hf_mbim_nrtcws_config_mode = -1;
static int hf_mbim_nrtcws_config_wlan_active = -1;
static int hf_mbim_nrtcws_config_wlan_safe_rx = -1;
static int hf_mbim_nrtcws_config_wlan_bandwidth = -1;
static int hf_mbim_nrtcws_config_bt_active = -1;
static int hf_mbim_nrtcws_config_bt_safe_rx = -1;
static int hf_mbim_nrtcws_info_lte_active = -1;
static int hf_mbim_nrtcws_info_wlan_safe_rx_min = -1;
static int hf_mbim_nrtcws_info_wlan_safe_rx_max = -1;
static int hf_mbim_nrtcws_info_bt_safe_rx_min = -1;
static int hf_mbim_nrtcws_info_bt_safe_rx_max = -1;
static int hf_mbim_nrtcws_info_lte_sps_period = -1;
static int hf_mbim_nrtcws_info_lte_sps_duration = -1;
static int hf_mbim_nrtcws_info_lte_sps_initial_offset = -1;
static int hf_mbim_usbprofile_cmd_length = -1;
static int hf_mbim_usbprofile_cmd_buffer = -1;
static int hf_mbim_usbprofile_rsp_length = -1;
static int hf_mbim_usbprofile_rsp_buffer = -1;
static int hf_mbim_ciq_set_mode = -1;
static int hf_mbim_ciq_set_debug_info_size = -1;
static int hf_mbim_ciq_set_debug_info = -1;
static int hf_mbim_ciq_info_mode = -1;
static int hf_mbim_atds_signal_info_rssi = -1;
static int hf_mbim_atds_signal_info_ber = -1;
static int hf_mbim_atds_signal_info_rscp = -1;
static int hf_mbim_atds_signal_info_ecno = -1;
static int hf_mbim_atds_signal_info_rsrq = -1;
static int hf_mbim_atds_signal_info_rsrp = -1;
static int hf_mbim_atds_signal_info_rssnr = -1;
static int hf_mbim_atds_location_info_lac = -1;
static int hf_mbim_atds_location_info_tac = -1;
static int hf_mbim_atds_location_info_cellid = -1;
static int hf_mbim_atds_operator_provider_id_offset = -1;
static int hf_mbim_atds_operator_provider_id_size = -1;
static int hf_mbim_atds_operator_provider_state = -1;
static int hf_mbim_atds_operator_provider_name_offset = -1;
static int hf_mbim_atds_operator_provider_name_size = -1;
static int hf_mbim_atds_operator_plmn_mode = -1;
static int hf_mbim_atds_operator_rssi = -1;
static int hf_mbim_atds_operator_error_rate = -1;
static int hf_mbim_atds_operator_provider_id = -1;
static int hf_mbim_atds_operator_provider_name = -1;
static int hf_mbim_atds_operators_elem_count = -1;
static int hf_mbim_atds_operators_operator_offset = -1;
static int hf_mbim_atds_operators_operator_size = -1;
static int hf_mbim_atds_rat_info_mode = -1;
static int hf_mbim_atds_projection_table_type = -1;
static int hf_mbim_atds_projection_table_bar5min = -1;
static int hf_mbim_atds_projection_table_a5 = -1;
static int hf_mbim_atds_projection_table_b5 = -1;
static int hf_mbim_atds_projection_table_bar4min = -1;
static int hf_mbim_atds_projection_table_a4 = -1;
static int hf_mbim_atds_projection_table_b4 = -1;
static int hf_mbim_atds_projection_table_bar3min = -1;
static int hf_mbim_atds_projection_table_a3 = -1;
static int hf_mbim_atds_projection_table_b3 = -1;
static int hf_mbim_atds_projection_table_bar2min = -1;
static int hf_mbim_atds_projection_table_a2 = -1;
static int hf_mbim_atds_projection_table_b2 = -1;
static int hf_mbim_atds_projection_table_bar1min = -1;
static int hf_mbim_atds_projection_table_a1 = -1;
static int hf_mbim_atds_projection_table_b1 = -1;
static int hf_mbim_atds_projection_table_bar0min = -1;
static int hf_mbim_atds_projection_table_a0 = -1;
static int hf_mbim_atds_projection_table_b0 = -1;
static int hf_mbim_atds_projection_tables_elem_count = -1;
static int hf_mbim_atds_projection_tables_projection_table_offset = -1;
static int hf_mbim_atds_projection_tables_projection_table_size = -1;
static int hf_mbim_multiflow_caps_info_control_caps = -1;
static int hf_mbim_multiflow_caps_info_control_caps_uplink = -1;
static int hf_mbim_multiflow_caps_info_control_caps_downlink = -1;
static int hf_mbim_set_multiflow_state_state = -1;
static int hf_mbim_multiflow_state_info_state = -1;
static int hf_mbim_multiflow_tft_info_session_id = -1;
static int hf_mbim_multiflow_tft_info_elem_count = -1;
static int hf_mbim_multiflow_tft_info_tft_list_offset = -1;
static int hf_mbim_multiflow_tft_info_tft_list_size = -1;
static int hf_mbim_version = -1;
static int hf_mbim_extended_version = -1;
static int hf_mbim_set_ms_provisioned_context_v2_operation = -1;
static int hf_mbim_set_ms_provisioned_context_v2_ip_type = -1;
static int hf_mbim_set_ms_provisioned_context_v2_enable = -1;
static int hf_mbim_set_ms_provisioned_context_v2_roaming = -1;
static int hf_mbim_set_ms_provisioned_context_v2_media_type = -1;
static int hf_mbim_set_ms_provisioned_context_v2_source = -1;
static int hf_mbim_set_ms_provisioned_context_v2_access_string = -1;
static int hf_mbim_set_ms_provisioned_context_v2_access_string_offset = -1;
static int hf_mbim_set_ms_provisioned_context_v2_access_string_size = -1;
static int hf_mbim_set_ms_provisioned_context_v2_user_name = -1;
static int hf_mbim_set_ms_provisioned_context_v2_user_name_offset = -1;
static int hf_mbim_set_ms_provisioned_context_v2_user_name_size = -1;
static int hf_mbim_set_ms_provisioned_context_v2_password = -1;
static int hf_mbim_set_ms_provisioned_context_v2_password_offset = -1;
static int hf_mbim_set_ms_provisioned_context_v2_password_size = -1;
static int hf_mbim_set_ms_provisioned_context_v2_compression = -1;
static int hf_mbim_set_ms_provisioned_context_v2_auth_protocol = -1;
static int hf_mbim_ms_provisioned_context_info_v2_elem_count = -1;
static int hf_mbim_ms_provisioned_context_info_v2_list_offset = -1;
static int hf_mbim_ms_provisioned_context_info_v2_list_size = -1;
static int hf_mbim_ms_provisioned_context_info_v2_context_id = -1;
static int hf_mbim_ms_network_blacklist_info_blacklist_state = -1;
static int hf_mbim_ms_network_blacklist_state_sim_provider_actuated = -1;
static int hf_mbim_ms_network_blacklist_state_network_provider_actuated = -1;
static int hf_mbim_ms_network_blacklist_info_elem_count = -1;
static int hf_mbim_ms_network_blacklist_info_list_offset = -1;
static int hf_mbim_ms_network_blacklist_info_list_size = -1;
static int hf_mbim_ms_network_blacklist_provider_mcc = -1;
static int hf_mbim_ms_network_blacklist_provider_mnc = -1;
static int hf_mbim_ms_network_blacklist_provider_type = -1;
static int hf_mbim_sys_caps_info_number_of_executors = -1;
static int hf_mbim_sys_caps_info_number_of_slots = -1;
static int hf_mbim_sys_caps_info_concurrency = -1;
static int hf_mbim_sys_caps_info_modem_id = -1;
static int hf_mbim_ms_device_slot_mapping_info_map_count = -1;
static int hf_mbim_ms_device_slot_mapping_info_map_offset = -1;
static int hf_mbim_ms_device_slot_mapping_info_map_size = -1;
static int hf_mbim_ms_device_slot_mapping_info_executor_slot_index = -1;
static int hf_mbim_ms_slot_info_req_slot_index = -1;
static int hf_mbim_ms_slot_info_slot_index = -1;
static int hf_mbim_ms_slot_info_state = -1;
static int hf_mbim_base_station_max_gsm_count = -1;
static int hf_mbim_base_station_max_umts_count = -1;
static int hf_mbim_base_station_max_td_scdma_count = -1;
static int hf_mbim_base_station_max_lte_count = -1;
static int hf_mbim_base_station_max_cdma_count = -1;
static int hf_mbim_base_station_max_nr_count = -1;
static int hf_mbim_base_station_provider_id_offset = -1;
static int hf_mbim_base_station_provider_id_size = -1;
static int hf_mbim_base_station_location_area_code = -1;
static int hf_mbim_base_station_cell_id = -1;
static int hf_mbim_base_station_timing_advance = -1;
static int hf_mbim_base_station_arfcn = -1;
static int hf_mbim_base_station_base_station_id = -1;
static int hf_mbim_base_station_rx_level = -1;
static int hf_mbim_base_station_provider_id = -1;
static int hf_mbim_base_station_frequency_info_ul = -1;
static int hf_mbim_base_station_frequency_info_dl = -1;
static int hf_mbim_base_station_frequency_info_nt = -1;
static int hf_mbim_base_station_uarfcn = -1;
static int hf_mbim_base_station_primary_scrambling_code = -1;
static int hf_mbim_base_station_rscp = -1;
static int hf_mbim_base_station_ecno = -1;
static int hf_mbim_base_station_path_loss = -1;
static int hf_mbim_base_station_call_parameter = -1;
static int hf_mbim_base_station_earfcn = -1;
static int hf_mbim_base_station_physical_cell_id = -1;
static int hf_mbim_base_station_tac = -1;
static int hf_mbim_base_station_rsrp = -1;
static int hf_mbim_base_station_rsrq = -1;
static int hf_mbim_base_station_serving_cell_flag = -1;
static int hf_mbim_base_station_nid = -1;
static int hf_mbim_base_station_sid = -1;
static int hf_mbim_base_station_base_latitude = -1;
static int hf_mbim_base_station_base_longitude = -1;
static int hf_mbim_base_station_ref_pn = -1;
static int hf_mbim_base_station_gps_seconds = -1;
static int hf_mbim_base_station_pilot_strength = -1;
static int hf_mbim_base_station_nci = -1;
static int hf_mbim_base_station_cell_id_offset = -1;
static int hf_mbim_base_station_cell_id_size = -1;
static int hf_mbim_base_station_sinr = -1;
static int hf_mbim_base_station_cell_id_string = -1;
static int hf_mbim_base_station_system_type = -1;
static int hf_mbim_base_station_system_sub_type = -1;
static int hf_mbim_base_station_gsm_serving_cell_offset = -1;
static int hf_mbim_base_station_gsm_serving_cell_size = -1;
static int hf_mbim_base_station_umts_serving_cell_offset = -1;
static int hf_mbim_base_station_umts_serving_cell_size = -1;
static int hf_mbim_base_station_td_scdma_serving_cell_offset = -1;
static int hf_mbim_base_station_td_scdma_serving_cell_size = -1;
static int hf_mbim_base_station_lte_serving_cell_offset = -1;
static int hf_mbim_base_station_lte_serving_cell_size = -1;
static int hf_mbim_base_station_gsm_nmr_offset = -1;
static int hf_mbim_base_station_gsm_nmr_size = -1;
static int hf_mbim_base_station_umts_mrl_offset = -1;
static int hf_mbim_base_station_umts_mrl_size = -1;
static int hf_mbim_base_station_td_scdma_mrl_offset = -1;
static int hf_mbim_base_station_td_scdma_mrl_size = -1;
static int hf_mbim_base_station_lte_mrl_offset = -1;
static int hf_mbim_base_station_lte_mrl_size = -1;
static int hf_mbim_base_station_cdma_mrl_offset = -1;
static int hf_mbim_base_station_cdma_mrl_size = -1;
static int hf_mbim_base_station_nr_serving_cell_offset = -1;
static int hf_mbim_base_station_nr_serving_cell_size = -1;
static int hf_mbim_base_station_nr_neighbor_cells_offset = -1;
static int hf_mbim_base_station_nr_neighbor_cells_size = -1;
static int hf_mbim_base_station_count = -1;
static int hf_mbim_ms_modem_config_config_status = -1;
static int hf_mbim_ms_registration_params_info_mico_mode = -1;
static int hf_mbim_ms_registration_params_info_drx_params = -1;
static int hf_mbim_ms_registration_params_info_ladn_info = -1;
static int hf_mbim_ms_registration_params_info_default_pdu_hint = -1;
static int hf_mbim_ms_registration_params_info_re_register_if_needed = -1;
static int hf_mbim_ms_network_params_info_mico_indication = -1;
static int hf_mbim_ms_network_params_info_drx_params = -1;
static int hf_mbim_ms_wake_reason_wake_type = -1;
static int hf_mbim_ms_wake_reason_session_id = -1;
static int hf_mbim_ms_wake_reason_command_payload_offset = -1;
static int hf_mbim_ms_wake_reason_command_payload_size = -1;
static int hf_mbim_ms_wake_reason_command_payload = -1;
static int hf_mbim_ms_wake_reason_packet_original_size = -1;
static int hf_mbim_ms_wake_reason_packet_saved_offset = -1;
static int hf_mbim_ms_wake_reason_packet_saved_size = -1;
static int hf_mbim_ms_wake_reason_packet_saved_data = -1;
static int hf_mbim_ms_slot_id = -1;
static int hf_mbim_ms_open_channel_app_id_size = -1;
static int hf_mbim_ms_open_channel_app_id_offset = -1;
static int hf_mbim_ms_open_channel_select_p2_arg = -1;
static int hf_mbim_ms_uicc_channel_group = -1;
static int hf_mbim_ms_open_channel_app_id = -1;
static int hf_mbim_ms_uicc_status = -1;
static int hf_mbim_ms_uicc_channel = -1;
static int hf_mbim_ms_uicc_response_length = -1;
static int hf_mbim_ms_uicc_response_offset = -1;
static int hf_mbim_ms_uicc_response = -1;
static int hf_mbim_ms_apdu_secure_messaging = -1;
static int hf_mbim_ms_apdu_type = -1;
static int hf_mbim_ms_apdu_command_size = -1;
static int hf_mbim_ms_apdu_command_offset = -1;
static int hf_mbim_ms_apdu_command = -1;
static int hf_mbim_ms_terminal_capability_count = -1;
static int hf_mbim_ms_terminal_capability_offset = -1;
static int hf_mbim_ms_terminal_capability_size = -1;
static int hf_mbim_ms_terminal_capability = -1;
static int hf_mbim_ms_reset_pass_through_action = -1;
static int hf_mbim_ms_atr_info_atr_offset = -1;
static int hf_mbim_ms_atr_info_atr_size = -1;
static int hf_mbim_ms_app_info_app_type = -1;
static int hf_mbim_ms_app_info_app_id_offset = -1;
static int hf_mbim_ms_app_info_app_id_size = -1;
static int hf_mbim_ms_app_info_app_id = -1;
static int hf_mbim_ms_app_info_app_name_offset = -1;
static int hf_mbim_ms_app_info_app_name_size = -1;
static int hf_mbim_ms_app_info_app_name = -1;
static int hf_mbim_ms_app_info_num_pins = -1;
static int hf_mbim_ms_app_info_pin_ref_offset = -1;
static int hf_mbim_ms_app_info_pin_ref_size = -1;
static int hf_mbim_ms_app_info_pin_ref = -1;
static int hf_mbim_ms_app_list_version = -1;
static int hf_mbim_ms_app_list_app_count = -1;
static int hf_mbim_ms_app_list_active_app_index = -1;
static int hf_mbim_ms_app_list_size = -1;
static int hf_mbim_ms_app_list_app_info_offset = -1;
static int hf_mbim_ms_app_list_app_info_size = -1;
static int hf_mbim_ms_file_path_version = -1;
static int hf_mbim_ms_file_path_app_id_offset = -1;
static int hf_mbim_ms_file_path_app_id_size = -1;
static int hf_mbim_ms_file_path_file_path_offset = -1;
static int hf_mbim_ms_file_path_file_path_size = -1;
static int hf_mbim_ms_file_path_app_id = -1;
static int hf_mbim_ms_file_path_file_path = -1;
static int hf_mbim_ms_file_status_version = -1;
static int hf_mbim_ms_file_status_status_word_1 = -1;
static int hf_mbim_ms_file_status_status_word_2 = -1;
static int hf_mbim_ms_file_status_file_accessibility = -1;
static int hf_mbim_ms_file_status_file_type = -1;
static int hf_mbim_ms_file_status_file_structure = -1;
static int hf_mbim_ms_file_status_item_count = -1;
static int hf_mbim_ms_file_status_size = -1;
static int hf_mbim_ms_file_status_file_lock_status = -1;
static int hf_mbim_ms_response_version = -1;
static int hf_mbim_ms_response_status_word_1 = -1;
static int hf_mbim_ms_response_status_word_2 = -1;
static int hf_mbim_ms_response_response_data_offset = -1;
static int hf_mbim_ms_response_response_data_size = -1;
static int hf_mbim_ms_response_response_data = -1;
static int hf_mbim_ms_access_binary_version = -1;
static int hf_mbim_ms_access_binary_app_id_offset = -1;
static int hf_mbim_ms_access_binary_app_id_size = -1;
static int hf_mbim_ms_access_binary_file_path_offset = -1;
static int hf_mbim_ms_access_binary_file_path_size = -1;
static int hf_mbim_ms_access_binary_file_offset = -1;
static int hf_mbim_ms_access_binary_number_of_bytes = -1;
static int hf_mbim_ms_access_binary_local_pin_offset = -1;
static int hf_mbim_ms_access_binary_local_pin_size = -1;
static int hf_mbim_ms_access_binary_binary_data_offset = -1;
static int hf_mbim_ms_access_binary_binary_data_size = -1;
static int hf_mbim_ms_access_binary_app_id = -1;
static int hf_mbim_ms_access_binary_file_path = -1;
static int hf_mbim_ms_access_binary_local_pin = -1;
static int hf_mbim_ms_access_binary_binary_data = -1;
static int hf_mbim_ms_access_record_version = -1;
static int hf_mbim_ms_access_record_app_id_offset = -1;
static int hf_mbim_ms_access_record_app_id_size = -1;
static int hf_mbim_ms_access_record_file_path_offset = -1;
static int hf_mbim_ms_access_record_file_path_size = -1;
static int hf_mbim_ms_access_record_record_number = -1;
static int hf_mbim_ms_access_record_local_pin_offset = -1;
static int hf_mbim_ms_access_record_local_pin_size = -1;
static int hf_mbim_ms_access_record_record_data_offset = -1;
static int hf_mbim_ms_access_record_record_data_size = -1;
static int hf_mbim_ms_access_record_app_id = -1;
static int hf_mbim_ms_access_record_file_path = -1;
static int hf_mbim_ms_access_record_local_pin = -1;
static int hf_mbim_ms_access_record_record_data = -1;
static int hf_mbim_fragmented_payload = -1;
static int hf_mbim_request_in = -1;
static int hf_mbim_response_in = -1;
static int hf_mbim_descriptor = -1;
static int hf_mbim_descriptor_version = -1;
static int hf_mbim_descriptor_max_control_message = -1;
static int hf_mbim_descriptor_number_filters = -1;
static int hf_mbim_descriptor_max_filter_size = -1;
static int hf_mbim_descriptor_max_segment_size = -1;
static int hf_mbim_descriptor_network_capabilities = -1;
static int hf_mbim_descriptor_network_capabilities_max_datagram_size = -1;
static int hf_mbim_descriptor_network_capabilities_ntb_input_size = -1;
static int hf_mbim_descriptor_extended_version = -1;
static int hf_mbim_descriptor_max_outstanding_command_messages = -1;
static int hf_mbim_descriptor_mtu = -1;
static int hf_mbim_bulk = -1;
static int hf_mbim_bulk_nth_signature = -1;
static int hf_mbim_bulk_nth_header_length = -1;
static int hf_mbim_bulk_nth_sequence_number = -1;
static int hf_mbim_bulk_nth_block_length = -1;
static int hf_mbim_bulk_nth_block_length_32 = -1;
static int hf_mbim_bulk_nth_ndp_index = -1;
static int hf_mbim_bulk_nth_ndp_index_32 = -1;
static int hf_mbim_bulk_ndp_signature = -1;
static int hf_mbim_bulk_ndp_signature_ips_session_id = -1;
static int hf_mbim_bulk_ndp_signature_ipc_session_id = -1;
static int hf_mbim_bulk_ndp_signature_dss_session_id = -1;
static int hf_mbim_bulk_ndp_signature_dsc_session_id = -1;
static int hf_mbim_bulk_ndp_length = -1;
static int hf_mbim_bulk_ndp_next_ndp_index = -1;
static int hf_mbim_bulk_ndp_next_ndp_index_32 = -1;
static int hf_mbim_bulk_ndp_reserved = -1;
static int hf_mbim_bulk_ndp_reserved2 = -1;
static int hf_mbim_bulk_ndp_datagram_index = -1;
static int hf_mbim_bulk_ndp_datagram_index_32 = -1;
static int hf_mbim_bulk_ndp_datagram_length = -1;
static int hf_mbim_bulk_ndp_datagram_length_32 = -1;
static int hf_mbim_bulk_ndp_datagram = -1;
static int hf_mbim_bulk_ndp_nb_datagrams = -1;
static int hf_mbim_bulk_total_nb_datagrams = -1;
static int hf_mbim_bulk_ndp_ctrl = -1;
static int hf_mbim_bulk_ndp_ctrl_message_type = -1;
static int hf_mbim_bulk_ndp_ctrl_message_length = -1;
static int hf_mbim_bulk_ndp_ctrl_multiflow_status = -1;
static int hf_mbim_bulk_ndp_ctrl_multiflow_watermark = -1;
static int hf_mbim_bulk_ndp_ctrl_message_payload = -1;
static int hf_mbim_fragments = -1;
static int hf_mbim_fragment = -1;
static int hf_mbim_fragment_overlap = -1;
static int hf_mbim_fragment_overlap_conflict = -1;
static int hf_mbim_fragment_multiple_tails = -1;
static int hf_mbim_fragment_too_long_fragment = -1;
static int hf_mbim_fragment_error = -1;
static int hf_mbim_fragment_count = -1;
static int hf_mbim_reassembled_in = -1;
static int hf_mbim_reassembled_length = -1;
static int hf_mbim_reassembled_data = -1;

static expert_field ei_mbim_max_ctrl_transfer = EI_INIT;
static expert_field ei_mbim_unexpected_msg = EI_INIT;
static expert_field ei_mbim_unexpected_info_buffer = EI_INIT;
static expert_field ei_mbim_illegal_on_link_prefix_length = EI_INIT;
static expert_field ei_mbim_unknown_sms_format = EI_INIT;
static expert_field ei_mbim_unexpected_uuid_value = EI_INIT;
static expert_field ei_mbim_too_many_items = EI_INIT;
static expert_field ei_mbim_alignment_error = EI_INIT;
static expert_field ei_mbim_invalid_block_len = EI_INIT;
static expert_field ei_mbim_out_of_bounds_index = EI_INIT;
static expert_field ei_mbim_oversized_string = EI_INIT;
static expert_field ei_mbim_oversized_pdu = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_mbim = -1;
static gint ett_mbim_msg_header = -1;
static gint ett_mbim_frag_header = -1;
static gint ett_mbim_info_buffer = -1;
static gint ett_mbim_bitmap = -1;
static gint ett_mbim_pair_list = -1;
static gint ett_mbim_pin = -1;
static gint ett_mbim_buffer = -1;
static gint ett_mbim_sc_address = -1;
static gint ett_mbim_pac = -1;
static gint ett_mbim_thermal_threshold_setting = -1;
static gint ett_mbim_fragment = -1;
static gint ett_mbim_fragments = -1;
static gint ett_mbim_bulk_ndp_ctrl = -1;

static dissector_table_t dss_dissector_table;
static dissector_handle_t bertlv_handle;
static dissector_handle_t etsi_cat_handle;
static dissector_handle_t gsm_sms_handle;
static dissector_handle_t cdma_sms_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t eth_fcs_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;
static dissector_handle_t bulk_ndp_ctrl_handle;
static dissector_handle_t mbim_control_handle;
static dissector_handle_t iso7816_atr_handle;

static gboolean mbim_control_decode_unknown_itf = FALSE;

enum {
    SMS_PDU_AUTOMATIC,
    SMS_PDU_3GPP,
    SMS_PDU_3GPP2
};

static const enum_val_t mbim_sms_pdu_format_vals[] = {
    {"automatic", "Automatic", SMS_PDU_AUTOMATIC},
    {"3GPP", "3GPP", SMS_PDU_3GPP},
    {"3GPP2","3GPP2", SMS_PDU_3GPP2},
    {NULL, NULL, -1}
};
static gint mbim_sms_pdu_format = SMS_PDU_AUTOMATIC;

enum mbim_extended_version_vals {
    MBIM_Extended_Version_Unknown,
    MBIM_Extended_Version_1,
    MBIM_Extended_Version_2,
    MBIM_Extended_Version_3,
    MBIM_Extended_Version_4,
};

static const enum_val_t preferred_mbim_extended_version_vals[] = {
    {"1.0", "1.0", MBIM_Extended_Version_1},
    {"2.0", "2.0", MBIM_Extended_Version_2},
    {"3.0", "3.0", MBIM_Extended_Version_3},
    {"4.0", "4.0", MBIM_Extended_Version_4},
    {NULL, NULL, -1}
};
static gint preferred_mbim_extended_version = MBIM_Extended_Version_1;

#define SHOULD_MBIM_EX2_BE_APPLIED(mbim_conv) \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_2 || \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_Unknown && preferred_mbim_extended_version == MBIM_Extended_Version_2)) ? 1 : 0

#define SHOULD_MBIM_EX2_AND_HIGHER_BE_APPLIED(mbim_conv) \
            (mbim_conv->mbim_extended_version >= MBIM_Extended_Version_2 || \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_Unknown && preferred_mbim_extended_version >= MBIM_Extended_Version_2)) ? 1 : 0

#define SHOULD_MBIM_EX3_BE_APPLIED(mbim_conv) \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_3 || \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_Unknown && preferred_mbim_extended_version == MBIM_Extended_Version_3)) ? 1 : 0

#define SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv) \
            (mbim_conv->mbim_extended_version >= MBIM_Extended_Version_3 || \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_Unknown && preferred_mbim_extended_version >= MBIM_Extended_Version_3)) ? 1 : 0

#define SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv) \
            (mbim_conv->mbim_extended_version >= MBIM_Extended_Version_4 || \
            (mbim_conv->mbim_extended_version == MBIM_Extended_Version_Unknown && preferred_mbim_extended_version >= MBIM_Extended_Version_4)) ? 1 : 0

#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~(((int)(Pow2))-1)) )

static reassembly_table mbim_reassembly_table;

static wmem_map_t *mbim_uuid_ext_hash = NULL;

static const fragment_items mbim_frag_items = {
    &ett_mbim_fragment,
    &ett_mbim_fragments,
    &hf_mbim_fragments,
    &hf_mbim_fragment,
    &hf_mbim_fragment_overlap,
    &hf_mbim_fragment_overlap_conflict,
    &hf_mbim_fragment_multiple_tails,
    &hf_mbim_fragment_too_long_fragment,
    &hf_mbim_fragment_error,
    &hf_mbim_fragment_count,
    &hf_mbim_reassembled_in,
    &hf_mbim_reassembled_length,
    &hf_mbim_reassembled_data,
    "MBIM fragments"
};

struct mbim_conv_info {
    wmem_map_t *trans;
    wmem_tree_t *open;
    guint32 open_count;
    guint32 cellular_class;
    enum mbim_extended_version_vals mbim_extended_version;
};

struct mbim_pair_list {
    guint32 offset;
    guint32 size;
};

#define MBIM_MAX_ITEMS 1000

#define MBIM_OPEN_MSG            0x00000001
#define MBIM_CLOSE_MSG           0x00000002
#define MBIM_COMMAND_MSG         0x00000003
#define MBIM_HOST_ERROR_MSG      0x00000004
#define MBIM_OPEN_DONE           0x80000001
#define MBIM_CLOSE_DONE          0x80000002
#define MBIM_COMMAND_DONE        0x80000003
#define MBIM_FUNCTION_ERROR_MSG  0x80000004
#define MBIM_INDICATE_STATUS_MSG 0x80000007

static const value_string mbim_msg_type_vals[] = {
    { MBIM_OPEN_MSG, "OPEN_MSG"},
    { MBIM_CLOSE_MSG, "CLOSE_MSG"},
    { MBIM_COMMAND_MSG, "COMMAND_MSG"},
    { MBIM_HOST_ERROR_MSG, "HOST_ERROR_MSG"},
    { MBIM_OPEN_DONE, "OPEN_DONE"},
    { MBIM_CLOSE_DONE, "CLOSE_DONE"},
    { MBIM_COMMAND_DONE, "COMMAND_DONE"},
    { MBIM_FUNCTION_ERROR_MSG, "FUNCTION_ERROR_MSG"},
    { MBIM_INDICATE_STATUS_MSG, "INDICATE_STATUS_MSG"},
    { 0, NULL}
};

static const value_string mbim_command_type_vals[] = {
    { MBIM_COMMAND_QUERY, "Query"},
    { MBIM_COMMAND_SET, "Set"},
    { 0, NULL}
};

static const value_string mbim_error_status_code_vals[] = {
    { 1, "TIMEOUT_FRAGMENT"},
    { 2, "FRAGMENT_OUT_OF_SEQUENCE"},
    { 3, "LENGTH_MISMATCH"},
    { 4, "DUPLICATED_TID"},
    { 5, "NOT_OPENED"},
    { 6, "UNKNOWN"},
    { 7, "CANCEL"},
    { 8, "MAX_TRANSFER"},
    { 0, NULL}
};

static const value_string mbim_status_code_vals[] = {
    {   0, "SUCCESS"},
    {   1, "BUSY"},
    {   2, "FAILURE"},
    {   3, "SIM_NOT_INSERTED"},
    {   4, "BAD_SIM"},
    {   5, "PIN_REQUIRED"},
    {   6, "PIN_DISABLED"},
    {   7, "NOT_REGISTERED"},
    {   8, "PROVIDERS_NOT_FOUND"},
    {   9, "NO_DEVICE_SUPPORT"},
    {  10, "PROVIDER_NOT_VISIBLE"},
    {  11, "DATA_CLASS_NOT_AVAILABLE"},
    {  12, "PACKET_SERVICE_DETACHED"},
    {  13, "MAX_ACTIVATED_CONTEXTS"},
    {  14, "NOT_INITIALIZED"},
    {  15, "VOICE_CALL_IN_PROGRESS"},
    {  16, "CONTEXT_NOT_ACTIVATED"},
    {  17, "SERVICE_NOT_ACTIVATED"},
    {  18, "INVALID_ACCESS_STRING"},
    {  19, "INVALID_USER_NAME_PWD"},
    {  20, "RADIO_POWER_OFF"},
    {  21, "INVALID_PARAMETERS"},
    {  22, "READ_FAILURE"},
    {  23, "WRITE_FAILURE"},
    {  24, "Reserved"},
    {  25, "NO_PHONEBOOK"},
    {  26, "PARAMETER_TOO_LONG"},
    {  27, "STK_BUSY"},
    {  28, "OPERATION_NOT_ALLOWED"},
    {  29, "MEMORY_FAILURE"},
    {  30, "INVALID_MEMORY_INDEX"},
    {  31, "MEMORY_FULL"},
    {  32, "FILTER_NOT_SUPPORTED"},
    {  33, "DSS_INSTANCE_LIMIT"},
    {  34, "INVALID_DEVICE_SERVICE_OPERATION"},
    {  35, "AUTH_INCORRECT_AUTN"},
    {  36, "AUTH_SYNC_FAILURE"},
    {  37, "AUTH_AMF_NOT_SET"},
    {  38, "CONTEXT_NOT_SUPPORTED"},
    {  39, "SHAREABILITY_CONDITION_ERROR"},
    {  40, "PIN_FAILURE"},
    {  41, "NO_LTE_ATTACH_CONFIG"},
    {  42, "SESSION_ALREADY_EXISTS"},
    { 100, "SMS_UNKNOWN_SMSC_ADDRESS"},
    { 101, "SMS_NETWORK_TIMEOUT"},
    { 102, "SMS_LANG_NOT_SUPPORTED"},
    { 103, "SMS_ENCODING_NOT_SUPPORTED"},
    { 104, "SMS_FORMAT_NOT_SUPPORTED"},
    { 105, "SMS_MORE_DATA"},
    { 200, "MATCHING_PDU_SESSION_FOUND"},
    { 201, "DISSOCIATION_NEEDED_FOR_APPLICATION"},
    { 202, "ERROR_INVALID_SLOT"},
    { 203, "NO_MATCHING_URSP_RULE"},
    { 204, "DEFAULT_URSP_RULE"},
    { 0x87430001, "UICC_NO_LOGICAL_CHANNELS"},
    { 0x87430002, "UICC_SELECT_FAILED"},
    { 0x87430003, "UICC_INVALID_LOGICAL_CHANNEL"},
    { 0, NULL}
};
static value_string_ext mbim_status_code_vals_ext = VALUE_STRING_EXT_INIT(mbim_status_code_vals);

struct mbim_uuid {
    guint8 service_idx;
    e_guid_t uuid;
};

#define UUID_BASIC_CONNECT              0
#define UUID_SMS                        1
#define UUID_USSD                       2
#define UUID_PHONEBOOK                  3
#define UUID_STK                        4
#define UUID_AUTH                       5
#define UUID_DSS                        6
#define UUID_MULTICARRIER               7
#define UUID_MS_HOSTSHUTDOWN            8
#define UUID_MSFWID                     9
#define UUID_QMI                       10 /* Qualcomm proprietary UUID */
#define UUID_INTEL_FWUSVC              11 /* Intel  firmware update service proprietary UUID */
#define UUID_INTEL_DPTF                12 /* Intel proprietary UUID */
#define UUID_INTEL_SAR                 13 /* Intel proprietary UUID */
#define UUID_INTEL_ACT                 14 /* Intel adaptive clocking proprietary UUID */
#define UUID_INTEL_TRCSVC              15 /* Intel trace service proprietary UUID */
#define UUID_INTEL_NRTC                16 /* Intel proprietary UUID */
#define UUID_INTEL_USB_PROFILE         17 /* Intel USB profile proprietary UUID */
#define UUID_INTEL_CIQ                 18 /* Intel proprietary UUID */
#define UUID_ATDS                      19 /* AT&T extensions proprietary UUID */
#define UUID_MULTIFLOW                 20
#define UUID_BASIC_CONNECT_EXTENSIONS  21 /* Microsoft */
#define UUID_MS_SARCONTROL             22 /* Microsoft */
#define UUID_MS_UICC_LOW_LEVEL         23
#define UUID_MAX                       24
#define UUID_EXT_IDX                  255

static const struct mbim_uuid mbim_uuid_service_id_vals[UUID_MAX] = {
    { UUID_BASIC_CONNECT, {0xa289cc33, 0xbcbb, 0x8b4f, { 0xb6, 0xb0, 0x13, 0x3e, 0xc2, 0xaa, 0xe6, 0xdf}}},
    { UUID_SMS, {0x533fbeeb, 0x14fe, 0x4467, {0x9f, 0x90, 0x33, 0xa2, 0x23, 0xe5, 0x6c, 0x3f}}},
    { UUID_USSD, {0xe550a0c8, 0x5e82, 0x479e, {0x82, 0xf7, 0x10, 0xab, 0xf4, 0xc3, 0x35, 0x1f}}},
    { UUID_PHONEBOOK, {0x4bf38476, 0x1e6a, 0x41db, {0xb1, 0xd8, 0xbe, 0xd2, 0x89, 0xc2, 0x5b, 0xdb}}},
    { UUID_STK, {0xd8f20131, 0xfcb5, 0x4e17, {0x86, 0x02, 0xd6, 0xed, 0x38, 0x16, 0x16, 0x4c}}},
    { UUID_AUTH, {0x1d2b5ff7, 0x0aa1, 0x48b2, {0xaa, 0x52, 0x50, 0xf1, 0x57, 0x67, 0x17, 0x4e}}},
    { UUID_DSS, {0xc08a26dd, 0x7718, 0x4382, {0x84, 0x82, 0x6e, 0x0d, 0x58, 0x3c, 0x4d, 0x0e}}},
    { UUID_MULTICARRIER, {0x8b569648, 0x628d, 0x4653, {0x9b, 0x9f, 0x10, 0x25, 0x40, 0x44, 0x24, 0xe1}}},
    { UUID_MS_HOSTSHUTDOWN, {0x883b7c26, 0x985f, 0x43fa, {0x98, 0x04, 0x27, 0xd7, 0xfb, 0x80, 0x95, 0x9c}}},
    { UUID_MSFWID, {0xe9f7dea2, 0xfeaf, 0x4009, {0x93, 0xce, 0x90, 0xa3, 0x69, 0x41, 0x03, 0xb6}}},
    { UUID_QMI, {0xd1a30bc2, 0xf97a, 0x6e43, {0xbf, 0x65, 0xc7, 0xe2, 0x4f, 0xb0, 0xf0, 0xd3}}},
    { UUID_INTEL_FWUSVC, {0x0ed374cb, 0xf835, 0x4474, {0xbc, 0x11, 0x3b, 0x3f, 0xd7, 0x6f, 0x56, 0x41}}},
    { UUID_INTEL_DPTF, {0xfdc22af2, 0xf441, 0x4d46, {0xaf, 0x8d, 0x25, 0x9f, 0xcd, 0xde, 0x46, 0x35}}},
    { UUID_INTEL_SAR, {0x10e40d69, 0x375a, 0x42ce, {0xa2, 0x97, 0x90, 0x61, 0x64, 0xf2, 0x75, 0x4c}}},
    { UUID_INTEL_ACT, {0xed19555d, 0xa6ac, 0x4327, {0x8e, 0xb1, 0xfc, 0x02, 0x2e, 0x5e, 0x23, 0x88}}},
    { UUID_INTEL_TRCSVC, {0x59a7f323, 0xfe5a, 0x4301, {0xb1, 0x85, 0xb8, 0xea, 0x9e, 0x61, 0x67, 0xb7}}},
    { UUID_INTEL_NRTC, {0x2b6d8c5a, 0x0ca9, 0x418f, {0x8a, 0xac, 0x1a, 0x9d, 0xc8, 0xe3, 0x28, 0x66}}},
    { UUID_INTEL_USB_PROFILE, {0xfa142322, 0x166b, 0x4fd9, {0x89, 0xf0, 0x99, 0xbe, 0x90, 0xae, 0x8e, 0x3d}}},
    { UUID_INTEL_CIQ, {0x6A2A8150, 0xABCA, 0x4b11, {0xA4, 0xE2, 0xF2, 0xFC, 0x87, 0x9F, 0x54, 0x81}}},
    { UUID_ATDS, {0x5967bdcc, 0x7fd2, 0x49a2, {0x9f, 0x5c, 0xb2, 0xe7, 0x0e, 0x52, 0x7d, 0xb3}}},
    { UUID_MULTIFLOW, {0x8d8f32d9, 0xf7c2, 0x4419, {0xb2, 0x8b, 0xde, 0xdc, 0xde, 0x20, 0x5e, 0xd8}}},
    { UUID_BASIC_CONNECT_EXTENSIONS, {0x3d01dcc5, 0xfef5, 0x4d05, {0x0d, 0x3a, 0xbe, 0xf7, 0x05, 0x8e, 0x9a, 0xaf}}},
    { UUID_MS_SARCONTROL, {0x68223d04, 0x9f6c, 0x4e0f, {0x82, 0x2d, 0x28, 0x44, 0x1f, 0xb7, 0x23, 0x40}}},
    { UUID_MS_UICC_LOW_LEVEL, {0xc2f6588e, 0xf037, 0x4bc9, {0x86, 0x65, 0xf4, 0xd4, 0x4b, 0xd0, 0x93, 0x67}}}
};

static const value_string mbim_service_id_vals[] = {
    { UUID_BASIC_CONNECT, "UUID_BASIC_CONNECT"},
    { UUID_SMS, "UUID_SMS"},
    { UUID_USSD, "UUID_USSD"},
    { UUID_PHONEBOOK, "UUID_PHONEBOOK"},
    { UUID_STK, "UUID_STK"},
    { UUID_AUTH, "UUID_AUTH"},
    { UUID_DSS, "UUID_DSS"},
    { UUID_MULTICARRIER, "UUID_MULTICARRIER"},
    { UUID_MS_HOSTSHUTDOWN, "UUID_MS_HOSTSHUTDOWN"},
    { UUID_MSFWID, "UUID_MSFWID"},
    { UUID_QMI, "UUID_QMI"},
    { UUID_INTEL_FWUSVC, "UUID_INTEL_FWUSVC"},
    { UUID_INTEL_DPTF, "UUID_INTEL_DPTF"},
    { UUID_INTEL_SAR, "UUID_INTEL_SAR"},
    { UUID_INTEL_ACT, "UUID_INTEL_ACT"},
    { UUID_INTEL_TRCSVC, "UUID_INTEL_TRCSVC"},
    { UUID_INTEL_NRTC, "UUID_INTEL_NRTC"},
    { UUID_INTEL_USB_PROFILE, "UUID_INTEL_USB_PROFILE"},
    { UUID_INTEL_CIQ, "UUID_INTEL_CIQ"},
    { UUID_ATDS, "UUID_ATDS"},
    { UUID_MULTIFLOW, "UUID_MULTIFLOW"},
    { UUID_BASIC_CONNECT_EXTENSIONS, "UUID_BASIC_CONNECT_EXTENSIONS"},
    { UUID_MS_SARCONTROL, "UUID_MS_SARCONTROL"},
    { UUID_MS_UICC_LOW_LEVEL, "UUID_MS_UICC_LOW_LEVEL"},
    { 0, NULL}
};
static value_string_ext mbim_service_id_vals_ext = VALUE_STRING_EXT_INIT(mbim_service_id_vals);

#define MBIM_CID_DEVICE_CAPS                   1
#define MBIM_CID_SUBSCRIBER_READY_STATUS       2
#define MBIM_CID_RADIO_STATE                   3
#define MBIM_CID_PIN                           4
#define MBIM_CID_PIN_LIST                      5
#define MBIM_CID_HOME_PROVIDER                 6
#define MBIM_CID_PREFERRED_PROVIDERS           7
#define MBIM_CID_VISIBLE_PROVIDERS             8
#define MBIM_CID_REGISTER_STATE                9
#define MBIM_CID_PACKET_SERVICE                10
#define MBIM_CID_SIGNAL_STATE                  11
#define MBIM_CID_CONNECT                       12
#define MBIM_CID_PROVISIONED_CONTEXTS          13
#define MBIM_CID_SERVICE_ACTIVATION            14
#define MBIM_CID_IP_CONFIGURATION              15
#define MBIM_CID_DEVICE_SERVICES               16
#define MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST 19
#define MBIM_CID_PACKET_STATISTICS             20
#define MBIM_CID_NETWORK_IDLE_HINT             21
#define MBIM_CID_EMERGENCY_MODE                22
#define MBIM_CID_IP_PACKET_FILTERS             23
#define MBIM_CID_MULTICARRIER_PROVIDERS        24

static const value_string mbim_uuid_basic_connect_cid_vals[] = {
    { MBIM_CID_DEVICE_CAPS, "DEVICE_CAPS"},
    { MBIM_CID_SUBSCRIBER_READY_STATUS, "SUBSCRIBER_READY_STATUS"},
    { MBIM_CID_RADIO_STATE, "RADIO_STATE"},
    { MBIM_CID_PIN, "PIN"},
    { MBIM_CID_PIN_LIST, "PIN_LIST"},
    { MBIM_CID_HOME_PROVIDER, "HOME_PROVIDER"},
    { MBIM_CID_PREFERRED_PROVIDERS, "PREFERRED_PROVIDERS"},
    { MBIM_CID_VISIBLE_PROVIDERS, "VISIBLE_PROVIDERS"},
    { MBIM_CID_REGISTER_STATE, "REGISTER_STATE"},
    { MBIM_CID_PACKET_SERVICE, "PACKET_SERVICE"},
    { MBIM_CID_SIGNAL_STATE, "SIGNAL_STATE"},
    { MBIM_CID_CONNECT, "CONNECT"},
    { MBIM_CID_PROVISIONED_CONTEXTS, "PROVISIONED_CONTEXTS"},
    { MBIM_CID_SERVICE_ACTIVATION, "SERVICE_ACTIVATION"},
    { MBIM_CID_IP_CONFIGURATION, "IP_CONFIGURATION"},
    { MBIM_CID_DEVICE_SERVICES, "DEVICE_SERVICES"},
    { MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST, "DEVICE_SERVICE_SUBSCRIBE_LIST"},
    { MBIM_CID_PACKET_STATISTICS, "PACKET_STATISTICS"},
    { MBIM_CID_NETWORK_IDLE_HINT, "NETWORK_IDLE_HINT"},
    { MBIM_CID_EMERGENCY_MODE, "EMERGENCY_MODE"},
    { MBIM_CID_IP_PACKET_FILTERS, "IP_PACKET_FILTERS"},
    { MBIM_CID_MULTICARRIER_PROVIDERS, "MULTICARRIER_PROVIDERS"},
    { 0, NULL}
};
static value_string_ext mbim_uuid_basic_connect_cid_vals_ext = VALUE_STRING_EXT_INIT(mbim_uuid_basic_connect_cid_vals);

#define MBIM_CID_SMS_CONFIGURATION        1
#define MBIM_CID_SMS_READ                 2
#define MBIM_CID_SMS_SEND                 3
#define MBIM_CID_SMS_DELETE               4
#define MBIM_CID_SMS_MESSAGE_STORE_STATUS 5

static const value_string mbim_uuid_sms_cid_vals[] = {
    { MBIM_CID_SMS_CONFIGURATION, "SMS_CONFIGURATION"},
    { MBIM_CID_SMS_READ, "SMS_READ"},
    { MBIM_CID_SMS_SEND, "SMS_SEND"},
    { MBIM_CID_SMS_DELETE, "SMS_DELETE"},
    { MBIM_CID_SMS_MESSAGE_STORE_STATUS, "SMS_MESSAGE_STORE_STATUS"},
    { 0, NULL}
};

#define MBIM_CID_USSD 1

static const value_string mbim_uuid_ussd_cid_vals[] = {
    { MBIM_CID_USSD, "USSD"},
    { 0, NULL}
};

#define MBIM_CID_PHONEBOOK_CONFIGURATION 1
#define MBIM_CID_PHONEBOOK_READ          2
#define MBIM_CID_PHONEBOOK_DELETE        3
#define MBIM_CID_PHONEBOOK_WRITE         4

static const value_string mbim_uuid_phonebook_cid_vals[] = {
    { MBIM_CID_PHONEBOOK_CONFIGURATION, "PHONEBOOK_CONFIGURATION"},
    { MBIM_CID_PHONEBOOK_READ, "PHONEBOOK_READ"},
    { MBIM_CID_PHONEBOOK_DELETE, "PHONEBOOK_DELETE"},
    { MBIM_CID_PHONEBOOK_WRITE, "PHONEBOOK_WRITE"},
    { 0, NULL}
};

#define MBIM_CID_STK_PAC               1
#define MBIM_CID_STK_TERMINAL_RESPONSE 2
#define MBIM_CID_STK_ENVELOPE          3

static const value_string mbim_uuid_stk_cid_vals[] = {
    { MBIM_CID_STK_PAC, "STK_PAC"},
    { MBIM_CID_STK_TERMINAL_RESPONSE, "STK_TERMINAL_RESPONSE"},
    { MBIM_CID_STK_ENVELOPE, "STK_ENVELOPE"},
    { 0, NULL}
};

#define MBIM_CID_AKA_AUTH  1
#define MBIM_CID_AKAP_AUTH 2
#define MBIM_CID_SIM_AUTH  3

static const value_string mbim_uuid_auth_cid_vals[] = {
    { MBIM_CID_AKA_AUTH, "AKA_AUTH"},
    { MBIM_CID_AKAP_AUTH, "AKAP_AUTH"},
    { MBIM_CID_SIM_AUTH, "SIM_AUTH"},
    { 0, NULL}
};

#define MBIM_CID_DSS_CONNECT 1

static const value_string mbim_uuid_dss_cid_vals[] = {
    { MBIM_CID_DSS_CONNECT, "DSS_CONNECT"},
    { 0, NULL}
};

#define MBIM_CID_MULTICARRIER_CAPABILITIES     1
#define MBIM_CID_LOCATION_INFO                 2
#define MBIM_CID_MULTICARRIER_CURRENT_CID_LIST 3

static const value_string mbim_uuid_multicarrier_cid_vals[] = {
    { MBIM_CID_MULTICARRIER_CAPABILITIES, "MULTICARRIER_CAPABILITIES"},
    { MBIM_CID_LOCATION_INFO, "LOCATION_INFO"},
    { MBIM_CID_MULTICARRIER_CURRENT_CID_LIST, "MULTICARRIER_CURRENT_CID_LIST"},
    { 0, NULL}
};

#define MBIM_CID_MS_HOSTSHUTDOWN    1
#define MBIM_CID_MS_HOSTPRESHUTDOWN 2

static const value_string mbim_uuid_ms_hostshutdown_cid_vals[] = {
    { MBIM_CID_MS_HOSTSHUTDOWN, "MS_HOSTSHUTDOWN"},
    { MBIM_CID_MS_HOSTPRESHUTDOWN, "MS_HOSTPRESHUTDOWN"},
    { 0, NULL}
};

#define MBIM_CID_MSFWID_FIRMWAREID 1

static const value_string mbim_uuid_msfwid_cid_vals[] = {
    { MBIM_CID_MSFWID_FIRMWAREID, "MSFWID_FIRMWAREID"},
    { 0, NULL}
};

#define MBIM_CID_QMI_QMI 1

static const value_string mbim_uuid_qmi_cid_vals[] = {
    { MBIM_CID_QMI_QMI, "QMI"},
    { 0, NULL}
};

#define MBIM_CID_INTC_MODEM_REBOOT 1

static const value_string mbim_uuid_intel_fwusvc_cid_vals[] = {
    { MBIM_CID_INTC_MODEM_REBOOT, "INTC_MODEM_REBOOT"},
    { 0, NULL}
};

#define MBIM_CID_INTC_THERMAL_STATE 0x02000100

static const value_string mbim_uuid_intel_dptf_cid_vals[] = {
    { MBIM_CID_INTC_THERMAL_STATE, "INTC_THERMAL_STATE"},
    { 0, NULL}
};

#define MBIM_CID_INTC_SAR_CONFIG 1

static const value_string mbim_uuid_intel_sar_cid_vals[] = {
    { MBIM_CID_INTC_SAR_CONFIG, "INTC_SAR_CONFIG"},
    { 0, NULL}
};

#define MBIM_CID_INTC_ADPCLK_MODE 0x02000010

static const value_string mbim_uuid_intel_act_cid_vals[] = {
    { MBIM_CID_INTC_ADPCLK_MODE, "INTC_ADPCLK_MODE"},
    { 0, NULL}
};

#define MBIM_CID_INTC_TRACE      1
#define MBIM_CID_INTC_TRACE_DATA 2

static const value_string mbim_uuid_intel_trcsvc_cid_vals[] = {
    { MBIM_CID_INTC_TRACE, "INTC_TRACE"},
    { MBIM_CID_INTC_TRACE_DATA, "INTC_TRACE_DATA"},
    { 0, NULL}
};

#define MBIM_CID_INTC_NRTAPP 1
#define MBIM_CID_INTC_NRTCWS 2

static const value_string mbim_uuid_intel_nrtc_cid_vals[] = {
    { MBIM_CID_INTC_NRTAPP, "INTC_NRTAPP"},
    { MBIM_CID_INTC_NRTCWS, "INTC_NRTCWS"},
    { 0, NULL}
};

#define MBIM_CID_INTC_USBPROFILE 1

static const value_string mbim_uuid_intel_usb_profile_cid_vals[] = {
    { MBIM_CID_INTC_USBPROFILE, "INTC_USBPROFILE"},
    { 0, NULL}
};

#define MBIM_CID_INTC_CIQ 1

static const value_string mbim_uuid_intel_ciq_cid_vals[] = {
    { MBIM_CID_INTC_CIQ, "INTC_CIQ"},
    { 0, NULL}
};

#define MBIM_CID_ATDS_SIGNAL                 1
#define MBIM_CID_ATDS_LOCATION               2
#define MBIM_CID_ATDS_OPERATORS              3
#define MBIM_CID_ATDS_RAT                    4
#define MBIM_CID_ATDS_REGISTER_STATE         9
#define MBIM_CID_ATDS_SET_PROJECTION_TABLES 10

static const value_string mbim_uuid_atds_cid_vals[] = {
    { MBIM_CID_ATDS_SIGNAL, "ATDS_SIGNAL"},
    { MBIM_CID_ATDS_LOCATION, "ATDS_LOCATION"},
    { MBIM_CID_ATDS_OPERATORS, "ATDS_OPERATORS"},
    { MBIM_CID_ATDS_RAT, "ATDS_RAT"},
    { MBIM_CID_ATDS_REGISTER_STATE, "ATDS_REGISTER_STATE"},
    { MBIM_CID_ATDS_SET_PROJECTION_TABLES, "ATDS_SET_PROJECTION_TABLES"},
    { 0, NULL}
};

#define MBIM_CID_MULTIFLOW_CAPS     1
#define MBIM_CID_MULTIFLOW_UPLINK   2
#define MBIM_CID_MULTIFLOW_DOWNLINK 3
#define MBIM_CID_MULTIFLOW_TFT      4

static const value_string mbim_uuid_multiflow_cid_vals[] = {
    { MBIM_CID_MULTIFLOW_CAPS, "MULTIFLOW_CAPS"},
    { MBIM_CID_MULTIFLOW_UPLINK, "MULTIFLOW_UPLINK"},
    { MBIM_CID_MULTIFLOW_DOWNLINK, "MULTIFLOW_DOWNLINK"},
    { MBIM_CID_MULTIFLOW_TFT, "MULTIFLOW_TFT"},
    { 0, NULL}
};

#define MBIM_CID_MS_PROVISIONED_CONTEXT_V2  1
#define MBIM_CID_MS_NETWORK_BLACKLIST       2
#define MBIM_CID_MS_LTE_ATTACH_CONFIG       3
#define MBIM_CID_MS_LTE_ATTACH_STATUS       4
#define MBIM_CID_MS_SYS_CAPS                5
#define MBIM_CID_MS_DEVICE_CAPS_V2          6
#define MBIM_CID_MS_DEVICE_SLOT_MAPPINGS    7
#define MBIM_CID_MS_SLOT_INFO_STATUS        8
#define MBIM_CID_PCO                        9
#define MBIM_CID_MS_DEVICE_RESET           10
#define MBIM_CID_BASE_STATIONS_INFO        11
#define MBIM_CID_LOCATION_INFO_STATUS      12
#define MBIM_CID_MS_MODEM_LOGGING_CONFIG   13
#define MBIM_CID_MS_PIN_INFO_EX2           14
#define MBIM_CID_VERSION                   15
#define MBIM_CID_MS_MODEM_CONFIG           16
#define MBIM_CID_MS_REGISTRATION_PARAMS    17
#define MBIM_CID_MS_NETWORK_PARAMS         18
#define MBIM_CID_MS_WAKE_REASON            19
#define MBIM_CID_MS_UE_POLICY              20

static const value_string mbim_uuid_basic_connect_extensions_cid_vals[] = {
    { MBIM_CID_MS_PROVISIONED_CONTEXT_V2, "MS_PROVISIONED_CONTEXT_V2"},
    { MBIM_CID_MS_NETWORK_BLACKLIST, "MS_NETWORK_BLACKLIST"},
    { MBIM_CID_MS_LTE_ATTACH_CONFIG, "MS_LTE_ATTACH_CONFIG"},
    { MBIM_CID_MS_LTE_ATTACH_STATUS, "MS_LTE_ATTACH_STATUS"},
    { MBIM_CID_MS_SYS_CAPS, "MS_SYS_CAPS"},
    { MBIM_CID_MS_DEVICE_CAPS_V2, "MS_DEVICE_CAPS_V2"},
    { MBIM_CID_MS_DEVICE_SLOT_MAPPINGS, "MS_DEVICE_SLOT_MAPPINGS"},
    { MBIM_CID_MS_SLOT_INFO_STATUS, "MS_SLOT_INFO_STATUS"},
    { MBIM_CID_PCO, "PCO"},
    { MBIM_CID_MS_DEVICE_RESET, "MS_DEVICE_RESET"},
    { MBIM_CID_BASE_STATIONS_INFO, "BASE_STATIONS_INFO"},
    { MBIM_CID_LOCATION_INFO_STATUS, "LOCATION_INFO_STATUS"},
    { MBIM_CID_MS_MODEM_LOGGING_CONFIG, "MS_MODEM_LOGGING_CONFIG"},
    { MBIM_CID_MS_PIN_INFO_EX2, "MS_PIN_INFO_EX2"},
    { MBIM_CID_VERSION, "VERSION"},
    { MBIM_CID_MS_MODEM_CONFIG, "MS_MODEM_CONFIG"},
    { MBIM_CID_MS_REGISTRATION_PARAMS, "MS_REGISTRATION_PARAMS"},
    { MBIM_CID_MS_NETWORK_PARAMS, "MS_NETWORK_PARAMS"},
    { MBIM_CID_MS_WAKE_REASON, "MS_WAKE_REASON"},
    { MBIM_CID_MS_UE_POLICY, "MS_UE_POLICY"},
    { 0, NULL}
};

#define MBIM_CID_MS_SAR_CONFIG          1
#define MBIM_CID_MS_TRANSMISSION_STATUS 2

static const value_string mbim_uuid_ms_sarcontrol_cid_vals[] = {
    { MBIM_CID_MS_SAR_CONFIG, "MS_SAR_CONFIG"},
    { MBIM_CID_MS_TRANSMISSION_STATUS, "MS_TRANSMISSION_STATUS"},
    { 0, NULL}
};

#define MBIM_CID_MS_UICC_ATR                 1
#define MBIM_CID_MS_UICC_OPEN_CHANNEL        2
#define MBIM_CID_MS_UICC_CLOSE_CHANNEL       3
#define MBIM_CID_MS_UICC_APDU                4
#define MBIM_CID_MS_UICC_TERMINAL_CAPABILITY 5
#define MBIM_CID_MS_UICC_RESET               6
#define MBIM_CID_MS_UICC_APP_LIST            7
#define MBIM_CID_MS_UICC_FILE_STATUS         8
#define MBIM_CID_MS_UICC_ACCESS_BINARY       9
#define MBIM_CID_MS_UICC_ACCESS_RECORD      10

static const value_string mbim_uuid_ms_uicc_low_level_cid_vals[] = {
    { MBIM_CID_MS_UICC_ATR, "MS_UICC_ATR" },
    { MBIM_CID_MS_UICC_OPEN_CHANNEL, "MS_UICC_OPEN_CHANNEL" },
    { MBIM_CID_MS_UICC_CLOSE_CHANNEL, "MS_UICC_CLOSE_CHANNEL" },
    { MBIM_CID_MS_UICC_APDU, "MS_UICC_APDU" },
    { MBIM_CID_MS_UICC_TERMINAL_CAPABILITY, "MS_UICC_TERMINAL_CAPABILITY" },
    { MBIM_CID_MS_UICC_RESET, "MS_UICC_RESET" },
    { MBIM_CID_MS_UICC_APP_LIST, "MS_UICC_APP_LIST" },
    { MBIM_CID_MS_UICC_FILE_STATUS, "MS_UICC_FILE_STATUS" },
    { MBIM_CID_MS_UICC_ACCESS_BINARY, "MS_UICC_ACCESS_BINARY" },
    { MBIM_CID_MS_UICC_ACCESS_RECORD, "MS_UICC_ACCESS_RECORD" },
    { 0, NULL}
};

struct mbim_uuid_info_ {
    int *hf_entry;
    const value_string *cid_list;
    value_string_ext *cid_list_ext;
};

static const struct mbim_uuid_info_ mbim_uuid_info[UUID_MAX] = {
    { &hf_mbim_uuid_basic_connect_cid, NULL, &mbim_uuid_basic_connect_cid_vals_ext}, /* UUID_BASIC_CONNECT */
    { &hf_mbim_uuid_sms_cid, mbim_uuid_sms_cid_vals, NULL}, /* UUID_SMS */
    { &hf_mbim_uuid_ussd_cid, mbim_uuid_ussd_cid_vals, NULL}, /* UUID_USSD */
    { &hf_mbim_uuid_phonebook_cid, mbim_uuid_phonebook_cid_vals, NULL}, /* UUID_PHONEBOOK */
    { &hf_mbim_uuid_stk_cid, mbim_uuid_stk_cid_vals, NULL}, /* UUID_STK */
    { &hf_mbim_uuid_auth_cid, mbim_uuid_auth_cid_vals, NULL}, /* UUID_AUTH */
    { &hf_mbim_uuid_dss_cid, mbim_uuid_dss_cid_vals, NULL}, /* UUID_DSS */
    { &hf_mbim_uuid_multicarrier_cid, mbim_uuid_multicarrier_cid_vals, NULL}, /* UUID_MULTICARRIER */
    { &hf_mbim_uuid_ms_hostshutdown_cid, mbim_uuid_ms_hostshutdown_cid_vals, NULL}, /* UUID_MS_HOSTSHUTDOWN */
    { &hf_mbim_uuid_msfwid_cid, mbim_uuid_msfwid_cid_vals, NULL}, /* UUID_MSFWID */
    { &hf_mbim_uuid_qmi_cid, mbim_uuid_qmi_cid_vals, NULL}, /* UUID_QMI */
    { &hf_mbim_uuid_intel_fwusvc_cid, mbim_uuid_intel_fwusvc_cid_vals, NULL}, /* UUID_INTEL_FWUSVC */
    { &hf_mbim_uuid_intel_dptf_cid, mbim_uuid_intel_dptf_cid_vals, NULL}, /* UUID_INTEL_DPTF */
    { &hf_mbim_uuid_intel_sar_cid, mbim_uuid_intel_sar_cid_vals, NULL}, /* UUID_INTEL_SAR */
    { &hf_mbim_uuid_intel_act_cid, mbim_uuid_intel_act_cid_vals, NULL}, /* UUID_INTEL_ACT */
    { &hf_mbim_uuid_intel_trcsvc_cid, mbim_uuid_intel_trcsvc_cid_vals, NULL}, /* UUID_INTEL_TRCSVC */
    { &hf_mbim_uuid_intel_nrtc_cid, mbim_uuid_intel_nrtc_cid_vals, NULL}, /* UUID_INTEL_NRTC */
    { &hf_mbim_uuid_intel_usb_profile_cid, mbim_uuid_intel_usb_profile_cid_vals, NULL}, /* UUID_INTEL_USB_PROFILE */
    { &hf_mbim_uuid_intel_ciq_cid, mbim_uuid_intel_ciq_cid_vals, NULL}, /* UUID_INTEL_CIQ */
    { &hf_mbim_uuid_atds_cid, mbim_uuid_atds_cid_vals, NULL}, /* UUID_ATDS */
    { &hf_mbim_uuid_multiflow_cid, mbim_uuid_multiflow_cid_vals, NULL}, /* UUID_MULTIFLOW */
    { &hf_mbim_uuid_basic_connect_extensions_cid, mbim_uuid_basic_connect_extensions_cid_vals, NULL}, /* UUID_BASIC_CONNECT_EXTENSIONS */
    { &hf_mbim_uuid_ms_sarcontrol_cid, mbim_uuid_ms_sarcontrol_cid_vals, NULL}, /* UUID_MS_SARCONTROL */
    { &hf_mbim_uuid_ms_uicc_low_level_cid, mbim_uuid_ms_uicc_low_level_cid_vals, NULL} /* UUID_MS_UICC_LOW_LEVEL */
};

static const value_string mbim_device_caps_info_device_type_vals[] = {
    { 0, "Unknown"},
    { 1, "Embedded"},
    { 2, "Removable"},
    { 3, "Remote"},
    { 0, NULL}
};

#define MBIM_CELLULAR_CLASS_GSM  1
#define MBIM_CELLULAR_CLASS_CDMA 2

static const value_string mbim_cellular_class_vals[] = {
    { MBIM_CELLULAR_CLASS_GSM, "GSM"},
    { MBIM_CELLULAR_CLASS_CDMA, "CDMA"},
    { 0, NULL}
};

static const value_string mbim_device_caps_info_voice_class_vals[] = {
    { 0, "Unknown"},
    { 1, "No Voice"},
    { 2, "Separate Voice Data"},
    { 3, "Simultaneous Voice Data"},
    { 0, NULL}
};

static const value_string mbim_packet_service_info_frequency_range_vals[] = {
    { 0, "Unknown"},
    { 1, "Range1"},
    { 2, "Range2"},
    { 3, "Range1AndRange2"},
    { 0, NULL}
};

static int * const mbim_device_caps_info_sim_class_fields[] = {
    &hf_mbim_device_caps_info_sim_class_logical,
    &hf_mbim_device_caps_info_sim_class_removable,
    NULL
};

static int * const mbim_data_class_fields[] = {
    &hf_mbim_data_class_gprs,
    &hf_mbim_data_class_edge,
    &hf_mbim_data_class_umts,
    &hf_mbim_data_class_hsdpa,
    &hf_mbim_data_class_hsupa,
    &hf_mbim_data_class_lte,
    &hf_mbim_data_class_5g,
    &hf_mbim_data_class_reserved_gsm,
    &hf_mbim_data_class_1xrtt,
    &hf_mbim_data_class_1xevdo,
    &hf_mbim_data_class_1xevdoreva,
    &hf_mbim_data_class_1xevdv,
    &hf_mbim_data_class_3xrtt,
    &hf_mbim_data_class_1xevdorevb,
    &hf_mbim_data_class_umb,
    &hf_mbim_data_class_reserved_cdma,
    &hf_mbim_data_class_custom,
    NULL
};

static int * const mbim_device_caps_info_sms_caps_fields[] = {
    &hf_mbim_device_caps_info_sms_caps_pdu_receive,
    &hf_mbim_device_caps_info_sms_caps_pdu_send,
    &hf_mbim_device_caps_info_sms_caps_text_receive,
    &hf_mbim_device_caps_info_sms_caps_text_send,
    NULL
};

static int * const mbim_device_caps_info_control_caps_fields[] = {
    &hf_mbim_device_caps_info_control_caps_reg_manual,
    &hf_mbim_device_caps_info_control_caps_hw_radio_switch,
    &hf_mbim_device_caps_info_control_caps_cdma_mobile_ip,
    &hf_mbim_device_caps_info_control_caps_cdma_simple_ip,
    &hf_mbim_device_caps_info_control_caps_multi_carrier,
    &hf_mbim_device_caps_info_control_caps_esim,
    &hf_mbim_device_caps_info_control_caps_ue_policy_route_selection,
    &hf_mbim_device_caps_info_control_caps_sim_hot_swap_capable,
    &hf_mbim_device_caps_info_control_caps_use_ursp_rule_on_epc_capable,
    NULL
};

static int * const mbim_data_subclass_fields[] = {
    &hf_mbim_data_subclass_5gendc,
    &hf_mbim_data_subclass_5gnr,
    &hf_mbim_data_subclass_5gnedc,
    &hf_mbim_data_subclass_5gelte,
    &hf_mbim_data_subclass_5gngendc,
    NULL
};

static const value_string mbim_subscr_ready_status_ready_state_vals[] = {
    { 0, "Not Initialized"},
    { 1, "Initialized"},
    { 2, "SIM Not Inserted"},
    { 3, "Bad SIM"},
    { 4, "Failure"},
    { 5, "Not Activated"},
    { 6, "Device Locked"},
    { 0, NULL}
};

static int * const mbim_subscr_ready_status_flags_fields[] = {
    &hf_mbim_subscr_ready_status_flag_esim,
    &hf_mbim_subscr_ready_status_flag_sim_removability_known,
    &hf_mbim_subscr_ready_status_flag_sim_removable,
    &hf_mbim_subscr_ready_status_flag_sim_slot_active,
    NULL
};

static const value_string mbim_subscr_ready_status_ready_info_vals[] = {
    { 0, "None"},
    { 1, "Protect Unique ID"},
    { 0, NULL}
};

static const value_string mbim_radio_state_vals[] = {
    { 0, "Radio Off"},
    { 1, "Radio On"},
    { 0, NULL}
};

static const value_string mbim_pin_type_vals[] = {
    {  0, "None"},
    {  1, "Custom"},
    {  2, "PIN 1"},
    {  3, "PIN 2"},
    {  4, "Device SIM PIN"},
    {  5, "Device First SIM PIN"},
    {  6, "Network PIN"},
    {  7, "Network Subset PIN"},
    {  8, "Service Provider PIN"},
    {  9, "Corporate PIN"},
    { 10, "Subsidy Lock"},
    { 11, "PUK 1"},
    { 12, "PUK 2"},
    { 13, "Device First SIM PUK"},
    { 14, "Network PUK"},
    { 15, "Network Subset PUK"},
    { 16, "Service Provider PUK"},
    { 17, "Corporate PUK"},
    { 18, "Corporate NEV"},
    { 19, "Corporate ADM"},
    { 0, NULL}
};

static const value_string mbim_pin_operation_vals[] = {
    { 0, "Enter"},
    { 1, "Enable"},
    { 2, "Disable"},
    { 3, "Change"},
    { 0, NULL}
};

static const value_string mbim_pin_state_vals[] = {
    { 0, "Unlocked"},
    { 1, "Locked"},
    { 0, NULL}
};

static const value_string mbim_pin_mode_vals[] = {
    { 0, "Not Supported"},
    { 1, "Enabled"},
    { 2, "Disabled"},
    { 0, NULL}
};

static const value_string mbim_pin_format_vals[] = {
    { 0, "Unknown"},
    { 1, "Numeric"},
    { 2, "Alpha Numeric"},
    { 0, NULL}
};

static const value_string mbim_ms_modem_config_status_vals[] = {
    { 0, "Unknown"},
    { 1, "Started"},
    { 2, "Completed"},
    { 0, NULL}
};

static const value_string mbim_ms_mico_mode_vals[] = {
    { 0, "Disabled"},
    { 1, "Enabled"},
    { 2, "Unsupported"},
    { 3, "Default"},
    { 0, NULL}
};

static const value_string mbim_ms_mico_indication_vals[] = {
    { 0, "Not Allocated"},
    { 1, "Allocated"},
    { 0xffffffff, "Not Available"},
    { 0, NULL}
};
static const value_string mbim_ms_pre_dflt_nssai_info_access_type_vals[] = {
    { 0, "Unknown"},
    { 1, "3GPP"},
    { 2, "Non3GPP"},
    { 0, NULL}
};
static const value_string mbim_ms_default_pdu_hint_vals[] = {
    { 0, "Activation Unlikely"},
    { 1, "Activation Likely"},
    { 0, NULL}
};

static const value_string mbim_ms_ladn_ind_vals[] = {
    { 0, "Info Not Needed"},
    { 1, "Info Requested"},
    { 0, NULL}
};

static const value_string mbim_ms_drx_params_vals[] = {
    { 0, "Not Specified"},
    { 1, "Not Supported"},
    { 2, "Cycle32"},
    { 3, "Cycle64"},
    { 4, "Cycle128"},
    { 5, "Cycle256"},
    { 0, NULL}
};

static const value_string hf_mbim_ms_wake_reason_wake_type_vals[] = {
    { 0, "CID Response"},
    { 1, "CID Indication"},
    { 2, "Packet"},
    { 0, NULL}
};

#define TLV_TYPE_UNKNOWN                        0
#define TLV_TYPE_UE_POLICIES                    1
#define TLV_TYPE_SINGLE_NSSAI                   2
#define TLV_TYPE_ALLOWED_NSSAI                  3
#define TLV_TYPE_CFG_NSSAI                      4
#define TLV_TYPE_DFLT_CFG_NSSAI                 5
#define TLV_TYPE_PRECFG_DFLT_CFG_NSSAI          6
#define TLV_TYPE_REJ_NSSAI                      7
#define TLV_TYPE_LADN                           8
#define TLV_TYPE_TAI                            9
#define TLV_TYPE_WCHAR_STR                     10
#define TLV_TYPE_UINT16_TBL                    11
#define TLV_TYPE_EAP_PACKET                    12
#define TLV_TYPE_PCO                           13
#define TLV_TYPE_ROUTE_SELECTION_DESCRIPTORS   14
#define TLV_TYPE_TRAFFIC_PARAMETERS            15
#define TLV_TYPE_WAKE_COMMAND                  16
#define TLV_TYPE_WAKE_PACKET                   17
#define TLV_TYPE_TYPE_OSID                     18
#define TLV_TYPE_TYPE_3GPP_REL_VERSION         19
#define TLV_TYPE_TYPE_URSP_RULES_TD_ONLY       20
#define TLV_TYPE_TYPE_SESSION_ID               21

static const value_string mbim_tlv_type_vals[] = {
    { TLV_TYPE_UNKNOWN, "UNKNOWN"},
    { TLV_TYPE_UE_POLICIES, "UE_POLICIES"},
    { TLV_TYPE_SINGLE_NSSAI, "SINGLE_NSSAI"},
    { TLV_TYPE_ALLOWED_NSSAI, "ALLOWED_NSSAI"},
    { TLV_TYPE_CFG_NSSAI, "CFG_NSSAI"},
    { TLV_TYPE_DFLT_CFG_NSSAI, "DFLT_CFG_NSSAI"},
    { TLV_TYPE_PRECFG_DFLT_CFG_NSSAI, "PRECFG_DFLT_CFG_NSSAI"},
    { TLV_TYPE_REJ_NSSAI, "REJ_NSSAI"},
    { TLV_TYPE_LADN, "LADN"},
    { TLV_TYPE_TAI, "TAI"},
    { TLV_TYPE_WCHAR_STR, "WCHAR_STR"},
    { TLV_TYPE_UINT16_TBL, "UINT16_TBL"},
    { TLV_TYPE_EAP_PACKET, "EAP_PACKET"},
    { TLV_TYPE_PCO, "PCO"},
    { TLV_TYPE_ROUTE_SELECTION_DESCRIPTORS, "ROUTE_SELECTION_DESCRIPTORS"},
    { TLV_TYPE_TRAFFIC_PARAMETERS, "TRAFFIC_PARAMETERS"},
    { TLV_TYPE_WAKE_COMMAND, "WAKE_COMMAND"},
    { TLV_TYPE_WAKE_PACKET, "WAKE_PACKET"},
    { TLV_TYPE_TYPE_OSID, "OS_ID"},
    { TLV_TYPE_TYPE_3GPP_REL_VERSION, "3GPP_REL_VERSION"},
    { TLV_TYPE_TYPE_URSP_RULES_TD_ONLY, "URSP_RULES_TD_ONLY"},
    { TLV_TYPE_TYPE_SESSION_ID, "SESSION_ID"},
    { 0, NULL}
};

static int * const mbim_provider_state_fields[] = {
    &hf_mbim_provider_state_home,
    &hf_mbim_provider_state_forbidden,
    &hf_mbim_provider_state_preferred,
    &hf_mbim_provider_state_visible,
    &hf_mbim_provider_state_registered,
    &hf_mbim_provider_state_preferred_multicarrier,
    NULL
};

#define URSP_TC_TYPE_MATCH_ALL                      0x1
#define URSP_TC_TYPE_OSID_APPID                     0x8
#define URSP_TC_TYPE_IPV4                           0x10
#define URSP_TC_TYPE_IPV6                           0x21
#define URSP_TC_TYPE_PROTOCOL_ID_OR_NEXT_HEADER     0x30
#define URSP_TC_TYPE_PORT                           0x50
#define URSP_TC_TYPE_PORT_RANGE                     0x51
#define URSP_TC_TYPE_SECURITY_PARAM_INDEX           0x60
#define URSP_TC_TYPE_SERVICE_OR_TRAFFIC_CLASS       0x70
#define URSP_TC_TYPE_FLOW_LABEL                     0x80
#define URSP_TC_TYPE_MAC_ADDRESS                    0x81
#define URSP_TC_TYPE_C_TAG_VID                      0x83
#define URSP_TC_TYPE_S_TAG_VID                      0x84
#define URSP_TC_TYPE_C_TAG_PCP_AND_DEI              0x85
#define URSP_TC_TYPE_S_TAG_PCP_AND_DEI              0x86
#define URSP_TC_TYPE_ETHER                          0x87
#define URSP_TC_TYPE_DNN                            0x88
#define URSP_TC_TYPE_CONNECTION_CAPABILITY          0x90
#define URSP_TC_TYPE_FQDN                           0x91
#define URSP_TC_TYPE_APPID                          0xa0

static const value_string ursp_tc_type_vals[] = {
    { URSP_TC_TYPE_MATCH_ALL, "Match all"},
    { URSP_TC_TYPE_OSID_APPID, "OS Id + OS App Id"},
    { URSP_TC_TYPE_IPV4, "IPv4 remote address"},
    { URSP_TC_TYPE_IPV6, "IPv6 remote address/prefix length"},
    { URSP_TC_TYPE_PROTOCOL_ID_OR_NEXT_HEADER, "Protocol identifier/next header"},
    { URSP_TC_TYPE_PORT, "Single remote port"},
    { URSP_TC_TYPE_PORT_RANGE, "Remote port range"},
    { URSP_TC_TYPE_SECURITY_PARAM_INDEX, "Security parameter index"},
    { URSP_TC_TYPE_SERVICE_OR_TRAFFIC_CLASS, "Type of service/traffic class"},
    { URSP_TC_TYPE_FLOW_LABEL, "Flow label"},
    { URSP_TC_TYPE_MAC_ADDRESS, "Destination MAC address"},
    { URSP_TC_TYPE_C_TAG_VID, "802.1Q C-TAG VID"},
    { URSP_TC_TYPE_S_TAG_VID, "802.1Q S-TAG VID"},
    { URSP_TC_TYPE_C_TAG_PCP_AND_DEI, "802.1Q C-TAG PCP/DEI"},
    { URSP_TC_TYPE_S_TAG_PCP_AND_DEI, "802.1Q S-TAG PCP/DEI"},
    { URSP_TC_TYPE_ETHER, "Ethertype"},
    { URSP_TC_TYPE_DNN, "DNN"},
    { URSP_TC_TYPE_CONNECTION_CAPABILITY, "Connection capabilities"},
    { URSP_TC_TYPE_FQDN, "Destination FQDN"},
    { URSP_TC_TYPE_APPID, "OS App Id"},
    { 0, NULL}
};
static int* const ursp_tc_connection_capability_flags_fields[] = {
    &hf_mbim_ms_ursp_tc_connection_capability_flag_ims,
    &hf_mbim_ms_ursp_tc_connection_capability_flag_mms,
    &hf_mbim_ms_ursp_tc_connection_capability_flag_supl,
    &hf_mbim_ms_ursp_tc_connection_capability_flag_internet,
    NULL
};

static void
mbim_rssi_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-113 or less dBm (0)");
    } else if (val < 31) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d dBm (%u)", -113 + 2*val, val);
    } else if (val == 31) {
        snprintf(s, ITEM_LABEL_LENGTH, "-51 or greater dBm (31)");
    } else if (val == 99) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (99)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static const value_string mbim_error_rate_vals[] = {
    {  0, "Frame error rate < 0.01%%"},
    {  1, "Frame error rate 0.01-0.1%%"},
    {  2, "Frame error rate 0.1-0.5%%"},
    {  3, "Frame error rate 0.5-1.0%%"},
    {  4, "Frame error rate 1.0-2.0%%"},
    {  5, "Frame error rate 2.0-4.0%%"},
    {  6, "Frame error rate 4.0-8.0%%"},
    {  7, "Frame error rate > 8.0%%"},
    { 99, "Unknown or undetectable"},
    { 0, NULL}
};

static const value_string mbim_visible_providers_action_vals[] = {
    { 0, "Full Scan"},
    { 1, "Restricted Scan"},
    {0, NULL}
};

static const value_string mbim_register_action_vals[] = {
    { 0, "Automatic"},
    { 1, "Manual"},
    { 0, NULL}
};

static const value_string mbim_register_state_vals[] = {
    { 0, "Unknown"},
    { 1, "Deregistered"},
    { 2, "Searching"},
    { 3, "Home"},
    { 4, "Roaming"},
    { 5, "Partner"},
    { 6, "Denied"},
    { 0, NULL}
};

static const value_string mbim_register_mode_vals[] = {
    { 0, "Unknown"},
    { 1, "Automatic"},
    { 2, "Manual"},
    { 0, NULL}
};

static int * const mbim_registration_state_info_registration_flags_fields[] = {
    &hf_mbim_registration_state_info_registration_flags_manual_selection_not_available,
    &hf_mbim_registration_state_info_registration_flags_packet_service_auto_attach,
    NULL
};

static const value_string mbim_packet_service_action_vals[] = {
    { 0, "Attach"},
    { 1, "Detach"},
    { 0, NULL}
};

static const value_string mbim_tai_list_type_vals[] = {
    { 0, "Non Consecutive TAC"},
    { 1, "Consecutive TAC"},
    { 2, "Multi PLMN TAC"},
    { 0, NULL}
};

static const value_string mbim_packet_service_state_vals[] = {
    { 0, "Unknown"},
    { 1, "Attaching"},
    { 2, "Attached"},
    { 3, "Detaching"},
    { 4, "Detached"},
    { 0, NULL},
};

static const value_string mbim_activation_command_vals[] = {
    { 0, "Deactivate"},
    { 1, "Activate"},
    { 0, NULL}
};

static const value_string mbim_activation_option_vals[] = {
    { 0, "Default"},
    { 1, "Per Non Default URSP Rules"},
    { 2, "Per Default URSP Rules"},
    { 3, "Per URSP Rules"},
    { 0, NULL}
};

static const value_string mbim_compression_vals[] = {
    { 0, "None"},
    { 1, "Enable"},
    { 0, NULL}
};

static const value_string mbim_auth_protocol_vals[]= {
    { 0, "None"},
    { 1, "PAP"},
    { 2, "CHAP"},
    { 3, "MS CHAPv2"},
    { 0, NULL}
};

static const value_string mbim_context_ip_type_vals[] = {
    { 0, "Default"},
    { 1, "IPv4"},
    { 2, "IPv6"},
    { 3, "IPv4v6"},
    { 4, "IPv4 and IPv6"},
    { 0, NULL}
};

static const value_string mbim_activation_state_vals[] = {
    { 0, "Unknown"},
    { 1, "Activated"},
    { 2, "Activating"},
    { 3, "Deactivated"},
    { 4, "Deactivating"},
    { 0, NULL}
};

static const value_string mbim_voice_call_state_vals[] = {
    { 0, "None"},
    { 1, "In Progress"},
    { 2, "Hang Up"},
    { 0, NULL}
};

#define UUID_CONTEXT_NONE                  0
#define UUID_CONTEXT_INTERNET              1
#define UUID_CONTEXT_VPN                   2
#define UUID_CONTEXT_VOICE                 3
#define UUID_CONTEXT_VIDEO_SHARE           4
#define UUID_CONTEXT_PURCHASE              5
#define UUID_CONTEXT_IMS                   6
#define UUID_CONTEXT_MMS                   7
#define UUID_CONTEXT_LOCAL                 8
#define UUID_CONTEXT_MS_ADMIN              9
#define UUID_CONTEXT_MS_APP               10
#define UUID_CONTEXT_MS_XCAP              11
#define UUID_CONTEXT_MS_TETHERING         12
#define UUID_CONTEXT_MS_EMERGENCY_CALLING 13

static const struct mbim_uuid mbim_uuid_context_type_vals[] = {
    { UUID_CONTEXT_NONE, {0xb43f758c, 0xa560, 0x4b46, {0xb3, 0x5e, 0xc5, 0x86, 0x96, 0x41, 0xfb, 0x54}}},
    { UUID_CONTEXT_INTERNET, {0x7e5e2a7e, 0x4e6f, 0x7272, {0x73, 0x6b, 0x65, 0x6e, 0x7e, 0x5e, 0x2a, 0x7e}}},
    { UUID_CONTEXT_VPN, {0x9b9f7bbe, 0x8952, 0x44b7, {0x83, 0xac, 0xca, 0x41, 0x31, 0x8d, 0xf7, 0xa0}}},
    { UUID_CONTEXT_VOICE, {0x88918294, 0x0ef4, 0x4396, {0x8c, 0xca, 0xa8, 0x58, 0x8f, 0xbc, 0x02, 0xb2}}},
    { UUID_CONTEXT_VIDEO_SHARE, {0x05a2a716, 0x7c34, 0x4b4d, {0x9a, 0x91, 0xc5, 0xef, 0x0c, 0x7a, 0xaa, 0xcc}}},
    { UUID_CONTEXT_PURCHASE, {0xb3272496, 0xac6c, 0x422b, {0xa8, 0xc0, 0xac, 0xf6, 0x87, 0xa2, 0x72, 0x17}}},
    { UUID_CONTEXT_IMS, {0x21610D01, 0x3074, 0x4BCE, {0x94, 0x25, 0xB5, 0x3A, 0x07, 0xD6, 0x97, 0xD6}}},
    { UUID_CONTEXT_MMS, {0x46726664, 0x7269, 0x6bc6, {0x96, 0x24, 0xd1, 0xd3, 0x53, 0x89, 0xac, 0xa9}}},
    { UUID_CONTEXT_LOCAL, {0xa57a9afc, 0xb09f, 0x45d7, {0xbb, 0x40, 0x03, 0x3c, 0x39, 0xf6, 0x0d, 0xb9}}},
    { UUID_CONTEXT_MS_ADMIN, {0x5f7e4c2e, 0xe80b, 0x40a9, {0xa2, 0x39, 0xf0, 0xab, 0xcf, 0xd1, 0x1f, 0x4b}}},
    { UUID_CONTEXT_MS_APP, {0x74d88a3d, 0xdfbd, 0x4799, {0x9a, 0x8c, 0x73, 0x10, 0xa3, 0x7b, 0xb2, 0xee}}},
    { UUID_CONTEXT_MS_XCAP, {0x50d378a7, 0xbaa5, 0x4a50, {0xb8, 0x72, 0x3f, 0xe5, 0xbb, 0x46, 0x34, 0x11}}},
    { UUID_CONTEXT_MS_TETHERING, {0x5e4e0601, 0x48dc, 0x4e2b, {0xac, 0xb8, 0x08, 0xb4, 0x01, 0x6b, 0xba, 0xac}}},
    { UUID_CONTEXT_MS_EMERGENCY_CALLING, {0x5f41adb8, 0x204e, 0x4d31, {0x9d, 0xa8, 0xb3, 0xc9, 0x70, 0xe3, 0x60, 0xf2}}}
};

static const value_string mbim_context_type_vals[] = {
    { UUID_CONTEXT_NONE, "None"},
    { UUID_CONTEXT_INTERNET, "Internet"},
    { UUID_CONTEXT_VPN, "VPN"},
    { UUID_CONTEXT_VOICE, "Voice"},
    { UUID_CONTEXT_VIDEO_SHARE, "Video Share"},
    { UUID_CONTEXT_PURCHASE, "Purchase"},
    { UUID_CONTEXT_IMS, "IMS"},
    { UUID_CONTEXT_MMS, "MMS"},
    { UUID_CONTEXT_LOCAL, "Local"},
    { UUID_CONTEXT_MS_ADMIN, "MS Administrative Purposes"},
    { UUID_CONTEXT_MS_APP, "MS Operator App"},
    { UUID_CONTEXT_MS_XCAP, "MS XCAP Provisioning for IMS"},
    { UUID_CONTEXT_MS_TETHERING, "MS Mobile Hotspot Tethering"},
    { UUID_CONTEXT_MS_EMERGENCY_CALLING, "MS IMS Emergency Calling"},
    { 0, NULL}
};

static int * const mbim_ip_configuration_info_ipv4_configuration_available_fields[] = {
    &hf_mbim_ip_configuration_info_ipv4_configuration_available_address,
    &hf_mbim_ip_configuration_info_ipv4_configuration_available_gateway,
    &hf_mbim_ip_configuration_info_ipv4_configuration_available_dns,
    &hf_mbim_ip_configuration_info_ipv4_configuration_available_mtu,
    NULL
};

static int * const mbim_ip_configuration_info_ipv6_configuration_available_fields[] = {
    &hf_mbim_ip_configuration_info_ipv6_configuration_available_address,
    &hf_mbim_ip_configuration_info_ipv6_configuration_available_gateway,
    &hf_mbim_ip_configuration_info_ipv6_configuration_available_dns,
    &hf_mbim_ip_configuration_info_ipv6_configuration_available_mtu,
    NULL
};

static int * const mbim_device_service_element_dss_payload_fields[] = {
    &hf_mbim_device_service_element_dss_payload_host_device,
    &hf_mbim_device_service_element_dss_payload_device_host,
    NULL
};

static const value_string mbim_network_idle_hint_states_vals[] = {
    { 0, "Disabled"},
    { 1, "Enabled"},
    { 0, NULL}
};

static const value_string mbim_emergency_mode_states_vals[] = {
    { 0, "Off"},
    { 1, "On"},
    { 0, NULL}
};

static const value_string mbim_sms_storage_state_vals[] = {
    { 0, "Not Initialized"},
    { 1, "Initialized"},
    { 0, NULL}
};

#define MBIM_SMS_FORMAT_PDU  0
#define MBIM_SMS_FORMAT_CDMA 1

static const value_string mbim_sms_format_vals[] = {
    { MBIM_SMS_FORMAT_PDU, "PDU"},
    { MBIM_SMS_FORMAT_CDMA, "CDMA"},
    { 0, NULL}
};

static const value_string mbim_sms_flag_vals[] = {
    { 0, "All"},
    { 1, "Index"},
    { 2, "New"},
    { 3, "Old"},
    { 4, "Sent"},
    { 5, "Draft"},
    { 0, NULL}
};

static const value_string mbim_sms_cdma_lang_vals[] = {
    { 0, "Unknown"},
    { 1, "English"},
    { 2, "French"},
    { 3, "Spanish"},
    { 4, "Japanese"},
    { 5, "Korean"},
    { 6, "Chinese"},
    { 7, "Hebrew"},
    { 0, NULL}
};

#define MBIM_ENCODING_OCTET        0
#define MBIM_ENCODING_EPM          1
#define MBIM_ENCODING_7BIT_ASCII   2
#define MBIM_ENCODING_IA5          3
#define MBIM_ENCODING_UNICODE      4
#define MBIM_ENCODING_SHIFT_JIS    5
#define MBIM_ENCODING_KOREAN       6
#define MBIM_ENCODING_LATIN_HEBREW 7
#define MBIM_ENCODING_LATIN        8
#define MBIM_ENCODING_GSM_7BIT     9

static const value_string mbim_sms_cdma_encoding_vals[] = {
    { MBIM_ENCODING_OCTET, "Octet"},
    { MBIM_ENCODING_EPM, "EPM"},
    { MBIM_ENCODING_7BIT_ASCII, "7 Bit ASCII"},
    { MBIM_ENCODING_IA5, "IA5"},
    { MBIM_ENCODING_UNICODE, "Unicode"},
    { MBIM_ENCODING_SHIFT_JIS, "Shift-JIS"},
    { MBIM_ENCODING_KOREAN, "Korean"},
    { MBIM_ENCODING_LATIN_HEBREW, "Latin Hebrew"},
    { MBIM_ENCODING_LATIN, "Latin"},
    { MBIM_ENCODING_GSM_7BIT, "GSM 7 Bit"},
    { 0, NULL}
};

static const value_string mbim_sms_message_status_vals[] = {
    { 0, "New"},
    { 1, "Old"},
    { 2, "Draft"},
    { 3, "Sent"},
    { 0, NULL}
};

static int * const mbim_sms_status_info_flags_fields[] = {
    &hf_mbim_sms_status_info_flags_message_store_full,
    &hf_mbim_sms_status_info_flags_new_message,
    NULL
};

static const value_string mbim_ussd_action_vals[] = {
    { 0, "Initiate"},
    { 1, "Continue"},
    { 2, "Cancel"},
    { 0, NULL}
};

static const value_string mbim_ussd_response_vals[] = {
    { 0, "No Action Required"},
    { 1, "Action Required"},
    { 2, "Terminated By NW"},
    { 3, "Other Local Client"},
    { 4, "Operation Not Supported"},
    { 5, "Network Time Out"},
    { 0, NULL}
};

static const value_string mbim_ussd_session_state_vals[] = {
    { 0, "New Session"},
    { 1, "Existing Session"},
    { 0, NULL}
};

static const value_string mbim_phonebook_state_vals[] = {
    { 0, "Not Initialized"},
    { 1, "Initialized"},
    { 0, NULL}
};

static const value_string mbim_phonebook_flag_vals[] = {
    { 0, "All"},
    { 1, "Index"},
    { 0, NULL}
};

static const value_string mbim_phonebook_write_flag_vals[] = {
    { 0, "Unused"},
    { 1, "Index"},
    { 0, NULL}
};

static const true_false_string mbim_pac_host_control_val = {
  "Host wants to handle command",
  "Host does not want to handle command"
};

static const value_string mbim_stk_pac_profile_vals[] = {
    { 0, "Not Handled By Function Cannot Be Handled By Host"},
    { 1, "Not Handled By Function May Be Handled By Host"},
    { 2, "Handled By Function Only Transparent To Host"},
    { 3, "Handled By Function Notification To Host Possible"},
    { 4, "Handled By Function Notification To Host Enabled"},
    { 5, "Handled By Function Can Be Overridden By Host"},
    { 6, "Handled By Host Function Not Able To Handle"},
    { 7, "Handled By Host Function Able To Handle"},
    { 0, NULL}
};

static const value_string mbim_stk_pac_type_vals[] = {
    { 0, "Proactive Command"},
    { 1, "Notification"},
    { 0, NULL}
};

static const value_string mbim_dss_link_state_vals[] = {
    { 0, "Deactivate"},
    { 1, "Activate"},
    { 0, NULL}
};

static int * const mbim_multicarrier_capabilities_fields[] = {
    &hf_mbim_multicarrier_capabilities_info_capabilities_static_scan,
    &hf_mbim_multicarrier_capabilities_info_capabilities_fw_requires_reboot,
    NULL
};

static const value_string mbim_geoid_vals[] = {
    {       0x2, "Antigua and Barbuda"},
    {       0x3, "Afghanistan"},
    {       0x4, "Algeria"},
    {       0x5, "Azerbaijan"},
    {       0x6, "Albania"},
    {       0x7, "Armenia"},
    {       0x8, "Andorra"},
    {       0x9, "Angola"},
    {       0xA, "American Samoa"},
    {       0xB, "Argentina"},
    {       0xC, "Australia"},
    {       0xE, "Austria"},
    {      0x11, "Bahrain"},
    {      0x12, "Barbados"},
    {      0x13, "Botswana"},
    {      0x14, "Bermuda"},
    {      0x15, "Belgium"},
    {      0x16, "Bahamas, The"},
    {      0x17, "Bangladesh"},
    {      0x18, "Belize"},
    {      0x19, "Bosnia and Herzegovina"},
    {      0x1A, "Bolivia"},
    {      0x1B, "Myanmar"},
    {      0x1C, "Benin"},
    {      0x1D, "Belarus"},
    {      0x1E, "Solomon Islands"},
    {      0x20, "Brazil"},
    {      0x22, "Bhutan"},
    {      0x23, "Bulgaria"},
    {      0x25, "Brunei"},
    {      0x26, "Burundi"},
    {      0x27, "Canada"},
    {      0x28, "Cambodia"},
    {      0x29, "Chad"},
    {      0x2A, "Sri Lanka"},
    {      0x2B, "Congo"},
    {      0x2C, "Congo (DRC)"},
    {      0x2D, "China"},
    {      0x2E, "Chile"},
    {      0x31, "Cameroon"},
    {      0x32, "Comoros"},
    {      0x33, "Colombia"},
    {      0x36, "Costa Rica"},
    {      0x37, "Central African Republic"},
    {      0x38, "Cuba"},
    {      0x39, "Cape Verde"},
    {      0x3B, "Cyprus"},
    {      0x3D, "Denmark"},
    {      0x3E, "Djibouti"},
    {      0x3F, "Dominica"},
    {      0x41, "Dominican Republic"},
    {      0x42, "Ecuador"},
    {      0x43, "Egypt"},
    {      0x44, "Ireland"},
    {      0x45, "Equatorial Guinea"},
    {      0x46, "Estonia"},
    {      0x47, "Eritrea"},
    {      0x48, "El Salvador"},
    {      0x49, "Ethiopia"},
    {      0x4B, "Czech Republic"},
    {      0x4D, "Finland"},
    {      0x4E, "Fiji Islands"},
    {      0x50, "Micronesia"},
    {      0x51, "Faroe Islands"},
    {      0x54, "France"},
    {      0x56, "Gambia, The"},
    {      0x57, "Gabon"},
    {      0x58, "Georgia"},
    {      0x59, "Ghana"},
    {      0x5A, "Gibraltar"},
    {      0x5B, "Grenada"},
    {      0x5D, "Greenland"},
    {      0x5E, "Germany"},
    {      0x62, "Greece"},
    {      0x63, "Guatemala"},
    {      0x64, "Guinea"},
    {      0x65, "Guyana"},
    {      0x67, "Haiti"},
    {      0x68, "Hong Kong S.A.R."},
    {      0x6A, "Honduras"},
    {      0x6C, "Croatia"},
    {      0x6D, "Hungary"},
    {      0x6E, "Iceland"},
    {      0x6F, "Indonesia"},
    {      0x71, "India"},
    {      0x72, "British Indian Ocean Territory"},
    {      0x74, "Iran"},
    {      0x75, "Israel"},
    {      0x76, "Italy"},
    {      0x77, "Cote d'Ivoire"},
    {      0x79, "Iraq"},
    {      0x7A, "Japan"},
    {      0x7C, "Jamaica"},
    {      0x7D, "Jan Mayen"},
    {      0x7E, "Jordan"},
    {      0x7F, "Johnston Atoll"},
    {      0x81, "Kenya"},
    {      0x82, "Kyrgyzstan"},
    {      0x83, "North Korea"},
    {      0x85, "Kiribati"},
    {      0x86, "Korea"},
    {      0x88, "Kuwait"},
    {      0x89, "Kazakhstan"},
    {      0x8A, "Laos"},
    {      0x8B, "Lebanon"},
    {      0x8C, "Latvia"},
    {      0x8D, "Lithuania"},
    {      0x8E, "Liberia"},
    {      0x8F, "Slovakia"},
    {      0x91, "Liechtenstein"},
    {      0x92, "Lesotho"},
    {      0x93, "Luxembourg"},
    {      0x94, "Libya"},
    {      0x95, "Madagascar"},
    {      0x97, "Macao S.A.R."},
    {      0x98, "Moldova"},
    {      0x9A, "Mongolia"},
    {      0x9C, "Malawi"},
    {      0x9D, "Mali"},
    {      0x9E, "Monaco"},
    {      0x9F, "Morocco"},
    {      0xA0, "Mauritius"},
    {      0xA2, "Mauritania"},
    {      0xA3, "Malta"},
    {      0xA4, "Oman"},
    {      0xA5, "Maldives"},
    {      0xA6, "Mexico"},
    {      0xA7, "Malaysia"},
    {      0xA8, "Mozambique"},
    {      0xAD, "Niger"},
    {      0xAE, "Vanuatu"},
    {      0xAF, "Nigeria"},
    {      0xB0, "Netherlands"},
    {      0xB1, "Norway"},
    {      0xB2, "Nepal"},
    {      0xB4, "Nauru"},
    {      0xB5, "Suriname"},
    {      0xB6, "Nicaragua"},
    {      0xB7, "New Zealand"},
    {      0xB8, "Palestinian Authority"},
    {      0xB9, "Paraguay"},
    {      0xBB, "Peru"},
    {      0xBE, "Pakistan"},
    {      0xBF, "Poland"},
    {      0xC0, "Panama"},
    {      0xC1, "Portugal"},
    {      0xC2, "Papua New Guinea"},
    {      0xC3, "Palau"},
    {      0xC4, "Guinea-Bissau"},
    {      0xC5, "Qatar"},
    {      0xC6, "Reunion"},
    {      0xC7, "Marshall Islands"},
    {      0xC8, "Romania"},
    {      0xC9, "Philippines"},
    {      0xCA, "Puerto Rico"},
    {      0xCB, "Russia"},
    {      0xCC, "Rwanda"},
    {      0xCD, "Saudi Arabia"},
    {      0xCE, "St. Pierre and Miquelon"},
    {      0xCF, "St. Kitts and Nevis"},
    {      0xD0, "Seychelles"},
    {      0xD1, "South Africa"},
    {      0xD2, "Senegal"},
    {      0xD4, "Slovenia"},
    {      0xD5, "Sierra Leone"},
    {      0xD6, "San Marino"},
    {      0xD7, "Singapore"},
    {      0xD8, "Somalia"},
    {      0xD9, "Spain"},
    {      0xDA, "St. Lucia"},
    {      0xDB, "Sudan"},
    {      0xDC, "Svalbard"},
    {      0xDD, "Sweden"},
    {      0xDE, "Syria"},
    {      0xDF, "Switzerland"},
    {      0xE0, "United Arab Emirates"},
    {      0xE1, "Trinidad and Tobago"},
    {      0xE3, "Thailand"},
    {      0xE4, "Tajikistan"},
    {      0xE7, "Tonga"},
    {      0xE8, "Togo"},
    {      0xE9, "Sao Tome and Principe"},
    {      0xEA, "Tunisia"},
    {      0xEB, "Turkey"},
    {      0xEC, "Tuvalu"},
    {      0xED, "Taiwan"},
    {      0xEE, "Turkmenistan"},
    {      0xEF, "Tanzania"},
    {      0xF0, "Uganda"},
    {      0xF1, "Ukraine"},
    {      0xF2, "United Kingdom"},
    {      0xF4, "United States"},
    {      0xF5, "Burkina Faso"},
    {      0xF6, "Uruguay"},
    {      0xF7, "Uzbekistan"},
    {      0xF8, "St. Vincent and the Grenadines"},
    {      0xF9, "Venezuela"},
    {      0xFB, "Vietnam"},
    {      0xFC, "Virgin Islands"},
    {      0xFD, "Vatican City"},
    {      0xFE, "Namibia"},
    {     0x101, "Western Sahara (disputed)"},
    {     0x102, "Wake Island"},
    {     0x103, "Samoa"},
    {     0x104, "Swaziland"},
    {     0x105, "Yemen"},
    {     0x107, "Zambia"},
    {     0x108, "Zimbabwe"},
    {     0x10D, "Serbia and Montenegro (Former)"},
    {     0x10E, "Montenegro"},
    {     0x10F, "Serbia"},
    {     0x111, "Curacao"},
    {     0x114, "South Sudan"},
    {     0x12C, "Anguilla"},
    {     0x12D, "Antarctica"},
    {     0x12E, "Aruba"},
    {     0x12F, "Ascension Island"},
    {     0x130, "Ashmore and Cartier Islands"},
    {     0x131, "Baker Island"},
    {     0x132, "Bouvet Island"},
    {     0x133, "Cayman Islands"},
    {     0x135, "Christmas Island"},
    {     0x136, "Clipperton Island"},
    {     0x137, "Cocos (Keeling) Islands"},
    {     0x138, "Cook Islands"},
    {     0x139, "Coral Sea Islands"},
    {     0x13A, "Diego Garcia"},
    {     0x13B, "Falkland Islands (Islas Malvinas)"},
    {     0x13D, "French Guiana"},
    {     0x13E, "French Polynesia"},
    {     0x13F, "French Southern and Antarctic Lands"},
    {     0x141, "Guadeloupe"},
    {     0x142, "Guam"},
    {     0x143, "Guantanamo Bay"},
    {     0x144, "Guernsey"},
    {     0x145, "Heard Island and McDonald Islands"},
    {     0x146, "Howland Island"},
    {     0x147, "Jarvis Island"},
    {     0x148, "Jersey"},
    {     0x149, "Kingman Reef"},
    {     0x14A, "Martinique"},
    {     0x14B, "Mayotte"},
    {     0x14C, "Montserrat"},
    {     0x14E, "New Caledonia"},
    {     0x14F, "Niue"},
    {     0x150, "Norfolk Island"},
    {     0x151, "Northern Mariana Islands"},
    {     0x152, "Palmyra Atoll"},
    {     0x153, "Pitcairn Islands"},
    {     0x154, "Rota Island"},
    {     0x155, "Saipan"},
    {     0x156, "South Georgia and the South Sandwich Islands"},
    {     0x157, "St. Helena"},
    {     0x15A, "Tinian Island"},
    {     0x15B, "Tokelau"},
    {     0x15C, "Tristan da Cunha"},
    {     0x15D, "Turks and Caicos Islands"},
    {     0x15F, "Virgin Islands, British"},
    {     0x160, "Wallis and Futuna"},
    {    0x3B16, "Man, Isle of"},
    {    0x4CA2, "Macedonia, Former Yugoslav Republic of"},
    {    0x52FA, "Midway Islands"},
    {    0x78F7, "Sint Maarten (Dutch part)"},
    {    0x7BDA, "Saint Martin (French part)"},
    {  0x6F60E7, "Democratic Republic of Timor-Leste"},
    {  0x9906F5, "Aland Islands"},
    { 0x9A55C4F, "Saint Barthelemy"},
    { 0x9A55D40, "U.S. Minor Outlying Islands"},
    { 0x9A55D42, "Bonaire, Saint Eustatius and Saba"},
    { 0, NULL}
};
static value_string_ext mbim_geoid_vals_ext = VALUE_STRING_EXT_INIT(mbim_geoid_vals);

static int * const mbim_descriptor_network_capabilities_fields[] = {
    &hf_mbim_descriptor_network_capabilities_max_datagram_size,
    &hf_mbim_descriptor_network_capabilities_ntb_input_size,
    NULL
};

static const value_string mbim_thermal_config_enable_vals[] = {
    { 0, "Disable"},
    { 1, "Enable"},
    { 0, NULL}
};

static const value_string mbim_sar_status_vals[] = {
    { 0, "Disabled"},
    { 1, "Enabled"},
    { 0, NULL}
};

static const value_string mbim_ms_sar_config_sar_mode_vals[] = {
    { 0, "Device"},
    { 1, "OS"},
    { 0, NULL}
};

static const value_string mbim_ms_sar_config_sar_wifi_integration_vals[] = {
    { 0, "Not Integrated"},
    { 1, "Integrated"},
    { 0, NULL}
};

static void
mbim_degrees_fmt(gchar *s, guint32 v)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%.1f Degrees Celsius (%u)", (float)v/10.0, v);
}

static const value_string mbim_adpclk_activate_state_vals[] = {
    { 0, "Deactivate"},
    { 1, "Activate"},
    { 0, NULL}
};

static const value_string mbim_connect_status_vals[] = {
    { 0, "Disconnected from the Base Station"},
    { 1, "Connected to the Base Station"},
    { 0, NULL}
};

static const value_string mbim_trace_config_vals[] = {
    { 0, "Tracing disabled"},
    { 1, "Default configuration for tracing"},
    { 0, NULL}
};

static const value_string mbim_ber_vals[] = {
    { 0, "BER < 0,2%%"},
    { 1, "0,2%% < BER < 0,4%%"},
    { 2, "0,4%% < BER < 0,8%%"},
    { 3, "0,8%% < BER < 1,6%%"},
    { 4, "1,6%% < BER < 3,2%%"},
    { 5, "3,2%% < BER < 6,4%%"},
    { 6, "6,4%% < BER < 12,8%%"},
    { 7, "12,8%% < BER"},
    { 99, "Unknown or undetectable"},
    { 0, NULL}
};

static void
mbim_rscp_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-120 or less dBm (0)");
    } else if (val < 96) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d dBm (%u)", -120 + val, val);
    } else if (val == 96) {
        snprintf(s, ITEM_LABEL_LENGTH, "-24 or greater dBm (96)");
    } else if (val == 255) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (255)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static void
mbim_ecno_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-24 or less dBm (0)");
    } else if (val < 49) {
        snprintf(s, ITEM_LABEL_LENGTH, "%.1f dBm (%u)", -24 + ((float)val/2), val);
    } else if (val == 49) {
        snprintf(s, ITEM_LABEL_LENGTH, "0.5 or greater dBm (49)");
    } else if (val == 255) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (255)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static void
mbim_rsrq_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-19.5 or less dBm (0)");
    } else if (val < 34) {
        snprintf(s, ITEM_LABEL_LENGTH, "%.1f dBm (%u)", -19.5 + ((float)val/2), val);
    } else if (val == 34) {
        snprintf(s, ITEM_LABEL_LENGTH, "-2.5 or greater dBm (34)");
    } else if (val == 255) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (255)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static void
mbim_rsrp_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-140 or less dBm (0)");
    } else if (val < 97) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d dBm (%u)", -140 + val, val);
    } else if (val == 97) {
        snprintf(s, ITEM_LABEL_LENGTH, "-43 or greater dBm (97)");
    } else if (val == 255) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (255)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static void
mbim_rssnr_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "-5 or less dB (0)");
    } else if (val < 35) {
        snprintf(s, ITEM_LABEL_LENGTH, "%d dB (%u)", -5 + val, val);
    } else if (val == 35) {
        snprintf(s, ITEM_LABEL_LENGTH, "30 or greater dB (35)");
    } else if (val == 255) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown or undetectable (255)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "Invalid value (%u)", val);
    }
}

static void
mbim_rsrp_signal_state_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "SS-RSRP < -156dBm (0)");
    } else if (val < 126) {
        snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= SS-RSRP < %ddBm (%u)", val - 157, val - 156, val);
    } else if (val == 126) {
        snprintf(s, ITEM_LABEL_LENGTH, "-31dBm <= SS-RSRP (126)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "invalid (127)");
    }
}

static void
mbim_snr_signal_state_fmt(gchar *s, guint32 val)
{
    if (val == 0) {
        snprintf(s, ITEM_LABEL_LENGTH, "SS-SINR < -23dB (0)");
    } else if (val < 127) {
        snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SS-SINR < %.1fdB (%u)", (((float)val - 1) / 2) - 23, ((float)val / 2) - 23, val);
    } else if (val == 127){
        snprintf(s, ITEM_LABEL_LENGTH, "40dB <= SS-SINR (127)");
    } else {
        snprintf(s, ITEM_LABEL_LENGTH, "invalid (128)");
    }
}

static void
mbim_version_fmt(gchar* s, guint32 val)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%u.%u", val / 256, val % 256);
}

static const value_string mbim_atds_operator_plmn_mode_vals[] = {
    { 0, "GSM"},
    { 6, "UTRAN"},
    { 7, "LTE"},
    { 0, NULL}
};

static const value_string mbim_adts_rat_info_mode_vals[]= {
    { 0, "Automatic"},
    { 1, "2G only"},
    { 2, "3G only"},
    { 3, "4G only"},
    { 0, NULL}
};

static const value_string mbim_adts_projection_table_type_vals[]= {
    { 0, "RSSI"},
    { 1, "RSCP"},
    { 2, "Ec/No"},
    { 3, "RSRP"},
    { 7, "RS SNR"},
    { 0, NULL}
};

static void
mbim_projection_table_coeff_fmt(gchar *s, guint32 val)
{
    gint32 coeff = (gint32)val;

    snprintf(s, ITEM_LABEL_LENGTH, "%.3f (%d)", ((float)coeff)/1000, coeff);
}

#define MBIM_NDP_CTRL_MULTIFLOW_STATUS 0

static const value_string mbim_ndp_ctrl_msg_type_vals[] = {
    { MBIM_NDP_CTRL_MULTIFLOW_STATUS, "MULTIFLOW_STATUS"},
    { 0, NULL}
};

static const value_string mbim_ndp_ctrl_multiflow_status_vals[] = {
    { 0, "OK"},
    { 1, "High Watermark"},
    { 2, "Low Watermark"},
    { 0, NULL}
};

static int * const mbim_multiflow_caps_info_control_caps_fields[] = {
    &hf_mbim_multiflow_caps_info_control_caps_uplink,
    &hf_mbim_multiflow_caps_info_control_caps_downlink,
    NULL
};

static const value_string mbim_multiflow_state_vals[] = {
    { 0, "Off"},
    { 1, "On"},
    { 0, NULL}
};

static const value_string mbim_ms_context_roaming_control_vals[] = {
    { 0, "HomeOnly"},
    { 1, "PartnerOnly"},
    { 2, "NonPartnerOnly"},
    { 3, "HomeAndPartner"},
    { 4, "HomeAndNonPartner"},
    { 5, "PartnerAndNonPartner"},
    { 6, "AllowAll"},
    { 0, NULL}
};

static const value_string mbim_ms_context_media_type_vals[] = {
    { 0, "CellularOnly"},
    { 1, "WifiOnly"},
    { 2, "All"},
    { 0, NULL}
};

static const value_string mbim_ms_context_enable_vals[] = {
    { 0, "Disabled"},
    { 1, "Enabled"},
    { 0, NULL}
};

static const value_string mbim_ms_context_source_vals[] = {
    { 0, "Admin"},
    { 1, "User"},
    { 2, "Operator"},
    { 3, "Modem"},
    { 4, "Device"},
    { 0, NULL}
};

static const value_string mbim_ms_context_operations_vals[] = {
    { 0, "Default"},
    { 1, "Delete"},
    { 2, "RestoreFactory"},
    { 0, NULL}
};

static int * const mbim_ms_network_blacklist_state_fields[] = {
    &hf_mbim_ms_network_blacklist_state_sim_provider_actuated,
    &hf_mbim_ms_network_blacklist_state_network_provider_actuated,
    NULL
};

static const value_string mbim_ms_network_blacklist_type_vals[] = {
    { 0, "SIM"},
    { 1, "Network"},
    { 0, NULL}
};

static const value_string mbim_ms_uiccslot_state_vals[] = {
    { 0, "Unknown"},
    { 1, "OffEmpty"},
    { 2, "Off"},
    { 3, "Empty"},
    { 4, "NotReady"},
    { 5, "Active"},
    { 6, "Error"},
    { 7, "ActiveEsim"},
    { 8, "ActiveEsimNoProfiles"},
    { 0, NULL}
};

static const value_string mbim_base_station_serving_cell_flag_vals[] = {
    { 0, "Neighbor Cell"},
    { 1, "Serving cell"},
    { 0, NULL}
};

static const value_string mbim_ms_uicc_app_type_vals[] = {
    { 0, "Unknown"},
    { 1, "Mf"},
    { 2, "SIM"},
    { 3, "RUIM"},
    { 4, "USIM"},
    { 5, "CSIM"},
    { 6, "ISIM"},
    { 0, NULL}
};
static const value_string mbim_ms_apdu_secure_messaging_vals[] = {
    { 0, "None"},
    { 1, "No Hdr Auth"},
    { 0, NULL}
};
static const value_string mbim_ms_apdu_type_vals[] = {
    { 0, "Interindustry"},
    { 1, "Extended"},
    { 0, NULL}
};
static const value_string mbim_ms_reset_pass_through_action_vals[] = {
    { 0, "Disabled"},
    { 1, "Enabled"},
    { 0, NULL}
};

static const value_string mbim_uicc_file_accessibility_vals[] = {
    { 0, "Unknown"},
    { 1, "NotShareable"},
    { 2, "Shareable"},
    { 0, NULL}
};

static const value_string mbim_uicc_file_type_vals[] = {
    { 0, "Unknown"},
    { 1, "WorkingEf"},
    { 2, "InternalEf"},
    { 3, "DfOrAdf"},
    { 0, NULL}
};

static const value_string mbim_uicc_file_structure_vals[] = {
    { 0, "Unknown"},
    { 1, "Transparent"},
    { 2, "Cyclic"},
    { 3, "Linear"},
    { 4, "BerTLV"},
    { 0, NULL}
};

static void mbim_dissect_tlv_ie(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset);

static guint8
mbim_dissect_service_id_uuid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint hf,
                             gint *offset, struct mbim_uuid_ext **uuid_ext_info, gboolean is_net_guid)
{
    e_guid_t uuid;
    guint i;
    guint32 uuid_ext[4];

    if (is_net_guid)
    {
        tvb_get_ntohguid(tvb, *offset, &uuid);
    }
    else
    {
        tvb_get_letohguid(tvb, *offset, &uuid);
    }
    for (i = 0; i < UUID_MAX; i++) {
        if (memcmp(&uuid, &(mbim_uuid_service_id_vals[i].uuid), sizeof(e_guid_t)) == 0) {
            break;
        }
    }

    if ((i == UUID_MAX) && mbim_uuid_ext_hash && uuid_ext_info) {
        /* Let's check if UUID is known in extension table */
        uuid_ext[0] = tvb_get_ntohl(tvb, *offset);
        uuid_ext[1] = tvb_get_ntohl(tvb, *offset + 4);
        uuid_ext[2] = tvb_get_ntohl(tvb, *offset + 8);
        uuid_ext[3] = tvb_get_ntohl(tvb, *offset + 12);

        *uuid_ext_info = (struct mbim_uuid_ext *)wmem_map_lookup(mbim_uuid_ext_hash, uuid_ext);
        if (*uuid_ext_info) {
            proto_tree_add_guid_format_value(tree, hf, tvb, *offset, 16, &uuid, "%s (%s)",
                                             (*uuid_ext_info)->uuid_name, guid_to_str(pinfo->pool, &uuid));
            *offset += 16;
            return UUID_EXT_IDX;
        }
    }

    proto_tree_add_guid_format_value(tree, hf, tvb, *offset, 16, &uuid, "%s (%s)",
                                     val_to_str_ext_const(i, &mbim_service_id_vals_ext, "Unknown"),
                                     guid_to_str(pinfo->pool, &uuid));
    *offset += 16;

    return i;
}

static guint32
mbim_dissect_cid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, guint8 uuid_idx,
                 struct mbim_uuid_ext *uuid_ext_info)
{
    guint32 cid;

    cid = tvb_get_letohl(tvb, *offset);
    if (uuid_idx < UUID_MAX) {
        proto_tree_add_uint(tree, *mbim_uuid_info[uuid_idx].hf_entry, tvb, *offset, 4, cid);
        if (mbim_uuid_info[uuid_idx].cid_list_ext) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                            val_to_str_ext_const(cid, mbim_uuid_info[uuid_idx].cid_list_ext, "Unknown"));
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(cid, mbim_uuid_info[uuid_idx].cid_list, "Unknown"));
        }
    } else if (uuid_idx == UUID_EXT_IDX) {
        const gchar* cid_string = val_to_str_const(cid, uuid_ext_info->uuid_cid_list, "Unknown");

        proto_tree_add_uint_format_value(tree, hf_mbim_cid, tvb, *offset, 4, cid, "%s (%u)", cid_string , cid);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", cid_string);
    } else {
        proto_tree_add_uint(tree, hf_mbim_cid, tvb, *offset, 4, cid);
        col_append_str(pinfo->cinfo, COL_INFO, ": Unknown");
    }
    *offset += 4;
    return cid;
}

static void
mbim_dissect_ms_plmn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint16 mnc;
    proto_tree_add_item(tree, hf_mbim_ms_plmn_mcc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    mnc = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    if (mnc & 0x8000) {
        proto_tree_add_uint_format_value(tree, hf_mbim_ms_plmn_mnc, tvb, offset, 2, mnc, "%02u", mnc & 0x7fff);
    }
    else {
        proto_tree_add_uint_format_value(tree, hf_mbim_ms_plmn_mnc, tvb, offset, 2, mnc, "%03u", mnc & 0x7fff);
    }
    /* offset += 2; */
}

static void
mbim_dissect_ms_tai_list_single_plmn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
    guint32 tac_element, i;
    mbim_dissect_ms_plmn(tvb, pinfo, tree, *offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_tai_list_single_plmn_tac_element, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tac_element);
    *offset += 1;
    for (i = 0; i < tac_element; i++) {
        proto_tree_add_item(tree, hf_mbim_ms_tai_tac, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
}

static void
mbim_dissect_ms_tai_list_multi_plmn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
    proto_tree* subtree;
    guint32 tai_element, i;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_tai_list_multi_plmn_tai_element, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tai_element);
    *offset += 1;
    for (i = 0; i < tai_element; i++) {
        subtree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_mbim_pair_list, NULL, "TAI #%u", i + 1);
        mbim_dissect_ms_plmn(tvb, pinfo, subtree, *offset);
        *offset += 4;
        proto_tree_add_item(subtree, hf_mbim_ms_tai_tac, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
    }
}

static gboolean
mbim_dissect_ms_single_tai(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
    guint32 tai_list_type;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_tai_list_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tai_list_type);
    *offset += 1;
    switch (tai_list_type) {
        case 0:
        case 1:
            mbim_dissect_ms_tai_list_single_plmn(tvb, pinfo, tree, offset);
            break;
        case 2:
            mbim_dissect_ms_tai_list_multi_plmn(tvb, pinfo, tree, offset);
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_mbim_unexpected_msg, tvb, *offset, 1);
            return FALSE;
    }
    return TRUE;
}
static void
mbim_dissect_ms_tai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, guint32 data_len)
{
    proto_tree* subtree;
    gint32 base_offset = offset;
    gint32 tai_list_info_element_pos = 1;
    while ((guint32)offset - base_offset < data_len) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "TAI List Info #%u", tai_list_info_element_pos);
        if (!mbim_dissect_ms_single_tai(tvb, pinfo, subtree, &offset)) {
            break;
        }
        tai_list_info_element_pos++;
    }
}

static void
mbim_dissect_ms_wake_command(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    guint8 uuid_idx;
    struct mbim_uuid_ext *uuid_ext_info = NULL;
    guint payload_offset;
    guint32 payload_size;
    proto_tree *wake_command_tree;

    gint begin_offset = offset;

    wake_command_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Wake Command");

    uuid_idx = mbim_dissect_service_id_uuid(tvb, pinfo, wake_command_tree, hf_mbim_device_service_id, &offset, &uuid_ext_info, TRUE);
    mbim_dissect_cid(tvb, pinfo, wake_command_tree, &offset, uuid_idx, uuid_ext_info);
    proto_tree_add_item_ret_uint(wake_command_tree, hf_mbim_ms_wake_reason_command_payload_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &payload_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(wake_command_tree, hf_mbim_ms_wake_reason_command_payload_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &payload_size);
    offset += 4;
    if (payload_offset && payload_size)
    {
        proto_tree_add_bytes_format(wake_command_tree, hf_mbim_ms_wake_reason_command_payload, tvb, begin_offset + payload_offset, payload_size, NULL, "Payload");
    }
}

static void
mbim_dissect_ms_wake_packet(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    guint packet_offset;
    guint packet_size;
    proto_tree *wake_packet_tree;
    gint begin_offset = offset;

    wake_packet_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Wake Packet");

    proto_tree_add_item(wake_packet_tree, hf_mbim_single_packet_filter_filter_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(wake_packet_tree, hf_mbim_ms_wake_reason_packet_original_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(wake_packet_tree, hf_mbim_ms_wake_reason_packet_saved_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &packet_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(wake_packet_tree, hf_mbim_ms_wake_reason_packet_saved_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &packet_size);
    /* offset += 4; */
    if (packet_offset && packet_size)
    {
        proto_tree_add_bytes_format(wake_packet_tree, hf_mbim_ms_wake_reason_packet_saved_data, tvb, begin_offset + packet_offset, packet_size, NULL, "Saved Packet Data");
    }
}

static void
mbim_dissect_snssai(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    guint snssai_length;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_snssai_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &snssai_length);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbim_ms_snssai_slice_service_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    if(snssai_length >= 4) {
        proto_tree_add_item(tree, hf_mbim_ms_snssai_slice_differentiator, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
        *offset += 3;
    }
    if (snssai_length == 2 || snssai_length>=5) {
        proto_tree_add_item(tree, hf_mbim_ms_snssai_mapped_slice_service_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
    }
    if (snssai_length == 8) {
        proto_tree_add_item(tree, hf_mbim_ms_snssai_mapped_slice_differentiator, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
        *offset += 3;
    }
}

static void
mbim_dissect_nssai(tvbuff_t* tvb, proto_tree* tree, gint offset, gint nssai_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = offset;
    gint snssai_pos = 1;
    while (offset - base_offset < nssai_buffer_length) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "S-NSSAI #%u", snssai_pos);
        mbim_dissect_snssai(tvb,subtree, &offset);
        snssai_pos++;
    }
}

static void
mbim_dissect_precfg_dflt_cfg_nssai(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, gint nssai_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = offset;
    gint precfg_dflt_cfg_nssai_pos = 1;
    while ((offset - base_offset < nssai_buffer_length) && precfg_dflt_cfg_nssai_pos < 2) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Preconfigured default configured NSSAI #%u", precfg_dflt_cfg_nssai_pos);
        proto_tree_add_item(subtree, hf_mbim_ms_pre_dflt_nssai_info_access_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Default configured NSSAI");
        mbim_dissect_tlv_ie(tvb, pinfo, subtree, &offset);
        precfg_dflt_cfg_nssai_pos++;
    }
}

static void
mbim_dissect_rej_snssai(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    guint snssai_length;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_snssai_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &snssai_length);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbim_ms_rej_snssai_cause, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbim_ms_snssai_slice_service_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    if (snssai_length == 4) {
        proto_tree_add_item(tree, hf_mbim_ms_snssai_slice_differentiator, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
        *offset += 3;
    }
}

static void
mbim_dissect_rej_nssai(tvbuff_t* tvb, proto_tree* tree, gint offset, gint rej_nssai_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = offset;
    gint snssai_pos = 1;
    while (offset - base_offset < rej_nssai_buffer_length) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Rejected S-NSSAI #%u", snssai_pos);
        mbim_dissect_rej_snssai(tvb, subtree, &offset);
        snssai_pos++;
    }
}

static void
mbim_dissect_ladn(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, gint rej_nssai_buffer_length)
{
    proto_tree* subtree, * ladn_tree;
    gint base_offset = offset;
    gint ladn_pos = 1;
    while (offset - base_offset < rej_nssai_buffer_length) {
        ladn_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "LADN #%u", ladn_pos);
        subtree = proto_tree_add_subtree_format(ladn_tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "DNN");
        mbim_dissect_tlv_ie(tvb, pinfo, subtree, &offset);
        subtree = proto_tree_add_subtree_format(ladn_tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "TAI");
        if (!mbim_dissect_ms_single_tai(tvb, pinfo, subtree, &offset)) {
            break;
        }
        ladn_pos++;
    }
}

static void
mbim_dissect_tcs(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset, gint tcs_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = *offset;
    gint tc_pos = 1;
    gint tc_type;
    gint tc_value_length;
    while (*offset - base_offset < tcs_buffer_length) {
        subtree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_mbim_pair_list, NULL, "Traffic component #%u", tc_pos);
        proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_type, tvb, *offset, 1, ENC_BIG_ENDIAN, &tc_type);
        *offset += 1;
        switch (tc_type) {
            case URSP_TC_TYPE_MATCH_ALL:
                break;
            case URSP_TC_TYPE_OSID_APPID:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_os_id, tvb, *offset, 16, ENC_NA);
                *offset += 16;
                proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 1, ENC_BIG_ENDIAN, &tc_value_length);
                *offset += 1;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_app_id, tvb, *offset, tc_value_length, ENC_ASCII | ENC_NA);
                *offset += tc_value_length;
                break;
            case URSP_TC_TYPE_IPV4:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_ipv4, tvb, *offset, 4, ENC_NA);
                *offset += 4;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_ipv4_mask, tvb, *offset, 4, ENC_NA);
                *offset += 4;
                break;
            case URSP_TC_TYPE_IPV6:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_ipv6, tvb, *offset, 16, ENC_NA);
                *offset += 16;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_ipv6_prefix_length, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case URSP_TC_TYPE_PROTOCOL_ID_OR_NEXT_HEADER:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_proto_id, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset += 1;
                break;
            case URSP_TC_TYPE_PORT:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset += 2;
                break;
            case URSP_TC_TYPE_PORT_RANGE:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_port_range_low, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset += 2;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_port_range_high, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset += 2;
                break;
            case URSP_TC_TYPE_SECURITY_PARAM_INDEX:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 4, ENC_NA);
                *offset += 4;
                break;
            case URSP_TC_TYPE_SERVICE_OR_TRAFFIC_CLASS:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 2, ENC_NA);
                *offset += 2;
                break;
            case URSP_TC_TYPE_FLOW_LABEL:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 3, ENC_NA);
                *offset += 3;
                break;
            case URSP_TC_TYPE_MAC_ADDRESS:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 6, ENC_NA);
                *offset += 6;
                break;
            case URSP_TC_TYPE_C_TAG_VID:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 2, ENC_NA);
                *offset += 2;
                break;
            case URSP_TC_TYPE_S_TAG_VID:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 2, ENC_NA);
                *offset += 2;
                break;
            case URSP_TC_TYPE_C_TAG_PCP_AND_DEI:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case URSP_TC_TYPE_S_TAG_PCP_AND_DEI:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case URSP_TC_TYPE_ETHER:
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_byte_value, tvb, *offset, 2, ENC_NA);
                *offset += 2;
                break;
            case URSP_TC_TYPE_DNN:
                proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tc_value_length);
                *offset += 1;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_dnn, tvb, *offset, tc_value_length, ENC_APN_STR | ENC_NA);
                *offset += tc_value_length;
                break;
            case URSP_TC_TYPE_CONNECTION_CAPABILITY:
                proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tc_value_length);
                *offset += 1;
                for (int i = 0; i < tc_value_length; i++) {
                    proto_tree_add_bitmask(subtree, tvb, *offset, hf_mbim_ms_ursp_tc_capability, ett_mbim_bitmap,
                        ursp_tc_connection_capability_flags_fields, ENC_LITTLE_ENDIAN);
                    *offset += 1;
                }
                break;
            case URSP_TC_TYPE_FQDN:
                proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tc_value_length);
                *offset += 1;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_fqdn, tvb, *offset, tc_value_length, ENC_APN_STR | ENC_NA);
                *offset += tc_value_length;
                break;
            case URSP_TC_TYPE_APPID:
                proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &tc_value_length);
                *offset += 1;
                proto_tree_add_item(subtree, hf_mbim_ms_ursp_tc_app_id, tvb, *offset, tc_value_length, ENC_LITTLE_ENDIAN | ENC_ASCII);
                *offset += tc_value_length;
                break;
            default:
                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, tvb, *offset, tcs_buffer_length - (*offset - base_offset));
                return;
        }
        tc_pos++;
    }
}

static void
mbim_dissect_td(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
    proto_tree* subtree;
    guint tcs_length;
    subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_mbim_pair_list, NULL, "Traffic descriptor");
    proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, *offset, 2, ENC_BIG_ENDIAN, &tcs_length);
    *offset += 2;
    mbim_dissect_tcs(tvb, pinfo, subtree, offset, tcs_length);
}

static void
mbim_dissect_tps(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, gint tp_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = offset;
    gint tp_pos = 1;
    gint tp_length;
    while (offset - base_offset < tp_buffer_length) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Traffic parameter #%u", tp_pos);
        proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_ursp_tc_length, tvb, offset, 2, ENC_BIG_ENDIAN, &tp_length);
        offset += 2;
        mbim_dissect_tcs(tvb, pinfo, subtree, &offset, tp_length);
        tp_pos++;
    }
}

static void
mbim_dissect_ursp_rules(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, gint ursp_rules_buffer_length)
{
    proto_tree* subtree;
    gint base_offset = offset;
    gint ursp_rule_pos = 1;
    while (offset - base_offset < ursp_rules_buffer_length) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "URSP rule #%u", ursp_rule_pos);
        proto_tree_add_item(subtree, hf_mbim_ms_ursp_precedence, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        mbim_dissect_td(tvb, pinfo, subtree, &offset);
        ursp_rule_pos++;
    }
}

static void
mbim_dissect_tlv_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    guint tlv_data_offset;
    guint padding_length;
    guint data_length;
    guint tlv_type = TLV_TYPE_UNKNOWN;

    proto_tree_add_item_ret_uint(tree, hf_mbim_tlv_ie_type, tvb, *offset, 2, ENC_LITTLE_ENDIAN, &tlv_type);
    *offset += 2;
    proto_tree_add_item(tree, hf_mbim_tlv_ie_reserved, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_mbim_tlv_ie_padding_length, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &padding_length);
    *offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_mbim_tlv_ie_data_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &data_length);
    *offset += 4;
    tlv_data_offset = *offset;
    if (data_length) {
        // New TLV types will be added here
        switch (tlv_type) {
            case TLV_TYPE_SINGLE_NSSAI:
                mbim_dissect_snssai(tvb, tree, offset);
                break;
            case TLV_TYPE_ALLOWED_NSSAI:
            case TLV_TYPE_CFG_NSSAI:
            case TLV_TYPE_DFLT_CFG_NSSAI:
                mbim_dissect_nssai(tvb, tree, *offset, data_length);
                break;
            case TLV_TYPE_PRECFG_DFLT_CFG_NSSAI:
                mbim_dissect_precfg_dflt_cfg_nssai(tvb, pinfo, tree, *offset, data_length);
                break;
            case TLV_TYPE_REJ_NSSAI:
                mbim_dissect_rej_nssai(tvb, tree, *offset, data_length);
                break;
            case TLV_TYPE_LADN:
                mbim_dissect_ladn(tvb, pinfo, tree, *offset, data_length);
                break;
            case TLV_TYPE_TAI:
                mbim_dissect_ms_tai(tvb, pinfo, tree, *offset, data_length);
                break;
            case TLV_TYPE_WCHAR_STR:
                proto_tree_add_item(tree, hf_mbim_tlv_ie_data_wchar_str, tvb, *offset, data_length, ENC_LITTLE_ENDIAN | ENC_UTF_16);
                break;
            case TLV_TYPE_TRAFFIC_PARAMETERS:
                mbim_dissect_tps(tvb, pinfo, tree, *offset, data_length);
                break;
            case TLV_TYPE_WAKE_COMMAND:
                mbim_dissect_ms_wake_command(tvb, pinfo, tree, *offset);
                break;
            case TLV_TYPE_WAKE_PACKET:
                mbim_dissect_ms_wake_packet(tvb, pinfo, tree, *offset);
                break;
            case TLV_TYPE_TYPE_OSID:
                proto_tree_add_item(tree, hf_mbim_tlv_ie_data_guid, tvb, *offset, 16, ENC_NA);
                break;
            case TLV_TYPE_TYPE_3GPP_REL_VERSION:
                proto_tree_add_item(tree, hf_mbim_tlv_ie_data_int32, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
                break;
            case TLV_TYPE_TYPE_URSP_RULES_TD_ONLY:
                mbim_dissect_ursp_rules(tvb,pinfo, tree, *offset, data_length);
                break;
            case TLV_TYPE_TYPE_SESSION_ID:
                proto_tree_add_item(tree, hf_mbim_tlv_ie_data_int32, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
                break;
            default:
                proto_tree_add_item(tree, hf_mbim_tlv_ie_unnamed_data, tvb, *offset, data_length, ENC_NA);
                break;
        }
        *offset = tlv_data_offset + data_length;
    }
    if (padding_length) {
        proto_tree_add_item(tree, hf_mbim_tlv_ie_padding, tvb, *offset, padding_length, ENC_NA);
        *offset += padding_length;
    }
}

static void
mbim_dissect_tlv_ie_list(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint tlv_offset, gint buffer_base_offset, gint buffer_length)
{
    proto_tree* unnamed_ies;
    while (tlv_offset - buffer_base_offset < buffer_length) {
        unnamed_ies = proto_tree_add_subtree_format(tree, tvb, tlv_offset, 0, ett_mbim_pair_list, NULL, "Unnamed IE's");
        mbim_dissect_tlv_ie(tvb, pinfo, unnamed_ies, &tlv_offset);
    }
}

static void
mbim_dissect_device_caps_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
                              struct mbim_conv_info *mbim_conv)
{
    gint base_offset;
    guint32 custom_class_offset, custom_class_size, device_id_offset, device_id_size,
            fw_info_offset, fw_info_size, hw_info_offset, hw_info_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_device_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_cellular_class, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &mbim_conv->cellular_class);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_voice_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sim_class, ett_mbim_bitmap,
                           mbim_device_caps_info_sim_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_data_class, ett_mbim_bitmap,
                           mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sms_caps, ett_mbim_bitmap,
                           mbim_device_caps_info_sms_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_control_caps, ett_mbim_bitmap,
                           mbim_device_caps_info_control_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_max_sessions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_custom_data_class_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &custom_class_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_custom_data_class_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &custom_class_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_device_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &device_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_device_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &device_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_fw_info_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fw_info_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_fw_info_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fw_info_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_hw_info_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &hw_info_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_hw_info_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &hw_info_size);
    /*offset += 4;*/
    if (custom_class_offset && custom_class_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_custom_data_class, tvb, base_offset + custom_class_offset,
                                custom_class_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (custom_class_size > 22) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (device_id_offset && device_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_device_id, tvb, base_offset + device_id_offset,
                                 device_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if ((mbim_conv->cellular_class == MBIM_CELLULAR_CLASS_GSM) && (device_id_size > 30)) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        } else if (device_id_size > 36) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (fw_info_offset && fw_info_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_fw_info, tvb, base_offset + fw_info_offset,
                                 fw_info_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (fw_info_size > 60) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (hw_info_offset && hw_info_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_hw_info, tvb, base_offset + hw_info_offset,
                                 hw_info_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (hw_info_size > 60) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_subscriber_ready_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                                     struct mbim_conv_info *mbim_conv)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, subscriber_id_offset, subscriber_id_size, sim_icc_id_offset, sim_icc_id_size, elem_count;
    proto_item *it;
    wmem_array_t *pair_list = NULL;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_subscr_ready_status_ready_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_subscr_ready_status_flags, ett_mbim_bitmap,
            mbim_subscr_ready_status_flags_fields, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item_ret_uint(tree, hf_mbim_subscr_ready_status_susbcr_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &subscriber_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_subscr_ready_status_susbcr_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &subscriber_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_subscr_ready_status_sim_icc_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sim_icc_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_subscr_ready_status_sim_icc_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sim_icc_id_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_subscr_ready_status_ready_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_subscr_ready_status_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;

    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Telephone Numbers Ref List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_subscr_ready_status_tel_nb_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_subscr_ready_status_tel_nb_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
    }
    if (subscriber_id_offset && subscriber_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_subscr_ready_status_susbcr_id, tvb, base_offset + subscriber_id_offset,
                                 subscriber_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if ((mbim_conv->cellular_class == MBIM_CELLULAR_CLASS_CDMA) && (subscriber_id_size > 20)) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        } else if (subscriber_id_size > 30) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (sim_icc_id_offset && sim_icc_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_subscr_ready_status_sim_icc_id, tvb, base_offset + sim_icc_id_offset,
                                 sim_icc_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (sim_icc_id_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    for (i = 0; i < elem_count; i++) {
        p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
        if (p_pair_list_item->offset && p_pair_list_item->size) {
            it = proto_tree_add_item(tree, hf_mbim_subscr_ready_status_tel_nb, tvb, base_offset + p_pair_list_item->offset,
                                     p_pair_list_item->size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
            if (p_pair_list_item->size > 44) {
                expert_add_info(pinfo, it, &ei_mbim_oversized_string);
            }
        }
    }
}

static void
mbim_dissect_set_pin(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 pin_offset, pin_size, new_pin_offset, new_pin_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_pin_pin_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_pin_pin_pin_operation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_pin_pin_pin_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pin_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_pin_pin_pin_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pin_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_pin_new_pin_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &new_pin_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_pin_new_pin_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &new_pin_size);
    /*offset += 4;*/
    if (pin_offset && pin_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_pin_pin, tvb, base_offset + pin_offset,
                                 pin_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (pin_size > 32) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (new_pin_offset && new_pin_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_pin_new_pin, tvb, base_offset + new_pin_offset,
                                 new_pin_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (new_pin_size > 32) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_pin_list_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    const char *pin_list[10] = { "PIN 1", "PIN 2", "Device SIM PIN", "Device First SIM PIN", "Network PIN",
                                 "Network Subset PIN", "Service Provider PIN", "Corporate PIN", "Subsidy Lock",
                                 "Custom"};
    guint i;
    guint32 length;
    proto_tree *subtree;

    for (i = 0; i < 10; i++) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_mbim_pin, NULL, pin_list[i]);
        proto_tree_add_item(subtree, hf_mbim_pin_list_pin_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_pin_list_pin_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        length = tvb_get_letohl(tvb, offset);
        if (length == 0xffffffff) {
            proto_tree_add_uint_format_value(subtree, hf_mbim_pin_list_pin_length_min, tvb, offset, 4,
                                             length, "Not available (0xffffffff)");
        } else {
            proto_tree_add_uint(subtree, hf_mbim_pin_list_pin_length_min, tvb, offset, 4, length);
        }
        offset += 4;
        length = tvb_get_letohl(tvb, offset);
        if (length == 0xffffffff) {
            proto_tree_add_uint_format_value(subtree, hf_mbim_pin_list_pin_length_max, tvb, offset, 4,
                                             length, "Not available (0xffffffff)");
        } else {
            proto_tree_add_uint(subtree, hf_mbim_pin_list_pin_length_max, tvb, offset, 4, length);
        }
        offset += 4;
    }
}

static void
mbim_dissect_provider(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 provider_id_offset, provider_id_size, provider_name_offset, provider_name_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_provider_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_provider_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_provider_state, ett_mbim_bitmap,
                           mbim_provider_state_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_provider_provider_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_provider_provider_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_size);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_provider_cellular_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_provider_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_provider_error_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    /*offset += 4;*/
    if (provider_id_offset && provider_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_provider_provider_id, tvb, base_offset + provider_id_offset,
                                 provider_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_id_size > 12) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (provider_name_offset && provider_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_provider_provider_name, tvb, base_offset + provider_name_offset,
                                 provider_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_name_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_providers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_providers_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Providers Ref List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_providers_provider_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_providers_provider_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Provider #%u", i+1);
                mbim_dissect_provider(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_set_register_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 provider_id_offset, provider_id_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_register_state_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_register_state_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_register_state_register_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_register_state_data_class, ett_mbim_bitmap,
                           mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    /*offset += 4;*/
    if (provider_id_offset && provider_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_register_state_provider_id, tvb, base_offset + provider_id_offset,
                                 provider_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_id_size > 12) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_registration_state_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    gint base_offset;
    guint32 provider_id_offset, provider_id_size, provider_name_offset, provider_name_size,
            roaming_text_offset, roaming_text_size, nw_error;
    proto_item *it;

    base_offset = offset;
    nw_error = tvb_get_letohl(tvb, offset);
    if (nw_error == 0) {
        proto_tree_add_uint_format_value(tree, hf_mbim_registration_state_info_nw_error, tvb, offset, 4, nw_error, "Success (0)");
    } else {
        proto_tree_add_uint(tree, hf_mbim_registration_state_info_nw_error, tvb, offset, 4, nw_error);
    }
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_registration_state_info_register_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_registration_state_info_register_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_registration_state_info_available_data_classes, ett_mbim_bitmap,
                           mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_registration_state_info_current_cellular_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_provider_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_provider_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_roaming_text_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &roaming_text_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_registration_state_info_roaming_text_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &roaming_text_size);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_registration_state_info_registration_flags, ett_mbim_bitmap,
                           mbim_registration_state_info_registration_flags_fields, ENC_LITTLE_ENDIAN);
    if (SHOULD_MBIM_EX2_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        offset += 4;
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_registration_state_info_preferred_data_class, ett_mbim_bitmap,
                    mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    }
    /*offset += 4;*/
    if (provider_id_offset && provider_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_registration_state_info_provider_id, tvb, base_offset + provider_id_offset,
                                 provider_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_id_size > 12) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (provider_name_offset && provider_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_registration_state_info_provider_name, tvb, base_offset + provider_name_offset,
                                 provider_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_name_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (roaming_text_offset && roaming_text_size) {
        it = proto_tree_add_item(tree, hf_mbim_registration_state_info_roaming_text, tvb, base_offset + roaming_text_offset,
                                 roaming_text_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (roaming_text_size > 126) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_packet_service_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv, guint32 buffer_len)
{
    proto_tree *tai_ie;
    guint32 nw_error;
    guint32 base_offset = offset;

    nw_error = tvb_get_letohl(tvb, offset);
    if (nw_error == 0) {
        proto_tree_add_uint_format_value(tree, hf_mbim_packet_service_info_nw_error, tvb, offset, 4, nw_error, "Success (0)");
    } else {
        proto_tree_add_uint(tree, hf_mbim_packet_service_info_nw_error, tvb, offset, 4, nw_error);
    }
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_packet_service_info_packet_service_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX2_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_packet_service_info_current_data_class, ett_mbim_bitmap,
                    mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_packet_service_info_highest_available_data_class, ett_mbim_bitmap,
                    mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    }
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_packet_service_info_uplink_speed, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_packet_service_info_downlink_speed, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    if (SHOULD_MBIM_EX2_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_packet_service_info_frequency_range, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_packet_service_info_data_subclass, ett_mbim_bitmap,
            mbim_data_subclass_fields, ENC_LITTLE_ENDIAN);
        offset += 4;
        tai_ie = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Tracking Area Identity");
        mbim_dissect_ms_plmn(tvb, pinfo, tai_ie, offset);
        offset += 4;
        proto_tree_add_item(tai_ie, hf_mbim_ms_tai_tac, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        mbim_dissect_tlv_ie_list(tvb, pinfo, tree, offset, base_offset, buffer_len);
    }
}

static void
mbim_dissect_set_signal_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    guint32 error_rate_threshold;

    proto_tree_add_item(tree, hf_mbim_set_signal_state_signal_strength_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_signal_state_rssi_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    error_rate_threshold = tvb_get_letohl(tvb, offset);
    if (error_rate_threshold == 0xffffffff) {
        proto_tree_add_uint_format_value(tree, hf_mbim_set_signal_state_error_rate_threshold, tvb, offset, 4,
                                         error_rate_threshold, "No report (0xffffffff)");
    } else {
        proto_tree_add_item(tree, hf_mbim_set_signal_state_error_rate_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_signal_state_element(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_signal_state_element_rsrp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_element_snr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_element_rsrp_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_element_snr_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_signal_state_element_system_type, ett_mbim_bitmap,
        mbim_data_class_fields, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_signal_state_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 error_rate_threshold, rsrp_snr_offset, rsrp_snr_size, elem_count, i;
    const gint signal_state_elem_size = 20;
    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_signal_state_info_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_info_error_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_info_signal_strength_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_signal_state_info_rssi_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    error_rate_threshold = tvb_get_letohl(tvb, offset);
    if (error_rate_threshold == 0xffffffff) {
        proto_tree_add_uint_format_value(tree, hf_mbim_signal_state_info_error_rate_threshold, tvb, offset, 4,
            error_rate_threshold, "No report (0xffffffff)");
    } else {
        proto_tree_add_item(tree, hf_mbim_signal_state_info_error_rate_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    offset += 4;
    if (SHOULD_MBIM_EX2_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item_ret_uint(tree, hf_mbim_signal_state_info_rsrp_snr_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &rsrp_snr_offset);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_mbim_signal_state_info_rsrp_snr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &rsrp_snr_size);
        if (rsrp_snr_offset && rsrp_snr_size) {
            offset = base_offset + rsrp_snr_offset;
            proto_tree_add_item_ret_uint(tree, hf_mbim_signal_state_info_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
            offset += 4;
            for (i = 0; i < elem_count; i++) {
                offset += signal_state_elem_size * i;
                subtree = proto_tree_add_subtree_format(tree, tvb, offset, signal_state_elem_size, ett_mbim_pair_list, NULL, "RSRP SNR Info #%u", i + 1);
                mbim_dissect_signal_state_element(tvb, pinfo, subtree, offset);
            }
        }
    }
}

static guint8
mbim_dissect_context_type_uuid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    e_guid_t uuid;
    guint i;

    tvb_get_ntohguid(tvb, *offset, &uuid);

    for (i = 0; i < array_length(mbim_uuid_context_type_vals); i++) {
        if (memcmp(&uuid, &(mbim_uuid_context_type_vals[i].uuid), sizeof(e_guid_t)) == 0) {
            break;
        }
    }
    proto_tree_add_guid_format_value(tree, hf_mbim_context_type, tvb, *offset, 16, &uuid, "%s (%s)",
                                     val_to_str_const(i, mbim_context_type_vals, "Unknown"), guid_to_str(pinfo->pool, &uuid));
    *offset += 16;

    return i;
}

static void
mbim_dissect_set_connect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 access_string_offset, access_string_size, user_name_offset, user_name_size,
            password_offset, password_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_connect_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_activation_command, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_access_string_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &access_string_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_access_string_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &access_string_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_user_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &user_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_user_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &user_name_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_password_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &password_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_connect_password_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &password_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_compression, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_auth_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_ip_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    mbim_dissect_context_type_uuid(tvb, pinfo, tree, &offset);
    if (access_string_offset && access_string_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_connect_access_string, tvb, base_offset + access_string_offset,
                                 access_string_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (access_string_size > 200) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (user_name_offset && user_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_connect_user_name, tvb, base_offset + user_name_offset,
                                 user_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (user_name_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (password_offset && password_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_connect_password, tvb, base_offset + password_offset,
                                 password_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (password_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_set_connect_v3_and_higher(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, guint32 buffer_len, struct mbim_conv_info* mbim_conv)
{
    gint32 base_offset = offset;
    proto_tree *access_string, *user_name, *password, *snssai;

    proto_tree_add_item(tree, hf_mbim_set_connect_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_activation_command, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_set_connect_activation_option, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item(tree, hf_mbim_set_connect_compression, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_auth_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_connect_ip_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    mbim_dissect_context_type_uuid(tvb, pinfo, tree, &offset);
    proto_tree_add_item(tree, hf_mbim_set_connect_media_preference, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    access_string = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Access String");
    mbim_dissect_tlv_ie(tvb, pinfo, access_string, &offset);
    user_name = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "User Name");
    mbim_dissect_tlv_ie(tvb, pinfo, user_name, &offset);
    password = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Password");
    mbim_dissect_tlv_ie(tvb, pinfo, password, &offset);
    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        snssai = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "S-NSSAI");
        mbim_dissect_tlv_ie(tvb, pinfo, snssai, &offset);
    }
    mbim_dissect_tlv_ie_list(tvb, pinfo, tree, offset, base_offset, buffer_len);
}

static void
mbim_dissect_connect_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv, guint32 buffer_len)
{
    gint32 base_offset = offset;
    proto_tree *access_string, *snssai;
    guint32 nw_error;

    proto_tree_add_item(tree, hf_mbim_connect_info_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_connect_info_activation_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_connect_info_voice_call_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_connect_info_ip_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    mbim_dissect_context_type_uuid(tvb, pinfo, tree, &offset);
    nw_error = tvb_get_letohl(tvb, offset);
    if (nw_error == 0) {
        proto_tree_add_uint_format_value(tree, hf_mbim_connect_info_nw_error, tvb, offset, 4, nw_error, "Success (0)");
    } else {
        proto_tree_add_uint(tree, hf_mbim_connect_info_nw_error, tvb, offset, 4, nw_error);
    }
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        offset += 4;
        proto_tree_add_item(tree, hf_mbim_connect_info_access_media, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        access_string = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Access String");
        mbim_dissect_tlv_ie(tvb, pinfo, access_string, &offset);
        if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
            snssai = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "S-NSSAI");
            mbim_dissect_tlv_ie(tvb, pinfo, snssai, &offset);
        }
        mbim_dissect_tlv_ie_list(tvb, pinfo, tree, offset, base_offset, buffer_len);
    }
}

static void
mbim_dissect_context(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gboolean is_set)
{
    gint base_offset;
    guint32 access_string_offset, access_string_size, user_name_offset, user_name_size,
            password_offset, password_size, provider_id_offset = 0, provider_id_size = 0;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_context_context_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    mbim_dissect_context_type_uuid(tvb, pinfo, tree, &offset);
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_access_string_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &access_string_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_access_string_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &access_string_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_user_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &user_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_user_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &user_name_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_password_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &password_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_context_password_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &password_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_context_compression, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_context_auth_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (is_set) {
        proto_tree_add_item_ret_uint(tree, hf_mbim_context_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_mbim_context_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
        offset += 4;
    }
    if (access_string_offset && access_string_size) {
        it = proto_tree_add_item(tree, hf_mbim_context_access_string, tvb, base_offset + access_string_offset,
                                 access_string_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (access_string_size > 200) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (user_name_offset && user_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_context_user_name, tvb, base_offset + user_name_offset,
                                 user_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (user_name_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (password_offset && password_size) {
        it = proto_tree_add_item(tree, hf_mbim_context_password, tvb, base_offset + password_offset,
                                 password_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (password_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (provider_id_offset && provider_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_context_provider_id, tvb, base_offset + provider_id_offset,
                                 provider_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_id_size > 12) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_provisioned_contexts_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_provisioned_contexts_info_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Provisioned Context Ref List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_provisioned_contexts_info_provisioned_context_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_provisioned_contexts_info_provisioned_context_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "Provisioned Context #%u", i+1);
                mbim_dissect_context(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset, FALSE);
            }
        }
    }
}

static void
mbim_dissect_ipv4_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    guint32 on_link_prefix_length;
    proto_item *ti;

    ti = proto_tree_add_item_ret_uint(tree, hf_mbim_ipv4_element_on_link_prefix_length,
                                      tvb, *offset, 4, ENC_LITTLE_ENDIAN, &on_link_prefix_length);
    *offset += 4;
    if (on_link_prefix_length > 32) {
        expert_add_info_format(pinfo, ti, &ei_mbim_illegal_on_link_prefix_length,
                               "Illegal On Link Prefix Length %u (max is 32)", on_link_prefix_length);
    }
    proto_tree_add_item(tree, hf_mbim_ipv4_element_ipv4_address, tvb, *offset, 4, ENC_NA);
    *offset += 4;
}

static void
mbim_dissect_ipv6_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset)
{
    guint32 on_link_prefix_length;
    proto_item *ti;

    ti = proto_tree_add_item_ret_uint(tree, hf_mbim_ipv6_element_on_link_prefix_length, tvb,
                                      *offset, 4, ENC_LITTLE_ENDIAN, &on_link_prefix_length);
    *offset += 4;
    if (on_link_prefix_length > 128) {
        expert_add_info_format(pinfo, ti, &ei_mbim_illegal_on_link_prefix_length,
                               "Illegal On Link Prefix Length %u (max is 128)", on_link_prefix_length);
    }
    proto_tree_add_item(tree, hf_mbim_ipv6_element_ipv6_address, tvb, *offset, 16, ENC_NA);
    *offset += 16;
}

static void
mbim_dissect_ip_configuration_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 i, ipv4_address_count, ipv4_address_offset, ipv6_address_count, ipv6_address_offset,
            ipv4_gateway_offset, ipv6_gateway_offset, ipv4_dns_count, ipv4_dns_offset,
            ipv6_dns_count, ipv6_dns_offset;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ip_configuration_info_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_ip_configuration_info_ipv4_configuration_available,
                           ett_mbim_bitmap, mbim_ip_configuration_info_ipv4_configuration_available_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_ip_configuration_info_ipv6_configuration_available,
                           ett_mbim_bitmap, mbim_ip_configuration_info_ipv6_configuration_available_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv4_address_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv4_address_count);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv4_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv4_address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv6_address_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv6_address_count);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv6_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv6_address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv4_gateway_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv4_gateway_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv6_gateway_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv6_gateway_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv4_dns_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv4_dns_count);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv4_dns_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv4_dns_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv6_dns_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv6_dns_count);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ip_configuration_info_ipv6_dns_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ipv6_dns_offset);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv4_mtu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv6_mtu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (ipv4_address_count && ipv4_address_offset) {
        offset = base_offset + ipv4_address_offset;
        for (i = 0; i < ipv4_address_count; i++) {
            mbim_dissect_ipv4_element(tvb, pinfo, tree, &offset);
        }
    }
    if (ipv6_address_count && ipv6_address_offset) {
        offset = base_offset + ipv6_address_offset;
        for (i = 0; i < ipv6_address_count; i++) {
            mbim_dissect_ipv6_element(tvb, pinfo, tree, &offset);
        }
    }
    if (ipv4_gateway_offset) {
        proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv4_gateway,
                            tvb, base_offset + ipv4_gateway_offset, 4, ENC_NA);
    }
    if (ipv6_gateway_offset) {
        proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv6_gateway,
                            tvb, base_offset + ipv6_gateway_offset, 16, ENC_NA);
    }
    if (ipv4_dns_count && ipv4_dns_offset) {
        offset = base_offset + ipv4_dns_offset;
        for (i = 0; i < ipv4_dns_count; i++) {
            proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv4_dns,
                                tvb, offset, 4, ENC_NA);
            offset += 4;
        }
    }
    if (ipv6_dns_count && ipv6_dns_offset) {
        offset = base_offset + ipv6_dns_offset;
        for (i = 0; i < ipv6_dns_count; i++) {
            proto_tree_add_item(tree, hf_mbim_ip_configuration_info_ipv6_dns,
                                tvb, offset, 16, ENC_NA);
            offset += 16;
        }
    }
}

static void
mbim_dissect_device_service_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint8 uuid_idx;
    guint32 i, cid_count, cid;
    struct mbim_uuid_ext *uuid_ext_info = NULL;

    uuid_idx = mbim_dissect_service_id_uuid(tvb, pinfo, tree, hf_mbim_device_service_element_device_service_id, &offset, &uuid_ext_info, TRUE);
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_service_element_dss_payload,
                           ett_mbim_bitmap, mbim_device_service_element_dss_payload_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_service_element_max_dss_instances, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_service_element_cid_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cid_count);
    offset += 4;
    for (i = 0; i < cid_count; i++) {
        cid = tvb_get_letohl(tvb, offset);
        if (uuid_idx < UUID_MAX) {
            if (mbim_uuid_info[uuid_idx].cid_list_ext) {
                proto_tree_add_uint_format_value(tree, hf_mbim_device_service_element_cid, tvb, offset, 4, cid, "%s (%u)",
                                                 val_to_str_ext_const(cid, mbim_uuid_info[uuid_idx].cid_list_ext, "Unknown"), cid);
            } else {
                proto_tree_add_uint_format_value(tree, hf_mbim_device_service_element_cid, tvb, offset, 4, cid, "%s (%u)",
                                                 val_to_str_const(cid, mbim_uuid_info[uuid_idx].cid_list, "Unknown"), cid);
            }
        } else if (uuid_idx == UUID_EXT_IDX) {
            proto_tree_add_uint_format_value(tree, hf_mbim_device_service_element_cid, tvb, offset, 4, cid, "%s (%u)",
                                             val_to_str_const(cid, uuid_ext_info->uuid_cid_list, "Unknown"), cid);
        } else {
            proto_tree_add_uint(tree, hf_mbim_device_service_element_cid, tvb, offset, 4, cid);
        }
        offset += 4;
    }
 }

static void
mbim_dissect_device_services_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, device_services_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_services_info_device_services_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &device_services_count);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_services_info_max_dss_sessions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (device_services_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*device_services_count, ett_mbim_pair_list, NULL, "Device Services Ref List");
        for (i = 0; i < device_services_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_device_services_info_device_services_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_device_services_info_device_services_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < device_services_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "Device Service Element #%u", i+1);
                mbim_dissect_device_service_element(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_event_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint8 uuid_idx;
    guint32 i, cid_count, cid;
    struct mbim_uuid_ext *uuid_ext_info = NULL;

    uuid_idx = mbim_dissect_service_id_uuid(tvb, pinfo, tree, hf_mbim_event_entry_device_service_id, &offset, &uuid_ext_info, TRUE);
    proto_tree_add_item_ret_uint(tree, hf_mbim_event_entry_cid_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cid_count);
    offset += 4;
    for (i = 0; i < cid_count; i++) {
        cid = tvb_get_letohl(tvb, offset);
        if (uuid_idx < UUID_MAX) {
            if (mbim_uuid_info[uuid_idx].cid_list_ext) {
                proto_tree_add_uint_format_value(tree, hf_mbim_event_entry_cid, tvb, offset, 4, cid, "%s (%u)",
                                                 val_to_str_ext_const(cid, mbim_uuid_info[uuid_idx].cid_list_ext, "Unknown"), cid);
            } else {
                proto_tree_add_uint_format_value(tree, hf_mbim_event_entry_cid, tvb, offset, 4, cid, "%s (%u)",
                                                 val_to_str_const(cid, mbim_uuid_info[uuid_idx].cid_list, "Unknown"), cid);
            }
        } else if (uuid_idx == UUID_EXT_IDX) {
            proto_tree_add_uint_format_value(tree, hf_mbim_device_service_element_cid, tvb, offset, 4, cid, "%s (%u)",
                                             val_to_str_const(cid, uuid_ext_info->uuid_cid_list, "Unknown"), cid);
        } else {
            proto_tree_add_uint(tree, hf_mbim_event_entry_cid, tvb, offset, 4, cid);
        }
        offset += 4;
    }
 }

static void
mbim_dissect_device_service_subscribe_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, element_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_service_subscribe_element_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &element_count);
    offset += 4;
    if (element_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*element_count, ett_mbim_pair_list, NULL, "Device Service Subscribe Ref List");
        for (i = 0; i < element_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_device_service_subscribe_device_service_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_device_service_subscribe_device_service_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < element_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "Device Service Element #%u", i+1);
                mbim_dissect_event_entry(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_packet_statistics_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_in_discards, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_in_errors, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_in_octets, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_in_packets, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_out_octets, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_out_packets, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_out_errors, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_packet_statistics_info_out_discards, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_single_packet_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    gint base_offset;
    guint32 filter_size, packet_filter_offset, packet_mask_offset;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_single_packet_filter_filter_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &filter_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_single_packet_filter_packet_filter_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &packet_filter_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_single_packet_filter_packet_mask_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &packet_mask_offset);
    offset += 4;
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_single_packet_filter_filter_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        /* offset += 4; */
    }
    if (filter_size) {
        if (packet_filter_offset) {
            proto_tree_add_item(tree, hf_mbim_single_packet_filter_packet_filter, tvb, base_offset + packet_filter_offset,
                                filter_size, ENC_NA);
        }
        if (packet_mask_offset) {
            proto_tree_add_item(tree, hf_mbim_single_packet_filter_packet_mask, tvb, base_offset + packet_mask_offset,
                                filter_size, ENC_NA);
        }
    }
}

static void
mbim_dissect_packet_filters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, packet_filters_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_packet_filters_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_packet_filters_packet_filters_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &packet_filters_count);
    offset += 4;
    if (packet_filters_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*packet_filters_count, ett_mbim_pair_list, NULL, "Packet Filter Ref List");
        for (i = 0; i < packet_filters_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_packet_filters_packet_filters_packet_filter_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_packet_filters_packet_filters_packet_filter_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < packet_filters_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "Packet Filter Element #%u", i+1);
                mbim_dissect_single_packet_filter(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset, mbim_conv);
            }
        }
    }
}

static void
mbim_dissect_set_sms_configuration(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 sc_address_offset, sc_address_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_sms_configuration_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_sms_configuration_sc_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sc_address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_sms_configuration_sc_address_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sc_address_size);
    /*offset += 4;*/
    if (sc_address_offset && sc_address_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_sms_configuration_sc_address, tvb, base_offset + sc_address_offset,
                                 sc_address_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (sc_address_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_sms_configuration_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 sc_address_offset, sc_address_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_sms_configuration_info_sms_storage_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_configuration_info_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_configuration_info_max_messages, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_configuration_info_cdma_short_message_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_configuration_info_sc_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sc_address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_configuration_info_sc_address_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sc_address_size);
    /*offset += 4;*/
    if (sc_address_offset && sc_address_size) {
        it = proto_tree_add_item(tree, hf_mbim_sms_configuration_info_sc_address, tvb, base_offset + sc_address_offset,
                                 sc_address_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (sc_address_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_sms_pdu_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                            struct mbim_conv_info *mbim_conv)
{
    gint base_offset;
    guint32 message_status, pdu_data_offset, pdu_data_size;
    tvbuff_t *sms_tvb;
    proto_item *ti;
    proto_tree *subtree, *sc_tree;
    guint8 sc_address_size;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_sms_pdu_record_message_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_pdu_record_message_status, tvb, offset, 4, ENC_LITTLE_ENDIAN, &message_status);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_pdu_record_pdu_data_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pdu_data_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_pdu_record_pdu_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pdu_data_size);
    /*offset += 4;*/
    if (pdu_data_offset && pdu_data_size) {
        if ((((mbim_sms_pdu_format == SMS_PDU_AUTOMATIC) && (mbim_conv->cellular_class & MBIM_CELLULAR_CLASS_GSM)) ||
             (mbim_sms_pdu_format == SMS_PDU_3GPP)) && gsm_sms_handle) {
            ti = proto_tree_add_item(tree, hf_mbim_sms_pdu_record_pdu_data, tvb, base_offset + pdu_data_offset,
                                     pdu_data_size, ENC_NA);
            if (pdu_data_size > 183) {
                expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
            }
            subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
            sc_address_size = tvb_get_guint8(tvb, base_offset + pdu_data_offset);
            sc_tree = proto_tree_add_subtree(subtree, tvb, base_offset + pdu_data_offset, 1 + sc_address_size,
                                     ett_mbim_sc_address, NULL, "Service Center Address");
            proto_tree_add_uint(sc_tree, hf_mbim_sms_pdu_record_pdu_data_sc_address_size, tvb,
                                base_offset + pdu_data_offset, 1, sc_address_size);
            if (sc_address_size) {
                de_cld_party_bcd_num(tvb, sc_tree, pinfo, base_offset + pdu_data_offset + 1,
                                     sc_address_size, NULL, 0);
            }
            if (pdu_data_size > (guint32)(sc_address_size + 1)) {
                pdu_data_size -= sc_address_size + 1;
                sms_tvb = tvb_new_subset_length(tvb, base_offset + pdu_data_offset + 1 + sc_address_size,
                                         pdu_data_size);
                pinfo->p2p_dir = (message_status < 2) ? P2P_DIR_SENT : P2P_DIR_RECV;
                call_dissector(gsm_sms_handle, sms_tvb, pinfo, subtree);
            }
        } else {
            ti = proto_tree_add_item(tree, hf_mbim_sms_pdu_record_pdu_data, tvb, base_offset + pdu_data_offset,
                                     pdu_data_size, ENC_NA);
            if (pdu_data_size > 255) {
                expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
            }
            subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
            if ((((mbim_sms_pdu_format == SMS_PDU_AUTOMATIC) && (mbim_conv->cellular_class & MBIM_CELLULAR_CLASS_CDMA)) ||
                 (mbim_sms_pdu_format == SMS_PDU_3GPP2)) && cdma_sms_handle) {
                sms_tvb = tvb_new_subset_length(tvb, base_offset + pdu_data_offset, pdu_data_size);
                call_dissector(cdma_sms_handle, sms_tvb, pinfo, subtree);
            }
        }
    }
}

static void mbim_decode_sms_cdma_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const int hfindex, gint offset,
                                      guint32 encoding_id, guint32 size_in_bytes, guint32 size_in_chars)
{
    unsigned char *src, *dest;

    switch (encoding_id) {
        case MBIM_ENCODING_7BIT_ASCII:
            proto_tree_add_ascii_7bits_item(tree, hfindex, tvb, (offset << 3), size_in_chars);
            break;
        case MBIM_ENCODING_IA5:
            src = (unsigned char*)tvb_get_ascii_7bits_string(pinfo->pool, tvb, (offset << 3), size_in_chars);
            dest = (unsigned char*)wmem_alloc(pinfo->pool, (const size_t)size_in_chars + 1);
            IA5_7BIT_decode(dest, src, size_in_chars);
            proto_tree_add_string(tree, hfindex, tvb, offset, size_in_bytes, (const char*)dest);
            break;
        case MBIM_ENCODING_UNICODE:
            proto_tree_add_item(tree, hfindex, tvb, offset, size_in_bytes, ENC_UCS_2|ENC_BIG_ENDIAN);
            break;
        case MBIM_ENCODING_LATIN_HEBREW:
            proto_tree_add_item(tree, hfindex, tvb, offset, size_in_bytes, ENC_ISO_8859_8|ENC_NA);
            break;
        case MBIM_ENCODING_LATIN:
            proto_tree_add_item(tree, hfindex, tvb, offset, size_in_bytes, ENC_ISO_8859_1|ENC_NA);
            break;
        case MBIM_ENCODING_GSM_7BIT:
            proto_tree_add_ts_23_038_7bits_packed_item(tree, hfindex, tvb, (offset << 3), size_in_chars);
            break;
        default:
            break;
    }
}

static void
mbim_dissect_sms_cdma_record(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 address_offset, address_size, timestamp_offset, timestamp_size, encoding_id,
            encoded_message_offset, size_in_bytes, size_in_chars;
    proto_item *ti;
    proto_tree *subtree;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_sms_cdma_record_message_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_cdma_record_message_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_address_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &address_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_timestamp_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &timestamp_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_timestamp_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &timestamp_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_encoding_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &encoding_id);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_cdma_record_language_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_encoded_message_offset, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &encoded_message_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_size_in_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size_in_bytes);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_cdma_record_size_in_characters, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size_in_chars);
    /*offset += 4;*/
    if (address_offset && address_size) {
        it = proto_tree_add_item(tree, hf_mbim_sms_cdma_record_address, tvb, base_offset + address_offset,
                                 address_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (address_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (timestamp_offset && timestamp_size) {
        it = proto_tree_add_item(tree, hf_mbim_sms_cdma_record_timestamp, tvb, base_offset + timestamp_offset,
                                 timestamp_size, ENC_NA|ENC_ASCII);
        if (timestamp_size > 21) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (encoded_message_offset && size_in_bytes) {
        ti = proto_tree_add_item(tree, hf_mbim_sms_cdma_record_encoded_message, tvb, base_offset + encoded_message_offset,
                                 size_in_bytes, ENC_NA);
        if (size_in_bytes > 160) {
            expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
        }
        subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
        mbim_decode_sms_cdma_text(tvb, pinfo, subtree, hf_mbim_sms_cdma_record_encoded_message_text,
                                  (base_offset + encoded_message_offset), encoding_id, size_in_bytes, size_in_chars);
    }
}

static void
mbim_dissect_sms_read_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_sms_read_req_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_read_req_flag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_read_req_message_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_sms_read_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                           struct mbim_conv_info *mbim_conv)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, format, element_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_read_info_format, tvb, offset, 4, ENC_LITTLE_ENDIAN, &format);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_read_info_element_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &element_count);
    offset += 4;
    if (element_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*element_count, ett_mbim_pair_list, NULL, "SMS Ref List");
        for (i = 0; i < element_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_sms_read_info_sms_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_sms_read_info_sms_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < element_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "SMS Element #%u", i+1);
                if (format == MBIM_SMS_FORMAT_PDU) {
                    mbim_dissect_sms_pdu_record(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset, mbim_conv);
                } else if (format == MBIM_SMS_FORMAT_CDMA) {
                    mbim_dissect_sms_cdma_record(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
                } else {
                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unknown_sms_format, tvb,
                                          base_offset + p_pair_list_item->offset, p_pair_list_item->size);
                }
            }
        }
    }
}

static void
mbim_dissect_sms_send_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                          struct mbim_conv_info *mbim_conv)
{
    gint base_offset;
    guint32 pdu_data_offset, pdu_data_size;
    tvbuff_t *sms_tvb;
    proto_item *ti;
    proto_tree *subtree, *sc_tree;
    guint8 sc_address_size;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_pdu_pdu_data_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pdu_data_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_pdu_pdu_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pdu_data_size);
    /*offset += 4;*/
    if (pdu_data_offset && pdu_data_size) {
        if ((((mbim_sms_pdu_format == SMS_PDU_AUTOMATIC) && (mbim_conv->cellular_class & MBIM_CELLULAR_CLASS_GSM)) ||
             (mbim_sms_pdu_format == SMS_PDU_3GPP)) && gsm_sms_handle) {
            ti = proto_tree_add_item(tree, hf_mbim_sms_send_pdu_pdu_data, tvb, base_offset + pdu_data_offset,
                                     pdu_data_size, ENC_NA);
            if (pdu_data_size > 183) {
                expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
            }
            subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
            sc_address_size = tvb_get_guint8(tvb, base_offset + pdu_data_offset);
            sc_tree = proto_tree_add_subtree(subtree, tvb, base_offset + pdu_data_offset, 1 + sc_address_size,
                                     ett_mbim_sc_address, NULL, "Service Center Address");
            proto_tree_add_uint(sc_tree, hf_mbim_sms_send_pdu_pdu_data_sc_address_size, tvb,
                                base_offset + pdu_data_offset, 1, sc_address_size);
            if (sc_address_size) {
                de_cld_party_bcd_num(tvb, sc_tree, pinfo, base_offset + pdu_data_offset + 1,
                                     sc_address_size, NULL, 0);
            }
            if (pdu_data_size > (guint32)(sc_address_size + 1)) {
                pdu_data_size -= sc_address_size + 1;
                sms_tvb = tvb_new_subset_length(tvb, base_offset + pdu_data_offset + 1 + sc_address_size,
                                         pdu_data_size);
                pinfo->p2p_dir = P2P_DIR_RECV;
                call_dissector(gsm_sms_handle, sms_tvb, pinfo, subtree);
            }
        } else {
            ti = proto_tree_add_item(tree, hf_mbim_sms_send_pdu_pdu_data, tvb, base_offset + pdu_data_offset,
                                     pdu_data_size, ENC_NA);
            if (pdu_data_size > 255) {
                expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
            }
            subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
            if ((((mbim_sms_pdu_format == SMS_PDU_AUTOMATIC) && (mbim_conv->cellular_class & MBIM_CELLULAR_CLASS_CDMA)) ||
                 (mbim_sms_pdu_format == SMS_PDU_3GPP2)) && cdma_sms_handle) {
                sms_tvb = tvb_new_subset_length(tvb, base_offset + pdu_data_offset, pdu_data_size);
                call_dissector(cdma_sms_handle, sms_tvb, pinfo, subtree);
            }
        }
    }
}

static void
mbim_dissect_sms_send_cdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 encoding_id, address_offset, address_size, encoded_message_offset,
            size_in_bytes, size_in_chars;
    proto_item *ti;
    proto_tree *subtree;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_encoding_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &encoding_id);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sms_send_cdma_language_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_address_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &address_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_address_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &address_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_encoded_message_offset, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &encoded_message_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_size_in_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size_in_bytes);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_sms_send_cdma_size_in_characters, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size_in_chars);
    /*offset += 4;*/
    if (address_offset && address_size) {
        ti = proto_tree_add_item(tree, hf_mbim_sms_send_cdma_address, tvb, base_offset + address_offset,
                                 address_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (address_size > 40) {
            expert_add_info(pinfo, ti, &ei_mbim_oversized_string);
        }
    }
    if (encoded_message_offset && size_in_bytes) {
        ti = proto_tree_add_item(tree, hf_mbim_sms_send_cdma_encoded_message, tvb, base_offset + encoded_message_offset,
                                 size_in_bytes, ENC_NA);
        if (size_in_bytes > 160) {
            expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
        }
        subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
        mbim_decode_sms_cdma_text(tvb, pinfo, subtree, hf_mbim_sms_send_cdma_encoded_message_text,
                                  (base_offset + encoded_message_offset), encoding_id, size_in_bytes, size_in_chars);
    }
}

static void
mbim_dissect_set_sms_send(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                          struct mbim_conv_info *mbim_conv)
{
    guint32 format;

    proto_tree_add_item_ret_uint(tree, hf_mbim_set_sms_send_format, tvb, offset, 4, ENC_LITTLE_ENDIAN, &format);
    offset += 4;
    if (format == MBIM_SMS_FORMAT_PDU) {
        mbim_dissect_sms_send_pdu(tvb, pinfo, tree, offset, mbim_conv);
    } else if (format == MBIM_SMS_FORMAT_CDMA) {
        mbim_dissect_sms_send_cdma(tvb, pinfo, tree, offset);
    } else {
        proto_tree_add_expert(tree, pinfo, &ei_mbim_unknown_sms_format, tvb, offset, -1);
    }
}

static void
mbim_dissect_set_ussd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *ti;
    proto_tree *subtree;
    gint base_offset;
    guint32 ussd_payload_offset, ussd_payload_length;
    guint8 encoding;
    tvbuff_t *ussd_tvb;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_ussd_ussd_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    ti = proto_tree_add_item(tree, hf_mbim_set_ussd_ussd_data_coding_scheme, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
    encoding = dissect_cbs_data_coding_scheme(tvb, pinfo, subtree, offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ussd_ussd_payload_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ussd_payload_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ussd_ussd_payload_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ussd_payload_length);
    /*offset += 4;*/
    if (ussd_payload_offset && ussd_payload_length) {
        ti = proto_tree_add_item(tree, hf_mbim_set_ussd_ussd_payload, tvb, base_offset + ussd_payload_offset,
                                 ussd_payload_length, ENC_NA);
        if (ussd_payload_length > 160) {
            expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
        }
        subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
        ussd_tvb = tvb_new_subset_length(tvb, base_offset + ussd_payload_offset, ussd_payload_length);
        switch (encoding) {
            case SMS_ENCODING_7BIT:
            case SMS_ENCODING_7BIT_LANG:
                proto_tree_add_item(subtree, hf_mbim_set_ussd_ussd_payload_text,
                                    ussd_tvb, 0, ussd_payload_length, ENC_3GPP_TS_23_038_7BITS|ENC_NA);
                break;
            case SMS_ENCODING_8BIT:
                /* XXX - ASCII, or some extended ASCII? */
                proto_tree_add_item(subtree, hf_mbim_set_ussd_ussd_payload_text,
                                    ussd_tvb , 0, ussd_payload_length, ENC_ASCII);
                break;
            case SMS_ENCODING_UCS2:
            case SMS_ENCODING_UCS2_LANG:
                proto_tree_add_item(subtree, hf_mbim_set_ussd_ussd_payload_text,
                                    ussd_tvb , 0, ussd_payload_length, ENC_UCS_2|ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }
    }
}

static void
mbim_dissect_ussd_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *ti;
    proto_tree *subtree;
    gint base_offset;
    guint32 ussd_payload_offset, ussd_payload_length;
    guint8 encoding;
    tvbuff_t *ussd_tvb;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ussd_info_ussd_response, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ussd_info_ussd_session_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    ti = proto_tree_add_item(tree, hf_mbim_ussd_info_ussd_data_coding_scheme, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
    encoding = dissect_cbs_data_coding_scheme(tvb, pinfo, subtree, offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ussd_info_ussd_payload_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ussd_payload_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ussd_info_ussd_payload_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ussd_payload_length);
    /*offset += 4;*/
    if (ussd_payload_offset && ussd_payload_length) {
        ti = proto_tree_add_item(tree, hf_mbim_ussd_info_ussd_payload, tvb, base_offset + ussd_payload_offset,
                                 ussd_payload_length, ENC_NA);
        if (ussd_payload_length > 160) {
            expert_add_info(pinfo, ti, &ei_mbim_oversized_pdu);
        }
        subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
        ussd_tvb = tvb_new_subset_length(tvb, base_offset + ussd_payload_offset, ussd_payload_length);
        switch (encoding) {
            case SMS_ENCODING_7BIT:
            case SMS_ENCODING_7BIT_LANG:
                proto_tree_add_item(subtree, hf_mbim_ussd_info_ussd_payload_text,
                                    ussd_tvb, 0, ussd_payload_length, ENC_3GPP_TS_23_038_7BITS|ENC_NA);
                break;
            case SMS_ENCODING_8BIT:
                /* XXX - ASCII, or some extended ASCII? */
                proto_tree_add_item(subtree, hf_mbim_ussd_info_ussd_payload_text,
                                    ussd_tvb , 0, ussd_payload_length, ENC_ASCII);
                break;
            case SMS_ENCODING_UCS2:
            case SMS_ENCODING_UCS2_LANG:
                proto_tree_add_item(subtree, hf_mbim_ussd_info_ussd_payload_text,
                                    ussd_tvb , 0, ussd_payload_length, ENC_UCS_2|ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }
    }
}

static void
mbim_dissect_phonebook_configuration_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_phonebook_configuration_info_phonebook_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_phonebook_configuration_info_total_nb_of_entries, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_phonebook_configuration_info_used_entries, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_phonebook_configuration_info_max_number_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_phonebook_configuration_info_max_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_phonebook_entry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 number_offset, number_length, name_offset, name_length;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_phonebook_entry_entry_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_phonebook_entry_number_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &number_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_phonebook_entry_number_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &number_length);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_phonebook_entry_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_phonebook_entry_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_length);
    /*offset += 4;*/
    if (number_offset && number_length) {
        proto_tree_add_item(tree, hf_mbim_phonebook_entry_number, tvb, base_offset + number_offset,
                            number_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
    }
    if (name_offset && name_length) {
        proto_tree_add_item(tree, hf_mbim_phonebook_entry_name, tvb, base_offset + name_offset,
                            name_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
    }
}

static void
mbim_dissect_phonebook_read_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, element_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_phonebook_read_info_element_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &element_count);
    offset += 4;
    if (element_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*element_count, ett_mbim_pair_list, NULL, "Phonebook Ref List");
        for (i = 0; i < element_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_phonebook_read_info_phonebook_offset,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_phonebook_read_info_phonebook_size,
                                tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < element_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset,
                                         p_pair_list_item->size, ett_mbim_pair_list, NULL, "Phonebook Element #%u", i+1);
                mbim_dissect_phonebook_entry(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_set_phonebook_write(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 number_offset, number_length, name_offset, name_length;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_phonebook_write_save_flag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_phonebook_write_save_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_phonebook_write_number_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &number_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_phonebook_write_number_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &number_length);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_phonebook_write_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_phonebook_write_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_length);
    /*offset += 4;*/
    if (number_offset && number_length) {
        proto_tree_add_item(tree, hf_mbim_set_phonebook_write_number, tvb, base_offset + number_offset,
                            number_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
    }
    if (name_offset && name_length) {
        proto_tree_add_item(tree, hf_mbim_set_phonebook_write_name, tvb, base_offset + name_offset,
                            name_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
    }
}

static void
mbim_dissect_set_stk_pac(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_mbim_set_stk_pac_pac_host_control, tvb, offset, 32, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_mbim_pac);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_refresh, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_more_time, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_poll_interval, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_polling_off, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_set_up_evt_list, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_set_up_call, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_send_ss, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_send_ussd, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_send_short_msg, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_send_dtmf, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_launch_browser, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_geo_loc_req, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_play_tone, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_display_text, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_inkey, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_input, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_select_item, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_set_up_menu, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_prov_local_info, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_timer_management, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_set_up_idle_mode_text, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_perform_card_apdu, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_power_on_card, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_power_off_card, tvb, offset+4, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_reader_status, tvb, offset+4, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_run_at_cmd, tvb, offset+4, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_lang_notif, tvb, offset+4, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_open_channel, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_close_channel, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_receive_data, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_send_data, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_channel_status, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_service_search, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_service_info, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_declare_service, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_set_frames, tvb, offset+6, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_get_frames_status, tvb, offset+6, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_retrieve_multimedia_msg, tvb, offset+7, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_submit_multimedia_msg, tvb, offset+7, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_display_multimedia_msg, tvb, offset+7, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_activate, tvb, offset+8, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_contactless_state_changed, tvb, offset+8, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_cmd_container, tvb, offset+9, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_encapsulated_session_ctrl, tvb, offset+9, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_set_stk_pac_pac_host_control_end_proact_session, tvb, offset+10, 1, ENC_NA);
}

static void
mbim_dissect_stk_pac_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_mbim_stk_pac_info_pac_support, tvb, offset, 256, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_mbim_pac);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_refresh, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_more_time, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_poll_interval, tvb, offset+3, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_polling_off, tvb, offset+4, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_set_up_evt_list, tvb, offset+5, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_set_up_call, tvb, offset+10, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_send_ss, tvb, offset+11, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_send_ussd, tvb, offset+12, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_send_short_msg, tvb, offset+13, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_send_dtmf, tvb, offset+14, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_launch_browser, tvb, offset+15, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_geo_loc_req, tvb, offset+16, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_play_tone, tvb, offset+20, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_display_text, tvb, offset+21, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_inkey, tvb, offset+22, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_input, tvb, offset+23, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_select_item, tvb, offset+24, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_set_up_menu, tvb, offset+25, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_prov_local_info, tvb, offset+26, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_timer_management, tvb, offset+27, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_set_up_idle_mode_text, tvb, offset+28, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_perform_card_apdu, tvb, offset+30, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_power_on_card, tvb, offset+31, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_power_off_card, tvb, offset+32, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_reader_status, tvb, offset+33, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_run_at_cmd, tvb, offset+34, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_lang_notif, tvb, offset+35, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_open_channel, tvb, offset+40, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_close_channel, tvb, offset+41, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_receive_data, tvb, offset+42, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_send_data, tvb, offset+43, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_channel_status, tvb, offset+44, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_service_search, tvb, offset+45, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_service_info, tvb, offset+46, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_declare_service, tvb, offset+47, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_set_frames, tvb, offset+50, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_get_frames_status, tvb, offset+51, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_retrieve_multimedia_msg, tvb, offset+60, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_submit_multimedia_msg, tvb, offset+61, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_display_multimedia_msg, tvb, offset+62, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_activate, tvb, offset+70, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_contactless_state_changed, tvb, offset+71, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_cmd_container, tvb, offset+72, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_encapsulated_session_ctrl, tvb, offset+73, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_mbim_stk_pac_info_pac_support_end_proact_session, tvb, offset+81, 1, ENC_NA);
}

static void
mbim_dissect_set_stk_terminal_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    tvbuff_t *pac_tvb;
    guint32 response_length;
    proto_item *ti;
    proto_tree *subtree;

    proto_tree_add_item_ret_uint(tree, hf_mbim_set_stk_terminal_response_response_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_length);
    offset += 4;
    ti = proto_tree_add_item(tree, hf_mbim_set_stk_terminal_response_data_buffer, tvb, offset, response_length, ENC_NA);
    if (etsi_cat_handle) {
        subtree = proto_item_add_subtree(ti, ett_mbim_buffer);
        pac_tvb = tvb_new_subset_length(tvb, offset, response_length);
        call_dissector(etsi_cat_handle, pac_tvb, pinfo, subtree);
    }
}

static void
mbim_dissect_stk_terminal_response_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 result_data_string_offset, result_data_string_length;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_stk_terminal_response_info_result_data_string_offset,
                                 tvb, offset, 4, ENC_LITTLE_ENDIAN, &result_data_string_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_stk_terminal_response_info_result_data_string_length,
                                 tvb, offset, 4, ENC_LITTLE_ENDIAN, &result_data_string_length);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_stk_terminal_response_info_status_word, tvb, offset,
                        4, ENC_LITTLE_ENDIAN);
    if (result_data_string_offset && result_data_string_length) {
        proto_tree_add_item(tree, hf_mbim_stk_terminal_response_info_result_data_string, tvb,
                            base_offset + result_data_string_offset, result_data_string_length, ENC_NA);
    }
}

static void
mbim_dissect_aka_auth_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_aka_auth_req_rand, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_aka_auth_req_autn, tvb, offset, 16, ENC_NA);
}

static void
mbim_dissect_aka_auth_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_aka_auth_info_res, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_aka_auth_info_res_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_aka_auth_info_ik, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_aka_auth_info_ck, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_aka_auth_info_auts, tvb, offset, 14, ENC_NA);
}

static void
mbim_dissect_akap_auth_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 network_name_offset, network_name_length;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_akap_auth_req_rand, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_akap_auth_req_autn, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item_ret_uint(tree, hf_mbim_akap_auth_req_network_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &network_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_akap_auth_req_network_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &network_name_length);
    /*offset += 4;*/
    if (network_name_offset && network_name_length) {
        proto_tree_add_item(tree, hf_mbim_akap_auth_req_network_name, tvb, base_offset + network_name_offset,
                            network_name_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
    }
}

static void
mbim_dissect_akap_auth_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_akap_auth_info_res, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_akap_auth_info_res_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_akap_auth_info_ik, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_akap_auth_info_ck, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_akap_auth_info_auts, tvb, offset, 14, ENC_NA);
}

static void
mbim_dissect_sim_auth_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_sim_auth_req_rand1, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_sim_auth_req_rand2, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_sim_auth_req_rand3, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_mbim_sim_auth_req_n, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_sim_auth_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_sres1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_kc1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_sres2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_kc2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_sres3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_kc3, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_sim_auth_info_n, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_set_dss_connect(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    guint32 dss_session_id;
    struct mbim_uuid_ext *uuid_ext_info = NULL;

    mbim_dissect_service_id_uuid(tvb, pinfo, tree, hf_mbim_set_dss_connect_device_service_id, &offset, &uuid_ext_info, TRUE);
    dss_session_id = tvb_get_letohl(tvb, offset);
    dissector_delete_uint("mbim.dss_session_id", dss_session_id, NULL);
    if ((dss_session_id <= 255) && uuid_ext_info && uuid_ext_info->dss_handle) {
        dissector_add_uint("mbim.dss_session_id", dss_session_id, uuid_ext_info->dss_handle);
    }
    proto_tree_add_uint(tree, hf_mbim_set_dss_connect_dss_session_id, tvb, offset, 4, dss_session_id);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_dss_connect_dss_link_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_muticarrier_current_cid_list_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    guint8 service_idx;

    service_idx = mbim_dissect_service_id_uuid(tvb, pinfo, tree, hf_mbim_multicarrier_current_cid_list_req_uuid, &offset, NULL, TRUE);
    if (service_idx != UUID_MULTICARRIER) {
        expert_add_info_format(pinfo, NULL, &ei_mbim_unexpected_uuid_value,
                               "Unexpected UUID value, should be UUID_MULTICARRIER");
    }
}

static void
mbim_dissect_muticarrier_current_cid_list_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    guint32 i, cid_count;

    proto_tree_add_item_ret_uint(tree, hf_mbim_multicarrier_current_cid_list_info_cid_count,
                                 tvb, offset, 4, ENC_LITTLE_ENDIAN, &cid_count);
    offset += 4;
    for (i = 0; i < cid_count; i++) {
        proto_tree_add_item(tree, hf_mbim_multicarrier_current_cid_list_info_cid,
                            tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

static void
mbim_dissect_thermal_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    int i;
    proto_tree *subtree;

    for (i = 0; i < 4; i++) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 24, ett_mbim_thermal_threshold_setting, NULL, "Threshold %u", i);
        proto_tree_add_item(subtree, hf_mbim_thermal_config_enable, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_thermal_config_temp_sensor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_thermal_config_alarm_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_thermal_config_threshold_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_thermal_config_hyst_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_mbim_thermal_config_sampling_period, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

static void
mbim_dissect_thermal_state_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_current_temp_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_enable, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_temp_sensor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_alarm_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_threshold_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_hyst_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_thermal_state_info_sampling_period, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_sar_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 buffer_len)
{
    proto_tree_add_item(tree, hf_mbim_sar_config_sar_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (buffer_len > 4) {
        proto_tree_add_item(tree, hf_mbim_sar_config_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_ms_sar_config_state(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_ms_sar_config_state_sar_antenna_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_sar_config_state_sar_backoff_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void
mbim_dissect_ms_sar_config(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, gboolean is_response)
{
    proto_tree* subtree;
    guint32 i, elem_count;
    wmem_array_t* pair_list;
    struct mbim_pair_list pair_list_item, * p_pair_list_item;
    gint base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_sar_config_sar_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_sar_config_sar_backoff_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (is_response) {
        proto_tree_add_item(tree, hf_mbim_ms_sar_config_sar_wifi_Integration, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_sar_config_element_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8 * elem_count, ett_mbim_pair_list, NULL, "SAR Config State List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_sar_config_element_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_sar_config_element_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                    ett_mbim_pair_list, NULL, "SAR Config State #%u", i + 1);
                mbim_dissect_ms_sar_config_state(tvb, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_ms_transmission_status(tvbuff_t* tvb, proto_tree* tree, gint offset, gboolean is_response)
{
    proto_tree_add_item(tree, hf_mbim_ms_transmission_status_channel_notification, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (is_response) {
        proto_tree_add_item(tree, hf_mbim_ms_transmission_status_transmission_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item(tree, hf_mbim_ms_transmission_status_hysteresis_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}


static void
mbim_dissect_adpclk_freq_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 buffer_len)
{
    proto_tree_add_item(tree, hf_mbim_adpclk_freq_info_adpclk_freq_value_center_freq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_adpclk_freq_info_adpclk_freq_value_freq_spread, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (buffer_len > 8) {
        proto_tree_add_item(tree, hf_mbim_adpclk_freq_info_adpclk_freq_value_noise_power, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        if (buffer_len > 12) {
            proto_tree_add_item(tree, hf_mbim_adpclk_freq_info_adpclk_freq_value_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            if (buffer_len > 16) {
                proto_tree_add_item(tree, hf_mbim_adpclk_freq_info_adpclk_freq_value_connect_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
        }
    }
}

static void
mbim_dissect_adpclk_freq_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_adpclk_freq_info_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Element Offset Length Pair");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_adpclk_freq_info_adpclk_freq_value_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_adpclk_freq_info_adpclk_freq_value_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "ADPCLK Freq Value #%u", i+1);
                mbim_dissect_adpclk_freq_value(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset, p_pair_list_item->size);
            }
        }
    }
}

static void
mbim_dissect_nrtcws_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 buffer_len)
{
    proto_tree_add_item(tree, hf_mbim_nrtcws_config_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (buffer_len > 2) {
        proto_tree_add_item(tree, hf_mbim_nrtcws_config_wlan_active, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mbim_nrtcws_config_wlan_safe_rx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mbim_nrtcws_config_wlan_bandwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mbim_nrtcws_config_bt_active, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_mbim_nrtcws_config_bt_safe_rx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_nrtcws_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_lte_active, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_wlan_safe_rx_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_wlan_safe_rx_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_bt_safe_rx_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_bt_safe_rx_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_lte_sps_period, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_lte_sps_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mbim_nrtcws_info_lte_sps_initial_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_atds_signal_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_ber, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_rscp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_ecno, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_rsrq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_rsrp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_signal_info_rssnr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_atds_operator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 provider_id_offset, provider_id_size, provider_name_offset, provider_name_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_operator_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_operator_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_atds_operator_provider_state, ett_mbim_bitmap,
                           mbim_provider_state_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_operator_provider_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_operator_provider_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_size);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_atds_operator_plmn_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_atds_operator_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item (tree, hf_mbim_atds_operator_error_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    if (provider_id_offset && provider_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_atds_operator_provider_id, tvb, base_offset + provider_id_offset,
                                 provider_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_id_size > 12) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (provider_name_offset && provider_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_atds_operator_provider_name, tvb, base_offset + provider_name_offset,
                                 provider_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (provider_name_size > 40) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_atds_operators(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_operators_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Operators List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_atds_operators_operator_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_atds_operators_operator_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Operator #%u", i+1);
                mbim_dissect_atds_operator(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_atds_projection_table(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar5min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar4min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar3min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar2min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar1min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_bar0min, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_a0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_atds_projection_table_b0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_atds_projection_tables(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_atds_projection_tables_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Projection Tables List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_atds_projection_tables_projection_table_offset,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_atds_projection_tables_projection_table_size,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Projection Table #%u", i+1);
                mbim_dissect_atds_projection_table(tvb, pinfo, subtree, base_offset + p_pair_list_item->offset);
            }
        }
    }
}

static void
mbim_dissect_multiflow_tft_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_multiflow_tft_info_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_multiflow_tft_info_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "TFT List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_multiflow_tft_info_tft_list_offset,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_multiflow_tft_info_tft_list_size,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "TFT #%u", i+1);
                de_sm_tflow_temp(tvb, subtree, pinfo, base_offset + p_pair_list_item->offset, p_pair_list_item->size, NULL, 0);
            }
        }
    }
}

static void
mbim_dissect_ms_context_v2_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, gint base_offset, struct mbim_conv_info* mbim_conv)
{
    guint32 access_string_offset, access_string_size, user_name_offset, user_name_size, password_offset, password_size;
    proto_item *it;
    proto_tree* snssai;

    mbim_dissect_context_type_uuid(tvb, pinfo, tree, offset);
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_ip_type, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_enable, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_roaming, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_media_type, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_source, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_access_string_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &access_string_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_access_string_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &access_string_size);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_user_name_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &user_name_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_user_name_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &user_name_size);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_password_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &password_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_set_ms_provisioned_context_v2_password_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &password_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_compression, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_auth_protocol, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        snssai = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_mbim_pair_list, NULL, "S-NSSAI");
        mbim_dissect_tlv_ie(tvb, pinfo, snssai, offset);
    }
    if (access_string_offset && access_string_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_access_string, tvb,
                                 base_offset + access_string_offset, access_string_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (access_string_size > 200) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (user_name_offset && user_name_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_user_name, tvb,
                                 base_offset + user_name_offset, user_name_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (user_name_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (password_offset && password_size) {
        it = proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_password, tvb,
                              base_offset + password_offset, password_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (password_size > 510) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_set_ms_provisioned_context_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    gint base_offset;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_set_ms_provisioned_context_v2_operation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    mbim_dissect_ms_context_v2_base(tvb, pinfo, tree, &offset, base_offset, mbim_conv);
}

static void
mbim_dissect_ms_provisioned_context_info_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    proto_tree *subtree;
    gint base_offset, item_offset, base_item_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_provisioned_context_info_v2_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Provisioned Contexts Ref List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_provisioned_context_info_v2_list_offset,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_provisioned_context_info_v2_list_size,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Context #%u", i+1);
                item_offset = base_offset + p_pair_list_item->offset;
                base_item_offset = item_offset;
                proto_tree_add_item(subtree, hf_mbim_ms_provisioned_context_info_v2_context_id, tvb, item_offset, 4, ENC_LITTLE_ENDIAN);
                item_offset += 4;
                mbim_dissect_ms_context_v2_base(tvb, pinfo, subtree, &item_offset, base_item_offset, mbim_conv);
            }
        }
    }
}

static void
mbim_dissect_ms_network_blacklist_info(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *subtree;
    gint base_offset, item_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_ms_network_blacklist_info_blacklist_state,
                           ett_mbim_bitmap, mbim_ms_network_blacklist_state_fields, ENC_LITTLE_ENDIAN);

    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_network_blacklist_info_elem_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Provider Blacklist Ref List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_network_blacklist_info_list_offset,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_network_blacklist_info_list_size,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Blacklisted Provider #%u", i+1);
                item_offset = base_offset + p_pair_list_item->offset;
                proto_tree_add_item(subtree, hf_mbim_ms_network_blacklist_provider_mcc, tvb, item_offset, 4, ENC_LITTLE_ENDIAN);
                item_offset += 4;
                proto_tree_add_item(subtree, hf_mbim_ms_network_blacklist_provider_mnc, tvb, item_offset, 4, ENC_LITTLE_ENDIAN);
                item_offset += 4;
                proto_tree_add_item(subtree, hf_mbim_ms_network_blacklist_provider_type, tvb, item_offset, 4, ENC_LITTLE_ENDIAN);
            }
        }
    }
}

static void
mbim_dissect_sys_caps_info(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_sys_caps_info_number_of_executors, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sys_caps_info_number_of_slots, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sys_caps_info_concurrency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_sys_caps_info_modem_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_device_caps_v2_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
                              struct mbim_conv_info *mbim_conv)
{
    gint base_offset;
    guint32 custom_class_offset, custom_class_size, device_id_offset, device_id_size,
            fw_info_offset, fw_info_size, hw_info_offset, hw_info_size;
    proto_item *it;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_device_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_cellular_class, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &mbim_conv->cellular_class);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_voice_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sim_class, ett_mbim_bitmap,
                           mbim_device_caps_info_sim_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_data_class, ett_mbim_bitmap,
                           mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sms_caps, ett_mbim_bitmap,
                           mbim_device_caps_info_sms_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_control_caps, ett_mbim_bitmap,
                           mbim_device_caps_info_control_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_max_sessions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_custom_data_class_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &custom_class_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_custom_data_class_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &custom_class_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_device_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &device_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_device_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &device_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_fw_info_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fw_info_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_fw_info_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fw_info_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_hw_info_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &hw_info_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_hw_info_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &hw_info_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_v2_executor_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    if (custom_class_offset && custom_class_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_custom_data_class, tvb, base_offset + custom_class_offset,
                                custom_class_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (custom_class_size > 22) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (device_id_offset && device_id_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_device_id, tvb, base_offset + device_id_offset,
                                 device_id_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if ((mbim_conv->cellular_class == MBIM_CELLULAR_CLASS_GSM) && (device_id_size > 30)) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        } else if (device_id_size > 36) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (fw_info_offset && fw_info_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_fw_info, tvb, base_offset + fw_info_offset,
                                 fw_info_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (fw_info_size > 60) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
    if (hw_info_offset && hw_info_size) {
        it = proto_tree_add_item(tree, hf_mbim_device_caps_info_hw_info, tvb, base_offset + hw_info_offset,
                                 hw_info_size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
        if (hw_info_size > 60) {
            expert_add_info(pinfo, it, &ei_mbim_oversized_string);
        }
    }
}

static void
mbim_dissect_device_caps_v3_and_higher_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
    struct mbim_conv_info *mbim_conv)
{
    proto_tree *lte_band_class, *nr_band_class, *custom_data_class, *device_id, *firmware_info, *hardware_info;

    proto_tree_add_item(tree, hf_mbim_device_caps_info_device_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_device_caps_info_cellular_class, tvb, offset, 4,
        ENC_LITTLE_ENDIAN, &mbim_conv->cellular_class);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_voice_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sim_class, ett_mbim_bitmap,
        mbim_device_caps_info_sim_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_data_class, ett_mbim_bitmap,
        mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_sms_caps, ett_mbim_bitmap,
        mbim_device_caps_info_sms_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_control_caps, ett_mbim_bitmap,
        mbim_device_caps_info_control_caps_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_device_caps_info_data_subclass, ett_mbim_bitmap,
        mbim_data_subclass_fields, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_max_sessions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_v2_executor_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_device_caps_info_wcdma_band_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    lte_band_class = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "LTE Band Class");
    mbim_dissect_tlv_ie(tvb, pinfo, lte_band_class, &offset);

    nr_band_class = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "NR Band Class");
    mbim_dissect_tlv_ie(tvb, pinfo, nr_band_class, &offset);

    custom_data_class = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Custom Data Class");
    mbim_dissect_tlv_ie(tvb, pinfo, custom_data_class, &offset);

    device_id = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Device ID");
    mbim_dissect_tlv_ie(tvb, pinfo, device_id, &offset);

    firmware_info = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Firmware Info");
    mbim_dissect_tlv_ie(tvb, pinfo, firmware_info, &offset);

    hardware_info = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Hardware Info");
    mbim_dissect_tlv_ie(tvb, pinfo, hardware_info, &offset);
}

static void
mbim_dissect_ms_device_slot_mapping_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_ms_device_slot_mapping_info_map_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree *subtree;
    gint base_offset;
    guint32 i, elem_count;
    wmem_array_t *pair_list;
    struct mbim_pair_list pair_list_item, *p_pair_list_item;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_device_slot_mapping_info_map_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &elem_count);
    offset += 4;
    if (elem_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8*elem_count, ett_mbim_pair_list, NULL, "Slot Map List");
        for (i = 0; i < elem_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_device_slot_mapping_info_map_offset,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_device_slot_mapping_info_map_size,
                                         tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
        for (i = 0; i < elem_count; i++) {
            p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
            if (p_pair_list_item->offset && p_pair_list_item->size) {
                subtree = proto_tree_add_subtree_format(tree, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size,
                            ett_mbim_pair_list, NULL, "Device #%u", i+1);
                proto_tree_add_item(subtree, hf_mbim_ms_device_slot_mapping_info_executor_slot_index, tvb, base_offset + p_pair_list_item->offset, p_pair_list_item->size, ENC_LITTLE_ENDIAN);
            }
        }
    }
}

static void
mbim_dissect_base_station_info_req(tvbuff_t* tvb, proto_tree* tree, gint offset,
    struct mbim_conv_info* mbim_conv)
{
    proto_tree_add_item(tree, hf_mbim_base_station_max_gsm_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_max_umts_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_max_td_scdma_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_max_lte_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_max_cdma_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_base_station_max_nr_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void mbim_dissect_base_station_gsm_serving_cell_info(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    gint base_offset = offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_location_area_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_timing_advance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_arfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_base_station_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rx_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
}

static void mbim_dissect_base_station_gsm_nmr_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_location_area_code, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_arfcn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_base_station_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rx_level, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
}

static void mbim_dissect_base_station_umts_serving_cell_info(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    gint base_offset = offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_location_area_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_frequency_info_ul, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_frequency_info_dl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_frequency_info_nt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_uarfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_primary_scrambling_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rscp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_ecno, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_path_loss, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
}

static void mbim_dissect_base_station_umts_mrl_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_location_area_code, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_uarfcn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_primary_scrambling_code, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rscp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_ecno, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_path_loss, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
}

static void mbim_dissect_base_station_td_scdma_serving_cell_and_mrl_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_location_area_code, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_uarfcn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_call_parameter, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_timing_advance, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rscp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_path_loss, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
}

static void mbim_dissect_base_station_lte_serving_cell_info(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    gint base_offset = offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_earfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_physical_cell_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_tac, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_timing_advance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
}

static void mbim_dissect_base_station_lte_mrl_info(tvbuff_t* tvb, proto_tree* tree, gint *offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_earfcn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_physical_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_tac, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrq, tvb,* offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
}

static void mbim_dissect_base_station_cdma_mrl_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    proto_tree_add_item(tree, hf_mbim_base_station_serving_cell_flag, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_nid, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_sid, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_base_station_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_base_latitude, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_base_longitude, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_ref_pn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_gps_seconds, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_pilot_strength, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
}

static void mbim_dissect_base_station_nr_serving_cell_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_nci, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_mbim_base_station_physical_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_arfcn, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_tac, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrq, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_sinr, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_timing_advance, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
}

static void mbim_dissect_base_station_nr_neighbor_cell_info(tvbuff_t* tvb, proto_tree* tree, gint* offset)
{
    gint base_offset = *offset;
    guint32 provider_id_offset, provider_id_size, cell_id_offset, cell_id_size;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_mbim_base_station_system_sub_type, ett_mbim_bitmap,
        mbim_data_subclass_fields, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_provider_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &provider_id_size);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_cell_id_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &cell_id_offset);
    *offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_cell_id_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &cell_id_size);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_physical_cell_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_tac, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrp, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_rsrq, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_sinr, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbim_base_station_provider_id, tvb, base_offset + provider_id_offset,
        provider_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(provider_id_size, 4);
    proto_tree_add_item(tree, hf_mbim_base_station_cell_id_string, tvb, base_offset + cell_id_offset,
        cell_id_size, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    *offset += ROUND_UP_COUNT(cell_id_size, 4);
}

static void
mbim_dissect_base_station_info(tvbuff_t* tvb, proto_tree* tree, gint offset,
    struct mbim_conv_info* mbim_conv)
{
    proto_tree* subtree, *sub_subtree;
    gint base_offset = offset;
    guint32 gsm_serving_cell_offset, gsm_serving_cell_size, umts_serving_cell_offset, umts_serving_cell_size, td_scdma_serving_cell_offset, td_scdma_serving_cell_size,
        lte_serving_cell_offset, lte_serving_cell_size, gsm_nmr_offset, gsm_nmr_size, umts_mrl_offset, umts_mrl_size, td_scdma_mrl_offset, td_scdma_mrl_size,
        lte_mrl_offset, lte_mrl_size, cdma_mrl_offset, cdma_mrl_size, nr_serving_cells_offset = 0, nr_serving_cells_size = 0, nr_neighbor_cells_offset = 0, nr_neighbor_cells_size = 0;

    guint32 count;

    proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_base_station_system_type, ett_mbim_bitmap,
        mbim_data_class_fields, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mbim_base_station_system_sub_type, ett_mbim_bitmap,
            mbim_data_subclass_fields, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_gsm_serving_cell_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &gsm_serving_cell_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_gsm_serving_cell_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &gsm_serving_cell_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_umts_serving_cell_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &umts_serving_cell_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_umts_serving_cell_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &umts_serving_cell_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_td_scdma_serving_cell_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &td_scdma_serving_cell_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_td_scdma_serving_cell_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &td_scdma_serving_cell_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_lte_serving_cell_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_serving_cell_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_lte_serving_cell_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_serving_cell_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_gsm_nmr_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &gsm_nmr_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_gsm_nmr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &gsm_nmr_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_umts_mrl_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &umts_mrl_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_umts_mrl_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &umts_mrl_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_td_scdma_mrl_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &td_scdma_mrl_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_td_scdma_mrl_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &td_scdma_mrl_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_lte_mrl_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_mrl_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_lte_mrl_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_mrl_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_cdma_mrl_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cdma_mrl_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_cdma_mrl_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cdma_mrl_size);
    offset += 4;
    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_nr_serving_cell_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nr_serving_cells_offset);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_nr_serving_cell_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nr_serving_cells_size);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_nr_neighbor_cells_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nr_neighbor_cells_offset);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_mbim_base_station_nr_neighbor_cells_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nr_neighbor_cells_size);
    }

    if (gsm_serving_cell_offset && gsm_serving_cell_size) {
        offset = base_offset + gsm_serving_cell_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, gsm_serving_cell_size, ett_mbim_pair_list, NULL, "Gsm Serving Cell");
        mbim_dissect_base_station_gsm_serving_cell_info(tvb, subtree, offset);
    }

    if (umts_serving_cell_offset && umts_serving_cell_size) {
        offset = base_offset + umts_serving_cell_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, umts_serving_cell_size, ett_mbim_pair_list, NULL, "Umts Serving Cell");
        mbim_dissect_base_station_umts_serving_cell_info(tvb, subtree, offset);
    }

    if (td_scdma_serving_cell_offset && td_scdma_serving_cell_size) {
        offset = base_offset + td_scdma_serving_cell_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, td_scdma_serving_cell_size, ett_mbim_pair_list, NULL, "Td Scdma Serving Cell");
        mbim_dissect_base_station_td_scdma_serving_cell_and_mrl_info(tvb, subtree, &offset);
    }

    if (lte_serving_cell_offset && lte_serving_cell_size) {
        offset = base_offset + lte_serving_cell_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lte_serving_cell_size, ett_mbim_pair_list, NULL, "Lte Serving Cell");
        mbim_dissect_base_station_lte_serving_cell_info(tvb, subtree, offset);
    }

    if (gsm_nmr_offset && gsm_nmr_size) {
        offset = base_offset + gsm_nmr_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, gsm_nmr_size, ett_mbim_pair_list, NULL, "Gsm Nmr");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Nmr Info #%u", i);
            mbim_dissect_base_station_gsm_nmr_info(tvb, sub_subtree, &offset);
        }
    }

    if (umts_mrl_offset && umts_mrl_size) {
        offset = base_offset + umts_mrl_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, umts_mrl_size, ett_mbim_pair_list, NULL, "Umts Mrl");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Mrl Info #%u", i);
            mbim_dissect_base_station_umts_mrl_info(tvb, sub_subtree, &offset);
        }
    }

    if (td_scdma_mrl_offset && td_scdma_mrl_size) {
        offset = base_offset + td_scdma_mrl_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, td_scdma_mrl_size, ett_mbim_pair_list, NULL, "Td Scdma Mrl");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Mrl Info #%u", i);
            mbim_dissect_base_station_td_scdma_serving_cell_and_mrl_info(tvb, sub_subtree, &offset);
        }
    }

    if (lte_mrl_offset && lte_mrl_size) {
        offset = base_offset + lte_mrl_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lte_mrl_size, ett_mbim_pair_list, NULL, "Lte Mrl");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Mrl Info #%u", i);
            mbim_dissect_base_station_lte_mrl_info(tvb, sub_subtree, &offset);
        }
    }

    if (cdma_mrl_offset && cdma_mrl_size) {
        offset = base_offset + cdma_mrl_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lte_mrl_size, ett_mbim_pair_list, NULL, "Cdma Mrl");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Mrl Info #%u", i);
            mbim_dissect_base_station_cdma_mrl_info(tvb, sub_subtree, &offset);
        }
    }

    if (nr_serving_cells_offset && nr_serving_cells_size)
    {
        offset = base_offset + nr_serving_cells_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lte_mrl_size, ett_mbim_pair_list, NULL, "Nr Serving Cells");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Cell Info #%u", i);
            mbim_dissect_base_station_nr_serving_cell_info(tvb, sub_subtree, &offset);
        }
    }

    if (nr_neighbor_cells_offset && nr_neighbor_cells_size)
    {
        offset = base_offset + nr_neighbor_cells_offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, lte_mrl_size, ett_mbim_pair_list, NULL, "Nr Neighbor Cells");
        proto_tree_add_item_ret_uint(subtree, hf_mbim_base_station_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
        offset += 4;
        for (guint32 i = 0; i < count; i++) {
            sub_subtree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Cell Info #%u", i);
            mbim_dissect_base_station_nr_neighbor_cell_info(tvb, sub_subtree, &offset);
        }
    }
}

static void
mbim_dissect_version(tvbuff_t* tvb, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    guint32 extended_version;

    proto_tree_add_item(tree, hf_mbim_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(tree, hf_mbim_extended_version, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extended_version);
    switch (extended_version) {
        case 0x0100:
            mbim_conv->mbim_extended_version = MBIM_Extended_Version_1;
            break;
        case 0x0200:
            mbim_conv->mbim_extended_version = MBIM_Extended_Version_2;
            break;
        case 0x0300:
            mbim_conv->mbim_extended_version = MBIM_Extended_Version_3;
            break;
        case 0x0400:
            mbim_conv->mbim_extended_version = MBIM_Extended_Version_4;
            break;
        default:
            mbim_conv->mbim_extended_version = MBIM_Extended_Version_Unknown;
            break;
    }
}

static void
mbim_dissect_ms_modem_config_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 buffer_len)
{
    proto_tree *config_name, *unnamed_ies;
    guint32 base_offset;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_modem_config_config_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    config_name = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Config Name");
    mbim_dissect_tlv_ie(tvb, pinfo, config_name, &offset);
    while ((guint32)offset - base_offset < buffer_len) {
        unnamed_ies = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Unnamed IE's");
        mbim_dissect_tlv_ie(tvb, pinfo, unnamed_ies, &offset);
    }
}

static void
mbim_dissect_ms_registration_params_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 buffer_len)
{
    guint32 base_offset;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_registration_params_info_mico_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_registration_params_info_drx_params, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_registration_params_info_ladn_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_registration_params_info_default_pdu_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_registration_params_info_re_register_if_needed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    mbim_dissect_tlv_ie_list(tvb, pinfo, tree, offset, base_offset, buffer_len);
}

static void
mbim_dissect_ms_network_params_info(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset, guint32 buffer_len)
{
    guint32 base_offset =  offset;
    proto_tree_add_item(tree, hf_mbim_ms_network_params_info_mico_indication, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_network_params_info_drx_params, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    mbim_dissect_tlv_ie_list(tvb, pinfo, tree, offset, base_offset, buffer_len);
}

static void
mbim_dissect_ms_wake_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree *wake_reason_tree;
    proto_tree_add_item(tree, hf_mbim_ms_wake_reason_wake_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_wake_reason_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    wake_reason_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_mbim_pair_list, NULL, "Wake Reason");
    mbim_dissect_tlv_ie(tvb, pinfo, wake_reason_tree, &offset);
}

static void
mbim_dissect_ms_atr_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint base_offset;
    guint32 atr_offset, atr_size;
    tvbuff_t *next_tvb;

    base_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_atr_info_atr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &atr_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_atr_info_atr_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &atr_offset);

    if (atr_offset && atr_size) {
        if (iso7816_atr_handle) {
            next_tvb = tvb_new_subset_length(tvb, base_offset + atr_offset, atr_size);
            call_dissector(iso7816_atr_handle, next_tvb, pinfo, tree);
        } else {
            proto_tree_add_item(tree, hf_mbim_info_buffer, tvb, base_offset + atr_offset, atr_size, ENC_NA);
        }

        // TODO: check atr_size <= 33
    }
}

static void
mbim_dissect_ms_open_channel(tvbuff_t* tvb, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    guint32 base_offset = offset;
    guint32 app_id_offset, app_id_size;

    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_open_channel_app_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_open_channel_app_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_offset);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_open_channel_select_p2_arg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_uicc_channel_group, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    if (app_id_offset && app_id_size) {
        proto_tree_add_item(tree, hf_mbim_ms_open_channel_app_id, tvb, base_offset + app_id_offset, app_id_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_open_channel_info(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    guint32 base_offset = offset;
    guint32 response_offset, response_length;

    proto_tree_add_item(tree, hf_mbim_ms_uicc_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_uicc_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_uicc_response_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_length);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_uicc_response_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_offset);

    if (response_offset && response_length) {
        proto_tree_add_item(tree, hf_mbim_ms_uicc_response, tvb, base_offset + response_offset, response_length, ENC_NA);
    }
}

static void
mbim_dissect_ms_close_channel(tvbuff_t* tvb, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    proto_tree_add_item(tree, hf_mbim_ms_uicc_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_uicc_channel_group, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_ms_apdu(tvbuff_t* tvb, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    guint32 base_offset = offset;
    guint32 command_offset, command_size;
    proto_tree_add_item(tree, hf_mbim_ms_uicc_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_apdu_secure_messaging, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_apdu_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_apdu_command_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &command_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_apdu_command_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &command_offset);
    offset += 4;

    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    if (command_offset && command_size) {
        proto_tree_add_item(tree, hf_mbim_ms_apdu_command, tvb, base_offset + command_offset, command_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_apdu_info(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    guint32 base_offset = offset;
    guint32 response_offset, response_length;

    proto_tree_add_item(tree, hf_mbim_ms_uicc_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_uicc_response_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_length);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_uicc_response_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_offset);

    if (response_offset && response_length) {
        proto_tree_add_item(tree, hf_mbim_ms_uicc_response, tvb, base_offset + response_offset, response_length, ENC_NA);
    }
}

static void
mbim_dissect_ms_terminal_capability_info(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint information_buffer_base_offset, gint offset)
{
    guint32 capability_count;
    wmem_array_t* pair_list = NULL;
    struct mbim_pair_list pair_list_item, * p_pair_list_item;
    proto_tree* subtree;

    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_terminal_capability_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &capability_count);
    offset += 4;
    if (capability_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8 * capability_count, ett_mbim_pair_list, NULL, "Capability List");
        for (guint32 i = 0; i < capability_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_terminal_capability_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_terminal_capability_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
    }
    for (guint32 i = 0; i < capability_count; i++) {
        p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
        offset = information_buffer_base_offset + p_pair_list_item->offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, p_pair_list_item->size,
            ett_mbim_pair_list, NULL, "Capability #%u", i + 1);
        if (p_pair_list_item->size && p_pair_list_item->offset) {
            proto_tree_add_item(subtree, hf_mbim_ms_terminal_capability, tvb, offset, p_pair_list_item->size, ENC_NA);
        }
    }
}

static void
mbim_dissect_ms_set_terminal_capability(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    gint base_offset = offset;
    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    mbim_dissect_ms_terminal_capability_info(tvb,pinfo, tree, base_offset, offset);
}

static void
mbim_dissect_ms_set_reset(tvbuff_t* tvb, proto_tree* tree, gint offset, struct mbim_conv_info* mbim_conv)
{
    proto_tree_add_item(tree, hf_mbim_ms_reset_pass_through_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
        proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_ms_query_reset(tvbuff_t* tvb, proto_tree* tree, gint offset)
{
    proto_tree_add_item(tree, hf_mbim_ms_slot_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
mbim_dissect_ms_app_info_elements(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    guint32 base_offset = offset;
    guint32 app_id_offset, app_id_size, app_name_offset, app_name_size, pin_ref_offset, pin_ref_size, num_pins;

    proto_tree_add_item(tree, hf_mbim_ms_app_info_app_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_app_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_app_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_app_name_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_name_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_app_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_name_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_num_pins, tvb, offset, 4, ENC_LITTLE_ENDIAN, &num_pins);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_pin_ref_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pin_ref_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_info_pin_ref_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pin_ref_size);

    if (app_id_offset && app_id_size) {
        proto_tree_add_item(tree, hf_mbim_ms_app_info_app_id, tvb, base_offset + app_id_offset, app_id_size, ENC_NA);
    }
    if (app_name_offset && app_name_size) {
        proto_tree_add_item(tree, hf_mbim_ms_app_info_app_name, tvb, base_offset + app_name_offset, app_name_size, ENC_UTF_8 | ENC_NA);
    }
    if (num_pins) {
        proto_tree_add_item(tree, hf_mbim_ms_app_info_pin_ref, tvb, base_offset + pin_ref_offset, pin_ref_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_app_list(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint offset)
{
    gint base_offset;
    guint32 app_count;
    wmem_array_t* pair_list = NULL;
    struct mbim_pair_list pair_list_item, * p_pair_list_item;
    proto_tree* subtree;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_app_list_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_app_list_app_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_count);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_app_list_active_app_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_app_list_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (app_count) {
        pair_list = wmem_array_new(pinfo->pool, sizeof(struct mbim_pair_list));
        subtree = proto_tree_add_subtree(tree, tvb, offset, 8 * app_count, ett_mbim_pair_list, NULL, "App List");
        for (guint32 i = 0; i < app_count; i++) {
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_app_list_app_info_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.offset);
            offset += 4;
            proto_tree_add_item_ret_uint(subtree, hf_mbim_ms_app_list_app_info_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pair_list_item.size);
            offset += 4;
            wmem_array_append_one(pair_list, pair_list_item);
        }
    }
    for (guint32 i = 0; i < app_count; i++) {
        p_pair_list_item = (struct mbim_pair_list*)wmem_array_index(pair_list, i);
        offset = base_offset + p_pair_list_item->offset;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, p_pair_list_item->size,
            ett_mbim_pair_list, NULL, "App Info #%u", i + 1);
        if (p_pair_list_item->size && p_pair_list_item->offset) {
            mbim_dissect_ms_app_info_elements(tvb, pinfo, subtree, offset);
        }
    }
}

static void
mbim_dissect_ms_file_path(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    gint base_offset;
    guint32 app_id_offset, app_id_size, file_path_offset, file_path_size;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_file_path_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_file_path_app_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_file_path_app_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_file_path_file_path_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_file_path_file_path_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_size);
    if (app_id_offset && app_id_size) {
        proto_tree_add_item(tree, hf_mbim_ms_file_path_app_id, tvb, base_offset + app_id_offset,
            app_id_size, ENC_NA);
    }
    if (file_path_offset && file_path_size) {
        proto_tree_add_item(tree, hf_mbim_ms_file_path_file_path, tvb, base_offset + file_path_offset,
            file_path_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_file_status(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    guint32 i;

    proto_tree_add_item(tree, hf_mbim_ms_file_status_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_status_word_1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_status_word_2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_file_accessibility, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_file_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_file_structure, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_item_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_file_status_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    for (i = 0; i < 4; i++) {
        offset += 4;
        proto_tree_add_item(tree, hf_mbim_ms_file_status_file_lock_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
mbim_dissect_ms_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    gint base_offset;
    guint32 response_data_offset, response_data_size;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_response_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_response_status_word_1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_response_status_word_2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_response_response_data_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_data_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_response_response_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &response_data_size);
    if (response_data_offset && response_data_size) {
        proto_tree_add_item(tree, hf_mbim_ms_response_response_data, tvb, base_offset + response_data_offset,
            response_data_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_access_binary(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    gint base_offset;
    guint32 app_id_offset, app_id_size, file_path_offset, file_path_size, local_pin_offset, local_pin_size, binary_data_offset, binary_data_size;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_access_binary_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_app_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_app_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_file_path_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_file_path_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_access_binary_file_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_access_binary_number_of_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_local_pin_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &local_pin_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_local_pin_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &local_pin_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_binary_data_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &binary_data_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_binary_binary_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &binary_data_size);
    if (app_id_offset && app_id_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_binary_app_id, tvb, base_offset + app_id_offset,
            app_id_size, ENC_NA);
    }
    if (file_path_offset && file_path_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_binary_file_path, tvb, base_offset + file_path_offset,
            file_path_size, ENC_NA);
    }
    if (local_pin_offset && local_pin_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_binary_local_pin, tvb, base_offset + local_pin_offset,
            local_pin_size, ENC_UTF_8 | ENC_NA);
    }
    if (binary_data_offset && binary_data_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_binary_binary_data, tvb, base_offset + binary_data_offset,
            binary_data_size, ENC_NA);
    }
}

static void
mbim_dissect_ms_access_record(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint offset)
{
    gint base_offset;
    guint32 app_id_offset, app_id_size, file_path_offset, file_path_size, local_pin_offset, local_pin_size, record_data_offset, record_data_size;

    base_offset = offset;
    proto_tree_add_item(tree, hf_mbim_ms_access_record_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_app_id_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_app_id_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &app_id_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_file_path_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_file_path_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_path_size);
    offset += 4;
    proto_tree_add_item(tree, hf_mbim_ms_access_record_record_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_local_pin_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &local_pin_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_local_pin_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &local_pin_size);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_record_data_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &record_data_offset);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_mbim_ms_access_record_record_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &record_data_size);
    if (app_id_offset && app_id_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_record_app_id, tvb, base_offset + app_id_offset,
            app_id_size, ENC_NA);
    }
    if (file_path_offset && file_path_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_record_file_path, tvb, base_offset + file_path_offset,
            file_path_size, ENC_NA);
    }
    if (local_pin_offset && local_pin_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_record_local_pin, tvb, base_offset + local_pin_offset,
            local_pin_size, ENC_LITTLE_ENDIAN | ENC_UTF_8);
    }
    if (record_data_offset && record_data_size) {
        proto_tree_add_item(tree, hf_mbim_ms_access_record_record_data, tvb, base_offset + record_data_offset,
            record_data_size, ENC_NA);
    }
}

static int
dissect_mbim_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *mbim_tree, *header_tree, *subtree;
    gint offset = 0;
    guint32 msg_type, trans_id, open_count;
    guint64 trans_id_key, *p_trans_id_key;
    conversation_t *conversation;
    struct mbim_conv_info *mbim_conv;
    struct mbim_info *mbim_info = NULL;

    if (data) {
        usb_trans_info_t *usb_trans_info = ((usb_conv_info_t *)data)->usb_trans_info;
        if (usb_trans_info && (usb_trans_info->setup.request == 0x00)) {
            tree = proto_tree_get_parent_tree(tree);
        }
    }

    if (mbim_control_decode_unknown_itf && (tvb_reported_length_remaining(tvb, offset) < 12)) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MBIM");
    col_clear(pinfo->cinfo, COL_INFO);

    conversation = find_or_create_conversation(pinfo);
    mbim_conv = (struct mbim_conv_info *)conversation_get_proto_data(conversation, proto_mbim);
    if (!mbim_conv) {
        mbim_conv = wmem_new(wmem_file_scope(), struct mbim_conv_info);
        mbim_conv->trans = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
        mbim_conv->open = wmem_tree_new(wmem_file_scope());
        mbim_conv->cellular_class = 0;
        mbim_conv->mbim_extended_version = MBIM_Extended_Version_Unknown;
        mbim_conv->open_count = 0;
        wmem_tree_insert32(mbim_conv->open, pinfo->num, GUINT_TO_POINTER(mbim_conv->open_count));
        conversation_add_proto_data(conversation, proto_mbim, mbim_conv);
    }

    ti = proto_tree_add_item(tree, proto_mbim, tvb, offset, -1, ENC_NA);
    mbim_tree = proto_item_add_subtree(ti, ett_mbim);
    ti = proto_tree_add_item(mbim_tree, hf_mbim_control, tvb, offset, 0, ENC_NA);
    proto_item_set_hidden(ti);

    header_tree = proto_tree_add_subtree(mbim_tree, tvb, offset, 12, ett_mbim_msg_header, NULL, "Message Header");
    proto_tree_add_item_ret_uint(header_tree, hf_mbim_header_message_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &msg_type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%-19s", val_to_str_const(msg_type, mbim_msg_type_vals, "Unknown"));
    offset += 4;
    proto_tree_add_item(header_tree, hf_mbim_header_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(header_tree, hf_mbim_header_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &trans_id);
    offset += 4;

    switch (msg_type) {
        case MBIM_OPEN_MSG:
            {
                guint32 max_ctrl_transfer;

                if (!PINFO_FD_VISITED(pinfo)) {
                    mbim_conv->open_count++;
                    wmem_tree_insert32(mbim_conv->open, pinfo->num, GUINT_TO_POINTER(mbim_conv->open_count));
                }
                max_ctrl_transfer = tvb_get_letohl(tvb, offset);
                if (max_ctrl_transfer == 8) {
                    proto_tree_add_uint_format_value(mbim_tree, hf_mbim_max_ctrl_transfer, tvb, offset, 4, max_ctrl_transfer, "MBIM_ERROR_MAX_TRANSFER (%d)", max_ctrl_transfer);
                } else {
                    ti = proto_tree_add_uint(mbim_tree, hf_mbim_max_ctrl_transfer, tvb, offset, 4, max_ctrl_transfer);
                    if (max_ctrl_transfer < 64) {
                        expert_add_info(pinfo, ti, &ei_mbim_max_ctrl_transfer);
                    }
                }
            }
            break;
        case MBIM_CLOSE_MSG:
            break;
        case MBIM_COMMAND_MSG:
            {
                guint32 info_buff_len, current_frag, total_frag, cid, cmd_type;
                guint8 uuid_idx;
                fragment_head *frag_data;
                tvbuff_t *frag_tvb;
                struct mbim_uuid_ext *uuid_ext_info = NULL;

                subtree = proto_tree_add_subtree(mbim_tree, tvb, offset, 8, ett_mbim_frag_header, NULL, "Fragment Header");
                proto_tree_add_item_ret_uint(subtree, hf_mbim_fragment_total, tvb, offset, 4, ENC_LITTLE_ENDIAN, &total_frag);
                offset += 4;
                proto_tree_add_item_ret_uint(subtree, hf_mbim_fragment_current, tvb, offset, 4, ENC_LITTLE_ENDIAN, &current_frag);
                offset += 4;
                if (total_frag > 1) {
                    frag_data = fragment_add_seq_check(&mbim_reassembly_table, tvb, offset, pinfo,
                                                       trans_id, mbim_conv, current_frag,
                                                       tvb_reported_length_remaining(tvb, offset),
                                                       (current_frag != (total_frag-1)));
                    frag_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled MBIM control message",
                                                        frag_data, &mbim_frag_items, NULL, subtree);
                    if (!frag_tvb) {
                        /* Fragmentation reassembly not performed yet */
                        proto_tree_add_item(mbim_tree, hf_mbim_fragmented_payload, tvb, offset, -1, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": [Fragment #%u out of %u]", current_frag+1, total_frag);
                        break;
                    }
                    offset = 0;
                } else {
                    frag_tvb = tvb;
                }

                open_count = GPOINTER_TO_UINT(wmem_tree_lookup32_le(mbim_conv->open, pinfo->num));
                trans_id_key = ((guint64)open_count << 32) | trans_id;
                if (!PINFO_FD_VISITED(pinfo)) {
                    p_trans_id_key = wmem_new(wmem_file_scope(), guint64);
                    *p_trans_id_key = trans_id_key;
                    mbim_info = wmem_new(wmem_file_scope(), struct mbim_info);
                    mbim_info->req_frame = pinfo->num;
                    mbim_info->resp_frame = 0;
                    wmem_map_insert(mbim_conv->trans, p_trans_id_key, mbim_info);
                } else {
                    mbim_info = (struct mbim_info *)wmem_map_lookup(mbim_conv->trans, &trans_id_key);
                    if (mbim_info && mbim_info->resp_frame) {
                        proto_item *resp_it;

                        resp_it = proto_tree_add_uint(header_tree, hf_mbim_response_in, tvb, 0, 0, mbim_info->resp_frame);
                        proto_item_set_generated(resp_it);
                    }
                }

                uuid_idx = mbim_dissect_service_id_uuid(frag_tvb, pinfo, mbim_tree, hf_mbim_device_service_id, &offset, &uuid_ext_info, pinfo->rec->rec_header.packet_header.pkt_encap != WTAP_ENCAP_ETW);
                cid = mbim_dissect_cid(frag_tvb, pinfo, mbim_tree, &offset, uuid_idx, uuid_ext_info);
                proto_tree_add_item_ret_uint(mbim_tree, hf_mbim_command_type, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &cmd_type);
                if (mbim_info) {
                    mbim_info->cmd_type = cmd_type;
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(cmd_type, mbim_command_type_vals, "Unknown"));
                offset += 4;
                proto_tree_add_item_ret_uint(mbim_tree, hf_mbim_info_buffer_len, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &info_buff_len);
                offset += 4;
                subtree = mbim_tree;
                if (info_buff_len) {
                    subtree = proto_tree_add_subtree(mbim_tree, frag_tvb, offset, info_buff_len, ett_mbim_info_buffer, NULL, "Information Buffer");
                }
                switch (uuid_idx) {
                    case UUID_BASIC_CONNECT:
                        switch (cid) {
                            case MBIM_CID_DEVICE_CAPS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_SUBSCRIBER_READY_STATUS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                        proto_tree_add_item(subtree, hf_mbim_ms_slot_id, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                }
                                break;
                            case MBIM_CID_RADIO_STATE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_radio_state_set, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_PIN:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_pin(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_PIN_LIST:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_HOME_PROVIDER:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_provider(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_PREFERRED_PROVIDERS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_providers(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_VISIBLE_PROVIDERS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_visible_providers_req_action, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            case MBIM_CID_REGISTER_STATE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_register_state(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_PACKET_SERVICE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_set_packet_service_action,
                                                        frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_SIGNAL_STATE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_signal_state(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_CONNECT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                        mbim_dissect_set_connect_v3_and_higher(frag_tvb, pinfo, subtree, offset, info_buff_len, mbim_conv);
                                    } else {
                                        mbim_dissect_set_connect(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_connect_info_session_id, frag_tvb,
                                                        offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            case MBIM_CID_PROVISIONED_CONTEXTS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_context(frag_tvb, pinfo, subtree, offset, TRUE);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_SERVICE_ACTIVATION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_set_service_activation_data_buffer,
                                                        frag_tvb, offset, info_buff_len, ENC_NA);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_IP_CONFIGURATION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_ip_configuration_info_session_id, frag_tvb,
                                                        offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            case MBIM_CID_DEVICE_SERVICES:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_device_service_subscribe_list(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PACKET_STATISTICS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_NETWORK_IDLE_HINT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_network_idle_hint_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_EMERGENCY_MODE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_IP_PACKET_FILTERS:
                                mbim_dissect_packet_filters(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_MULTICARRIER_PROVIDERS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_providers(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_SMS:
                        switch (cid) {
                            case MBIM_CID_SMS_CONFIGURATION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_sms_configuration(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_SMS_READ:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_sms_read_req(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            case MBIM_CID_SMS_SEND:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_sms_send(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SMS_DELETE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_set_sms_delete_flag,
                                                        frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_set_sms_delete_message_index,
                                                        frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SMS_MESSAGE_STORE_STATUS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_USSD:
                        switch (cid) {
                            case MBIM_CID_USSD:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_ussd(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_PHONEBOOK:
                        switch (cid) {
                            case MBIM_CID_PHONEBOOK_CONFIGURATION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_PHONEBOOK_READ:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_phonebook_read_req_filter_flag, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_phonebook_read_req_filter_message_index, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            case MBIM_CID_PHONEBOOK_DELETE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_set_phonebook_delete_filter_flag, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_set_phonebook_delete_filter_message_index, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PHONEBOOK_WRITE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_phonebook_write(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_STK:
                        switch (cid) {
                            case MBIM_CID_STK_PAC:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_stk_pac(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                }
                                break;
                            case MBIM_CID_STK_TERMINAL_RESPONSE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_stk_terminal_response(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_STK_ENVELOPE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    tvbuff_t *env_tvb;
                                    proto_tree *env_tree;

                                    ti = proto_tree_add_item(subtree, hf_mbim_set_stk_envelope_data_buffer,
                                                             frag_tvb, offset, info_buff_len, ENC_NA);
                                    if (bertlv_handle) {
                                        env_tree = proto_item_add_subtree(ti, ett_mbim_buffer);
                                        env_tvb = tvb_new_subset_length(frag_tvb, offset, info_buff_len);
                                        call_dissector(bertlv_handle, env_tvb, pinfo, env_tree);
                                    }
                                } else if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_AUTH:
                        switch (cid) {
                            case MBIM_CID_AKA_AUTH:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_aka_auth_req(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            case MBIM_CID_AKAP_AUTH:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_akap_auth_req(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            case MBIM_CID_SIM_AUTH:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_sim_auth_req(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_DSS:
                        switch (cid) {
                            case MBIM_CID_DSS_CONNECT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_dss_connect(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MULTICARRIER:
                        switch (cid) {
                            case MBIM_CID_MULTICARRIER_CAPABILITIES:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_LOCATION_INFO:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_location_info_country, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTICARRIER_CURRENT_CID_LIST:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, info_buff_len);
                                } else {
                                    mbim_dissect_muticarrier_current_cid_list_req(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_HOSTSHUTDOWN:
                        switch (cid) {
                            case MBIM_CID_MS_HOSTSHUTDOWN:
                            case MBIM_CID_MS_HOSTPRESHUTDOWN:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MSFWID:
                        switch (cid) {
                            case MBIM_CID_MSFWID_FIRMWAREID:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_QMI:
                        switch (cid) {
                            case MBIM_CID_QMI_QMI:
                                if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_qmi_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_FWUSVC:
                        switch (cid) {
                            case MBIM_CID_INTC_MODEM_REBOOT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_DPTF:
                        switch (cid) {
                            case MBIM_CID_INTC_THERMAL_STATE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_thermal_config(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_query_thermal_state_temp_sensor_id, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_SAR:
                        switch (cid) {
                            case MBIM_CID_INTC_SAR_CONFIG:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_sar_config(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_ACT:
                        switch (cid) {
                            case MBIM_CID_INTC_ADPCLK_MODE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_adpclk_activate_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_TRCSVC:
                        switch (cid) {
                            case MBIM_CID_INTC_TRACE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_trace_config_config, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_INTC_TRACE_DATA:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_trace_config_config, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_NRTC:
                        switch (cid) {
                            case MBIM_CID_INTC_NRTAPP:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_nrtc_app_info_period, frag_tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                    offset += 2;
                                    proto_tree_add_item(subtree, hf_mbim_nrtc_app_info_duration, frag_tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_INTC_NRTCWS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_nrtcws_config(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_USB_PROFILE:
                        switch (cid) {
                            case MBIM_CID_INTC_USBPROFILE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    guint32 at_len;

                                    proto_tree_add_item_ret_uint(subtree, hf_mbim_usbprofile_cmd_length, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &at_len);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_usbprofile_cmd_buffer, frag_tvb, offset, at_len, ENC_LITTLE_ENDIAN|ENC_UTF_16);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_CIQ:
                        switch (cid) {
                            case MBIM_CID_INTC_CIQ:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    guint32 size;

                                    proto_tree_add_item(subtree, hf_mbim_ciq_set_mode, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item_ret_uint(subtree, hf_mbim_ciq_set_debug_info_size, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &size);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_ciq_set_debug_info, frag_tvb, offset, size, ENC_LITTLE_ENDIAN|ENC_UTF_16);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_ATDS:
                        switch (cid) {
                            case MBIM_CID_ATDS_SIGNAL:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_ATDS_LOCATION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_ATDS_OPERATORS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_atds_operators(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_ATDS_RAT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_atds_rat_info_mode, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_ATDS_REGISTER_STATE:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_ATDS_SET_PROJECTION_TABLES:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_atds_projection_tables(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MULTIFLOW:
                        switch (cid) {
                            case MBIM_CID_MULTIFLOW_CAPS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTIFLOW_UPLINK:
                            case MBIM_CID_MULTIFLOW_DOWNLINK:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_item(subtree, hf_mbim_set_multiflow_state_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTIFLOW_TFT:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_BASIC_CONNECT_EXTENSIONS:
                        switch (cid) {
                            case MBIM_CID_MS_PROVISIONED_CONTEXT_V2:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_set_ms_provisioned_context_v2(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_NETWORK_BLACKLIST:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_network_blacklist_info(pinfo, frag_tvb, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_LTE_ATTACH_CONFIG:
                            case MBIM_CID_MS_LTE_ATTACH_STATUS:
                                if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            case MBIM_CID_MS_SYS_CAPS:
                            case MBIM_CID_MS_DEVICE_CAPS_V2:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_DEVICE_SLOT_MAPPINGS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_device_slot_mapping_info(frag_tvb, pinfo, subtree, offset);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_SLOT_INFO_STATUS:
                                if (cmd_type == MBIM_COMMAND_QUERY) {
                                    proto_tree_add_item(subtree, hf_mbim_ms_slot_info_req_slot_index, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PCO:
                                if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            case MBIM_CID_MS_DEVICE_RESET:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_BASE_STATIONS_INFO:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    mbim_dissect_base_station_info_req(frag_tvb, subtree, offset, mbim_conv);
                                }
                                break;
                            case MBIM_CID_LOCATION_INFO_STATUS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_PIN_INFO_EX2:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                            case MBIM_CID_VERSION:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    mbim_dissect_version(frag_tvb, subtree, offset, mbim_conv);
                                }
                                break;
                            case MBIM_CID_MS_MODEM_CONFIG:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_REGISTRATION_PARAMS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_registration_params_info(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                }
                                else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_NETWORK_PARAMS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                else if (info_buff_len) {
                                    mbim_dissect_tlv_ie_list(frag_tvb, pinfo, subtree, offset, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_WAKE_REASON:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_UE_POLICY:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                else if (info_buff_len) {
                                    mbim_dissect_tlv_ie_list(frag_tvb, pinfo, subtree, offset, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_SARCONTROL:
                        switch (cid) {
                            case MBIM_CID_MS_SAR_CONFIG:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_sar_config(frag_tvb, pinfo, subtree, offset, FALSE);
                                }
                                else if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            case MBIM_CID_MS_TRANSMISSION_STATUS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_transmission_status(frag_tvb, subtree, offset, FALSE);
                                }
                                else if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_UICC_LOW_LEVEL:
                        switch (cid) {
                            case MBIM_CID_MS_UICC_ATR:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                        proto_tree_add_item(subtree, hf_mbim_ms_slot_id, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                }
                                break;
                            case MBIM_CID_MS_UICC_OPEN_CHANNEL:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_open_channel(frag_tvb, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_CLOSE_CHANNEL:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_close_channel(frag_tvb, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_APDU:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_apdu(frag_tvb, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_TERMINAL_CAPABILITY:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_set_terminal_capability(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                } else if (info_buff_len) {
                                    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                        proto_tree_add_item(subtree, hf_mbim_ms_slot_id, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    } else {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                }
                                break;
                            case MBIM_CID_MS_UICC_RESET:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    mbim_dissect_ms_set_reset(frag_tvb, subtree, offset, mbim_conv);
                                } else if (info_buff_len) {
                                    if (SHOULD_MBIM_EX4_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                        mbim_dissect_ms_query_reset(frag_tvb, subtree, offset);
                                    } else {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                }
                                break;
                            case MBIM_CID_MS_UICC_APP_LIST:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MS_UICC_ACCESS_BINARY:
                                mbim_dissect_ms_access_binary(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_MS_UICC_ACCESS_RECORD:
                                mbim_dissect_ms_access_record(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_MS_UICC_FILE_STATUS:
                                if (cmd_type == MBIM_COMMAND_SET) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                } else {
                                    mbim_dissect_ms_file_path(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_EXT_IDX:
                        {
                            gint cid_idx;
                            mbim_dissect_fct dissect_cid;

                            try_val_to_str_idx(cid, uuid_ext_info->uuid_cid_list, &cid_idx);
                            if (cid_idx != -1) {
                                dissect_cid = (cmd_type == MBIM_COMMAND_SET) ? uuid_ext_info->uuid_fct_list[cid_idx].cmd_set :
                                    uuid_ext_info->uuid_fct_list[cid_idx].cmd_query;
                                if (dissect_cid) {
                                    dissect_cid(frag_tvb, pinfo, subtree, offset, mbim_info);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                            } else {
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                            }
                        }
                        break;
                    default:
                        if (info_buff_len) {
                            proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                        }
                        break;
                }
            }
            break;
        case MBIM_FUNCTION_ERROR_MSG:
            open_count = GPOINTER_TO_UINT(wmem_tree_lookup32_le(mbim_conv->open, pinfo->num));
            trans_id_key = ((guint64)open_count << 32) | trans_id;
            mbim_info = (struct mbim_info *)wmem_map_lookup(mbim_conv->trans, &trans_id_key);
            if (!PINFO_FD_VISITED(pinfo)) {
                if (mbim_info) {
                    mbim_info->resp_frame = pinfo->num;
                }
            } else {
                if (mbim_info && mbim_info->req_frame) {
                    proto_item *req_it;

                    req_it = proto_tree_add_uint(header_tree, hf_mbim_request_in, tvb, 0, 0, mbim_info->req_frame);
                    proto_item_set_generated(req_it);
                }
            }
            /* FALLTHROUGH */
        case MBIM_HOST_ERROR_MSG:
            proto_tree_add_item(mbim_tree, hf_mbim_error_status_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case MBIM_OPEN_DONE:
        case MBIM_CLOSE_DONE:
            proto_tree_add_item(mbim_tree, hf_mbim_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case MBIM_COMMAND_DONE:
        case MBIM_INDICATE_STATUS_MSG:
            {
                guint32 info_buff_len, current_frag, total_frag, cid;
                guint8 uuid_idx;
                fragment_head *frag_data;
                tvbuff_t *frag_tvb;
                struct mbim_uuid_ext *uuid_ext_info = NULL;

                subtree = proto_tree_add_subtree(mbim_tree, tvb, offset, 8, ett_mbim_frag_header, NULL, "Fragment Header");
                proto_tree_add_item_ret_uint(subtree, hf_mbim_fragment_total, tvb, offset, 4, ENC_LITTLE_ENDIAN, &total_frag);
                offset += 4;
                proto_tree_add_item_ret_uint(subtree, hf_mbim_fragment_current, tvb, offset, 4, ENC_LITTLE_ENDIAN, &current_frag);
                offset += 4;
                if (total_frag > 1) {
                    frag_data = fragment_add_seq_check(&mbim_reassembly_table, tvb, offset, pinfo,
                                                       trans_id, mbim_conv, current_frag,
                                                       tvb_reported_length_remaining(tvb, offset),
                                                       (current_frag != (total_frag-1)));
                    frag_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled MBIM control message",
                                                        frag_data, &mbim_frag_items, NULL, subtree);
                    if (!frag_tvb) {
                        /* Fragmentation reassembly not performed yet */
                        proto_tree_add_item(mbim_tree, hf_mbim_fragmented_payload, tvb, offset, -1, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, ": [Fragment #%u out of %u]", current_frag+1, total_frag);
                        break;
                    }
                    offset = 0;
                } else {
                    frag_tvb = tvb;
                }

                if (msg_type == MBIM_COMMAND_DONE) {
                    open_count = GPOINTER_TO_UINT(wmem_tree_lookup32_le(mbim_conv->open, pinfo->num));
                    trans_id_key = ((guint64)open_count << 32) | trans_id;
                    mbim_info = (struct mbim_info *)wmem_map_lookup(mbim_conv->trans, &trans_id_key);
                    if (!PINFO_FD_VISITED(pinfo)) {
                        if (mbim_info) {
                            mbim_info->resp_frame = pinfo->num;
                        }
                    } else {
                        if (mbim_info && mbim_info->req_frame) {
                            proto_item *req_it;

                            req_it = proto_tree_add_uint(header_tree, hf_mbim_request_in, tvb, 0, 0, mbim_info->req_frame);
                            proto_item_set_generated(req_it);
                        }
                    }
                }

                uuid_idx = mbim_dissect_service_id_uuid(frag_tvb, pinfo, mbim_tree, hf_mbim_device_service_id, &offset, &uuid_ext_info, pinfo->rec->rec_header.packet_header.pkt_encap != WTAP_ENCAP_ETW);
                cid = mbim_dissect_cid(frag_tvb, pinfo, mbim_tree, &offset, uuid_idx, uuid_ext_info);
                if (msg_type == MBIM_COMMAND_DONE) {
                    proto_tree_add_item(mbim_tree, hf_mbim_status, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                }
                proto_tree_add_item_ret_uint(mbim_tree, hf_mbim_info_buffer_len, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &info_buff_len);
                offset += 4;
                if (info_buff_len == 0) {
                    break;
                }
                subtree = proto_tree_add_subtree(mbim_tree, frag_tvb, offset, info_buff_len, ett_mbim_info_buffer, NULL, "Information Buffer");
                switch (uuid_idx) {
                    case UUID_BASIC_CONNECT:
                        switch (cid) {
                            case MBIM_CID_DEVICE_CAPS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_device_caps_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SUBSCRIBER_READY_STATUS:
                                mbim_dissect_subscriber_ready_status(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_RADIO_STATE:
                                proto_tree_add_item(subtree, hf_mbim_radio_state_hw_radio_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                offset += 4;
                                proto_tree_add_item(subtree, hf_mbim_radio_state_sw_radio_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                break;
                            case MBIM_CID_PIN:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    guint32 attempts;

                                    proto_tree_add_item(subtree, hf_mbim_pin_info_pin_type, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_pin_info_pin_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    attempts = tvb_get_letohl(frag_tvb, offset);
                                    if (attempts == 0xffffffff) {
                                        proto_tree_add_uint_format(subtree, hf_mbim_pin_info_remaining_attempts, frag_tvb, offset, 4,
                                                                   attempts, "Not supported (0xffffffff)");
                                    } else {
                                        proto_tree_add_uint(subtree, hf_mbim_pin_info_remaining_attempts, frag_tvb, offset, 4, attempts);
                                    }
                                } else {
                                     proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PIN_LIST:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_pin_list_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_HOME_PROVIDER:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_provider(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PREFERRED_PROVIDERS:
                                mbim_dissect_providers(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_VISIBLE_PROVIDERS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_providers(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_REGISTER_STATE:
                                mbim_dissect_registration_state_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_PACKET_SERVICE:
                                mbim_dissect_packet_service_info(frag_tvb, pinfo, subtree, offset, mbim_conv, info_buff_len);
                                break;
                            case MBIM_CID_SIGNAL_STATE:
                                mbim_dissect_signal_state_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_CONNECT:
                                mbim_dissect_connect_info(frag_tvb, pinfo, subtree, offset, mbim_conv, info_buff_len);
                                break;
                            case MBIM_CID_PROVISIONED_CONTEXTS:
                                mbim_dissect_provisioned_contexts_info(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_SERVICE_ACTIVATION:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    guint32 nw_error;

                                    nw_error = tvb_get_letohl(frag_tvb, offset);
                                    if (nw_error == 0) {
                                        proto_tree_add_uint_format_value(subtree, hf_mbim_service_activation_info_nw_error,
                                                                         frag_tvb, offset, 4, nw_error, "Success (0)");
                                    } else {
                                        proto_tree_add_uint(subtree, hf_mbim_service_activation_info_nw_error,
                                                            frag_tvb, offset, 4, nw_error);
                                    }
                                    proto_tree_add_item(subtree, hf_mbim_service_activation_info_data_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_IP_CONFIGURATION:
                                mbim_dissect_ip_configuration_info(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_DEVICE_SERVICES:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_device_services_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_device_service_subscribe_list(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PACKET_STATISTICS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_packet_statistics_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_NETWORK_IDLE_HINT:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_network_idle_hint_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_EMERGENCY_MODE:
                                proto_tree_add_item(subtree, hf_mbim_emergency_mode_info_emergency_mode, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                break;
                            case MBIM_CID_IP_PACKET_FILTERS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_packet_filters(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MULTICARRIER_PROVIDERS:
                                mbim_dissect_providers(frag_tvb, pinfo, subtree, offset);
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_SMS:
                        switch (cid) {
                            case MBIM_CID_SMS_CONFIGURATION:
                                mbim_dissect_sms_configuration_info(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_SMS_READ:
                                mbim_dissect_sms_read_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_SMS_SEND:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_sms_send_info_message_reference, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SMS_DELETE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SMS_MESSAGE_STORE_STATUS:
                                proto_tree_add_bitmask(subtree, frag_tvb, offset, hf_mbim_sms_status_info_flags, ett_mbim_bitmap,
                                                       mbim_sms_status_info_flags_fields, ENC_LITTLE_ENDIAN);
                                offset += 4;
                                proto_tree_add_item(subtree, hf_mbim_sms_status_info_message_index, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_USSD:
                        switch (cid) {
                            case MBIM_CID_USSD:
                                mbim_dissect_ussd_info(frag_tvb, pinfo, subtree, offset);
                                break;
                            default:
                               proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_PHONEBOOK:
                        switch (cid) {
                            case MBIM_CID_PHONEBOOK_CONFIGURATION:
                                mbim_dissect_phonebook_configuration_info(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_PHONEBOOK_READ:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_phonebook_read_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_PHONEBOOK_DELETE:
                            case MBIM_CID_PHONEBOOK_WRITE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_STK:
                        switch (cid) {
                            case MBIM_CID_STK_PAC:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_stk_pac_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    tvbuff_t *pac_tvb;
                                    gint pac_length;
                                    proto_tree *pac_tree;

                                    proto_tree_add_item(subtree, hf_mbim_stk_pac_pac_type, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    pac_length = info_buff_len - 4;
                                    ti = proto_tree_add_item(subtree, hf_mbim_stk_pac_pac, frag_tvb, offset, pac_length, ENC_NA);
                                    if (bertlv_handle) {
                                        pac_tree = proto_item_add_subtree(ti, ett_mbim_buffer);
                                        pac_tvb = tvb_new_subset_length(frag_tvb, offset, pac_length);
                                        call_dissector(bertlv_handle, pac_tvb, pinfo, pac_tree);
                                    }
                                }
                                break;
                            case MBIM_CID_STK_TERMINAL_RESPONSE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_stk_terminal_response_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_STK_ENVELOPE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_stk_envelope_info_envelope_support,
                                                        frag_tvb, offset, 32, ENC_NA);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_AUTH:
                        switch (cid) {
                            case MBIM_CID_AKA_AUTH:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_aka_auth_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_AKAP_AUTH:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_akap_auth_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_SIM_AUTH:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_sim_auth_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_DSS:
                        switch (cid) {
                            case MBIM_CID_DSS_CONNECT:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MULTICARRIER:
                        switch (cid) {
                            case MBIM_CID_MULTICARRIER_CAPABILITIES:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_bitmask(subtree, frag_tvb, offset, hf_mbim_multicarrier_capabilities_info_capabilities,
                                                           ett_mbim_bitmap, mbim_multicarrier_capabilities_fields, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_LOCATION_INFO:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_location_info_country, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTICARRIER_CURRENT_CID_LIST:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_muticarrier_current_cid_list_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_HOSTSHUTDOWN:
                        switch (cid) {
                            case MBIM_CID_MS_HOSTSHUTDOWN:
                            case MBIM_CID_MS_HOSTPRESHUTDOWN:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MSFWID:
                        switch (cid) {
                            case MBIM_CID_MSFWID_FIRMWAREID:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_msfwid_firmwareid_info_firmware_id, frag_tvb, offset, 16, ENC_NA);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_QMI:
                        switch (cid) {
                            case MBIM_CID_QMI_QMI:
                                if (info_buff_len) {
                                    proto_tree_add_item(subtree, hf_mbim_qmi_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_FWUSVC:
                        switch (cid) {
                            case MBIM_CID_INTC_MODEM_REBOOT:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_DPTF:
                        switch (cid) {
                            case MBIM_CID_INTC_THERMAL_STATE:
                                if ((msg_type == MBIM_COMMAND_DONE) && mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    mbim_dissect_thermal_config(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    mbim_dissect_thermal_state_info(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_SAR:
                        switch (cid) {
                            case MBIM_CID_INTC_SAR_CONFIG:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_sar_config(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_ACT:
                        switch (cid) {
                            case MBIM_CID_INTC_ADPCLK_MODE:
                                if ((msg_type == MBIM_COMMAND_DONE) && info_buff_len &&
                                    mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                } else {
                                    mbim_dissect_adpclk_freq_info(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_TRCSVC:
                        switch (cid) {
                            case MBIM_CID_INTC_TRACE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_trace_config_config, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_INTC_TRACE_DATA:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_trace_config_config, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_NRTC:
                        switch (cid) {
                            case MBIM_CID_INTC_NRTAPP:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        proto_tree_add_item(subtree, hf_mbim_nrtc_app_info_period, frag_tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                        offset += 2;
                                        proto_tree_add_item(subtree, hf_mbim_nrtc_app_info_duration, frag_tvb, offset, 2, ENC_LITTLE_ENDIAN);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_INTC_NRTCWS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        mbim_dissect_nrtcws_config(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                    }
                                } else {
                                    mbim_dissect_nrtcws_info(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_USB_PROFILE:
                        switch (cid) {
                            case MBIM_CID_INTC_USBPROFILE:
                                if ((msg_type == MBIM_COMMAND_DONE) && ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) || info_buff_len)) {
                                    guint32 at_len;

                                    proto_tree_add_item_ret_uint(subtree, hf_mbim_usbprofile_rsp_length, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN, &at_len);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_usbprofile_rsp_buffer, frag_tvb, offset, at_len, ENC_LITTLE_ENDIAN|ENC_UTF_16);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_INTEL_CIQ:
                        switch (cid) {
                            case MBIM_CID_INTC_CIQ:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        proto_tree_add_item(subtree, hf_mbim_ciq_info_mode, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_ATDS:
                        switch (cid) {
                            case MBIM_CID_ATDS_SIGNAL:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_atds_signal_info(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_ATDS_LOCATION:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        proto_tree_add_item(subtree, hf_mbim_atds_location_info_lac, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                        offset += 4;
                                        proto_tree_add_item(subtree, hf_mbim_atds_location_info_tac, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                        offset += 4;
                                        proto_tree_add_item(subtree, hf_mbim_atds_location_info_cellid, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_ATDS_OPERATORS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        mbim_dissect_atds_operators(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_ATDS_RAT:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        proto_tree_add_item(subtree, hf_mbim_atds_rat_info_mode, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_ATDS_REGISTER_STATE:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_registration_state_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_ATDS_SET_PROJECTION_TABLES:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET) && info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    } else if ((mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) || info_buff_len) {
                                        mbim_dissect_atds_projection_tables(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MULTIFLOW:
                        switch (cid) {
                            case MBIM_CID_MULTIFLOW_CAPS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        proto_tree_add_bitmask(subtree, frag_tvb, offset, hf_mbim_multiflow_caps_info_control_caps,
                                                               ett_mbim_bitmap, mbim_multiflow_caps_info_control_caps_fields, ENC_LITTLE_ENDIAN);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTIFLOW_UPLINK:
                            case MBIM_CID_MULTIFLOW_DOWNLINK:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_multiflow_state_info_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, info_buff_len);
                                }
                                break;
                            case MBIM_CID_MULTIFLOW_TFT:
                                if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_multiflow_tft_info(frag_tvb, pinfo, subtree, offset);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_BASIC_CONNECT_EXTENSIONS:
                        switch (cid) {
                            case MBIM_CID_MS_PROVISIONED_CONTEXT_V2:
                                mbim_dissect_ms_provisioned_context_info_v2(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                break;
                            case MBIM_CID_MS_NETWORK_BLACKLIST:
                                mbim_dissect_ms_network_blacklist_info(pinfo, frag_tvb, subtree, offset);
                                break;
                            case MBIM_CID_MS_LTE_ATTACH_CONFIG:
                            case MBIM_CID_MS_LTE_ATTACH_STATUS:
                                proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                break;
                            case MBIM_CID_MS_SYS_CAPS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_sys_caps_info(frag_tvb, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_DEVICE_CAPS_V2:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        if (SHOULD_MBIM_EX3_AND_HIGHER_BE_APPLIED(mbim_conv)) {
                                            mbim_dissect_device_caps_v3_and_higher_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                        } else {
                                            mbim_dissect_device_caps_v2_info(frag_tvb, pinfo, subtree, offset, mbim_conv);
                                        }
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_DEVICE_SLOT_MAPPINGS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_ms_device_slot_mapping_info(frag_tvb, pinfo, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_SLOT_INFO_STATUS:
                                if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_ms_slot_info_slot_index, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                    offset += 4;
                                    proto_tree_add_item(subtree, hf_mbim_ms_slot_info_state, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                }
                                break;
                            case MBIM_CID_PCO:
                                proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                break;
                            case MBIM_CID_MS_DEVICE_RESET:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_QUERY)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else if (info_buff_len) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_BASE_STATIONS_INFO:
                                if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    mbim_dissect_base_station_info(frag_tvb, subtree, offset, mbim_conv);
                                }
                                break;
                            case MBIM_CID_LOCATION_INFO_STATUS:
                                if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                } else {
                                    proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                                }
                                break;
                            case MBIM_CID_MS_PIN_INFO_EX2:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                            case MBIM_CID_VERSION:
                                if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                else if (info_buff_len) {
                                    mbim_dissect_version(frag_tvb, subtree, offset, mbim_conv);
                                }
                                break;
                            case MBIM_CID_MS_MODEM_CONFIG:
                                mbim_dissect_ms_modem_config_info(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                break;
                            case MBIM_CID_MS_REGISTRATION_PARAMS:
                                mbim_dissect_ms_registration_params_info(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                break;
                            case MBIM_CID_MS_NETWORK_PARAMS:
                                mbim_dissect_ms_network_params_info(frag_tvb, pinfo, subtree, offset, info_buff_len);
                                break;
                            case MBIM_CID_MS_UE_POLICY:
                                mbim_dissect_tlv_ie_list(frag_tvb, pinfo, subtree, offset, offset, info_buff_len);
                                break;
                            case MBIM_CID_MS_WAKE_REASON:
                                mbim_dissect_ms_wake_reason(frag_tvb, pinfo, subtree, offset);
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_SARCONTROL:
                        switch (cid) {
                            case MBIM_CID_MS_SAR_CONFIG:
                                mbim_dissect_ms_sar_config(frag_tvb, pinfo, subtree, offset, TRUE);
                                break;
                            case MBIM_CID_MS_TRANSMISSION_STATUS:
                                mbim_dissect_ms_transmission_status(frag_tvb, subtree, offset, TRUE);
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_MS_UICC_LOW_LEVEL:
                        switch (cid) {
                            case MBIM_CID_MS_UICC_ATR:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_ms_atr_info(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_OPEN_CHANNEL:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_ms_open_channel_info(frag_tvb, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_CLOSE_CHANNEL:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_ms_uicc_status, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_APDU:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_ms_apdu_info(frag_tvb, subtree, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_TERMINAL_CAPABILITY:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    mbim_dissect_ms_terminal_capability_info(frag_tvb, pinfo, subtree, offset, offset);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_RESET:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    proto_tree_add_item(subtree, hf_mbim_ms_reset_pass_through_action, frag_tvb, offset, 4, ENC_LITTLE_ENDIAN);
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_APP_LIST:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_ms_app_list(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            case MBIM_CID_MS_UICC_ACCESS_BINARY:
                                mbim_dissect_ms_response(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_MS_UICC_ACCESS_RECORD:
                                mbim_dissect_ms_response(frag_tvb, pinfo, subtree, offset);
                                break;
                            case MBIM_CID_MS_UICC_FILE_STATUS:
                                if (msg_type == MBIM_COMMAND_DONE) {
                                    if (mbim_info && (mbim_info->cmd_type == MBIM_COMMAND_SET)) {
                                        proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                    } else {
                                        mbim_dissect_ms_file_status(frag_tvb, pinfo, subtree, offset);
                                    }
                                } else {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                }
                                break;
                            default:
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                                break;
                        }
                        break;
                    case UUID_EXT_IDX:
                        {
                            gint cid_idx;
                            mbim_dissect_fct dissect_cid;

                            try_val_to_str_idx(cid, uuid_ext_info->uuid_cid_list, &cid_idx);
                            if (cid_idx != -1) {
                                dissect_cid = (msg_type == MBIM_COMMAND_DONE) ? uuid_ext_info->uuid_fct_list[cid_idx].cmd_done :
                                    uuid_ext_info->uuid_fct_list[cid_idx].ind_status;
                                if (dissect_cid) {
                                    dissect_cid(frag_tvb, pinfo, subtree, offset, mbim_info);
                                } else if (info_buff_len) {
                                    proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_info_buffer, frag_tvb, offset, info_buff_len);
                                }
                            } else {
                                proto_tree_add_expert(subtree, pinfo, &ei_mbim_unexpected_msg, frag_tvb, offset, -1);
                            }
                        }
                        break;
                    default:
                        proto_tree_add_item(subtree, hf_mbim_info_buffer, frag_tvb, offset, info_buff_len, ENC_NA);
                        break;
                }
            }
            break;
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_mbim_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    guint8 length, type, subtype;

    length = tvb_get_guint8(tvb, 0);
    type = tvb_get_guint8(tvb, 1);
    subtype = tvb_get_guint8(tvb, 2);

    if ((type != 0x24) ||
        !(((subtype == 0x1b) && (length == 12)) || ((subtype == 0x1c) && (length == 8)))){
        return 0;
    }

    ti = proto_tree_add_item(tree, hf_mbim_descriptor, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(ti);

    if (subtype == 0x1b) {
        proto_tree_add_item(tree, hf_mbim_descriptor_version, tvb, 3, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_mbim_descriptor_max_control_message, tvb, 5, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_mbim_descriptor_number_filters, tvb, 7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mbim_descriptor_max_filter_size, tvb, 8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mbim_descriptor_max_segment_size, tvb, 9, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, 11, hf_mbim_descriptor_network_capabilities, ett_mbim_bitmap,
                               mbim_descriptor_network_capabilities_fields, ENC_NA);
    } else {
        proto_tree_add_item(tree, hf_mbim_descriptor_extended_version, tvb, 3, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_mbim_descriptor_max_outstanding_command_messages, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_mbim_descriptor_mtu, tvb, 6, 2, ENC_LITTLE_ENDIAN);
    }

    return length;
}

static int
dissect_mbim_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *sig_ti, *pi;
    proto_tree *mbim_tree, *subtree, *sig_tree;
    gboolean is_32bits;
    guint32 nth_sig, length, next_index, base_offset, offset, datagram_index, datagram_length,
            nb, total = 0, ndp = 0, block_len, dss_session_id;
    const char *signature;
    dissector_handle_t dissector;
    tvbuff_t *datagram_tvb;
    const guint32 NTH16 = 0x484D434E;
    const guint32 NTH32 = 0x686D636E;
    guint reported_length;

    if (tvb_captured_length(tvb) < 12) {
        return 0;
    }

    nth_sig = tvb_get_letohl(tvb, 0);
    if (nth_sig == NTH16) {
        is_32bits = FALSE;
    } else if (nth_sig == NTH32) {
        is_32bits = TRUE;
    } else {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MBIM");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_mbim, tvb, 0, -1, ENC_NA);
    mbim_tree = proto_item_add_subtree(ti, ett_mbim);
    ti =proto_tree_add_item(mbim_tree, hf_mbim_bulk, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(ti);

    subtree = proto_tree_add_subtree(mbim_tree, tvb, 0, 0, ett_mbim_msg_header, NULL, "NCM Transfer Header");
    proto_tree_add_item(subtree, hf_mbim_bulk_nth_signature, tvb, 0, 4, ENC_ASCII);
    proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_nth_header_length, tvb, 4, 2, ENC_LITTLE_ENDIAN, &length);
    proto_item_set_len(ti, length);
    proto_tree_add_item(subtree, hf_mbim_bulk_nth_sequence_number, tvb, 6, 2, ENC_LITTLE_ENDIAN);
    if (!is_32bits) {
        ti = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_nth_block_length, tvb, 8, 2, ENC_LITTLE_ENDIAN, &block_len);
        pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_nth_ndp_index, tvb, 10, 2, ENC_LITTLE_ENDIAN, &next_index);
    } else {
        ti = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_nth_block_length_32, tvb, 8, 4, ENC_LITTLE_ENDIAN, &block_len);
        pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_nth_ndp_index_32, tvb, 12, 4, ENC_LITTLE_ENDIAN, &next_index);
    }
    reported_length = tvb_reported_length(tvb);
    if (block_len != reported_length) {
        expert_add_info(pinfo, ti, &ei_mbim_invalid_block_len);
    }
    if (next_index % 4) {
        expert_add_info_format(pinfo, pi, &ei_mbim_alignment_error,
                               "NDP Index is not a multiple of 4 bytes");
        return tvb_captured_length(tvb);
    }
    if (next_index > reported_length) {
        expert_add_info(pinfo, pi, &ei_mbim_out_of_bounds_index);
        return tvb_captured_length(tvb);
    }

    while (next_index) {
        base_offset = offset = next_index;
        nb = 0;
        subtree = proto_tree_add_subtree(mbim_tree, tvb, offset, 0, ett_mbim_msg_header, NULL, "NCM Datagram Pointer");
        signature = (const char*)tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
        if ((!is_32bits && !strncmp(signature, "IPS", 3)) ||
            (is_32bits && !strncmp(signature, "ips", 3))) {
            sig_ti = proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset,
                                                      4, tvb_get_letohl(tvb, offset), "%c%c%c%u", signature[0],
                                                      signature[1], signature[2], signature[3]);
            sig_tree = proto_item_add_subtree(sig_ti, ett_mbim_msg_header);
            proto_tree_add_item(sig_tree, hf_mbim_bulk_ndp_signature_ips_session_id, tvb, offset+3, 1, ENC_NA);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%c%c%c%u", signature[0], signature[1],
                                signature[2], signature[3]);
            dissector = ip_handle;
        } else if ((!is_32bits && !strncmp(signature, "IPC", 3)) ||
                   (is_32bits && !strncmp(signature, "ipc", 3))) {
            sig_ti = proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset,
                                                      4, tvb_get_letohl(tvb, offset), "%c%c%c%u", signature[0],
                                                      signature[1], signature[2], signature[3]);
            sig_tree = proto_item_add_subtree(sig_ti, ett_mbim_msg_header);
            proto_tree_add_item(sig_tree, hf_mbim_bulk_ndp_signature_ipc_session_id, tvb, offset+3, 1, ENC_NA);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%c%c%c%u", signature[0], signature[1],
                                signature[2], signature[3]);
            dissector = bulk_ndp_ctrl_handle;
        } else if ((!is_32bits && !strncmp(signature, "DSS", 3)) ||
                   (is_32bits && !strncmp(signature, "dss", 3))) {
            sig_ti = proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset,
                                                      4, tvb_get_letohl(tvb, offset), "%c%c%c%u", signature[0],
                                                      signature[1], signature[2], signature[3]);
            sig_tree = proto_item_add_subtree(sig_ti, ett_mbim_msg_header);
            proto_tree_add_item_ret_uint(sig_tree, hf_mbim_bulk_ndp_signature_dss_session_id,
                                         tvb, offset+3, 1, ENC_LITTLE_ENDIAN, &dss_session_id);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%c%c%c%u", signature[0], signature[1],
                                signature[2], signature[3]);
            dissector = dissector_get_uint_handle(dss_dissector_table, dss_session_id);
            if (dissector == NULL) {
                dissector = data_handle;
            }
        } else if ((!is_32bits && !strncmp(signature, "DSC", 3)) ||
                   (is_32bits && !strncmp(signature, "dsc", 3))) {
            sig_ti = proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset,
                                                      4, tvb_get_letohl(tvb, offset), "%c%c%c%u", signature[0],
                                                      signature[1], signature[2], signature[3]);
            sig_tree = proto_item_add_subtree(sig_ti, ett_mbim_msg_header);
            proto_tree_add_item(sig_tree, hf_mbim_bulk_ndp_signature_dsc_session_id, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%c%c%c%u", signature[0], signature[1],
                                signature[2], signature[3]);
            dissector = bulk_ndp_ctrl_handle;
        } else if ((!is_32bits && !strcmp(signature, "NCM0")) ||
                   (is_32bits && !strcmp(signature, "ncm0"))) {
            proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset, 4,
                                             tvb_get_letohl(tvb, offset), "%s", signature);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, signature);
            dissector = eth_handle;
        } else if ((!is_32bits && !strcmp(signature, "NCM1")) ||
                   (is_32bits && !strcmp(signature, "ncm1"))) {
            proto_tree_add_uint_format_value(subtree, hf_mbim_bulk_ndp_signature, tvb, offset, 4,
                                             tvb_get_letohl(tvb, offset), "%s", signature);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, signature);
            dissector = eth_fcs_handle;
        } else {
            proto_tree_add_item(subtree, hf_mbim_bulk_ndp_signature, tvb, offset, 4, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "0x%08X", tvb_get_ntohl(tvb, offset));
            dissector = data_handle;
        }
        offset += 4;
        pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
        if (length % (is_32bits ? 8 : 4)) {
            expert_add_info_format(pinfo, pi, &ei_mbim_alignment_error, "Length is not a multiple of %u bytes",
                                   is_32bits ? 8 : 4);
            return tvb_captured_length(tvb);
        }
        proto_item_set_len(ti, length);
        offset += 2;
        if (!is_32bits) {
            pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_next_ndp_index, tvb,
                                              offset, 2, ENC_LITTLE_ENDIAN, &next_index);
            offset += 2;
        } else {
            proto_tree_add_item(subtree, hf_mbim_bulk_ndp_reserved, tvb,
                                offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_next_ndp_index_32,
                                              tvb, offset, 4, ENC_LITTLE_ENDIAN, &next_index);
            offset += 4;
            proto_tree_add_item(subtree, hf_mbim_bulk_ndp_reserved2, tvb,
                                offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        if (next_index % 4) {
            expert_add_info_format(pinfo, pi, &ei_mbim_alignment_error,
                                   "NDP Index is not a multiple of 4 bytes");
            return tvb_captured_length(tvb);
        }
        if (next_index > reported_length) {
            expert_add_info(pinfo, pi, &ei_mbim_out_of_bounds_index);
            return tvb_captured_length(tvb);
        }
        while ((offset - base_offset) < length) {
            if (!is_32bits) {
                pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_datagram_index, tvb,
                                                  offset, 2, ENC_LITTLE_ENDIAN, &datagram_index);
                offset += 2;
                proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_datagram_length, tvb,
                                             offset, 2, ENC_LITTLE_ENDIAN, &datagram_length);
                offset += 2;
            } else {
                pi = proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_datagram_index_32, tvb,
                                                  offset, 4, ENC_LITTLE_ENDIAN, &datagram_index);
                offset += 4;
                proto_tree_add_item_ret_uint(subtree, hf_mbim_bulk_ndp_datagram_length_32, tvb,
                                             offset, 4, ENC_LITTLE_ENDIAN, &datagram_length);
                offset += 4;
            }
            if (next_index > reported_length) {
                expert_add_info(pinfo, pi, &ei_mbim_out_of_bounds_index);
                return tvb_captured_length(tvb);
            }
            if (datagram_index && datagram_length) {
                proto_tree_add_item(subtree, hf_mbim_bulk_ndp_datagram, tvb,
                                    datagram_index, datagram_length, ENC_NA);
                datagram_tvb = tvb_new_subset_length(tvb, datagram_index, datagram_length);
                if (dissector) {
                    if (total) {
                        col_set_str(pinfo->cinfo, COL_PROTOCOL, "/");
                        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
                        col_set_str(pinfo->cinfo, COL_INFO, " | ");
                        col_set_fence(pinfo->cinfo, COL_INFO);
                    }
                    call_dissector(dissector, datagram_tvb, pinfo, tree);
                }
                col_set_fence(pinfo->cinfo, COL_PROTOCOL);
                col_set_fence(pinfo->cinfo, COL_INFO);
                nb++;
                if (++total > MBIM_MAX_ITEMS) {
                    expert_add_info_format(pinfo, NULL, &ei_mbim_too_many_items,
                                           "More than %u datagrams, dissection seems suspicious",
                                           MBIM_MAX_ITEMS);
                    return tvb_captured_length(tvb);
                }
             }
        }
        ti = proto_tree_add_uint(subtree, hf_mbim_bulk_ndp_nb_datagrams, tvb, 0, 0, nb);
        proto_item_set_generated(ti);
        if (++ndp > MBIM_MAX_ITEMS) {
            expert_add_info_format(pinfo, NULL, &ei_mbim_too_many_items,
                                   "More than %u NCM Datagram Pointers, dissection seems suspicious",
                                   MBIM_MAX_ITEMS);
            return tvb_captured_length(tvb);
        }
    }
    ti = proto_tree_add_uint(mbim_tree, hf_mbim_bulk_total_nb_datagrams, tvb, 0, 0, total);
    proto_item_set_generated(ti);

    return tvb_captured_length(tvb);
}

static gboolean
dissect_mbim_bulk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;

    if ((usb_conv_info == NULL) ||
        ((usb_conv_info->interfaceClass != IF_CLASS_CDC_DATA) &&
        (usb_conv_info->interfaceClass != IF_CLASS_UNKNOWN))) {
        return FALSE;
    }

    if (dissect_mbim_bulk(tvb, pinfo, tree, usb_conv_info)) {
        return TRUE;
    }
    return FALSE;
}

static int
dissect_mbim_decode_as(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;

    if (!data || (tvb_reported_length(tvb) == 0)) {
        return 0;
    }

    usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info = usb_conv_info->usb_trans_info;

    switch (usb_conv_info->transfer_type) {
        case URB_CONTROL:
            if (!usb_trans_info) {
                return dissect_mbim_control(tvb, pinfo, tree, usb_conv_info);
            } else if ((usb_trans_info->setup.request == 0x00) && (pinfo->srcport == NO_ENDPOINT)) {
                /* Skip Send Encapsulated Command header */
                tvbuff_t *mbim_tvb = tvb_new_subset_remaining(tvb, 7);
                return dissect_mbim_control(mbim_tvb, pinfo, tree, usb_conv_info);
            } else if ((usb_trans_info->setup.request == 0x01) && (pinfo->srcport != NO_ENDPOINT)) {
                return dissect_mbim_control(tvb, pinfo, tree, usb_conv_info);
            }
            break;
        case URB_BULK:
            return dissect_mbim_bulk(tvb, pinfo, tree, usb_conv_info);
        default:
            break;
    }
    return 0;
}

static int
dissect_mbim_bulk_ndp_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *ndp_ctrl_tree;
    proto_item *ti;
    gint offset = 0;
    guint32 msg_type, msg_len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MBIM NDP Control");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_protocol_format(tree, proto_mbim, tvb, 0, -1, "MBIM NDP Control");
    ndp_ctrl_tree = proto_item_add_subtree(ti, ett_mbim_bulk_ndp_ctrl);
    ti = proto_tree_add_item(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl, tvb, offset, 0, ENC_NA);
    proto_item_set_hidden(ti);

    proto_tree_add_item_ret_uint(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_message_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &msg_type);
    offset += 2;
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(msg_type, mbim_ndp_ctrl_msg_type_vals, "Unknown"));
    proto_tree_add_item_ret_uint(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_message_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &msg_len);
    offset += 2;

    switch (msg_type) {
        case MBIM_NDP_CTRL_MULTIFLOW_STATUS:
            {
                guint32 watermark;

                proto_tree_add_item(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_multiflow_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                watermark = tvb_get_letohl(tvb, offset);
                if (watermark == 0xffffffff) {
                    proto_tree_add_uint_format_value(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_multiflow_watermark, tvb, offset, 4,
                                                     watermark, "Not reported (0xffffffff)");
                } else {
                    proto_tree_add_uint_format_value(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_multiflow_watermark, tvb, offset, 4,
                                                     watermark, "%u payload bytes", watermark);
                }
            }
            break;
        default:
            proto_tree_add_item(ndp_ctrl_tree, hf_mbim_bulk_ndp_ctrl_message_payload, tvb, offset, msg_len-4, ENC_NA);
            break;
    }
    return tvb_captured_length(tvb);
}

static guint
mbim_uuid_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, 4*sizeof(guint32));
}

static gboolean
mbim_uuid_equal(gconstpointer v1, gconstpointer v2)
{
    const guint32 *uuid1 = (const guint32*)v1;
    const guint32 *uuid2 = (const guint32*)v2;

    return ((uuid1[0] == uuid2[0]) &&
            (uuid1[1] == uuid2[1]) &&
            (uuid1[2] == uuid2[2]) &&
            (uuid1[3] == uuid2[3]));
}

void mbim_register_uuid_ext(struct mbim_uuid_ext *uuid_ext)
{
    guint32 *uuid_key;

    if (!mbim_uuid_ext_hash) {
        mbim_uuid_ext_hash = wmem_map_new(wmem_epan_scope(), mbim_uuid_hash, mbim_uuid_equal);
    }

    uuid_key = (guint32 *)wmem_alloc(wmem_epan_scope(), 4*sizeof(guint32));
    memcpy(uuid_key, uuid_ext->uuid, 4*sizeof(guint32));
    wmem_map_insert(mbim_uuid_ext_hash, uuid_key, uuid_ext);
}

void
proto_register_mbim(void)
{
    module_t *mbim_module;
    expert_module_t* expert_mbim;

    static hf_register_info hf[] = {
        { &hf_mbim_control,
            { "Control", "mbim.control",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_header_message_type,
            { "Message Type", "mbim.control.header.message_type",
               FT_UINT32, BASE_HEX, VALS(mbim_msg_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_header_message_length,
            { "Message Length", "mbim.control.header.message_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_header_transaction_id,
            { "Transaction Id", "mbim.control.header.transaction_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_total,
            { "Total Fragments", "mbim.control.fragment.total",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_current,
            { "Current Fragment", "mbim.control.fragment.current",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_max_ctrl_transfer,
            { "Max Control Transfer", "mbim.control.max_control_transfer",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_id,
            { "Device Service Id", "mbim.control.device_service_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_basic_connect_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &mbim_uuid_basic_connect_cid_vals_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_sms_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_sms_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_ussd_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_ussd_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_phonebook_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_phonebook_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_stk_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_stk_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_auth_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_auth_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_dss_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_dss_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_multicarrier_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_multicarrier_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_ms_hostshutdown_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_ms_hostshutdown_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_msfwid_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_msfwid_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_qmi_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_qmi_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_fwusvc_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_fwusvc_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_dptf_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_dptf_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_sar_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_sar_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_act_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_act_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_trcsvc_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_trcsvc_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_nrtc_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_nrtc_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_usb_profile_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_usb_profile_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_intel_ciq_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_intel_ciq_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_atds_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_atds_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_multiflow_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_multiflow_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_basic_connect_extensions_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_basic_connect_extensions_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_ms_sarcontrol_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_ms_sarcontrol_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_uuid_ms_uicc_low_level_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_ms_uicc_low_level_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_cid,
            { "CID", "mbim.control.cid",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_command_type,
            { "Command Type", "mbim.control.command_type",
               FT_UINT32, BASE_DEC, VALS(mbim_command_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_info_buffer_len,
            { "Information Buffer Length", "mbim.control.info_buffer_len",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_info_buffer,
            { "Information Buffer", "mbim.control.info_buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_error_status_code,
            { "Error Status Code", "mbim.control.error_status_code",
               FT_UINT32, BASE_DEC, VALS(mbim_error_status_code_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_status,
            { "Status", "mbim.control.status",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &mbim_status_code_vals_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_type,
            { "Type", "mbim.control.tlv_ie.type",
               FT_UINT16, BASE_DEC, VALS(mbim_tlv_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_reserved,
            { "Reserved", "mbim.control.tlv_ie.reserved",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_padding_length,
            { "Padding Length", "mbim.control.tlv_ie.padding_length",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_data_length,
            { "Data Length", "mbim.control.tlv_ie.data_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_unnamed_data,
            { "Data", "mbim.control.tlv_ie.unnamed_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_data_wchar_str,
            { "Data", "mbim.control.tlv_ie.wchar_str_data",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_data_int32,
            { "Data", "mbim.control.tlv_ie.int32_data",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_data_guid,
            { "Data", "mbim.control.tlv_ie.guid_data",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_tlv_ie_padding,
            { "Padding", "mbim.control.tlv_ie.padding",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_length,
            { "Length", "mbim.control.ursp.tc_length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_precedence,
            { "Precedence", "mbim.control.ursp.precedence",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_type,
            { "Type", "mbim.control.ursp.tc_type",
               FT_UINT8, BASE_DEC, VALS(ursp_tc_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_os_id,
            { "Os Id", "mbim.control.ursp.tc_os_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_dnn,
            { "DNN", "mbim.control.ursp.tc_dnn",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_fqdn,
            { "FQDN", "mbim.control.ursp.tc_fqdn",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_ipv4,
            { "IPv4 Address", "mbim.control.ursp.tc_ipv4",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_ipv4_mask,
            { "IPv4 Mask", "mbim.control.ursp.tc_ipv4_mask",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_ipv6,
            { "IPv6 Address", "mbim.control.ursp.tc_ipv6",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_ipv6_prefix_length,
            { "IPv6 Prefix Length", "mbim.control.ursp.tc_ipv6_prefix_length",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_proto_id,
            { "Protocol Identifier", "mbim.control.ursp.tc_proto_id",
               FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_port,
            { "Port", "mbim.control.ursp.tc_port",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_port_range_low,
            { "Port Range Low", "mbim.control.ursp.tc_port_range_low",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_port_range_high,
            { "Port Range high", "mbim.control.ursp.tc_port_range_high",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_app_id,
            { "App Id", "mbim.control.ursp.tc_app_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_byte_value,
            { "Value", "mbim.control.ursp.tc_byte_value",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_capability,
            { "Capability", "mbim.control.ursp.tc_capability",
               FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_connection_capability_flag_ims,
            { "IMS", "mbim.control.ursp.tc_capability_ims",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_connection_capability_flag_mms,
            { "MMS", "mbim.control.ursp.tc_capability_mms",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_connection_capability_flag_supl,
            { "SUPL", "mbim.control.ursp.tc_capability_supl",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_ms_ursp_tc_connection_capability_flag_internet,
            { "Internet", "mbim.control.ursp.tc_capability_internet",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_ms_snssai_length,
            { "Length", "mbim.control.snssai.length",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_snssai_slice_service_type,
            { "SST", "mbim.control.snssai.sst",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_snssai_slice_differentiator,
            { "SD", "mbim.control.snssai.sd",
               FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_snssai_mapped_slice_service_type,
            { "Mapped SST", "mbim.control.snssai.mapped_sst",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_snssai_mapped_slice_differentiator,
            { "Mapped SD", "mbim.control.snssai.mapped_sd",
               FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_rej_snssai_cause,
            { "Rejected Cause", "mbim.control.rej_snssai.cause",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_pre_dflt_nssai_info_access_type,
            { "Access Type", "mbim.control.pre_dflt_nssai_info.access_type",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_pre_dflt_nssai_info_access_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_device_type,
            { "Device Type", "mbim.control.device_caps_info.device_type",
               FT_UINT32, BASE_DEC, VALS(mbim_device_caps_info_device_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_cellular_class,
            { "Cellular Class", "mbim.control.device_caps_info.cellular_class",
               FT_UINT32, BASE_DEC, VALS(mbim_cellular_class_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_voice_class,
            { "Voice Class", "mbim.control.device_caps_info.voice_class",
               FT_UINT32, BASE_DEC, VALS(mbim_device_caps_info_voice_class_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sim_class,
            { "SIM Class", "mbim.control.device_caps_info.sim_class",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sim_class_logical,
            { "Logical", "mbim.control.device_caps_info.sim_class.logical",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sim_class_removable,
            { "Removable", "mbim.control.device_caps_info.sim_class.removable",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_data_class,
            { "Data Class", "mbim.control.device_caps_info.data_class",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_gprs,
            { "GPRS", "mbim.control.data_class.gprs",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_edge,
            { "EDGE", "mbim.control.data_class.edge",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_umts,
            { "UMTS", "mbim.control.data_class.umts",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_hsdpa,
            { "HSDPA", "mbim.control.data_class.hsdpa",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_hsupa,
            { "HSUPA", "mbim.control.data_class.hsupa",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000010,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_lte,
            { "LTE", "mbim.control.data_class.lte",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000020,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_5g,
            { "5G", "mbim.control.data_class.5g",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000040,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_reserved_gsm,
            { "Reserved for future GSM classes", "mbim.control.data_class.reserved_gsm",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x0000ff80,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_1xrtt,
            { "1xRTT", "mbim.control.data_class.1xrtt",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00010000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_1xevdo,
            { "1xEV-DO", "mbim.control.data_class.1xevdo",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00020000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_1xevdoreva,
            { "1xEV-DO RevA", "mbim.control.data_class.1xevdoreva",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00040000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_1xevdv,
            { "1xEVDV", "mbim.control.data_class.1xevdv",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00080000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_3xrtt,
            { "3xRTT", "mbim.control.data_class.3xrtt",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00100000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_1xevdorevb,
            { "1xEV-DO RevB", "mbim.control.data_class.1xevdorevb",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00200000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_umb,
            { "UMB", "mbim.control.data_class.umb",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00400000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_reserved_cdma,
            { "Reserved for future CDMA classes", "mbim.control.data_class.reserved_cdma",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x7f800000,
              NULL, HFILL }
        },
        { &hf_mbim_data_class_custom,
            { "Custom", "mbim.control.data_class.custom",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x80000000,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sms_caps,
            { "SMS Caps", "mbim.control.device_caps_info.sms_caps",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sms_caps_pdu_receive,
            { "PDU Receive", "mbim.control.device_caps_info.sms_caps.pdu_receive",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sms_caps_pdu_send,
            { "PDU Send", "mbim.control.device_caps_info.sms_caps.pdu_send",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sms_caps_text_receive,
            { "Text Receive", "mbim.control.device_caps_info.sms_caps.text_receive",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_sms_caps_text_send,
            { "Text Send", "mbim.control.device_caps_info.sms_caps.text_send",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps,
            { "Control Caps", "mbim.control.device_caps_info.control_caps",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_reg_manual,
            { "Reg Manual", "mbim.control.device_caps_info.control_caps.reg_manual",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_hw_radio_switch,
            { "HW Radio Switch", "mbim.control.device_caps_info.control_caps.hw_radio_switch",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_cdma_mobile_ip,
            { "CDMA Mobile IP", "mbim.control.device_caps_info.control_caps.cdma_mobile_ip",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_cdma_simple_ip,
            { "CDMA Simple IP", "mbim.control.device_caps_info.control_caps.cdma_simple_ip",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_multi_carrier,
            { "Multi Carrier", "mbim.control.device_caps_info.control_caps.multi_carrier",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000010,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_esim,
            { "ESIM", "mbim.control.device_caps_info.control_caps.esim",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000020,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_ue_policy_route_selection,
            { "UE Policy Route Selection", "mbim.control.device_caps_info.control_caps.ue_policy_route_selection",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000040,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_sim_hot_swap_capable,
            { "Hot Swap Capable", "mbim.control.device_caps_info.control_caps.hot_swap_capable",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000080,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_control_caps_use_ursp_rule_on_epc_capable,
            { "Use URSP Rule On EPC Capable", "mbim.control.device_caps_info.control_caps.use_ursp_rule_on_epc_capable",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000100,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_max_sessions,
            { "Max Sessions", "mbim.control.device_caps_info.max_sessions",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_data_subclass,
            { "Data Subclass", "mbim.control.device_caps_info.data_subclass",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_data_subclass_5gendc,
            { "5G EN-DC", "mbim.control.data_subclass.5gendc",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_data_subclass_5gnr,
            { "5G NR", "mbim.control.data_subclass.5gnr",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_data_subclass_5gnedc,
            { "5G NE-DC", "mbim.control.data_subclass.5gnedc",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x0000004,
              NULL, HFILL }
        },
        { &hf_mbim_data_subclass_5gelte,
            { "5G eLTE", "mbim.control.data_subclass.5gelte",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_data_subclass_5gngendc,
            { "5G NG-EN-DC", "mbim.control.data_subclass.5gngendc",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000010,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_wcdma_band_class,
            { "WCDMA Band Class", "mbim.control.device_caps_info.wcdma_band_class",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_custom_data_class_offset,
            { "Custom Data Class Offset", "mbim.control.device_caps_info.custom_data_class.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_custom_data_class_size,
            { "Custom Data Class Size", "mbim.control.device_caps_info.custom_data_class.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_device_id_offset,
            { "Device Id Offset", "mbim.control.device_caps_info.device_id.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_device_id_size,
            { "Device Id Size", "mbim.control.device_caps_info.device_id.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_fw_info_offset,
            { "FW Info Offset", "mbim.control.device_caps_info.fw_info.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_fw_info_size,
            { "FW Info Size", "mbim.control.device_caps_info.fw_info.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_hw_info_offset,
            { "HW Info Offset", "mbim.control.device_caps_info.hw_info.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_hw_info_size,
            { "HW Info Size", "mbim.control.device_caps_info.hw_info.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_custom_data_class,
            { "Custom Data Class", "mbim.control.device_caps_info.custom_data_class",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_device_id,
            { "Device Id", "mbim.control.device_caps_info.device_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_fw_info,
            { "FW Info", "mbim.control.device_caps_info.fw_info",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_hw_info,
            { "HW Info", "mbim.control.device_caps_info.hw_info",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_caps_info_v2_executor_index,
            { "Executor Index", "mbim.control.device_caps_info.executor_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_ready_state,
            { "Ready State", "mbim.control.subscriber_ready_status.ready_state",
               FT_UINT32, BASE_DEC, VALS(mbim_subscr_ready_status_ready_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_flags,
            { "Flags", "mbim.control.subscriber_ready_status.flags",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_flag_esim,
            { "ESIM", "mbim.control.subscriber_ready_status.flags.esim",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_flag_sim_removability_known,
            { "SIM Removability Known", "mbim.control.subscriber_ready_status.flags.sim_removability_known",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_flag_sim_removable,
            { "SIM Removable", "mbim.control.subscriber_ready_status.flags.sim_removable",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_flag_sim_slot_active,
            { "SIM Slot Active", "mbim.control.subscriber_ready_status.flags.sim_slot_active",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_susbcr_id_offset,
            { "Subscriber Id Offset", "mbim.control.subscriber_ready_status.subscriber_id.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_susbcr_id_size,
            { "Subscriber Id Size", "mbim.control.subscriber_ready_status.subscriber_id.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_sim_icc_id_offset,
            { "SIM ICC Id Offset", "mbim.control.subscriber_ready_status.sim_icc_id.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_sim_icc_id_size,
            { "SIM ICC Id Size", "mbim.control.subscriber_ready_status.sim_icc_id.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_ready_info,
            { "Ready Info", "mbim.control.subscriber_ready_status.ready_info",
               FT_UINT32, BASE_DEC, VALS(mbim_subscr_ready_status_ready_info_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_elem_count,
            { "Element Count", "mbim.control.subscriber_ready_status.element_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_tel_nb_offset,
            { "Telephone Number Offset", "mbim.control.subscriber_ready_status.tel_nb.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_tel_nb_size,
            { "Telephone Number Size", "mbim.control.subscriber_ready_status.tel_nb.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_susbcr_id,
            { "Subscriber Id", "mbim.control.device_caps_info.subscriber_ready_status.subscriber_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_sim_icc_id,
            { "SIM ICC Id", "mbim.control.device_caps_info.subscriber_ready_status.sim_icc_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_subscr_ready_status_tel_nb,
            { "Telephone Number", "mbim.control.device_caps_info.subscriber_ready_status.tel_nb",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_radio_state_set,
            { "Radio Set", "mbim.control.radio_state.set",
               FT_UINT32, BASE_DEC, VALS(mbim_radio_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_radio_state_hw_radio_state,
            { "HW Radio State", "mbim.control.radio_state.hw_radio_state",
               FT_UINT32, BASE_DEC, VALS(mbim_radio_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_radio_state_sw_radio_state,
            { "SW Radio State", "mbim.control.radio_state.sw_radio_stat",
               FT_UINT32, BASE_DEC, VALS(mbim_radio_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_pin_type,
            { "PIN Type", "mbim.control.set_pin.pin_type",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_pin_pin_operation,
            { "PIN Operation", "mbim.control.set_pin.pin_operation",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_operation_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_pin_pin_offset,
            { "PIN Offset", "mbim.control.set_pin.pin.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_pin_pin_size,
            { "PIN Size", "mbim.control.set_pin.pin.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_new_pin_offset,
            { "New PIN Offset", "mbim.control.set_pin.new_pin.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_new_pin_size,
            { "New PIN Size", "mbim.control.set_pin.new_pin.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_pin,
            { "PIN", "mbim.control.set_pin.pin",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_pin_new_pin,
            { "New PIN", "mbim.control.set_pin.new_pin",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_info_pin_type,
            { "PIN Type", "mbim.control.pin_info.pin_type",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_info_pin_state,
            { "PIN State", "mbim.control.pin_info.pin_state",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_info_remaining_attempts,
            { "Remaining Attempts", "mbim.control.pin_info.remaining_attempts",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_list_pin_mode,
            { "PIN Mode", "mbim.control.pin_list.pin_mode",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_list_pin_format,
            { "PIN Format", "mbim.control.pin_list.pin_format",
               FT_UINT32, BASE_DEC, VALS(mbim_pin_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_list_pin_length_min,
            { "PIN Length Min", "mbim.control.pin_list.pin_length_min",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_pin_list_pin_length_max,
            { "PIN Length Max", "mbim.control.pin_list.pin_length_max",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state,
            { "Provider State", "mbim.control.provider_state",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_home,
            { "Home", "mbim.control.provider_state.home",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_forbidden,
            { "Forbidden", "mbim.control.provider_state.forbidden",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_preferred,
            { "Preferred", "mbim.control.provider_state.preferred",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_visible,
            { "Visible", "mbim.control.provider_state.visible",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_registered,
            { "Registered", "mbim.control.provider_state.registered",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
              NULL, HFILL }
        },
        { &hf_mbim_provider_state_preferred_multicarrier,
            { "Preferred Multicarrier", "mbim.control.provider_state.preferred_multicarrier",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_id_offset,
            { "Provider Id Offset", "mbim.control.provider.provider_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_id_size,
            { "Provider Id Size", "mbim.control.provider.provider_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_name_offset,
            { "Provider Name Offset", "mbim.control.provider.provider_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_name_size,
            { "Provider Name Size", "mbim.control.provider.provider_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_cellular_class,
            { "Cellular Class", "mbim.control.provider.cellular_class",
               FT_UINT32, BASE_DEC, VALS(mbim_cellular_class_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_rssi,
            { "RSSI", "mbim.control.provider.rssi",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rssi_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_error_rate,
            { "Error Rate", "mbim.control.provider.error_rate",
               FT_UINT32, BASE_DEC, VALS(mbim_error_rate_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_id,
            { "Provider Id", "mbim.control.provider.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provider_provider_name,
            { "Provider Name", "mbim.control.provider.provider_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_providers_elem_count,
            { "Element Count", "mbim.control.providers.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_providers_provider_offset,
            { "Provider Offset", "mbim.control.providers.provider_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_providers_provider_size,
            { "Provider Size", "mbim.control.providers.provider_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_visible_providers_req_action,
            { "Action", "mbim.control.visible_providers_req.action",
               FT_UINT32, BASE_DEC, VALS(mbim_visible_providers_action_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_register_state_provider_id_offset,
            { "Provider Id Offset", "mbim.control.set_register_state.provider_id.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_register_state_provider_id_size,
            { "Provider Id Size", "mbim.control.set_register_state.provider_id.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_register_state_register_action,
            { "Register Action", "mbim.control.set_register_state.register_action",
               FT_UINT32, BASE_DEC, VALS(mbim_register_action_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_register_state_data_class,
            { "Data Class", "mbim.control.set_register_state.data_class",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_register_state_provider_id,
            { "Provider Id", "mbim.control.set_register_state.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_nw_error,
            { "Network Error", "mbim.control.registration_state_info.nw_error",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nas_eps_emm_cause_values_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_register_state,
            { "Register State", "mbim.control.registration_state_info.register_state",
               FT_UINT32, BASE_DEC, VALS(mbim_register_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_register_mode,
            { "Register Mode", "mbim.control.registration_state_info.register_mode",
               FT_UINT32, BASE_DEC, VALS(mbim_register_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_available_data_classes,
            { "Available Data Classes", "mbim.control.registration_state_info.available_data_classes",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_current_cellular_class,
            { "Current Cellular Class", "mbim.control.registration_state_info.current_cellular_class",
               FT_UINT32, BASE_DEC, VALS(mbim_cellular_class_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_id_offset,
            { "Provider Id Offset", "mbim.control.registration_state_info.provider_id.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_id_size,
            { "Provider Id Size", "mbim.control.registration_state_info.provider_id.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_name_offset,
            { "Provider Name Offset", "mbim.control.registration_state_info.provider_name.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_name_size,
            { "Provider Name Size", "mbim.control.registration_state_info.provider_name.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_roaming_text_offset,
            { "Roaming Text Offset", "mbim.control.registration_state_info.roaming_text.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_roaming_text_size,
            { "Roaming Text Size", "mbim.control.registration_state_info.roaming_text.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_registration_flags,
            { "Registration Flags", "mbim.control.registration_state_info.registration_flags",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_registration_flags_manual_selection_not_available,
            { "Manual Selection Not Available", "mbim.control.registration_state_info.registration_flags.manual_selection_not_available",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_registration_flags_packet_service_auto_attach,
            { "Packet Service Auto Attach", "mbim.control.registration_state_info.registration_flags.packet_service_auto_attach",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_preferred_data_class,
            { "Preferred Data Class", "mbim.control.registration_state_info.preferred_data_class",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_id,
            { "Provider Id", "mbim.control.registration_state_info.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_provider_name,
            { "Provider Name", "mbim.control.registration_state_info.provider_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_registration_state_info_roaming_text,
            { "Roaming Text", "mbim.control.registration_state_info.roaming_text",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_packet_service_action,
            { "Action", "mbim.control.set_packet_service.action",
               FT_UINT32, BASE_DEC, VALS(mbim_packet_service_action_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_plmn_mcc,
            { "Mobile Country Code", "mbim.control.ms_plmn.mcc",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_plmn_mnc,
            { "Mobile Network Code", "mbim.control.ms_plmn.mnc",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_tai_tac,
            { "Tracking Area Code", "mbim.control.ms_tai.tac",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_tai_list_type,
            { "TAI List Type", "mbim.control.ms_tai.list_type",
               FT_UINT8, BASE_DEC, VALS(mbim_tai_list_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_tai_list_single_plmn_tac_element,
            { "TAC Element", "mbim.control.ms_tai.tac_element",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_tai_list_multi_plmn_tai_element,
            { "TAI Element", "mbim.control.ms_tai.tai_element",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_nw_error,
            { "Network Error", "mbim.control.packet_service_info.nw_error",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nas_eps_emm_cause_values_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_packet_service_state,
            { "Packet Service State", "mbim.control.packet_service_info.packet_service_state",
               FT_UINT32, BASE_DEC, VALS(mbim_packet_service_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_highest_available_data_class,
            { "Highest Available Data Class", "mbim.control.packet_service_info.highest_available_data_class",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_current_data_class,
            { "Current Data Class", "mbim.control.packet_service_info.current_data_class",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_uplink_speed,
            { "Uplink Speed", "mbim.control.packet_service_info.uplink_speed",
               FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_downlink_speed,
            { "Downlink Speed", "mbim.control.packet_service_info.downlink_speed",
               FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_frequency_range,
            { "Frequency Range", "mbim.control.packet_service_info.frequency_range",
               FT_UINT32, BASE_DEC, VALS(mbim_packet_service_info_frequency_range_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_service_info_data_subclass,
            { "Data Subclass", "mbim.control.packet_service_info.data_subclass",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_signal_state_signal_strength_interval,
            { "Signal Strength Interval", "mbim.control.set_signal_state.signal_strength_interval",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_signal_state_rssi_threshold,
            { "RSSI Threshold", "mbim.control.set_signal_state.rssi_threshold",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_signal_state_error_rate_threshold,
            { "Error Rate Threshold", "mbim.control.set_signal_state.error_rate_threshold",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_element_rsrp,
            { "RSRP", "mbim.control.signal_state_element.rsrp",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rsrp_signal_state_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_element_snr,
            { "SNR", "mbim.control.signal_state_element.snr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_snr_signal_state_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_element_rsrp_threshold,
            { "RSRP Threshold", "mbim.control.signal_state_element.rsrp_threshold",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_element_snr_threshold,
            { "SNR Threshold", "mbim.control.signal_state_element.snr_threshold",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_element_system_type,
            { "System Type", "mbim.control.signal_state_element.system_type",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_rssi,
            { "RSSI", "mbim.control.signal_state_info.rssi",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rssi_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_error_rate,
            { "Error Rate", "mbim.control.signal_state_info.error_rate",
               FT_UINT32, BASE_DEC, VALS(mbim_error_rate_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_signal_strength_interval,
            { "Signal Strength Interval", "mbim.control.signal_state_info.signal_strength_interval",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_rssi_threshold,
            { "RSSI Threshold", "mbim.control.signal_state_info.rssi_threshold",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_error_rate_threshold,
            { "Error Rate Threshold", "mbim.control.signal_state_info.error_rate_threshold",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_rsrp_snr_offset,
            { "Rsrp Snr Offset", "mbim.control.signal_state_info.rsrp_snr_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_rsrp_snr_size,
            { "Rsrp Snr Size", "mbim.control.signal_state_info.rsrp_snr_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_signal_state_info_elem_count,
            { "Element Count", "mbim.control.signal_state_info.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_type,
            { "Context Type", "mbim.control.context_type",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_session_id,
            { "Session Id", "mbim.control.set_connect.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_activation_command,
            { "Activation Command", "mbim.control.set_connect.activation_command",
               FT_UINT32, BASE_DEC, VALS(mbim_activation_command_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_activation_option,
            { "Activation Option", "mbim.control.set_connect.activation_option",
               FT_UINT32, BASE_DEC, VALS(mbim_activation_option_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_access_string_offset,
            { "Access String Offset", "mbim.control.set_connect.access_string_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_access_string_size,
            { "Access String Size", "mbim.control.set_connect.access_string_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_user_name_offset,
            { "User Name Offset", "mbim.control.set_connect.user_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_user_name_size,
            { "User Name Size", "mbim.control.set_connect.user_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_password_offset,
            { "Password Offset", "mbim.control.set_connect.password_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_password_size,
            { "Password Size", "mbim.control.set_connect.password_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_compression,
            { "Compression", "mbim.control.set_connect.compression",
               FT_UINT32, BASE_DEC, VALS(mbim_compression_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_auth_protocol,
            { "Authentication Protocol", "mbim.control.set_connect.auth_protocol",
               FT_UINT32, BASE_DEC, VALS(mbim_auth_protocol_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_ip_type,
            { "IP Type", "mbim.control.set_connect.ip_type",
               FT_UINT32, BASE_DEC, VALS(mbim_context_ip_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_access_string,
            { "Access String", "mbim.control.set_connect.access_string",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_user_name,
            { "User Name", "mbim.control.set_connect.user_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_password,
            { "Password", "mbim.control.set_connect.password",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_connect_media_preference,
            { "Media Preference", "mbim.control.set_connect.media_preference",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_session_id,
            { "Session Id", "mbim.control.connect_info.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_activation_state,
            { "Activation State", "mbim.control.connect_info.activation_state",
               FT_UINT32, BASE_DEC, VALS(mbim_activation_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_voice_call_state,
            { "Voice Call State", "mbim.control.connect_info.voice_call_state",
               FT_UINT32, BASE_DEC, VALS(mbim_voice_call_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_ip_type,
            { "IP Type", "mbim.control.connect_info.ip_type",
               FT_UINT32, BASE_DEC, VALS(mbim_context_ip_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_nw_error,
            { "Network Error", "mbim.control.connect_info.nw_error",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nas_eps_emm_cause_values_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_connect_info_access_media,
            { "Access Media", "mbim.control.connect_info.access_media",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_context_id,
            { "Context Id", "mbim.control.context.context_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_access_string_offset,
            { "Access String Offset", "mbim.control.context.access_string_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_access_string_size,
            { "Access String Size", "mbim.control.context.access_string_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_user_name_offset,
            { "User Name Offset", "mbim.control.context.user_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_user_name_size,
            { "User Name Size", "mbim.control.context.user_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_password_offset,
            { "Password Offset", "mbim.control.context.password_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_password_size,
            { "Password Size", "mbim.control.context.password_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_compression,
            { "Compression", "mbim.control.context.compression",
               FT_UINT32, BASE_DEC, VALS(mbim_compression_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_auth_protocol,
            { "Authentication Protocol", "mbim.control.context.auth_protocol",
               FT_UINT32, BASE_DEC, VALS(mbim_auth_protocol_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_provider_id_offset,
            { "Provider Id Offset", "mbim.control.context.provider_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_provider_id_size,
            { "Provider Id Size", "mbim.control.context.provider_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_access_string,
            { "Access String", "mbim.control.context.access_string",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_user_name,
            { "User Name", "mbim.control.context.user_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_password,
            { "Password", "mbim.control.context.password",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_context_provider_id,
            { "Provider Id", "mbim.control.context.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provisioned_contexts_info_elem_count,
            { "Element Count", "mbim.control.context.provisioned_contexts_info.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provisioned_contexts_info_provisioned_context_offset,
            { "Provisioned Context Offset", "mbim.control.context.provisioned_contexts_info.provisioned_context_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_provisioned_contexts_info_provisioned_context_size,
            { "Provisioned Context Size", "mbim.control.context.provisioned_contexts_info.provisioned_context_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_service_activation_data_buffer,
            { "Data Buffer", "mbim.control.set_service_activation.data_buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_service_activation_info_nw_error,
            { "Network Error", "mbim.control.service_activation_info.nw_error",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nas_eps_emm_cause_values_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_service_activation_info_data_buffer,
            { "Data Buffer", "mbim.control.service_activation_info.data_buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ipv4_element_on_link_prefix_length,
            { "On Link Prefix Length", "mbim.control.ipv4_element.on_link_prefix_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ipv4_element_ipv4_address,
            { "IPv4 Address", "mbim.control.ipv4_element.ipv4_address",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ipv6_element_on_link_prefix_length,
            { "On Link Prefix Length", "mbim.control.ipv6_element.on_link_prefix_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ipv6_element_ipv6_address,
            { "IPv6 Address", "mbim.control.ipv6_element.ipv6_address",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_session_id,
            { "Session Id", "mbim.control.ip_configuration_info.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_configuration_available,
            { "IPv4 Configuration Available", "mbim.control.ip_configuration_info.ipv4_configuration_available",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_configuration_available_address,
            { "Address", "mbim.control.ip_configuration_info.control_caps.ipv4_configuration_available.address",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_configuration_available_gateway,
            { "Gateway", "mbim.control.ip_configuration_info.control_caps.ipv4_configuration_available.gateway",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_configuration_available_dns,
            { "DNS Server", "mbim.control.ip_configuration_info.control_caps.ipv4_configuration_available.dns",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_configuration_available_mtu,
            { "MTU", "mbim.control.ip_configuration_info.control_caps.ipv4_configuration_available.mtu",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_configuration_available,
            { "IPv6 Configuration Available", "mbim.control.ip_configuration_info.ipv6_configuration_available",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_configuration_available_address,
            { "Address", "mbim.control.ip_configuration_info.control_caps.ipv6_configuration_available.address",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_configuration_available_gateway,
            { "Gateway", "mbim.control.ip_configuration_info.control_caps.ipv6_configuration_available.gateway",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_configuration_available_dns,
            { "DNS Server", "mbim.control.ip_configuration_info.control_caps.ipv6_configuration_available.dns",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000004,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_configuration_available_mtu,
            { "MTU", "mbim.control.ip_configuration_info.control_caps.ipv6_configuration_available.mtu",
               FT_BOOLEAN, 32, TFS(&tfs_available_not_available), 0x00000008,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_address_count,
            { "IPv4 Address Count", "mbim.control.ip_configuration_info.ipv4_address.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_address_offset,
            { "IPv4 Address Offset", "mbim.control.ip_configuration_info.ipv4_address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_address_count,
            { "IPv6 Address Count", "mbim.control.ip_configuration_info.ipv6_address.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_address_offset,
            { "IPv6 Address Offset", "mbim.control.ip_configuration_info.ipv6_address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_gateway_offset,
            { "IPv4 Gateway Offset", "mbim.control.ip_configuration_info.ipv4_gateway.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_gateway_offset,
            { "IPv6 Gateway Offset", "mbim.control.ip_configuration_info.ipv6_gateway.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_dns_count,
            { "IPv4 DNS Server Count", "mbim.control.ip_configuration_info.ipv4_dns.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_dns_offset,
            { "IPv4 DNS Server Offset", "mbim.control.ip_configuration_info.ipv4_dns.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_dns_count,
            { "IPv6 DNS Server Count", "mbim.control.ip_configuration_info.ipv6_dns.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_dns_offset,
            { "IPv6 DNS Server Offset", "mbim.control.ip_configuration_info.ipv6_dns.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_mtu,
            { "IPv4 MTU", "mbim.control.ip_configuration_info.ipv4_mtu",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_mtu,
            { "IPv6 MTU", "mbim.control.ip_configuration_info.ipv6_mtu",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_gateway,
            { "IPv4 Gateway", "mbim.control.ip_configuration_info.ipv4_gateway",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_gateway,
            { "IPv6 Gateway", "mbim.control.ip_configuration_info.ipv6_gateway",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv4_dns,
            { "IPv4 DNS Server", "mbim.control.ip_configuration_info.ipv4_dns",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ip_configuration_info_ipv6_dns,
            { "IPv6 DNS Server", "mbim.control.ip_configuration_info.ipv6_dns",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_device_service_id,
            { "Device Service Id", "mbim.control.device_service_element.device_service_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_dss_payload,
            { "DSS Payload", "mbim.control.device_service_element.dss_payload",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_dss_payload_host_device,
            { "Host To Device", "mbim.control.device_service_element.dss_payload.host_device",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_dss_payload_device_host,
            { "Device To Host", "mbim.control.device_service_element.dss_payload.device_host",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_max_dss_instances,
            { "Max DSS Instances", "mbim.control.device_service_element.max_dss_instances",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_cid_count,
            { "CID Count", "mbim.control.device_service_element.cid.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_element_cid,
            { "CID", "mbim.control.device_service_element.cid",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_services_info_device_services_count,
            { "Device Services Count", "mbim.control.device_services_info.device_services_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_services_info_max_dss_sessions,
            { "Max DSS Sessions", "mbim.control.device_services_info.max_dss_sessions",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_services_info_device_services_offset,
            { "Device Services Offset", "mbim.control.device_services_info.device_services.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_services_info_device_services_size,
            { "Device Services Size", "mbim.control.device_services_info.device_services.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_event_entry_device_service_id,
            { "Device Service Id", "mbim.control.event_entry.device_service_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_event_entry_cid_count,
            { "CID Count", "mbim.control.event_entry.cid.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_event_entry_cid,
            { "CID", "mbim.control.event_entry.cid",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_subscribe_element_count,
            { "Element Count", "mbim.control.device_service_subscribe.element_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_subscribe_device_service_offset,
            { "Device Service Offset", "mbim.control.device_service_subscribe.device_service.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_device_service_subscribe_device_service_size,
            { "Device Service Size", "mbim.control.device_service_subscribe.device_service.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_in_discards,
            { "In Discards", "mbim.control.packet_statistics_info.in_discards",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_in_errors,
            { "In Errors", "mbim.control.packet_statistics_info.in_errors",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_in_octets,
            { "In Octets", "mbim.control.packet_statistics_info.in_octets",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_in_packets,
            { "In Packets", "mbim.control.packet_statistics_info.in_packets",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_out_octets,
            { "Out Octets", "mbim.control.packet_statistics_info.out_octets",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_out_packets,
            { "Out Packets", "mbim.control.packet_statistics_info.out_packets",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_out_errors,
            { "Out Errors", "mbim.control.packet_statistics_info.out_errors",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_statistics_info_out_discards,
            { "Out Discards", "mbim.control.packet_statistics_info.out_discards",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_network_idle_hint_state,
            { "Network Idle Hint State", "mbim.control.network_idle_hint.state",
               FT_UINT32, BASE_DEC, VALS(mbim_network_idle_hint_states_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_emergency_mode_info_emergency_mode,
            { "Emergency Mode", "mbim.control.emergency_mode_info.mode",
               FT_UINT32, BASE_DEC, VALS(mbim_emergency_mode_states_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_filter_size,
            { "Filter Size", "mbim.control.single_packet_filter.filter_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_packet_filter_offset,
            { "Packet Filter Offset", "mbim.control.single_packet_filter.packet_filter.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_packet_mask_offset,
            { "Packet Mask Offset", "mbim.control.single_packet_filter.packet_mask.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_filter_id,
            { "Filter ID", "mbim.control.single_packet_filter.filter_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_packet_filter,
            { "Packet Filter", "mbim.control.single_packet_filter.packet_filter",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_single_packet_filter_packet_mask,
            { "Packet Mask", "mbim.control.single_packet_filter.packet_mask",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_filters_session_id,
            { "Session Id", "mbim.control.packet_filters.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_filters_packet_filters_count,
            { "Packet Filters Count", "mbim.control.packet_filters.packet_filters_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_filters_packet_filters_packet_filter_offset,
            { "Packet Filter Offset", "mbim.control.packet_filters.packet_filter.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_packet_filters_packet_filters_packet_filter_size,
            { "Packet Filters Size", "mbim.control.packet_filters.packet_filter.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_configuration_format,
            { "Format", "mbim.control.set_sms_configuration.format",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_configuration_sc_address_offset,
            { "Service Center Address Offset", "mbim.control.set_sms_configuration.sc_address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_configuration_sc_address_size,
            { "Service Center Address Size", "mbim.control.set_sms_configuration.sc_address.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_configuration_sc_address,
            { "Service Center Address", "mbim.control.set_sms_configuration.sc_address",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_sms_storage_state,
            { "SMS Storage State", "mbim.control.sms_configuration_info.sms_storage_state",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_storage_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_format,
            { "Format", "mbim.control.sms_configuration_info.format",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_max_messages,
            { "Max Messages", "mbim.control.sms_configuration_info.max_messages",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_cdma_short_message_size,
            { "CDMA Short Message Size", "mbim.control.sms_configuration_info.cdma_short_message_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_sc_address_offset,
            { "Service Center Address Offset", "mbim.control.sms_configuration_info.sc_address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_sc_address_size,
            { "Service Center Address Size", "mbim.control.sms_configuration_info.sc_address.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_configuration_info_sc_address,
            { "Service Center Address Size", "mbim.control.sms_configuration_info.sc_address",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_message_index,
            { "Message Index", "mbim.control.sms_pdu_record.message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_message_status,
            { "Message Status", "mbim.control.sms_pdu_record.message_status",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_message_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_pdu_data_offset,
            { "PDU Data Offset", "mbim.control.sms_pdu_record.pdu_data.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_pdu_data_size,
            { "PDU Data Size", "mbim.control.sms_pdu_record.pdu_data.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_pdu_data,
            { "PDU Data", "mbim.control.sms_pdu_record.pdu_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_pdu_record_pdu_data_sc_address_size,
            { "Size", "mbim.control.sms_pdu_record.pdu_data.sc_address_size",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_message_index,
            { "Message Index", "mbim.control.sms_cdma_record.message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_message_status,
            { "Message Status", "mbim.control.sms_cdma_record.message_status",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_message_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_address_offset,
            { "Address Offset", "mbim.control.sms_cdma_record.address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_address_size,
            { "Address Size", "mbim.control.sms_cdma_record.address.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_timestamp_offset,
            { "Timestamp Offset", "mbim.control.sms_cdma_record.timestamp.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_timestamp_size,
            { "Timestamp Size", "mbim.control.sms_cdma_record.timestamp.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_encoding_id,
            { "Encoding Id", "mbim.control.sms_cdma_record.encoding_id",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_cdma_encoding_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_language_id,
            { "Language Id", "mbim.control.sms_cdma_record.language_id",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_cdma_lang_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_encoded_message_offset,
            { "Encoded Message Offset", "mbim.control.sms_cdma_record.encoded_message.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_size_in_bytes,
            { "Size In Bytes", "mbim.control.sms_cdma_record.size_in_bytes",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_size_in_characters,
            { "Size In Characters", "mbim.control.sms_cdma_record.size_in_characters",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_address,
            { "Address", "mbim.control.sms_cdma_record.address",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_timestamp,
            { "Timestamp", "mbim.control.sms_cdma_record.timestamp",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_encoded_message,
            { "Encoded Message", "mbim.control.sms_cdma_record.encoded_message",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_cdma_record_encoded_message_text,
            { "Text", "mbim.control.sms_cdma_record.encoded_message.text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mbim_sms_read_req_format,
            { "Format", "mbim.control.sms_read_req.format",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_req_flag,
            { "Flag", "mbim.control.sms_read_req.flag",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_req_message_index,
            { "Message Index", "mbim.control.sms_read_req.message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_info_format,
            { "Format", "mbim.control.sms_read_info.format",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_info_element_count,
            { "Element Count", "mbim.control.sms_read_info.element_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_info_sms_offset,
            { "SMS Offset", "mbim.control.sms_read_info.sms.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_read_info_sms_size,
            { "SMS Size", "mbim.control.sms_read_info.sms.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_pdu_pdu_data_offset,
            { "PDU Data Offset", "mbim.control.sms_send_pdu.pdu_data.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_pdu_pdu_data_size,
            { "PDU Data Size", "mbim.control.sms_send_pdu.pdu_data.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_pdu_pdu_data,
            { "PDU Data", "mbim.control.sms_send_pdu.pdu_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_pdu_pdu_data_sc_address_size,
            { "Size", "mbim.control.sms_send_pdu.pdu_data.sc_address_size",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_encoding_id,
            { "Encoding Id", "mbim.control.sms_send_cdma.encoding_id",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_cdma_encoding_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_language_id,
            { "Language Id", "mbim.control.sms_send_cdma.language_id",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_cdma_lang_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_address_offset,
            { "Address Offset", "mbim.control.sms_send_cdma.address.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_address_size,
            { "Address Size", "mbim.control.sms_send_cdma.address.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_encoded_message_offset,
            { "Encoded Message Offset", "mbim.control.sms_send_cdma.encoded_message.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_size_in_bytes,
            { "Size In Bytes", "mbim.control.sms_send_cdma.size_in_bytes",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_size_in_characters,
            { "Size In Characters", "mbim.control.sms_send_cdma.size_in_characters",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_address,
            { "Address", "mbim.control.sms_send_cdma.address",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_encoded_message,
            { "Encoded Message", "mbim.control.sms_send_cdma.encoded_message",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_cdma_encoded_message_text,
            { "Text", "mbim.control.sms_send_cdma.encoded_message.text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mbim_set_sms_send_format,
            { "Format", "mbim.control.set_sms_send.format",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_format_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_send_info_message_reference,
            { "Message Reference", "mbim.control.sms_send_info.message_reference",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_delete_flag,
            { "Flag", "mbim.control.set_sms_delete.flag",
               FT_UINT32, BASE_DEC, VALS(mbim_sms_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_sms_delete_message_index,
            { "Message Index", "mbim.control.set_sms_delete.message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_status_info_flags,
            { "Flags", "mbim.control.sms_status_info.flags",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sms_status_info_flags_message_store_full,
            { "Message Store Full", "mbim.control.sms_status_info.flags.message_store_full",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_sms_status_info_flags_new_message,
            { "New Message", "mbim.control.sms_status_info.flags.new_message",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_sms_status_info_message_index,
            { "Message Index", "mbim.control.sms_status_info.message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_action,
            { "USSD Action", "mbim.control.set_ussd.ussd_action",
               FT_UINT32, BASE_DEC, VALS(mbim_ussd_action_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_data_coding_scheme,
            { "USSD Data Coding Scheme", "mbim.control.set_ussd.ussd_data_coding_scheme",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_payload_offset,
            { "USSD Payload Offset", "mbim.control.set_ussd.ussd_payload.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_payload_length,
            { "USSD Payload Length", "mbim.control.set_ussd.ussd_payload.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_payload,
            { "USSD Payload", "mbim.control.set_ussd.ussd_payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ussd_ussd_payload_text,
            { "USSD Payload Text", "mbim.control.set_ussd.ussd_payload.text",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_response,
            { "USSD Response", "mbim.control.info_ussd.ussd_response",
               FT_UINT32, BASE_DEC, VALS(mbim_ussd_response_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_session_state,
            { "USSD Session State", "mbim.control.info_ussd.ussd_session_state",
               FT_UINT32, BASE_DEC, VALS(mbim_ussd_session_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_data_coding_scheme,
            { "USSD Data Coding Scheme", "mbim.control.ussd_info.ussd_data_coding_scheme",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_payload_offset,
            { "USSD Payload Offset", "mbim.control.ussd_info.ussd_payload.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_payload_length,
            { "USSD Payload Length", "mbim.control.ussd_info.ussd_payload.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_payload,
            { "USSD Payload", "mbim.control.ussd_info.ussd_payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ussd_info_ussd_payload_text,
            { "USSD Payload Text", "mbim.control.ussd_info.ussd_payload.text",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_configuration_info_phonebook_state,
            { "Phonebook State", "mbim.control.phonebook_configuration_info.phonebook_state",
               FT_UINT32, BASE_DEC, VALS(mbim_phonebook_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_configuration_info_total_nb_of_entries,
            { "Total Number Of Entries", "mbim.control.phonebook_configuration_info.total_nb_of_entries",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_configuration_info_used_entries,
            { "Used Entries", "mbim.control.phonebook_configuration_info.used_entries",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_configuration_info_max_number_length,
            { "Max Number Length", "mbim.control.phonebook_configuration_info.max_number_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_configuration_info_max_name_length,
            { "Max Name Length", "mbim.control.phonebook_configuration_info.max_name_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_entry_index,
            { "Entry Index", "mbim.control.phonebook_entry.entry_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_number_offset,
            { "Number Offset", "mbim.control.phonebook_entry.number.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_number_length,
            { "Number Length", "mbim.control.phonebook_entry.number.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_name_offset,
            { "Name Offset", "mbim.control.phonebook_entry.name.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_name_length,
            { "Name Length", "mbim.control.phonebook_entry.name.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_number,
            { "Number", "mbim.control.phonebook_entry.number",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_entry_name,
            { "Name", "mbim.control.phonebook_entry.name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_read_req_filter_flag,
            { "Filter Flag", "mbim.control.phonebook_read_req.filter_flag",
               FT_UINT32, BASE_DEC, VALS(mbim_phonebook_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_read_req_filter_message_index,
            { "Filter Message Index", "mbim.control.phonebook_read_req.filter_message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_read_info_element_count,
            { "Element Count", "mbim.control.phonebook_read_info.element_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_read_info_phonebook_offset,
            { "Phonebook Offset", "mbim.control.phonebook_read_info.phonebook.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_phonebook_read_info_phonebook_size,
            { "Phonebook Size", "mbim.control.phonebook_read_info.phonebook.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_delete_filter_flag,
            { "Filter Flag", "mbim.control.set_phonebook_delete.filter_flag",
               FT_UINT32, BASE_DEC, VALS(mbim_phonebook_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_delete_filter_message_index,
            { "Filter Message Index", "mbim.control.set_phonebook_delete.filter_message_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_save_flag,
            { "Save Flag", "mbim.control.set_phonebook_write.save_flag",
               FT_UINT32, BASE_DEC, VALS(mbim_phonebook_write_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_save_index,
            { "Save Index", "mbim.control.set_phonebook_write.save_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_number_offset,
            { "Number Offset", "mbim.control.set_phonebook_write.number.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_number_length,
            { "Number Length", "mbim.control.set_phonebook_write.number.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_name_offset,
            { "Name Offset", "mbim.control.set_phonebook_write.name.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_name_length,
            { "Name Length", "mbim.control.set_phonebook_write.name.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_number,
            { "Number", "mbim.control.set_phonebook_write.number",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_phonebook_write_name,
            { "Name", "mbim.control.set_phonebook_write.name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control,
            { "PAC Host Control", "mbim.control.set_stk_pac.pac_host_control",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_refresh,
            { "Refresh", "mbim.control.set_stk_pac.pac_host_control.refresh",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_more_time,
            { "More Time", "mbim.control.set_stk_pac.pac_host_control.more_time",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_poll_interval,
            { "Poll Interval", "mbim.control.set_stk_pac.pac_host_control.poll_interval",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_polling_off,
            { "Polling Off", "mbim.control.set_stk_pac.pac_host_control.polling_off",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_set_up_evt_list,
            { "Set Up Event List", "mbim.control.set_stk_pac.pac_host_control.set_up_evt_list",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_set_up_call,
            { "Set Up Call", "mbim.control.set_stk_pac.pac_host_control.set_up_call",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_send_ss,
            { "Send SS", "mbim.control.set_stk_pac.pac_host_control.send_ss",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_send_ussd,
            { "Send USSD", "mbim.control.set_stk_pac.pac_host_control.send_ussd",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_send_short_msg,
            { "Send Short Message", "mbim.control.set_stk_pac.pac_host_control.send_short_msg",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_send_dtmf,
            { "Send DTMF", "mbim.control.set_stk_pac.pac_host_control.send_dtmf",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_launch_browser,
            { "Launch Browser", "mbim.control.set_stk_pac.pac_host_control.launch_browser",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x80,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_geo_loc_req,
            { "Geographical Location Request", "mbim.control.set_stk_pac.pac_host_control.geo_loc_req",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x01,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_play_tone,
            { "Play Tone", "mbim.control.set_stk_pac.pac_host_control.play_tone",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_display_text,
            { "Display Text", "mbim.control.set_stk_pac.pac_host_control.display_text",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_inkey,
            { "Get Inkey", "mbim.control.set_stk_pac.pac_host_control.get_inkey",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_input,
            { "Get Input", "mbim.control.set_stk_pac.pac_host_control.get_input",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x80,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_select_item,
            { "Select Item", "mbim.control.set_stk_pac.pac_host_control.select_item",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x01,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_set_up_menu,
            { "Set Up Menu", "mbim.control.set_stk_pac.pac_host_control.set_up_menu",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_prov_local_info,
            { "Provide Local Information", "mbim.control.set_stk_pac.pac_host_control.prov_local_info",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_timer_management,
            { "Timer Management", "mbim.control.set_stk_pac.pac_host_control.timer_management",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_set_up_idle_mode_text,
            { "Set Up Idle Mode Text", "mbim.control.set_stk_pac.pac_host_control.set_up_idle_mode_text",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_perform_card_apdu,
            { "Perform Card APDU", "mbim.control.set_stk_pac.pac_host_control.perform_card_apdu",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_power_on_card,
            { "Power On Card", "mbim.control.set_stk_pac.pac_host_control.power_on_card",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x80,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_power_off_card,
            { "Power Off Card", "mbim.control.set_stk_pac.pac_host_control.power_off_card",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x01,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_reader_status,
            { "Get Reader Status", "mbim.control.set_stk_pac.pac_host_control.get_reader_status",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_run_at_cmd,
            { "Run AT Command", "mbim.control.set_stk_pac.pac_host_control.run_at_cmd",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_lang_notif,
            { "Language Notification", "mbim.control.set_stk_pac.pac_host_control.lang_notif",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_open_channel,
            { "Open Channel", "mbim.control.set_stk_pac.pac_host_control.open_channel",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x01,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_close_channel,
            { "Close Channel", "mbim.control.set_stk_pac.pac_host_control.close_channel",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_receive_data,
            { "Receive Data", "mbim.control.set_stk_pac.pac_host_control.receive_data",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_send_data,
            { "Send Data", "mbim.control.set_stk_pac.pac_host_control.send_data",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_channel_status,
            { "Get Channel Status", "mbim.control.set_stk_pac.pac_host_control.get_channel_status",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_service_search,
            { "Service Search", "mbim.control.set_stk_pac.pac_host_control.service_search",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_service_info,
            { "Get Service Information", "mbim.control.set_stk_pac.pac_host_control.get_service_info",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_declare_service,
            { "Declare Service", "mbim.control.set_stk_pac.pac_host_control.declare_service",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x80,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_set_frames,
            { "Set Frames", "mbim.control.set_stk_pac.pac_host_control.set_frames",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x04,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_get_frames_status,
            { "Get Frames Status", "mbim.control.set_stk_pac.pac_host_control.get_frames_status",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_retrieve_multimedia_msg,
            { "Retrieve Multimedia Message", "mbim.control.set_stk_pac.pac_host_control.retrieve_multimedia_msg",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x10,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_submit_multimedia_msg,
            { "Submit Multimedia Message", "mbim.control.set_stk_pac.pac_host_control.submit_multimedia_msg",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_display_multimedia_msg,
            { "Display Multimedia Message", "mbim.control.set_stk_pac.pac_host_control.display_multimedia_msg",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_activate,
            { "Activate", "mbim.control.set_stk_pac.pac_host_control.activate",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x40,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_contactless_state_changed,
            { "Contactless State Changed", "mbim.control.set_stk_pac.pac_host_control.contactless_state_changed",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x80,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_cmd_container,
            { "Command Container", "mbim.control.set_stk_pac.pac_host_control.cmd_container",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x01,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_encapsulated_session_ctrl,
            { "Encapsulated Session Control", "mbim.control.set_stk_pac.pac_host_control.encapsulated_session_ctrl",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_pac_pac_host_control_end_proact_session,
            { "End Proactive Session", "mbim.control.set_stk_pac.pac_host_control.end_proact_session",
               FT_BOOLEAN, 8, TFS(&mbim_pac_host_control_val), 0x02,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support,
            { "PAC Host Control", "mbim.control.stk_pac_info.pac_support",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_refresh,
            { "Refresh", "mbim.control.stk_pac_info.pac_support.refresh",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_more_time,
            { "More Time", "mbim.control.stk_pac_info.pac_support.more_time",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_poll_interval,
            { "Poll Interval", "mbim.control.stk_pac_info.pac_support.poll_interval",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_polling_off,
            { "Polling Off", "mbim.control.stk_pac_info.pac_support.polling_off",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_set_up_evt_list,
            { "Set Up Event List", "mbim.control.stk_pac_info.pac_support.set_up_evt_list",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_set_up_call,
            { "Set Up Call", "mbim.control.stk_pac_info.pac_support.set_up_call",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_send_ss,
            { "Send SS", "mbim.control.stk_pac_info.pac_support.send_ss",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_send_ussd,
            { "Send USSD", "mbim.control.stk_pac_info.pac_support.send_ussd",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_send_short_msg,
            { "Send Short Message", "mbim.control.stk_pac_info.pac_support.send_short_msg",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_send_dtmf,
            { "Send DTMF", "mbim.control.stk_pac_info.pac_support.send_dtmf",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_launch_browser,
            { "Launch Browser", "mbim.control.stk_pac_info.pac_support.launch_browser",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_geo_loc_req,
            { "Geographical Location Request", "mbim.control.stk_pac_info.pac_support.geo_loc_req",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_play_tone,
            { "Play Tone", "mbim.control.stk_pac_info.pac_support.play_tone",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_display_text,
            { "Display Text", "mbim.control.stk_pac_info.pac_support.display_text",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_inkey,
            { "Get Inkey", "mbim.control.stk_pac_info.pac_support.get_inkey",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_input,
            { "Get Input", "mbim.control.stk_pac_info.pac_support.get_input",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_select_item,
            { "Select Item", "mbim.control.stk_pac_info.pac_support.select_item",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_set_up_menu,
            { "Set Up Menu", "mbim.control.stk_pac_info.pac_support.set_up_menu",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_prov_local_info,
            { "Provide Local Information", "mbim.control.stk_pac_info.pac_support.prov_local_info",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_timer_management,
            { "Timer Management", "mbim.control.stk_pac_info.pac_support.timer_management",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_set_up_idle_mode_text,
            { "Set Up Idle Mode Text", "mbim.control.stk_pac_info.pac_support.set_up_idle_mode_text",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_perform_card_apdu,
            { "Perform Card APDU", "mbim.control.stk_pac_info.pac_support.perform_card_apdu",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_power_on_card,
            { "Power On Card", "mbim.control.stk_pac_info.pac_support.power_on_card",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_power_off_card,
            { "Power Off Card", "mbim.control.stk_pac_info.pac_support.power_off_card",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_reader_status,
            { "Get Reader Status", "mbim.control.stk_pac_info.pac_support.get_reader_status",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_run_at_cmd,
            { "Run AT Command", "mbim.control.stk_pac_info.pac_support.run_at_cmd",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_lang_notif,
            { "Language Notification", "mbim.control.stk_pac_info.pac_support.lang_notif",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_open_channel,
            { "Open Channel", "mbim.control.stk_pac_info.pac_support.open_channel",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_close_channel,
            { "Close Channel", "mbim.control.stk_pac_info.pac_support.close_channel",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_receive_data,
            { "Receive Data", "mbim.control.stk_pac_info.pac_support.receive_data",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_send_data,
            { "Send Data", "mbim.control.stk_pac_info.pac_support.send_data",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_channel_status,
            { "Get Channel Status", "mbim.control.stk_pac_info.pac_support.get_channel_status",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_service_search,
            { "Service Search", "mbim.control.stk_pac_info.pac_support.service_search",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_service_info,
            { "Get Service Information", "mbim.control.stk_pac_info.pac_support.get_service_info",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_declare_service,
            { "Declare Service", "mbim.control.stk_pac_info.pac_support.declare_service",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_set_frames,
            { "Set Frames", "mbim.control.stk_pac_info.pac_support.set_frames",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_get_frames_status,
            { "Get Frames Status", "mbim.control.stk_pac_info.pac_support.get_frames_status",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_retrieve_multimedia_msg,
            { "Retrieve Multimedia Message", "mbim.control.stk_pac_info.pac_support.retrieve_multimedia_msg",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_submit_multimedia_msg,
            { "Submit Multimedia Message", "mbim.control.stk_pac_info.pac_support.submit_multimedia_msg",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_display_multimedia_msg,
            { "Display Multimedia Message", "mbim.control.stk_pac_info.pac_support.display_multimedia_msg",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_activate,
            { "Activate", "mbim.control.stk_pac_info.pac_support.activate",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_contactless_state_changed,
            { "Contactless State Changed", "mbim.control.stk_pac_info.pac_support.contactless_state_changed",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_cmd_container,
            { "Command Container", "mbim.control.stk_pac_info.pac_support.cmd_container",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_encapsulated_session_ctrl,
            { "Encapsulated Session Control", "mbim.control.stk_pac_info.pac_support.encapsulated_session_ctrl",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_info_pac_support_end_proact_session,
            { "End Proactive Session", "mbim.control.stk_pac_info.pac_support.end_proact_session",
               FT_UINT8, BASE_DEC, VALS(mbim_stk_pac_profile_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_pac_type,
            { "PAC Type", "mbim.control.stk_pac.pac_type",
               FT_UINT32, BASE_DEC, VALS(mbim_stk_pac_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_pac_pac,
            { "PAC", "mbim.control.stk_pac.pac",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_terminal_response_response_length,
            { "Response Length", "mbim.control.set_stk_terminal_response.response_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_terminal_response_data_buffer,
            { "Data Buffer", "mbim.control.set_stk_terminal_response.data_buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_terminal_response_info_result_data_string_offset,
            { "Result Data String Offset", "mbim.control.stk_terminal_response_info.result_data_string.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_terminal_response_info_result_data_string_length,
            { "Result Data String Length", "mbim.control.stk_terminal_response_info.result_data_string.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_terminal_response_info_status_word,
            { "Status Word", "mbim.control.stk_terminal_response_info.status_word",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_terminal_response_info_result_data_string,
            { "Result Data String", "mbim.control.stk_terminal_response_info.result_data_string",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_stk_envelope_data_buffer,
            { "Data Buffer", "mbim.control.set_stk_envelope.data_buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_stk_envelope_info_envelope_support,
            { "Envelope Support", "mbim.control.stk_envelope_info.envelope_support",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_req_rand,
            { "RAND", "mbim.control.aka_auth_req.rand",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_req_autn,
            { "AUTN", "mbim.control.aka_auth_req.autn",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_info_res,
            { "RES", "mbim.control.aka_auth_info.res",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_info_res_length,
            { "RES Length", "mbim.control.aka_auth_info.res_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_info_ik,
            { "IK", "mbim.control.aka_auth_info.ik",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_info_ck,
            { "CK", "mbim.control.aka_auth_info.ck",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_aka_auth_info_auts,
            { "AUTS", "mbim.control.aka_auth_info.auts",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_req_rand,
            { "RAND", "mbim.control.akap_auth_req.rand",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_req_autn,
            { "AUTN", "mbim.control.akap_auth_req.autn",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_req_network_name_offset,
            { "Network Name Offset", "mbim.control.akap_auth_req.network_name.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_req_network_name_length,
            { "Network Name Length", "mbim.control.akap_auth_req.network_name.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_req_network_name,
            { "Network Name", "mbim.control.akap_auth_req.network_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_info_res,
            { "RES", "mbim.control.akap_auth_info.res",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_info_res_length,
            { "RES Length", "mbim.control.akap_auth_info.res_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_info_ik,
            { "IK", "mbim.control.akap_auth_info.ik",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_info_ck,
            { "CK", "mbim.control.akap_auth_info.ck",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_akap_auth_info_auts,
            { "AUTS", "mbim.control.akap_auth_info.auts",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_req_rand1,
            { "RAND1", "mbim.control.sim_auth_req.rand1",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_req_rand2,
            { "RAND2", "mbim.control.sim_auth_req.rand2",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_req_rand3,
            { "RAND3", "mbim.control.sim_auth_req.rand3",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_req_n,
            { "n", "mbim.control.sim_auth_req.n",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_sres1,
            { "SRES1", "mbim.control.sim_auth_info.sres1",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_kc1,
            { "KC1", "mbim.control.sim_auth_info.kc1",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_sres2,
            { "SRES2", "mbim.control.sim_auth_info.sres2",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_kc2,
            { "KC2", "mbim.control.sim_auth_info.kc2",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_sres3,
            { "SRES3", "mbim.control.sim_auth_info.sres3",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_kc3,
            { "KC3", "mbim.control.sim_auth_info.kc3",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sim_auth_info_n,
            { "n", "mbim.control.sim_auth_info.n",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_dss_connect_device_service_id,
            { "Device Service Id", "mbim.control.set_dss_connect.device_service_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_dss_connect_dss_session_id,
            { "DSS Session Id", "mbim.control.set_dss_connect.dss_session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_dss_connect_dss_link_state,
            { "DSS Link State", "mbim.control.set_dss_connect.dss_link_state",
               FT_UINT32, BASE_DEC, VALS(mbim_dss_link_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_capabilities_info_capabilities,
            { "Capabilities", "mbim.control.multicarrier_capabilities_info.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_capabilities_info_capabilities_static_scan,
            { "Static Scan", "mbim.control.multicarrier_capabilities_info.capabilities.static_scan",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_capabilities_info_capabilities_fw_requires_reboot,
            { "FW Requires Reboot", "mbim.control.multicarrier_capabilities_info.capabilities.fw_requires_reboot",
               FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_location_info_country,
            { "Country", "mbim.control.location_info.country",
               FT_UINT32, BASE_HEX|BASE_EXT_STRING, &mbim_geoid_vals_ext, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_current_cid_list_req_uuid,
            { "UUID", "mbim.control.multicarrier_current_cid_list_req.uuid",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_current_cid_list_info_cid_count,
            { "CID Count", "mbim.control.multicarrier_current_cid_list_info.cid_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multicarrier_current_cid_list_info_cid,
            { "CID", "mbim.control.multicarrier_current_cid_list_info.cid",
               FT_UINT32, BASE_DEC, VALS(mbim_uuid_multicarrier_cid_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_msfwid_firmwareid_info_firmware_id,
            { "Firmware Id", "mbim.control.msfwid_firmwareid_info.firmware_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_qmi_buffer,
            { "Buffer", "mbim.control.qmi.buffer",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_enable,
            { "Enable", "mbim.control.thermal_config.enable",
               FT_UINT32, BASE_DEC, VALS(mbim_thermal_config_enable_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_temp_sensor_id,
            { "Temperature Sensor ID", "mbim.control.thermal_config.temp_sensor_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_alarm_id,
            { "Alarm ID", "mbim.control.thermal_config.alarm_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_threshold_value,
            { "Threshold Value", "mbim.control.thermal_config.threshold_value",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_degrees_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_hyst_value,
            { "Hysteresis Value", "mbim.control.thermal_config.hyst_value",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_degrees_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_config_sampling_period,
            { "Sampling Period", "mbim.control.thermal_config.sampling_period",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_query_thermal_state_temp_sensor_id,
            { "Temperature Sensor ID", "mbim.control.query_thermal_state.temp_sensor_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_current_temp_value,
            { "Current Temperature Value", "mbim.control.thermal_state_info.current_temp_value",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_degrees_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_enable,
            { "Enable", "mbim.control.thermal_state_info.enable",
               FT_UINT32, BASE_DEC, VALS(mbim_thermal_config_enable_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_temp_sensor_id,
            { "Temperature Sensor ID", "mbim.control.thermal_state_info.temp_sensor_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_alarm_id,
            { "Alarm ID", "mbim.control.thermal_state_info.alarm_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_threshold_value,
            { "Threshold Value", "mbim.control.thermal_state_info.threshold_value",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_degrees_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_hyst_value,
            { "Hysteresis Value", "mbim.control.thermal_state_info.hyst_value",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_degrees_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_thermal_state_info_sampling_period,
            { "Sampling Period", "mbim.control.thermal_state_info.sampling_period",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sar_config_sar_status,
            { "SAR Status", "mbim.control.sar_config.sar_status",
               FT_UINT32, BASE_DEC, VALS(mbim_sar_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sar_config_level,
            { "Level", "mbim.control.sar_config.level",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_sar_mode,
            { "SAR Mode", "mbim.control.ms_sar_config.sar_mode",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_sar_config_sar_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_sar_backoff_status,
            { "SAR Backoff Status", "mbim.control.ms_sar_config.sar_backoff_status",
               FT_BOOLEAN, BASE_DEC, TFS(&tfs_enabled_disabled), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_sar_wifi_Integration,
            { "SAR Wifi Integration", "mbim.control.ms_sar_config.sar_wifi_integration",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_sar_config_sar_wifi_integration_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_element_count,
            { "Element Count", "mbim.control.ms_sar_config.element_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_element_offset,
            { "Element Offset", "mbim.control.ms_sar_config.element_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_element_size,
            { "Element Size", "mbim.control.ms_sar_config.element_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_state_sar_antenna_index,
            { "SAR Antenna Index", "mbim.control.ms_sar_config.sar_antenna_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_sar_config_state_sar_backoff_index,
            { "SAR Backoff Index", "mbim.control.ms_sar_config.sar_backoff_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_transmission_status_channel_notification,
            { "Transmission Channel Notification", "mbim.control.ms_transmission_status.channel_notification",
               FT_BOOLEAN, BASE_DEC, TFS(&tfs_enabled_disabled), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_transmission_status_transmission_status,
            { "Transmission Status", "mbim.control.ms_transmission_status.transmission_status",
               FT_BOOLEAN, BASE_DEC, TFS(&tfs_active_inactive), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_transmission_status_hysteresis_timer,
            { "Hysteresis Timer", "mbim.control.ms_transmission_status.hysteresis_timer",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_activate_state,
            { "State", "mbim.control.adpclk_activate.state",
               FT_UINT32, BASE_DEC, VALS(mbim_adpclk_activate_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_elem_count,
            { "Element Count", "mbim.control.adpclk_freq_info.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_offset,
            { "ADPCLK Freq Value Offset", "mbim.control.adpclk_freq_info.adpclk_freq_value.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_size,
            { "ADPCLK Freq Value Size", "mbim.control.adpclk_freq_info.adpclk_freq_value.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_center_freq,
            { "Center Frequency", "mbim.control.adpclk_freq_info.adpclk_freq_value.center_freq",
               FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_freq_spread,
            { "Frequency Spread", "mbim.control.adpclk_freq_info.adpclk_freq_value.freq_spread",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_hz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_noise_power,
            { "Noise Power", "mbim.control.adpclk_freq_info.adpclk_freq_value.noise_power",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_rssi,
            { "Relative Signal Strength Indication", "mbim.control.adpclk_freq_info.adpclk_freq_value.rssi",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_adpclk_freq_info_adpclk_freq_value_connect_status,
            { "Connect Status", "mbim.control.adpclk_freq_info.adpclk_freq_value.connect_status",
               FT_UINT32, BASE_DEC, VALS(mbim_connect_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_trace_config_config,
            { "Configuration", "mbim.control.trace_config.config",
               FT_UINT32, BASE_DEC, VALS(mbim_trace_config_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtc_app_info_period,
            { "Period", "mbim.control.nrtc_app_info.period",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtc_app_info_duration,
            { "Duration", "mbim.control.nrtc_app_info.duration",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_mode,
            { "Mode", "mbim.control.nrtcws_config.mode",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_wlan_active,
            { "WLAN Active", "mbim.control.nrtcws_config.wlan_active",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_wlan_safe_rx,
            { "WLAN Safe Rx", "mbim.control.nrtcws_config.wlan_safe_rx",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_wlan_bandwidth,
            { "WLAN Bandwidth", "mbim.control.nrtcws_config.wlan_bandwidth",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_bt_active,
            { "BT Active", "mbim.control.nrtcws_config.bt_active",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_config_bt_safe_rx,
            { "BT Safe Rx", "mbim.control.nrtcws_config.bt_safe_rx",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_lte_active,
            { "LTE Active", "mbim.control.nrtcws_info.lte_active",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_wlan_safe_rx_min,
            { "WLAN Safe Rx Min", "mbim.control.nrtcws_info.wlan_safe_rx_min",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_wlan_safe_rx_max,
            { "WLAN Safe Rx Max", "mbim.control.nrtcws_info.wlan_safe_rx_max",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_bt_safe_rx_min,
            { "BT Safe Rx Min", "mbim.control.nrtcws_info.bt_safe_rx_min",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_bt_safe_rx_max,
            { "BT Safe Rx Max", "mbim.control.nrtcws_info.bt_safe_rx_max",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_lte_sps_period,
            { "LTE SPS Periodicity", "mbim.control.nrtcws_info.lte_sps_period",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_lte_sps_duration,
            { "LTE SPS Duration", "mbim.control.nrtcws_info.lte_sps_duration",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_nrtcws_info_lte_sps_initial_offset,
            { "LTE SPS Initial Offset", "mbim.control.nrtcws_info.lte_sps_initial_offset",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_usbprofile_cmd_length,
            { "Length", "mbim.control.usbprofile_cmd.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_usbprofile_cmd_buffer,
            { "Buffer", "mbim.control.usbprofile_cmd.buffer",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_usbprofile_rsp_length,
            { "Length", "mbim.control.usbprofile_rsp.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_usbprofile_rsp_buffer,
            { "Buffer", "mbim.control.usbprofile_rsp.buffer",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ciq_set_mode,
            { "Mode", "mbim.control.ciq_set.mode",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ciq_set_debug_info_size,
            { "Debug Info Size", "mbim.control.ciq_set.debug_info.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ciq_set_debug_info,
            { "Debug Info", "mbim.control.ciq_set.debug_info",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ciq_info_mode,
            { "Mode", "mbim.control.ciq_info.mode",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_rssi,
            { "RSSI", "mbim.control.atds_signal_info.rssi",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rssi_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_ber,
            { "BER", "mbim.control.atds_signal_info.ber",
               FT_UINT32, BASE_DEC, VALS(mbim_ber_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_rscp,
            { "RSCP", "mbim.control.atds_signal_info.rscp",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rscp_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_ecno,
            { "Ec/No", "mbim.control.atds_signal_info.ecno",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_ecno_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_rsrq,
            { "RSRQ", "mbim.control.atds_signal_info.rsrq",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rsrq_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_rsrp,
            { "RSRP", "mbim.control.atds_signal_info.rsrp",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rsrp_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_signal_info_rssnr,
            { "RS SNR", "mbim.control.atds_signal_info.rssnr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rssnr_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_location_info_lac,
            { "Location Area Code", "mbim.control.atds_location_info.lac",
               FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_location_info_tac,
            { "Tracking Area Code", "mbim.control.atds_location_info.tac",
               FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_location_info_cellid,
            { "Cell Identity", "mbim.control.atds_location_info.cellid",
               FT_UINT32, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_id_offset,
            { "Provider Id Offset", "mbim.control.atds_operator.provider_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_id_size,
            { "Provider Id Size", "mbim.control.atds_operator.provider_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_state,
            { "Provider State", "mbim.control.atds_operator.provider_state",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_name_offset,
            { "Provider Name Offset", "mbim.control.atds_operator.provider_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_name_size,
            { "Provider Name Size", "mbim.control.atds_operator.provider_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_plmn_mode,
            { "PLMN Mode", "mbim.control.atds_operator.plmn_mode",
               FT_UINT32, BASE_DEC, VALS(mbim_atds_operator_plmn_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_rssi,
            { "RSSI", "mbim.control.atds_operator.rssi",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_rssi_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_error_rate,
            { "Error Rate", "mbim.control.atds_operator.error_rate",
               FT_UINT32, BASE_DEC, VALS(mbim_error_rate_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_id,
            { "Provider Id", "mbim.control.atds_operator.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operator_provider_name,
            { "Provider Name", "mbim.control.atds_operator.provider_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operators_elem_count,
            { "Element Count", "mbim.control.atds_operators.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operators_operator_offset,
            { "Provider Offset", "mbim.control.atds_operators.provider_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_operators_operator_size,
            { "Provider Size", "mbim.control.atds_operators.provider_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_rat_info_mode,
            { "Mode", "mbim.control.atds_rat_info.mode",
               FT_UINT32, BASE_DEC, VALS(mbim_adts_rat_info_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_type,
            { "Type", "mbim.control.atds_projection_table.type",
               FT_UINT32, BASE_DEC, VALS(mbim_adts_projection_table_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar5min,
            { "Bar5 Min", "mbim.control.atds_projection_table.bar5min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a5,
            { "A5", "mbim.control.atds_projection_table.a5",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b5,
            { "B5", "mbim.control.atds_projection_table.b5",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar4min,
            { "Bar4 Min", "mbim.control.atds_projection_table.bar4min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a4,
            { "A4", "mbim.control.atds_projection_table.a4",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b4,
            { "B4", "mbim.control.atds_projection_table.b4",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar3min,
            { "Bar3 Min", "mbim.control.atds_projection_table.bar3min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a3,
            { "A3", "mbim.control.atds_projection_table.a3",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b3,
            { "B3", "mbim.control.atds_projection_table.b3",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar2min,
            { "Bar2 Min", "mbim.control.atds_projection_table.bar2min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a2,
            { "A2", "mbim.control.atds_projection_table.a2",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b2,
            { "B2", "mbim.control.atds_projection_table.b2",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar1min,
            { "Bar1 Min", "mbim.control.atds_projection_table.bar1min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a1,
            { "A1", "mbim.control.atds_projection_table.a1",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b1,
            { "B1", "mbim.control.atds_projection_table.b1",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_bar0min,
            { "Bar0 Min", "mbim.control.atds_projection_table.bar0min",
               FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_a0,
            { "A0", "mbim.control.atds_projection_table.a0",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_table_b0,
            { "B0", "mbim.control.atds_projection_table.b0",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(mbim_projection_table_coeff_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_tables_elem_count,
            { "Element Count", "mbim.control.atds_projection_tables.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_tables_projection_table_offset,
            { "Projection Table Offset", "mbim.control.atds_projection_tables.projection_table_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_atds_projection_tables_projection_table_size,
            { "Projection Table Size", "mbim.control.atds_projection_tables.projection_table_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_caps_info_control_caps,
            { "Control Caps", "mbim.control.multiflow_caps_info.control_caps",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_caps_info_control_caps_uplink,
            { "Uplink", "mbim.control.multiflow_caps_info.control_caps.uplink",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_caps_info_control_caps_downlink,
            { "Downlink", "mbim.control.multiflow_caps_info.control_caps.downlink",
               FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_set_multiflow_state_state,
            { "State", "mbim.control.set_multiflow_state.state",
               FT_UINT32, BASE_DEC, VALS(mbim_multiflow_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_state_info_state,
            { "State", "mbim.control.multiflow_state_info.state",
               FT_UINT32, BASE_DEC, VALS(mbim_multiflow_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_tft_info_session_id,
            { "Session Id", "mbim.control.multiflow_tft_info.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_tft_info_elem_count,
            { "Element Count", "mbim.control.multiflow_tft_info.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_tft_info_tft_list_offset,
            { "TFT List Offset", "mbim.control.multiflow_tft_info.tft_list_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_multiflow_tft_info_tft_list_size,
            { "TFT List Size", "mbim.control.multiflow_tft_info.tft_list_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_operation,
            { "Operation", "mbim.control.set_ms_provisioned_context_v2.operation",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_context_operations_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_ip_type,
            { "IP Type", "mbim.control.set_ms_provisioned_context_v2.ip_type",
               FT_UINT32, BASE_DEC, VALS(mbim_context_ip_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_enable,
            { "Enable", "mbim.control.set_ms_provisioned_context_v2.enable",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_context_enable_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_roaming,
            { "Roaming", "mbim.control.set_ms_provisioned_context_v2.roaming",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_context_roaming_control_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_media_type,
            { "Media Type", "mbim.control.set_ms_provisioned_context_v2.media_type",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_context_media_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_source,
            { "Source", "mbim.control.set_ms_provisioned_context_v2.source",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_context_source_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_access_string,
            { "Access String", "mbim.control.set_ms_provisioned_context_v2.access_string",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_access_string_offset,
            { "Access String Offset", "mbim.control.set_ms_provisioned_context_v2.access_string_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_access_string_size,
            { "Access String Size", "mbim.control.set_ms_provisioned_context_v2.access_string_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_user_name,
            { "User Name", "mbim.control.set_ms_provisioned_context_v2.user_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_user_name_offset,
            { "User Name Offset", "mbim.control.set_ms_provisioned_context_v2.user_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_user_name_size,
            { "User Name Size", "mbim.control.set_ms_provisioned_context_v2.user_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_password,
            { "Password", "mbim.control.set_ms_provisioned_context_v2.password",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_password_offset,
            { "Password Offset", "mbim.control.set_ms_provisioned_context_v2.password_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_password_size,
            { "Password Size", "mbim.control.set_ms_provisioned_context_v2.password_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_compression,
            { "Compression", "mbim.control.set_ms_provisioned_context_v2.compression",
               FT_UINT32, BASE_DEC, VALS(mbim_compression_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_set_ms_provisioned_context_v2_auth_protocol,
            { "Auth Protocol", "mbim.control.set_ms_provisioned_context_v2.auth_protocol",
               FT_UINT32, BASE_DEC, VALS(mbim_auth_protocol_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_provisioned_context_info_v2_elem_count,
            { "Element Count", "mbim.control.ms_provisioned_context_info_v2.auth_protocol",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_provisioned_context_info_v2_list_offset,
            { "Item Offset", "mbim.control.ms_provisioned_context_info_v2.list_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_provisioned_context_info_v2_list_size,
            { "Item Size", "mbim.control.ms_provisioned_context_info_v2.list_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_provisioned_context_info_v2_context_id,
            { "Context ID", "mbim.control.ms_provisioned_context_info_v2.context_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_state_sim_provider_actuated,
            { "SIM Provide Actuated", "mbim.control.ms_provisioned_context_info_v2.sim_provider_actuated",
               FT_BOOLEAN, 32, TFS(&tfs_activated_deactivated), 0x00000001,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_state_network_provider_actuated,
            { "Network Provider Actuated", "mbim.control.ms_provisioned_context_info_v2.network_provider_actuated",
               FT_BOOLEAN, 32, TFS(&tfs_activated_deactivated), 0x00000002,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_info_blacklist_state,
            { "Blacklist State", "mbim.control.mbim_ms_network_blacklist_info.blacklist_state",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_info_elem_count,
            { "Element Count", "mbim.control.mbim_ms_network_blacklist_info.elem_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_info_list_offset,
            { "Provider Blacklist Offset", "mbim.control.mbim_ms_network_blacklist_info.item_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_info_list_size,
            { "Provider Blacklist Size", "mbim.control.mbim_ms_network_blacklist_info.item_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_provider_mcc,
            { "MCC", "mbim.control.ms_network_blacklist_provider.mcc",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_provider_mnc,
            { "MNC", "mbim.control.ms_network_blacklist_provider.mnc",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_blacklist_provider_type,
            { "Blacklist Type", "mbim.control.ms_network_blacklist_provider.blacklist_type",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_network_blacklist_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_sys_caps_info_number_of_executors,
            { "Number of Executors", "mbim.control.sys_caps_info.number_of_executors",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sys_caps_info_number_of_slots,
            { "Number of Slots", "mbim.control.sys_caps_info.number_of_slots",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sys_caps_info_concurrency,
            { "Concurrency", "mbim.control.sys_caps_info.concurrency",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_sys_caps_info_modem_id,
            { "Modem Id", "mbim.control.sys_caps_info.modem_id",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_device_slot_mapping_info_map_count,
            { "Map Count", "mbim.control.ms_device_slot_mapping_info.map_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_device_slot_mapping_info_map_offset,
            { "Slot Map Offset", "mbim.control.ms_device_slot_mapping_info.map_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_device_slot_mapping_info_map_size,
            { "Slot Map Size", "mbim.control.ms_device_slot_mapping_info.map_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_device_slot_mapping_info_executor_slot_index,
            { "Slot Index", "mbim.control.ms_device_slot_mapping_info.slot_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_slot_info_req_slot_index,
            { "Slot Index", "mbim.control.ms_slot_info_req.slot_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_slot_info_slot_index,
            { "Slot Index", "mbim.control.ms_slot_info.slot_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_slot_info_state,
            { "State", "mbim.control.ms_slot_info.state",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_uiccslot_state_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_gsm_count,
            { "Max GSM Count", "mbim.control.base_station.max_gsm_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_umts_count,
            { "Max UMTS Count", "mbim.control.base_station.max_umts_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_td_scdma_count,
            { "Max TD-SCDMA Count", "mbim.control.base_station.max_td_scdma_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_lte_count,
            { "Max LTE Count", "mbim.control.base_station.max_lte_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_cdma_count,
            { "Max CDMA Count", "mbim.control.base_station.max_cdma_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_max_nr_count,
            { "Max NR Count", "mbim.control.base_station.max_nr_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_provider_id_offset,
            { "Provider Id Offset", "mbim.control.base_station.provider_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_provider_id_size,
            { "Provider Id Size", "mbim.control.base_station.provider_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_location_area_code,
            { "Location Area Code", "mbim.control.base_station.location_area_code",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cell_id,
            { "Cell Id", "mbim.control.base_station.cell_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_timing_advance,
            { "Timing Advance", "mbim.control.base_station.provider_timing_advance",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_arfcn,
            { "ARFCN", "mbim.control.base_station.arfcn",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_base_station_id,
            { "Base Station Id", "mbim.control.base_station.base_station_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_rx_level,
            { "Rx Level", "mbim.control.base_station.rx_level",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_provider_id,
            { "Provider Id", "mbim.control.base_station.provider_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_frequency_info_ul,
            { "Frequency Info Ul", "mbim.control.base_station.frequency_info_ul",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_frequency_info_dl,
            { "Frequency Info Dl", "mbim.control.base_station.frequency_info_dl",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_frequency_info_nt,
            { "Frequency Info Nt", "mbim.control.base_station.frequency_info_nt",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_uarfcn,
            { "UARFCN", "mbim.control.base_station.uarfcn",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_primary_scrambling_code,
            { "Primary Scrambling Code", "mbim.control.base_station.primary_scrambling_code",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_ecno,
            { "EcNo", "mbim.control.base_station.ecno",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_rscp,
            { "RSCP", "mbim.control.base_station.rscp",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_path_loss,
            { "Path Loss", "mbim.control.base_station.path_loss",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_call_parameter,
            { "Call Parameter", "mbim.control.base_station.call_parameter",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_earfcn,
            { "EARFCN", "mbim.control.base_station.earfcn",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_physical_cell_id,
            { "Physical Cell Id", "mbim.control.base_station.physical_cell_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_tac,
            { "TAC", "mbim.control.base_station.tac",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_rsrp,
            { "RSRP", "mbim.control.base_station.rsrp",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_rsrq,
            { "RSRQ", "mbim.control.base_station.rsrq",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_serving_cell_flag,
            { "Serving Cell Flag", "mbim.control.ms_slot_info.serving_cell_flag",
               FT_UINT32, BASE_DEC, VALS(mbim_base_station_serving_cell_flag_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nid,
            { "NID", "mbim.control.base_station.nid",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_sid,
            { "SID", "mbim.control.base_station.sid",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_base_latitude,
            { "Base Latitude", "mbim.control.base_station.base_latitude",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_base_longitude,
            { "Base Longitude", "mbim.control.base_station.base_longitude",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_ref_pn,
            { "Ref PN", "mbim.control.base_station.ref_pn",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_gps_seconds,
            { "GPS Seconds", "mbim.control.base_station.gps_seconds",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_pilot_strength,
            { "Pilot Strength", "mbim.control.base_station.pilot_strength",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nci,
            { "NCI", "mbim.control.base_station.nci",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_sinr,
            { "SINR", "mbim.control.base_station.sinr",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cell_id_offset,
            { "Cell Id Offset", "mbim.control.base_station.cell_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cell_id_size,
            { "Cell Id Size", "mbim.control.base_station.cell_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cell_id_string,
            { "Cell Id", "mbim.control.ms_app_info.cell_id",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_system_type,
            { "System Type", "mbim.control.base_station.system_type",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_system_sub_type,
            { "System Sub Type", "mbim.control.base_station.system_sub_type",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_gsm_serving_cell_offset,
            { "GSM Serving Cell Offset", "mbim.control.base_station.gsm_serving_cell_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_gsm_serving_cell_size,
            { "GSM Serving Cell size", "mbim.control.base_station.gsm_serving_cell_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_umts_serving_cell_offset,
            { "UMTS Serving Cell Offset", "mbim.control.base_station.umts_serving_cell_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_umts_serving_cell_size,
            { "UMTS Serving Cell Size", "mbim.control.base_station.umts_serving_cell_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_td_scdma_serving_cell_offset,
            { "TD-SCDMA Serving Cell Offset", "mbim.control.base_station.td_scdma_serving_cell_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_td_scdma_serving_cell_size,
            { "TD-SCDMA Serving Cell Size", "mbim.control.base_station.td_scdma_serving_cell_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_lte_serving_cell_offset,
            { "LTE Serving Cell Offset", "mbim.control.base_station.lte_serving_cell_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_lte_serving_cell_size,
            { "LTE Serving Cell Size", "mbim.control.base_station.lte_serving_cell_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_gsm_nmr_offset,
            { "GSM NMR Offset", "mbim.control.base_station.gsm_nmr_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_gsm_nmr_size,
            { "GSM NMR Size", "mbim.control.base_station.gsm_nmr_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_umts_mrl_offset,
            { "UMTS MRL Offset", "mbim.control.base_station.umts_mrl_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_umts_mrl_size,
            { "UMTS MRL Size", "mbim.control.base_station.umts_mrl_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_td_scdma_mrl_offset,
            { "TD-SCDMA MRL Offset", "mbim.control.base_station.td_scdma_mrl_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_td_scdma_mrl_size,
            { "TD-SCDMA MRL Offset", "mbim.control.base_station.td_scdma_mrl_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_lte_mrl_offset,
            { "LTE MRL Offset", "mbim.control.base_station.lte_mrl_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_lte_mrl_size,
            { "LTE MRL Size", "mbim.control.base_station.lte_mrl_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cdma_mrl_offset,
            { "CDMA MRL Offset", "mbim.control.base_station.cdma_mrl_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_cdma_mrl_size,
            { "CDMA MRL Size", "mbim.control.base_station.cdma_mrl_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nr_serving_cell_offset,
            { "NR Serving Cell Offset", "mbim.control.base_station.nr_serving_cell_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nr_serving_cell_size,
            { "NR Serving Cell Size", "mbim.control.base_station.nr_serving_cell_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nr_neighbor_cells_offset,
            { "NR Neighbor Cells Offset", "mbim.control.base_station.nr_neighbor_cells_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_nr_neighbor_cells_size,
            { "NR Neighbor Cells Size", "mbim.control.base_station.nr_neighbor_cells_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_base_station_count,
            { "Count", "mbim.control.base_station.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_version,
            { "MBIM Version", "mbim.control.bcd_mbim_version",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(mbim_version_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_extended_version,
            { "MBIM Extended Version", "mbim.control.bcd_mbim_extended_version",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(mbim_version_fmt), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_modem_config_config_status,
            { "Config Status", "mbim.control.ms_modem_config.config_status",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_modem_config_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_registration_params_info_mico_mode,
            { "Mico Mode", "mbim.control.ms_registration_params_info.mico_mode",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_mico_mode_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_registration_params_info_drx_params,
            { "DRX Params", "mbim.control.ms_registration_params_info.drx_params",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_drx_params_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_registration_params_info_ladn_info,
            { "LADN Info", "mbim.control.ms_registration_params_info.ladn_info",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_ladn_ind_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_registration_params_info_default_pdu_hint,
            { "Default PDU Hint", "mbim.control.ms_registration_params_info.default_pdu_hint",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_default_pdu_hint_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_registration_params_info_re_register_if_needed,
            { "Reregister If Needed", "mbim.control.ms_registration_params_info.re_register_if_needed",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_params_info_mico_indication,
            { "MICO indication", "mbim.control.ms_network_params_info.mico_indication",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_mico_indication_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_network_params_info_drx_params,
            { "DRX Params", "mbim.control.ms_network_params_info.drx_params",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_drx_params_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_wake_type,
            { "Wake Type", "mbim.control.ms_wake_reason.wake_type",
               FT_UINT32, BASE_DEC, VALS(hf_mbim_ms_wake_reason_wake_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_session_id,
            { "Session ID", "mbim.control.ms_wake_reason.session_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_command_payload_offset,
            { "Payload Offset", "mbim.control.ms_wake_reason.command_payload_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_command_payload_size,
            { "Payload Size", "mbim.control.ms_wake_reason.command_payload_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_command_payload,
            { "Payload", "mbim.control.ms_wake_reason.command_payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_packet_original_size,
            { "Original Size", "mbim.control.ms_wake_reason.packet_original_size",
                FT_UINT32, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_packet_saved_offset,
            { "Saved Offset", "mbim.control.ms_wake_reason.packet_saved_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_packet_saved_size,
            { "Saved Size", "mbim.control.ms_wake_reason.packet_saved_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_wake_reason_packet_saved_data,
            { "Saved Data", "mbim.control.ms_wake_reason.packet_saved_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_slot_id,
            { "Slot Id", "mbim.control.ms_dual_sim.slot_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_open_channel_app_id_size,
            { "App Id Size", "mbim.control.ms_open_channel.app_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_open_channel_app_id_offset,
            { "App Id Offset", "mbim.control.ms_open_channel.app_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_open_channel_select_p2_arg,
            { "Select P2 Arg", "mbim.control.ms_open_channel.select_p2_arg",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_channel_group,
            { "Channel Group", "mbim.control.ms_uicc.channel_group",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_open_channel_app_id,
            { "App Id", "mbim.control.ms_open_channel.app_id",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_status,
            { "Status", "mbim.control.ms_uicc.status",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_channel,
            { "Channel", "mbim.control.ms_uicc.channel",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_response_length,
            { "Response Length", "mbim.control.ms_uicc.response_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_response_offset,
            { "Response Offset", "mbim.control.ms_uicc.response_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_uicc_response,
            { "Response", "mbim.control.ms_uicc.response",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_apdu_secure_messaging,
            { "Secure messaging", "mbim.control.ms_apdu.secure_messaging",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_apdu_secure_messaging_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_apdu_type,
            { "Type", "mbim.control.ms_apdu.type",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_apdu_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_apdu_command_size,
            { "Command Size", "mbim.control.ms_apdu.command_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_apdu_command_offset,
            { "Command Offset", "mbim.control.ms_apdu.command_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_apdu_command,
            { "Command", "mbim.control.ms_apdu.command",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_terminal_capability_count,
            { "Capability Count", "mbim.control.ms_terminal_capability.count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_terminal_capability_offset,
            { "Capability offset", "mbim.control.ms_terminal_capability.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_terminal_capability_size,
            { "Capability size", "mbim.control.ms_terminal_capability.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_terminal_capability,
            { "Capability", "mbim.control.ms_terminal_capability.capability",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_reset_pass_through_action,
            { "Type", "mbim.control.ms_reset.pass_through_action",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_reset_pass_through_action_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_atr_info_atr_offset,
            { "ATR Offset", "mbim.control.ms_atr_info.atr_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_atr_info_atr_size,
            { "ATR Size", "mbim.control.ms_atr_info.atr_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_type,
            { "App Type", "mbim.control.ms_app_info.app_type",
               FT_UINT32, BASE_DEC, VALS(mbim_ms_uicc_app_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_id_offset,
            { "App ID Offset", "mbim.control.ms_app_info.app_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_id_size,
            { "App ID Size", "mbim.control.ms_app_info.app_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_id,
            { "App ID", "mbim.control.ms_app_info.app_id",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_name_offset,
            { "App Name Offset", "mbim.control.ms_app_info.app_name_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_name_size,
            { "App Name Size", "mbim.control.ms_app_info.app_name_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_app_name,
            { "App Name", "mbim.control.ms_app_info.app_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_num_pins,
            { "Num Pins", "mbim.control.ms_app_info.num_pins",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_pin_ref_offset,
            { "Pin Ref Offset", "mbim.control.ms_app_info.pin_ref_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_pin_ref_size,
            { "Pin Ref Size", "mbim.control.ms_app_info.pin_ref_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_info_pin_ref,
            { "Pin Ref", "mbim.control.ms_app_info.pin_ref",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_version,
            { "Version", "mbim.control.ms_app_list.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_app_count,
            { "App Count", "mbim.control.ms_app_list.app_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_active_app_index,
            { "Active App Index", "mbim.control.ms_app_list.active_app_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_size,
            { "App List Size", "mbim.control.ms_app_list.app_list_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_app_info_offset,
            { "App Info Offset", "mbim.control.ms_app_list.app_info_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_app_list_app_info_size,
            { "App Info Size", "mbim.control.ms_app_list.app_info_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_version,
            { "Version", "mbim.control.ms_file_path.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_app_id_offset,
            { "App ID Offset", "mbim.control.ms_file_path.app_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_app_id_size,
            { "App ID Size", "mbim.control.ms_file_path.app_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_file_path_offset,
            { "File Path Offset", "mbim.control.ms_file_path.file_path_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_file_path_size,
            { "File Path Size", "mbim.control.ms_file_path.file_path_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_app_id,
            { "App ID", "mbim.control.ms_file_path.app_id",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_path_file_path,
            { "File Path", "mbim.control.ms_file_path.file_path",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_version,
            { "Version", "mbim.control.ms_file_status.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_status_word_1,
            { "Status Word 1", "mbim.control.ms_file_status.status_word_1",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_status_word_2,
            { "Status Word 2", "mbim.control.ms_file_status.status_word_2",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_file_accessibility,
            { "File Accessibility", "mbim.control.ms_file_status.file_accessibility",
               FT_UINT32, BASE_DEC, VALS(mbim_uicc_file_accessibility_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_file_type,
            { "File Type", "mbim.control.ms_file_status.file_type",
               FT_UINT32, BASE_DEC, VALS(mbim_uicc_file_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_file_structure,
            { "File Structure", "mbim.control.ms_file_status.file_structure",
               FT_UINT32, BASE_DEC, VALS(mbim_uicc_file_structure_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_item_count,
            { "Item Count", "mbim.control.ms_file_status.item_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_size,
            { "Size", "mbim.control.ms_file_status.size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_file_status_file_lock_status,
            { "File Lock Status", "mbim.control.ms_file_status.file_lock_status",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_version,
            { "Version", "mbim.control.ms_response.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_status_word_1,
            { "Status Word 1", "mbim.control.ms_response.status_word_1",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_status_word_2,
            { "Status Word 2", "mbim.control.ms_response.status_word_2",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_response_data_offset,
            { "Data Offset", "mbim.control.ms_response.response_data_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_response_data_size,
            { "Data Size", "mbim.control.ms_response.response_data_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_response_response_data,
            { "Response Data", "mbim.control.ms_response.response_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_version,
            { "Version", "mbim.control.ms_access_binary.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_app_id_offset,
            { "App ID Offset", "mbim.control.ms_access_binary.app_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_app_id_size,
            { "App ID Size", "mbim.control.ms_access_binary.app_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_file_path_offset,
            { "File Path Offset", "mbim.control.ms_access_binary.file_path_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_file_path_size,
            { "File Path Size", "mbim.control.ms_access_binary.file_path_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_file_offset,
            { "File Offset", "mbim.control.ms_access_binary.file_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_number_of_bytes,
            { "Number of Bytes", "mbim.control.ms_access_binary.number_of_bytes",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_local_pin_offset,
            { "Local Pin Offset", "mbim.control.ms_access_binary.local_pin_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_local_pin_size,
            { "Local Pin Size", "mbim.control.ms_access_binary.local_pin_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_binary_data_offset,
            { "Binary Data Offset", "mbim.control.ms_access_binary.binary_data_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_binary_data_size,
            { "Binary Data Size", "mbim.control.ms_access_binary.binary_data_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_app_id,
            { "App ID", "mbim.control.ms_access_binary.app_id",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_file_path,
            { "File Path", "mbim.control.ms_access_binary.file_path",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_local_pin,
            { "Local Pin", "mbim.control.ms_access_binary.local_pin",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_binary_binary_data,
            { "Binary Data", "mbim.control.ms_access_binary.binary_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_version,
            { "Version", "mbim.control.ms_access_record.version",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_app_id_offset,
            { "App ID Offset", "mbim.control.ms_access_record.app_id_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_app_id_size,
            { "App ID Size", "mbim.control.ms_access_record.app_id_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_file_path_offset,
            { "File Path Offset", "mbim.control.ms_access_record.file_path_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_file_path_size,
            { "File Path Size", "mbim.control.ms_access_record.file_path_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_record_number,
            { "Record Number", "mbim.control.ms_access_record.record_number",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_local_pin_offset,
            { "Local Pin Offset", "mbim.control.ms_access_record.local_pin_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_local_pin_size,
            { "Local Pin Size", "mbim.control.ms_access_record.local_pin_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_record_data_offset,
            { "Record Data Offset", "mbim.control.ms_access_record.record_data_offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_record_data_size,
            { "Record Data Size", "mbim.control.ms_access_record.record_data_size",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_app_id,
            { "App ID", "mbim.control.ms_access_record.app_id",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_file_path,
            { "File Path", "mbim.control.ms_access_record.file_path",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_local_pin,
            { "Local Pin", "mbim.control.ms_access_record.local_pin",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_ms_access_record_record_data,
            { "Record_Data", "mbim.control.ms_access_record.record_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragmented_payload,
            { "Fragmented Payload", "mbim.control.fragmented_payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_request_in,
            { "Request In", "mbim.control.request_in",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
              NULL, HFILL }
        },
        { &hf_mbim_response_in,
            { "Response In", "mbim.control.response_in",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
              NULL, HFILL }
        },
        { &hf_mbim_descriptor,
            { "Descriptor", "mbim.descriptor",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_descriptor_version,
            { "bcdMBIMVersion", "mbim.descriptor.version",
               FT_UINT16, BASE_HEX, NULL, 0,
              "MBIM Version", HFILL }
        },
        { &hf_mbim_descriptor_max_control_message,
            { "wMaxControlMessage", "mbim.descriptor.max_control_message",
               FT_UINT16, BASE_DEC, NULL, 0,
              "Max Control Message", HFILL }
        },
        { &hf_mbim_descriptor_number_filters,
            { "bNumberFilters", "mbim.descriptor.number_filters",
               FT_UINT8, BASE_DEC, NULL, 0,
              "Number Of Packet Filters", HFILL }
        },
        { &hf_mbim_descriptor_max_filter_size,
            { "bMaxFilterSize", "mbim.descriptor.max_filter_size",
               FT_UINT8, BASE_DEC, NULL, 0,
              "Max Packet Filter Size", HFILL }
        },
        { &hf_mbim_descriptor_max_segment_size,
            { "wMaxSegmentSize", "mbim.descriptor.max_segment_size",
               FT_UINT16, BASE_DEC, NULL, 0,
              "Max Segment Size", HFILL }
        },
        { &hf_mbim_descriptor_network_capabilities,
            { "bmNetworkCapabilities", "mbim.descriptor.network_capabilities",
               FT_UINT8, BASE_HEX, NULL, 0,
              "Network Capabilities", HFILL }
        },
        { &hf_mbim_descriptor_network_capabilities_max_datagram_size,
            { "SetMaxDatagramSize/GetMaxDatagramSize", "mbim.descriptor.network_capabilities.max_datagram_size",
               FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
              NULL, HFILL }
        },
        { &hf_mbim_descriptor_network_capabilities_ntb_input_size,
            { "8-byte GetNtbInputSize/SetNtbInputSize", "mbim.descriptor.network_capabilities.ntb_input_size",
               FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
              NULL, HFILL }
        },
        { &hf_mbim_descriptor_extended_version,
            { "bcdMBIMExtendedVersion", "mbim.descriptor.extended_version",
               FT_UINT16, BASE_HEX, NULL, 0,
              "MBIM Extended Version", HFILL }
        },
        { &hf_mbim_descriptor_max_outstanding_command_messages,
            { "bMaxOutstandingCommandMessages", "mbim.descriptor.max_outstanding_command_messages",
               FT_UINT8, BASE_DEC, NULL, 0,
              "Max Outstanding Messages", HFILL }
        },
        { &hf_mbim_descriptor_mtu,
            { "wMTU", "mbim.descriptor.mtu",
               FT_UINT16, BASE_DEC, NULL, 0,
              "MTU", HFILL }
        },
        { &hf_mbim_bulk,
            { "Bulk", "mbim.bulk",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_signature,
            { "Signature", "mbim.bulk.nth.signature",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_header_length,
            { "Header Length", "mbim.bulk.nth.header_length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_sequence_number,
            { "Sequence Number", "mbim.bulk.nth.sequence_number",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_block_length,
            { "Block Length", "mbim.bulk.nth.block_length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_block_length_32,
            { "Block Length", "mbim.bulk.nth.block_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_ndp_index,
            { "NDP Index", "mbim.bulk.nth.ndp_index",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_nth_ndp_index_32,
            { "NDP Index", "mbim.bulk.nth.ndp_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_signature,
            { "Signature", "mbim.bulk.ndp.signature",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_signature_ips_session_id,
            { "IPS Session Id", "mbim.bulk.ndp.signature.ips_session_id",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_signature_ipc_session_id,
            { "IPC Session Id", "mbim.bulk.ndp.signature.ipc_session_id",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_signature_dss_session_id,
            { "DSS Session Id", "mbim.bulk.ndp.signature.dss_session_id",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_signature_dsc_session_id,
            { "DSC Session Id", "mbim.bulk.ndp.signature.dsc_session_id",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_length,
            { "Length", "mbim.bulk.ndp.length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_next_ndp_index,
            { "Next NDP Index", "mbim.bulk.ndp.next_ndp_index",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_next_ndp_index_32,
            { "Next NDP Index", "mbim.bulk.ndp.next_ndp_index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_reserved,
            { "Reserved", "mbim.bulk.ndp.reserved",
               FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_reserved2,
            { "Reserved", "mbim.bulk.ndp.reserved",
               FT_UINT32, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_datagram_index,
            { "Datagram Index", "mbim.bulk.ndp.datagram.index",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_datagram_index_32,
            { "Datagram Index", "mbim.bulk.ndp.datagram.index",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_datagram_length,
            { "Datagram Length", "mbim.bulk.ndp.datagram.length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_datagram_length_32,
            { "Datagram Length", "mbim.bulk.ndp.datagram.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_datagram,
            { "Datagram", "mbim.bulk.ndp.datagram",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_nb_datagrams,
            { "Number Of Datagrams", "mbim.bulk.ndp.nb_datagrams",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_total_nb_datagrams,
            { "Total Number Of Datagrams", "mbim.bulk.total_nb_datagrams",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl,
            { "NDP Control", "mbim.bulk.ndp_control",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl_message_type,
            { "Message Type", "mbim.bulk.ndp_control.message_type",
               FT_UINT16, BASE_HEX, VALS(mbim_ndp_ctrl_msg_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl_message_length,
            { "Message Length", "mbim.bulk.ndp_control.message_length",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl_multiflow_status,
            { "Multiflow Status", "mbim.bulk.ndp_control.multiflow.status",
               FT_UINT16, BASE_DEC, VALS(mbim_ndp_ctrl_multiflow_status_vals), 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl_multiflow_watermark,
            { "Multiflow Watermark", "mbim.bulk.ndp_control.multiflow.watermark",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_bulk_ndp_ctrl_message_payload,
            { "Message Payload", "mbim.bulk.ndp_control.message_payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragments,
            { "Fragments", "mbim.control.fragments",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment,
            { "Fragment", "mbim.control.fragment",
               FT_FRAMENUM, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_overlap,
            { "Fragment Overlap", "mbim.control.fragment_overlap",
               FT_BOOLEAN, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_overlap_conflict,
            { "Fragment Overlap Conflict", "mbim.control.fragment_overlap_conflict",
               FT_BOOLEAN, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_multiple_tails,
            { "Fragment Multiple Tails", "mbim.control.fragment_multiple_tails",
               FT_BOOLEAN, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_too_long_fragment,
            { "Too Long Fragment", "mbim.control.fragment_too_long_fragment",
               FT_BOOLEAN, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_error,
            { "Fragment Error", "mbim.control.fragment_error",
               FT_FRAMENUM, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_fragment_count,
            { "Fragment Count", "mbim.control.fragment_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_reassembled_in,
            { "Reassembled In", "mbim.control.reassembled_in",
               FT_FRAMENUM, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_reassembled_length,
            { "Reassembled Length", "mbim.control.reassembled_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_mbim_reassembled_data,
            { "Reassembled Data", "mbim.control.reassembled_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_mbim,
        &ett_mbim_msg_header,
        &ett_mbim_frag_header,
        &ett_mbim_info_buffer,
        &ett_mbim_bitmap,
        &ett_mbim_pair_list,
        &ett_mbim_pin,
        &ett_mbim_buffer,
        &ett_mbim_sc_address,
        &ett_mbim_pac,
        &ett_mbim_thermal_threshold_setting,
        &ett_mbim_fragment,
        &ett_mbim_fragments,
        &ett_mbim_bulk_ndp_ctrl
    };

    static ei_register_info ei[] = {
        { &ei_mbim_max_ctrl_transfer,
            { "mbim.max_control_transfer_too_small", PI_MALFORMED, PI_ERROR,
                "Max Control Transfer is less than 64 bytes", EXPFILL }},
        { &ei_mbim_unexpected_msg,
            { "mbim.unexpected_msg", PI_MALFORMED, PI_ERROR,
                "Unexpected message", EXPFILL }},
        { &ei_mbim_unexpected_info_buffer,
            { "mbim.unexpected_info_buffer", PI_MALFORMED, PI_WARN,
                "Unexpected Information Buffer", EXPFILL }},
        { &ei_mbim_illegal_on_link_prefix_length,
            { "mbim.illegal_on_link_prefix_length", PI_MALFORMED, PI_WARN,
                "Illegal On Link Prefix Length", EXPFILL }},
        { &ei_mbim_unknown_sms_format,
            { "mbim.unknown_sms_format", PI_PROTOCOL, PI_WARN,
                "Unknown SMS format", EXPFILL }},
        { &ei_mbim_unexpected_uuid_value,
            { "mbim.unexpected_uuid_value", PI_PROTOCOL, PI_WARN,
                "Unexpected UUID value", EXPFILL }},
        { &ei_mbim_too_many_items,
            { "mbim.too_many_items", PI_PROTOCOL, PI_WARN,
                "Too many items", EXPFILL }},
        { &ei_mbim_alignment_error,
            { "mbim.alignment_error", PI_MALFORMED, PI_ERROR,
                "Alignment error", EXPFILL }},
        { &ei_mbim_invalid_block_len,
            { "mbim.invalid_block_len", PI_PROTOCOL, PI_WARN,
                "NTH Block Length does not match packet length", EXPFILL }},
        { &ei_mbim_out_of_bounds_index,
            { "mbim.out_of_bounds_index", PI_MALFORMED, PI_ERROR,
                "Index is out of bounds", EXPFILL }},
        { &ei_mbim_oversized_string,
            { "mbim.oversized_string", PI_PROTOCOL, PI_WARN,
                "String exceeds maximum size allowed", EXPFILL }},
        { &ei_mbim_oversized_pdu,
            { "mbim.oversized_pdu", PI_PROTOCOL, PI_WARN,
                "PDU exceeds maximum size allowed", EXPFILL }}
    };

    proto_mbim = proto_register_protocol("Mobile Broadband Interface Model",
            "MBIM", "mbim");

    proto_register_field_array(proto_mbim, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mbim = expert_register_protocol(proto_mbim);
    expert_register_field_array(expert_mbim, ei, array_length(ei));

    reassembly_table_register(&mbim_reassembly_table,
                          &addresses_reassembly_table_functions);

    mbim_control_handle = register_dissector("mbim.control", dissect_mbim_control, proto_mbim);
    register_dissector("mbim.descriptor", dissect_mbim_descriptor, proto_mbim);
    register_dissector("mbim.bulk", dissect_mbim_bulk, proto_mbim);
    dss_dissector_table = register_dissector_table("mbim.dss_session_id",
        "MBIM DSS Session Id", proto_mbim, FT_UINT8, BASE_DEC);

    mbim_module = prefs_register_protocol(proto_mbim, proto_reg_handoff_mbim);
    prefs_register_obsolete_preference(mbim_module, "bulk_heuristic");
    prefs_register_bool_preference(mbim_module, "control_decode_unknown_itf",
        "Force decoding of unknown USB control data as MBIM",
        "Decode control data received on \"usb.control\" with an "
        "unknown interface class as MBIM",
        &mbim_control_decode_unknown_itf);
    prefs_register_enum_preference(mbim_module, "sms_pdu_format",
        "SMS PDU format",
        "Format used for SMS PDU decoding",
        &mbim_sms_pdu_format, mbim_sms_pdu_format_vals, FALSE);

    prefs_register_enum_preference(mbim_module, "extended_version",
        "Preferred MBIM Extended Version for decoding when MBIM_CID_VERSION not captured",
        NULL,
        &preferred_mbim_extended_version, preferred_mbim_extended_version_vals, FALSE);
}

void
proto_reg_handoff_mbim(void)
{
    static gboolean initialized = FALSE, mbim_control_decode_unknown_itf_prev = FALSE;

    if (!initialized) {
        dissector_handle_t mbim_decode_as_handle = create_dissector_handle(dissect_mbim_decode_as, proto_mbim);
        bertlv_handle = find_dissector_add_dependency("gsm_sim.bertlv", proto_mbim);
        etsi_cat_handle = find_dissector_add_dependency("etsi_cat", proto_mbim);
        gsm_sms_handle = find_dissector_add_dependency("gsm_sms", proto_mbim);
        cdma_sms_handle = find_dissector_add_dependency("ansi_637_trans", proto_mbim);
        eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_mbim);
        eth_fcs_handle = find_dissector_add_dependency("eth_withfcs", proto_mbim);
        ip_handle = find_dissector_add_dependency("ip", proto_mbim);
        iso7816_atr_handle = find_dissector_add_dependency("iso7816.atr", proto_mbim);
        data_handle = find_dissector("data");
        bulk_ndp_ctrl_handle = create_dissector_handle(dissect_mbim_bulk_ndp_ctrl, proto_mbim);
        heur_dissector_add("usb.bulk", dissect_mbim_bulk_heur, "MBIM USB bulk endpoint", "mbim_usb_bulk", proto_mbim, HEURISTIC_ENABLE);
        dissector_add_for_decode_as("usb.device", mbim_decode_as_handle);
        dissector_add_for_decode_as("usb.product", mbim_decode_as_handle);
        dissector_add_for_decode_as("usb.protocol", mbim_decode_as_handle);
        initialized = TRUE;
    }
    if (mbim_control_decode_unknown_itf != mbim_control_decode_unknown_itf_prev) {
        if (mbim_control_decode_unknown_itf) {
            dissector_add_uint("usb.control", IF_CLASS_UNKNOWN, mbim_control_handle);
        } else {
            dissector_delete_uint("usb.control", IF_CLASS_UNKNOWN, mbim_control_handle);
        }
        mbim_control_decode_unknown_itf_prev = mbim_control_decode_unknown_itf;
    }
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
