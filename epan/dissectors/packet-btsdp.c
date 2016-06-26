/* packet-btsdp.c
 * Routines for Bluetooth SDP dissection
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 * Copyright 2006, Ronnie Sahlberg
 *     - refactored for Wireshark checkin
 * Copyright 2013, Michal Labedzki  for Tieto Corporation
 *     - support SDP fragmentation (Continuation State)
 *     - implement DI 1.3
 *     - dissect profile specific attributes
 *     - fix service recognize
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
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/to_str.h>
#include <epan/iana_charsets.h>

#include "packet-btsdp.h"
#include "packet-btl2cap.h"

static gint proto_btsdp                                                    = -1;

static gint hf_pdu_id                                                      = -1;
static gint hf_tid                                                         = -1;
static gint hf_parameter_length                                            = -1;
static gint hf_ssr_total_count                                             = -1;
static gint hf_ssr_current_count                                           = -1;
static gint hf_error_code                                                  = -1;
static gint hf_attribute_id_list                                           = -1;
static gint hf_attribute_id_range                                          = -1;
static gint hf_attribute_id_range_from                                     = -1;
static gint hf_attribute_id_range_to                                       = -1;
static gint hf_attribute_list_byte_count                                   = -1;
static gint hf_maximum_service_record_count                                = -1;
static gint hf_maximum_attribute_byte_count                                = -1;
static gint hf_continuation_state                                          = -1;
static gint hf_continuation_state_length                                   = -1;
static gint hf_continuation_state_value                                    = -1;
static gint hf_fragment                                                    = -1;
static gint hf_partial_record_handle_list                                  = -1;
static gint hf_reassembled_record_handle_list                              = -1;
static gint hf_partial_attribute_list                                      = -1;
static gint hf_reassembled_attribute_list                                  = -1;
static gint hf_data_element                                                = -1;
static gint hf_data_element_size                                           = -1;
static gint hf_data_element_type                                           = -1;
static gint hf_data_element_var_size                                       = -1;
static gint hf_data_element_value                                          = -1;
static gint hf_data_element_value_nil                                      = -1;
static gint hf_data_element_value_boolean                                  = -1;
static gint hf_data_element_value_signed_int                               = -1;
static gint hf_data_element_value_unsigned_int                             = -1;
static gint hf_data_element_value_uuid_16                                  = -1;
static gint hf_data_element_value_uuid_32                                  = -1;
static gint hf_data_element_value_uuid_128                                 = -1;
static gint hf_data_element_value_uuid                                     = -1;
static gint hf_data_element_value_string                                   = -1;
static gint hf_data_element_value_url                                      = -1;
static gint hf_data_element_value_alternative                              = -1;
static gint hf_data_element_value_sequence                                 = -1;
static gint hf_profile_descriptor_list                                     = -1;
static gint hf_attribute_list                                              = -1;
static gint hf_attribute_lists                                             = -1;
static gint hf_service_search_pattern                                      = -1;
static gint hf_service_record_handle_list                                  = -1;
static gint hf_service_attribute                                           = -1;
static gint hf_service_attribute_id                                        = -1;
static gint hf_service_attribute_value                                     = -1;
static gint hf_service_attribute_id_generic                                = -1;
static gint hf_service_attribute_id_a2dp                                   = -1;
static gint hf_service_attribute_id_avrcp                                  = -1;
static gint hf_service_attribute_id_ctp                                    = -1;
static gint hf_service_attribute_id_bip_imaging_responder                  = -1;
static gint hf_service_attribute_id_bip_imaging_other                      = -1;
static gint hf_service_attribute_id_bpp                                    = -1;
static gint hf_service_attribute_id_bpp_rui                                = -1;
static gint hf_service_attribute_id_did                                    = -1;
static gint hf_service_attribute_id_dun                                    = -1;
static gint hf_service_attribute_id_fax                                    = -1;
static gint hf_service_attribute_id_ftp                                    = -1;
static gint hf_service_attribute_id_gnss                                   = -1;
static gint hf_service_attribute_id_hfp_hf                                 = -1;
static gint hf_service_attribute_id_hfp_ag                                 = -1;
static gint hf_service_attribute_id_hcrp                                   = -1;
static gint hf_service_attribute_id_hsp                                    = -1;
static gint hf_service_attribute_id_hdp                                    = -1;
static gint hf_service_attribute_id_hid                                    = -1;
static gint hf_service_attribute_id_wap                                    = -1;
static gint hf_service_attribute_id_map_mas                                = -1;
static gint hf_service_attribute_id_map_mns                                = -1;
static gint hf_service_attribute_id_opp                                    = -1;
static gint hf_service_attribute_id_pan_nap                                = -1;
static gint hf_service_attribute_id_pan_gn                                 = -1;
static gint hf_service_attribute_id_pan_panu                               = -1;
static gint hf_service_attribute_id_pbap                                   = -1;
static gint hf_service_attribute_id_synch                                  = -1;
static gint hf_service_attribute_id_ctn_as                                 = -1;
static gint hf_service_attribute_id_ctn_ns                                 = -1;
static gint hf_service_attribute_id_mps                                    = -1;
static gint hf_did_specification_id                                        = -1;
static gint hf_did_vendor_id                                               = -1;
static gint hf_did_vendor_id_bluetooth_sig                                 = -1;
static gint hf_did_vendor_id_usb_forum                                     = -1;
static gint hf_did_product_id                                              = -1;
static gint hf_did_primary_record                                          = -1;
static gint hf_did_version                                                 = -1;
static gint hf_did_vendor_id_source                                        = -1;
static gint hf_a2dp_sink_supported_features_reserved                       = -1;
static gint hf_a2dp_sink_supported_features_amplifier                      = -1;
static gint hf_a2dp_sink_supported_features_recorder                       = -1;
static gint hf_a2dp_sink_supported_features_speaker                        = -1;
static gint hf_a2dp_sink_supported_features_headphone                      = -1;
static gint hf_a2dp_source_supported_features_reserved                     = -1;
static gint hf_a2dp_source_supported_features_mixer                        = -1;
static gint hf_a2dp_source_supported_features_tuner                        = -1;
static gint hf_a2dp_source_supported_features_microphone                   = -1;
static gint hf_a2dp_source_supported_features_player                       = -1;
static gint hf_synch_supported_data_store                                  = -1;
static gint hf_ctp_external_network                                        = -1;
static gint hf_avrcp_ct_supported_features_reserved_7_15                   = -1;
static gint hf_avrcp_ct_supported_features_browsing                        = -1;
static gint hf_avrcp_ct_supported_features_reserved_4_5                    = -1;
static gint hf_avrcp_ct_supported_features_category_4                      = -1;
static gint hf_avrcp_ct_supported_features_category_3                      = -1;
static gint hf_avrcp_ct_supported_features_category_2                      = -1;
static gint hf_avrcp_ct_supported_features_category_1                      = -1;
static gint hf_avrcp_tg_supported_features_reserved_8_15                   = -1;
static gint hf_avrcp_tg_supported_features_multiple_player                 = -1;
static gint hf_avrcp_tg_supported_features_browsing                        = -1;
static gint hf_avrcp_tg_supported_features_group_navigation                = -1;
static gint hf_avrcp_tg_supported_features_settings                        = -1;
static gint hf_avrcp_tg_supported_features_category_4                      = -1;
static gint hf_avrcp_tg_supported_features_category_3                      = -1;
static gint hf_avrcp_tg_supported_features_category_2                      = -1;
static gint hf_avrcp_tg_supported_features_category_1                      = -1;
static gint hf_hsp_remote_audio_volume_control                             = -1;
static gint hf_gnss_supported_features                                     = -1;
static gint hf_pbap_pse_supported_repositories                             = -1;
static gint hf_pbap_pse_supported_repositories_reserved                    = -1;
static gint hf_pbap_pse_supported_repositories_favourites                  = -1;
static gint hf_pbap_pse_supported_repositories_speed_dial                  = -1;
static gint hf_pbap_pse_supported_repositories_sim_card                    = -1;
static gint hf_pbap_pse_supported_repositories_local_phonebook             = -1;
static gint hf_fax_support_class_1                                         = -1;
static gint hf_fax_support_class_2                                         = -1;
static gint hf_fax_support_class_2_vendor                                  = -1;
static gint hf_fax_support_audio_feedback                                  = -1;
static gint hf_ftp_goep_l2cap_psm                                          = -1;
static gint hf_map_mas_instance_id                                         = -1;
static gint hf_map_mas_supported_message_types_reserved                    = -1;
static gint hf_map_mas_supported_message_types_mms                         = -1;
static gint hf_map_mas_supported_message_types_sms_cdma                    = -1;
static gint hf_map_mas_supported_message_types_sms_gsm                     = -1;
static gint hf_map_mas_supported_message_types_email                       = -1;
static gint hf_hcrp_1284_id                                                = -1;
static gint hf_hcrp_device_location                                        = -1;
static gint hf_hcrp_device_name                                            = -1;
static gint hf_hcrp_friendly_name                                          = -1;
static gint hf_wap_network_address                                         = -1;
static gint hf_wap_gateway                                                 = -1;
static gint hf_wap_homepage_url                                            = -1;
static gint hf_wap_stack_type                                              = -1;
static gint hf_hdp_data_exchange                                           = -1;
static gint hf_hdp_support_procedure_reserved_5_7                          = -1;
static gint hf_hdp_support_procedure_sync_master_role                      = -1;
static gint hf_hdp_support_procedure_clock_synchronization_protocol        = -1;
static gint hf_hdp_support_procedure_reconnect_acceptance                  = -1;
static gint hf_hdp_support_procedure_reconnect_initiation                  = -1;
static gint hf_hdp_support_procedure_reserved                              = -1;
static gint hf_hdp_supported_features_data                                 = -1;
static gint hf_hdp_supported_features_data_mdep_id                         = -1;
static gint hf_hdp_supported_features_data_mdep_data_type                  = -1;
static gint hf_hdp_supported_features_data_mdep_role                       = -1;
static gint hf_hdp_supported_features_data_mdep_description                = -1;
static gint hf_hdp_supported_features_mdep_id                              = -1;
static gint hf_hdp_supported_features_mdep_data_type                       = -1;
static gint hf_hdp_supported_features_mdep_role                            = -1;
static gint hf_hdp_supported_features_mdep_description                     = -1;
static gint hf_pan_sercurity_description                                   = -1;
static gint hf_pan_ipv4_subnet                                             = -1;
static gint hf_pan_ipv6_subnet                                             = -1;
static gint hf_pan_max_net_access_rate                                     = -1;
static gint hf_pan_net_access_type                                         = -1;
static gint hf_opp_goep_l2cap_psm                                          = -1;
static gint hf_opp_supported_format                                        = -1;
static gint hf_dun_escape_sequence                                         = -1;
static gint hf_dun_support_audio_feedback                                  = -1;
static gint hf_hfp_hf_supported_features_reserved                          = -1;
static gint hf_hfp_hf_supported_features_wide_band_speech                  = -1;
static gint hf_hfp_hf_supported_features_remote_volume_control             = -1;
static gint hf_hfp_hf_supported_features_voice_recognition_activation      = -1;
static gint hf_hfp_hf_supported_features_cli_presentation_capability       = -1;
static gint hf_hfp_hf_supported_features_call_waiting_or_three_way_calling = -1;
static gint hf_hfp_hf_supported_features_ec_and_or_nr_function             = -1;
static gint hf_hfp_gw_network                                              = -1;
static gint hf_hfp_gw_supported_features_reserved                          = -1;
static gint hf_hfp_gw_supported_features_wide_band_speech                  = -1;
static gint hf_hfp_gw_supported_features_attach_phone_number_to_voice_tag  = -1;
static gint hf_hfp_gw_supported_features_inband_ring_tone_capability       = -1;
static gint hf_hfp_gw_supported_features_voice_recognition_function        = -1;
static gint hf_hfp_gw_supported_features_ec_and_or_nr_function             = -1;
static gint hf_hfp_gw_supported_features_three_way_calling                 = -1;
static gint hf_sdp_protocol_item                                           = -1;
static gint hf_sdp_protocol                                                = -1;
static gint hf_sdp_protocol_psm                                            = -1;
static gint hf_sdp_protocol_channel                                        = -1;
static gint hf_sdp_protocol_gatt_handle_start                              = -1;
static gint hf_sdp_protocol_gatt_handle_end                                = -1;
static gint hf_sdp_protocol_version                                        = -1;
static gint hf_sdp_protocol_bnep_type                                      = -1;
static gint hf_sdp_service_record_handle                                   = -1;
static gint hf_sdp_service_record_state                                    = -1;
static gint hf_sdp_service_info_time_to_live                               = -1;
static gint hf_sdp_service_availability                                    = -1;
static gint hf_sdp_service_documentation_url                               = -1;
static gint hf_sdp_service_client_executable_url                           = -1;
static gint hf_sdp_service_icon_url                                        = -1;
static gint hf_sdp_service_name                                            = -1;
static gint hf_sdp_service_description                                     = -1;
static gint hf_sdp_service_provider_name                                   = -1;
static gint hf_sdp_lang                                                    = -1;
static gint hf_sdp_lang_id                                                 = -1;
static gint hf_sdp_lang_code                                               = -1;
static gint hf_sdp_lang_encoding                                           = -1;
static gint hf_sdp_lang_attribute_base                                     = -1;
static gint hf_hid_descriptor_list_descriptor_data                         = -1;
static gint hf_hid_lang                                                    = -1;
static gint hf_hid_device_release_number                                   = -1;
static gint hf_hid_parser_version                                          = -1;
static gint hf_hid_device_subclass_type                                    = -1;
static gint hf_hid_device_subclass_subtype                                 = -1;
static gint hf_hid_device_subclass_reserved                                = -1;
static gint hf_hid_country_code                                            = -1;
static gint hf_hid_virtual_cable                                           = -1;
static gint hf_hid_reconnect_initiate                                      = -1;
static gint hf_hid_sdp_disable                                             = -1;
static gint hf_hid_battery_power                                           = -1;
static gint hf_hid_remote_wake                                             = -1;
static gint hf_hid_profile_version                                         = -1;
static gint hf_hid_supervision_timeout                                     = -1;
static gint hf_hid_normally_connectable                                    = -1;
static gint hf_hid_boot_device                                             = -1;
static gint hf_hid_ssr_host_max_latency                                    = -1;
static gint hf_hid_ssr_host_min_timeout                                    = -1;
static gint hf_hid_descriptor_list_type                                    = -1;
static gint hf_hid_descriptor_list_descriptor                              = -1;
static gint hf_bip_goep_l2cap_psm                                          = -1;
static gint hf_bip_supported_capabilities_reserved_4_7                     = -1;
static gint hf_bip_supported_capabilities_displaying                       = -1;
static gint hf_bip_supported_capabilities_printing                         = -1;
static gint hf_bip_supported_capabilities_capturing                        = -1;
static gint hf_bip_supported_capabilities_genering_imaging                 = -1;
static gint hf_bip_supported_features_reserved_9_15                        = -1;
static gint hf_bip_supported_features_remote_display                       = -1;
static gint hf_bip_supported_features_remote_camera                        = -1;
static gint hf_bip_supported_features_automatic_archive                    = -1;
static gint hf_bip_supported_features_advanced_image_printing              = -1;
static gint hf_bip_supported_features_image_pull                           = -1;
static gint hf_bip_supported_features_image_push_display                   = -1;
static gint hf_bip_supported_features_image_push_print                     = -1;
static gint hf_bip_supported_features_image_push_store                     = -1;
static gint hf_bip_supported_features_image_push                           = -1;
static gint hf_bip_supported_functions_reserved_17_31                      = -1;
static gint hf_bip_supported_functions_get_status                          = -1;
static gint hf_bip_supported_functions_reserved_15                         = -1;
static gint hf_bip_supported_functions_get_monitoring_image                = -1;
static gint hf_bip_supported_functions_start_archive                       = -1;
static gint hf_bip_supported_functions_reserved_12                         = -1;
static gint hf_bip_supported_functions_start_print                         = -1;
static gint hf_bip_supported_functions_delete_image                        = -1;
static gint hf_bip_supported_functions_get_linked_attachment               = -1;
static gint hf_bip_supported_functions_get_linked_thumbnail                = -1;
static gint hf_bip_supported_functions_get_image                           = -1;
static gint hf_bip_supported_functions_get_image_property                  = -1;
static gint hf_bip_supported_functions_get_images_list                     = -1;
static gint hf_bip_supported_functions_remote_display                      = -1;
static gint hf_bip_supported_functions_put_linked_thumbnail                = -1;
static gint hf_bip_supported_functions_put_linked_attachment               = -1;
static gint hf_bip_supported_functions_put_image                           = -1;
static gint hf_bip_supported_functions_get_capabilities                    = -1;
static gint hf_bip_supported_functions_reserved_13_31                      = -1;
static gint hf_bip_supported_functions_get_partial_image                   = -1;
static gint hf_bip_supported_functions_reserved_1_11                       = -1;
static gint hf_bip_supported_functions_reserved_1_4                        = -1;
static gint hf_bip_supported_functions_reserved_11_31                      = -1;
static gint hf_bip_total_imaging_data_capacity                             = -1;
static gint hf_bpp_document_formats_supported                              = -1;
static gint hf_bpp_character_repertoires_support                           = -1;
static gint hf_bpp_xhtml_print_image_formats_supported                     = -1;
static gint hf_bpp_color_supported                                         = -1;
static gint hf_bpp_1284_id                                                 = -1;
static gint hf_bpp_printer_name                                            = -1;
static gint hf_bpp_printer_location                                        = -1;
static gint hf_bpp_duplex_supported                                        = -1;
static gint hf_bpp_media_types_supported                                   = -1;
static gint hf_bpp_max_media_width                                         = -1;
static gint hf_bpp_max_media_length                                        = -1;
static gint hf_bpp_enhanced_layout_supported                               = -1;
static gint hf_bpp_rui_formats_supported                                   = -1;
static gint hf_bpp_reference_printing_rui_supported                        = -1;
static gint hf_bpp_direct_printing_rui_supported                           = -1;
static gint hf_bpp_reference_printing_top_url                              = -1;
static gint hf_bpp_direct_printing_top_url                                 = -1;
static gint hf_bpp_device_name                                             = -1;
static gint hf_bpp_printer_admin_rui_top_url                               = -1;
static gint hf_ctn_instance_id                                             = -1;
static gint hf_ctn_supported_features                                      = -1;
static gint hf_ctn_supported_features_reserved                             = -1;
static gint hf_ctn_supported_features_forward                              = -1;
static gint hf_ctn_supported_features_delete                               = -1;
static gint hf_ctn_supported_features_uploading                            = -1;
static gint hf_ctn_supported_features_downloading                          = -1;
static gint hf_ctn_supported_features_browsing                             = -1;
static gint hf_ctn_supported_features_notification                         = -1;
static gint hf_ctn_supported_features_account_management                   = -1;
static gint hf_mps_mpsd_scenarios                                          = -1;
static gint hf_mps_mpsd_scenarios_reserved                                 = -1;
static gint hf_mps_mpsd_scenarios_37                                       = -1;
static gint hf_mps_mpsd_scenarios_36                                       = -1;
static gint hf_mps_mpsd_scenarios_35                                       = -1;
static gint hf_mps_mpsd_scenarios_34                                       = -1;
static gint hf_mps_mpsd_scenarios_33                                       = -1;
static gint hf_mps_mpsd_scenarios_32                                       = -1;
static gint hf_mps_mpsd_scenarios_31                                       = -1;
static gint hf_mps_mpsd_scenarios_30                                       = -1;
static gint hf_mps_mpsd_scenarios_29                                       = -1;
static gint hf_mps_mpsd_scenarios_28                                       = -1;
static gint hf_mps_mpsd_scenarios_27                                       = -1;
static gint hf_mps_mpsd_scenarios_26                                       = -1;
static gint hf_mps_mpsd_scenarios_25                                       = -1;
static gint hf_mps_mpsd_scenarios_24                                       = -1;
static gint hf_mps_mpsd_scenarios_23                                       = -1;
static gint hf_mps_mpsd_scenarios_22                                       = -1;
static gint hf_mps_mpsd_scenarios_21                                       = -1;
static gint hf_mps_mpsd_scenarios_20                                       = -1;
static gint hf_mps_mpsd_scenarios_19                                       = -1;
static gint hf_mps_mpsd_scenarios_18                                       = -1;
static gint hf_mps_mpsd_scenarios_17                                       = -1;
static gint hf_mps_mpsd_scenarios_16                                       = -1;
static gint hf_mps_mpsd_scenarios_15                                       = -1;
static gint hf_mps_mpsd_scenarios_14                                       = -1;
static gint hf_mps_mpsd_scenarios_13                                       = -1;
static gint hf_mps_mpsd_scenarios_12                                       = -1;
static gint hf_mps_mpsd_scenarios_11                                       = -1;
static gint hf_mps_mpsd_scenarios_10                                       = -1;
static gint hf_mps_mpsd_scenarios_9                                        = -1;
static gint hf_mps_mpsd_scenarios_8                                        = -1;
static gint hf_mps_mpsd_scenarios_7                                        = -1;
static gint hf_mps_mpsd_scenarios_6                                        = -1;
static gint hf_mps_mpsd_scenarios_5                                        = -1;
static gint hf_mps_mpsd_scenarios_4                                        = -1;
static gint hf_mps_mpsd_scenarios_3                                        = -1;
static gint hf_mps_mpsd_scenarios_2                                        = -1;
static gint hf_mps_mpsd_scenarios_1                                        = -1;
static gint hf_mps_mpsd_scenarios_0                                        = -1;
static gint hf_mps_mpmd_scenarios                                          = -1;
static gint hf_mps_mpmd_scenarios_reserved                                 = -1;
static gint hf_mps_mpmd_scenarios_18                                       = -1;
static gint hf_mps_mpmd_scenarios_17                                       = -1;
static gint hf_mps_mpmd_scenarios_16                                       = -1;
static gint hf_mps_mpmd_scenarios_15                                       = -1;
static gint hf_mps_mpmd_scenarios_14                                       = -1;
static gint hf_mps_mpmd_scenarios_13                                       = -1;
static gint hf_mps_mpmd_scenarios_12                                       = -1;
static gint hf_mps_mpmd_scenarios_11                                       = -1;
static gint hf_mps_mpmd_scenarios_10                                       = -1;
static gint hf_mps_mpmd_scenarios_9                                        = -1;
static gint hf_mps_mpmd_scenarios_8                                        = -1;
static gint hf_mps_mpmd_scenarios_7                                        = -1;
static gint hf_mps_mpmd_scenarios_6                                        = -1;
static gint hf_mps_mpmd_scenarios_5                                        = -1;
static gint hf_mps_mpmd_scenarios_4                                        = -1;
static gint hf_mps_mpmd_scenarios_3                                        = -1;
static gint hf_mps_mpmd_scenarios_2                                        = -1;
static gint hf_mps_mpmd_scenarios_1                                        = -1;
static gint hf_mps_mpmd_scenarios_0                                        = -1;
static gint hf_mps_supported_profile_and_protocol_dependency               = -1;
static gint hf_mps_supported_profile_and_protocol_dependency_reserved                       = -1;
static gint hf_mps_supported_profile_and_protocol_dependency_dis_connection_order_behaviour = -1;
static gint hf_mps_supported_profile_and_protocol_dependency_gavdp_requirements             = -1;
static gint hf_mps_supported_profile_and_protocol_dependency_sniff_mode_during_streaming    = -1;
static gint hf_map_mas_goep_l2cap_psm                                      = -1;
static gint hf_map_mns_goep_l2cap_psm                                      = -1;
static gint hf_map_supported_features                                      = -1;
static gint hf_map_supported_features_reserved                             = -1;
static gint hf_map_supported_features_extended_event_report_1_1            = -1;
static gint hf_map_supported_features_instance_information_feature         = -1;
static gint hf_map_supported_features_delete_feature                       = -1;
static gint hf_map_supported_features_uploading_feature                    = -1;
static gint hf_map_supported_features_browsing_feature                     = -1;
static gint hf_map_supported_features_notification_feature                 = -1;
static gint hf_map_supported_features_notification_registration_feature    = -1;
static gint hf_pbap_pse_supported_features                                 = -1;
static gint hf_pbap_pse_supported_features_reserved                        = -1;
static gint hf_pbap_pse_supported_features_download                        = -1;
static gint hf_pbap_pse_supported_features_browsing                        = -1;
static gint hf_pbap_pse_supported_features_database_identifier             = -1;
static gint hf_pbap_pse_supported_features_folder_version_counters         = -1;
static gint hf_pbap_pse_supported_features_vcard_selecting                 = -1;
static gint hf_pbap_pse_supported_features_enhanced_missed_calls           = -1;
static gint hf_pbap_pse_supported_features_x_bt_uci_vcard_property         = -1;
static gint hf_pbap_pse_supported_features_x_bt_uid_vcard_property         = -1;
static gint hf_pbap_pse_supported_features_contact_referencing             = -1;
static gint hf_pbap_pse_supported_features_default_contact_image_format    = -1;
static gint hf_pbap_goep_l2cap_psm                                         = -1;

static gint ett_btsdp                                     = -1;
static gint ett_btsdp_ssr                                 = -1;
static gint ett_btsdp_des                                 = -1;
static gint ett_btsdp_attribute                           = -1;
static gint ett_btsdp_attribute_id                        = -1;
static gint ett_btsdp_attribute_value                     = -1;
static gint ett_btsdp_attribute_idlist                    = -1;
static gint ett_btsdp_service_search_pattern              = -1;
static gint ett_btsdp_continuation_state                  = -1;
static gint ett_btsdp_data_element                        = -1;
static gint ett_btsdp_data_element_value                  = -1;
static gint ett_btsdp_reassembled                         = -1;
static gint ett_btsdp_supported_features                  = -1;
static gint ett_btsdp_supported_features_mdep_id          = -1;
static gint ett_btsdp_supported_features_mdep_data_type   = -1;
static gint ett_btsdp_supported_features_mdep_role        = -1;
static gint ett_btsdp_supported_features_mdep_description = -1;
static gint ett_btsdp_protocol                            = -1;

static const int *hfx_ctn_supported_features[] = {
    &hf_ctn_supported_features_reserved,
    &hf_ctn_supported_features_forward,
    &hf_ctn_supported_features_delete,
    &hf_ctn_supported_features_uploading,
    &hf_ctn_supported_features_downloading,
    &hf_ctn_supported_features_browsing,
    &hf_ctn_supported_features_notification,
    &hf_ctn_supported_features_account_management,
    NULL
};

static const int *hfx_mps_mpsd_scenarios[] = {
    &hf_mps_mpsd_scenarios_reserved,
    &hf_mps_mpsd_scenarios_37,
    &hf_mps_mpsd_scenarios_36,
    &hf_mps_mpsd_scenarios_35,
    &hf_mps_mpsd_scenarios_34,
    &hf_mps_mpsd_scenarios_33,
    &hf_mps_mpsd_scenarios_32,
    &hf_mps_mpsd_scenarios_31,
    &hf_mps_mpsd_scenarios_30,
    &hf_mps_mpsd_scenarios_29,
    &hf_mps_mpsd_scenarios_28,
    &hf_mps_mpsd_scenarios_27,
    &hf_mps_mpsd_scenarios_26,
    &hf_mps_mpsd_scenarios_25,
    &hf_mps_mpsd_scenarios_24,
    &hf_mps_mpsd_scenarios_23,
    &hf_mps_mpsd_scenarios_22,
    &hf_mps_mpsd_scenarios_21,
    &hf_mps_mpsd_scenarios_20,
    &hf_mps_mpsd_scenarios_19,
    &hf_mps_mpsd_scenarios_18,
    &hf_mps_mpsd_scenarios_17,
    &hf_mps_mpsd_scenarios_16,
    &hf_mps_mpsd_scenarios_15,
    &hf_mps_mpsd_scenarios_14,
    &hf_mps_mpsd_scenarios_13,
    &hf_mps_mpsd_scenarios_12,
    &hf_mps_mpsd_scenarios_11,
    &hf_mps_mpsd_scenarios_10,
    &hf_mps_mpsd_scenarios_9,
    &hf_mps_mpsd_scenarios_8,
    &hf_mps_mpsd_scenarios_7,
    &hf_mps_mpsd_scenarios_6,
    &hf_mps_mpsd_scenarios_5,
    &hf_mps_mpsd_scenarios_4,
    &hf_mps_mpsd_scenarios_3,
    &hf_mps_mpsd_scenarios_2,
    &hf_mps_mpsd_scenarios_1,
    &hf_mps_mpsd_scenarios_0,
    NULL
};

static const int *hfx_mps_mpmd_scenarios[] = {
    &hf_mps_mpmd_scenarios_reserved,
    &hf_mps_mpmd_scenarios_18,
    &hf_mps_mpmd_scenarios_17,
    &hf_mps_mpmd_scenarios_16,
    &hf_mps_mpmd_scenarios_15,
    &hf_mps_mpmd_scenarios_14,
    &hf_mps_mpmd_scenarios_13,
    &hf_mps_mpmd_scenarios_12,
    &hf_mps_mpmd_scenarios_11,
    &hf_mps_mpmd_scenarios_10,
    &hf_mps_mpmd_scenarios_9,
    &hf_mps_mpmd_scenarios_8,
    &hf_mps_mpmd_scenarios_7,
    &hf_mps_mpmd_scenarios_6,
    &hf_mps_mpmd_scenarios_5,
    &hf_mps_mpmd_scenarios_4,
    &hf_mps_mpmd_scenarios_3,
    &hf_mps_mpmd_scenarios_2,
    &hf_mps_mpmd_scenarios_1,
    &hf_mps_mpmd_scenarios_0,
    NULL
};

static const int *hfx_mps_supported_profile_and_protocol_dependency[] = {
    &hf_mps_supported_profile_and_protocol_dependency_reserved,
    &hf_mps_supported_profile_and_protocol_dependency_dis_connection_order_behaviour,
    &hf_mps_supported_profile_and_protocol_dependency_gavdp_requirements,
    &hf_mps_supported_profile_and_protocol_dependency_sniff_mode_during_streaming,
    NULL
};

static const int *hfx_map_supported_features[] = {
    &hf_map_supported_features_reserved,
    &hf_map_supported_features_extended_event_report_1_1,
    &hf_map_supported_features_instance_information_feature,
    &hf_map_supported_features_delete_feature,
    &hf_map_supported_features_uploading_feature,
    &hf_map_supported_features_browsing_feature,
    &hf_map_supported_features_notification_feature,
    &hf_map_supported_features_notification_registration_feature,
    NULL
};

static const int *hfx_pbap_pse_supported_repositories[] = {
    &hf_pbap_pse_supported_repositories_reserved,
    &hf_pbap_pse_supported_repositories_favourites,
    &hf_pbap_pse_supported_repositories_speed_dial,
    &hf_pbap_pse_supported_repositories_sim_card,
    &hf_pbap_pse_supported_repositories_local_phonebook,
    NULL
};

static const int *hfx_pbap_pse_supported_features[] = {
    &hf_pbap_pse_supported_features_reserved,
    &hf_pbap_pse_supported_features_default_contact_image_format,
    &hf_pbap_pse_supported_features_contact_referencing,
    &hf_pbap_pse_supported_features_x_bt_uid_vcard_property,
    &hf_pbap_pse_supported_features_x_bt_uci_vcard_property,
    &hf_pbap_pse_supported_features_enhanced_missed_calls,
    &hf_pbap_pse_supported_features_vcard_selecting,
    &hf_pbap_pse_supported_features_folder_version_counters,
    &hf_pbap_pse_supported_features_database_identifier,
    &hf_pbap_pse_supported_features_browsing,
    &hf_pbap_pse_supported_features_download,
    NULL
};

static expert_field ei_btsdp_continuation_state_none = EI_INIT;
static expert_field ei_btsdp_continuation_state_large = EI_INIT;
static expert_field ei_data_element_value_large = EI_INIT;

static dissector_handle_t btsdp_handle;

static wmem_tree_t *tid_requests           = NULL;
static wmem_tree_t *continuation_states    = NULL;
static wmem_tree_t *record_handle_services = NULL;
static wmem_tree_t *service_infos          = NULL;

typedef struct _tid_request_t {
    guint32        interface_id;
    guint32        adapter_id;
    guint32        chandle;
    guint32        psm;
    guint32        tid;
    guint32        pdu_type;

    wmem_array_t  *uuid_array;
    guint32        record_handle;

    guint8        *continuation_state;
    guint8         continuation_state_length;

    guint32        data_length;
    guint8        *data;
} tid_request_t;

typedef struct _continuation_state_data_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32  psm;
    guint32  pdu_type;
    guint32  continuation_state[5];

    guint32  data_length;
    guint8  *data;
} continuation_state_data_t;

typedef struct _record_handle_service_t {
    guint32       interface_id;
    guint32       adapter_id;
    guint32       chandle;
    guint32       psm;
    guint32       record_handle;

    wmem_array_t *uuid_array;
} record_handle_service_t;

#define PDU_TYPE_SERVICE_SEARCH            0x00
#define PDU_TYPE_SERVICE_ATTRIBUTE         0x01
#define PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE  0x02

#define MAX_SDP_LEN 1024

extern value_string_ext ext_usb_vendors_vals;
extern value_string_ext ext_usb_products_vals;

static const value_string vs_pduid[] = {
    { 0x01,   "Error Response" },
    { 0x02,   "Service Search Request" },
    { 0x03,   "Service Search Response" },
    { 0x04,   "Service Attribute Request" },
    { 0x05,   "Service Attribute Response" },
    { 0x06,   "Service Search Attribute Request" },
    { 0x07,   "Service Search Attribute Response" },
    { 0, NULL }
};

static const value_string vs_general_attribute_id[] = {
    { 0x0000,   "Service Record Handle" },
    { 0x0001,   "Service Class ID List" },
    { 0x0002,   "Service Record State" },
    { 0x0003,   "Service ID" },
    { 0x0004,   "Protocol Descriptor List" },
    { 0x0005,   "Browse Group List" },
    { 0x0006,   "Language Base Attribute ID List" },
    { 0x0007,   "Service Info Time To Live" },
    { 0x0008,   "Service Availability" },
    { 0x0009,   "Bluetooth Profile Descriptor List" },
    { 0x000A,   "Documentation URL" },
    { 0x000B,   "Client Executable URL" },
    { 0x000C,   "Icon URL" },
    { 0x000D,   "Additional Protocol Descriptor Lists" },
    /* Localized string default offset is 0x100,
       the rest based on Language Base Attribute ID List */
    { 0x0100,   "Service Name" },
    { 0x0101,   "Service Description" },
    { 0x0102,   "Provider Name" },
    { 0, NULL }
};

static const value_string vs_a2dp_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_avrcp_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_bip_imaging_responder_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0310,   "Supported Capabilities" },
    { 0x0311,   "Supported Features" },
    { 0x0312,   "Supported Functions" },
    { 0x0313,   "Total Imaging Data Capacity" },
    { 0, NULL }
};

static const value_string vs_bip_imaging_other_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0312,   "Supported Functions" },
    { 0, NULL }
};

static const value_string vs_bpp_attribute_id[] = {
    { 0x0350,   "Document Formats Supported" },
    { 0x0352,   "Character Repertoires Supported" },
    { 0x0354,   "XHTML-Print Image Formats Supported" },
    { 0x0356,   "Color Supported" },
    { 0x0358,   "1284ID" },
    { 0x035A,   "Printer Name" },
    { 0x035C,   "Printer Location" },
    { 0x035E,   "Duplex Supported" },
    { 0x0360,   "Media Types Supported" },
    { 0x0362,   "Max Media Width" },
    { 0x0364,   "Max Media Length" },
    { 0x0366,   "Enhanced Layout Supported" },
    { 0x0368,   "RUI Formats Supported" },
    { 0x0370,   "Reference Printing RUI Supported" },
    { 0x0372,   "Direct Printing RUI Supported" },
    { 0x0374,   "Reference Printing Top URL" },
    { 0x0376,   "Direct Printing Top URL" },
    { 0x037A,   "Device Name" },
    { 0, NULL }
};

static const value_string vs_bpp_reflected_ui_attribute_id[] = {
    { 0x0368,   "RUI Formats Supported" },
    { 0x0378,   "Printer Admin RUI Top URL" },
    { 0, NULL }
};

static const value_string vs_ctp_attribute_id[] = {
    { 0x0301,   "External Network" },
    { 0, NULL }
};

static const value_string vs_did_attribute_id[] = {
    { 0x0200,   "Specification ID" },
    { 0x0201,   "Vendor ID" },
    { 0x0202,   "Product ID" },
    { 0x0203,   "Version" },
    { 0x0204,   "Primary Record" },
    { 0x0205,   "Vendor ID Source" },
    { 0, NULL }
};

static const value_string vs_dun_attribute_id[] = {
    { 0x0305,   "Audio Feedback Support" },
    { 0x0306,   "Escape Sequence" },
    { 0, NULL }
};


static const value_string vs_fax_attribute_id[] = {
    { 0x0302,   "Fax Class 1 Support" },
    { 0x0303,   "Fax Class 2.0 Support" },
    { 0x0304,   "Fax Class 2 Support (vendor-specific class)" },
    { 0x0305,   "Audio Feedback Support" },
    { 0, NULL }
};

static const value_string vs_ftp_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0, NULL }
};

static const value_string vs_gnss_attribute_id[] = {
    { 0x0200,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hfp_gw_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hfp_ag_attribute_id[] = {
    { 0x0301,   "Network" },
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hcrp_attribute_id[] = {
    { 0x0300,   "1284ID" },
    { 0x0302,   "Device Name" },
    { 0x0304,   "Friendly Name" },
    { 0x0306,   "Device Location" },
    { 0, NULL }
};

static const value_string vs_hsp_attribute_id[] = {
    { 0x0302,   "Remote Audio Volume Control" },
    { 0, NULL }
};

static const value_string vs_hdp_attribute_id[] = {
    { 0x0200,   "Support Features List" },
    { 0x0301,   "Data Exchange Specification" },
    { 0x0302,   "MCAP Supported Procedures" },
    { 0, NULL }
};

static const value_string vs_hid_attribute_id[] = {
    { 0x0200,   "Device Release Number" },
    { 0x0201,   "Parser Version" },
    { 0x0202,   "Device Subclass" },
    { 0x0203,   "Country Code" },
    { 0x0204,   "Virtual Cable" },
    { 0x0205,   "Reconnect Initiate" },
    { 0x0206,   "Descriptor List" },
    { 0x0207,   "LANG ID Base List" },
    { 0x0208,   "SDP Disable" },
    { 0x0209,   "Battery Power" },
    { 0x020A,   "Remote Wake" },
    { 0x020B,   "Profile Version" },
    { 0x020C,   "Supervision Timeout" },
    { 0x020D,   "Normally Connectable" },
    { 0x020E,   "BootDevice" },
    { 0x020F,   "SSR Host Max Latency" },
    { 0x0210,   "SSR Host Min Timeout" },
    { 0, NULL }
};

static const value_string vs_wap_attribute_id[] = {
    { 0x0306,   "Network Address" },
    { 0x0307,   "WAP Gateway" },
    { 0x0308,   "Home Page URL" },
    { 0x0309,   "WAP Stack Type" },
    { 0, NULL }
};

static const value_string vs_map_mas_attribute_id[] = {
    { 0x200,    "GOEP L2CAP PSM" }, /* MAP v1.2 and later */
    { 0x0315,   "MAS Instance ID" },
    { 0x0316,   "Supported Message Types" },
    { 0x0317,   "Supported Features" }, /* MAP v1.2 and later */
    { 0, NULL }
};

static const value_string vs_map_mns_attribute_id[] = {
    { 0x200,    "GOEP L2CAP PSM" }, /* MAP v1.2 and later */
    { 0x0317,   "Supported Features" }, /* MAP v1.2 and later */
    { 0, NULL }
};

static const value_string vs_opp_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0300,   "Service Version" },
    { 0x0303,   "Supported Formats List" },
    { 0, NULL }
};

static const value_string vs_pan_nap_attribute_id[] = {
    { 0x0200,   "IP Subnet" }, /* Deprecated */
    { 0x030A,   "Security Description" },
    { 0x030B,   "Net Access Type" },
    { 0x030C,   "Max Net Access Rate" },
    { 0x030D,   "IPv4Subnet" },
    { 0x030E,   "IPv6Subnet" },
    { 0, NULL }
};

static const value_string vs_pan_gn_attribute_id[] = {
    { 0x0200,   "IP Subnet" }, /* Deprecated */
    { 0x030A,   "Security Description" },
    { 0x030D,   "IPv4Subnet" },
    { 0x030E,   "IPv6Subnet" },
    { 0, NULL }
};

static const value_string vs_pan_panu_attribute_id[] = {
    { 0x030A,   "Security Description" },
    { 0, NULL }
};

static const value_string vs_pbap_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0314,   "Supported Repositories" },
    { 0x0317,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_synch_attribute_id[] = {
    { 0x0301,   "Supported Data Stores List" },
    { 0, NULL }
};

static const value_string vs_mps_attribute_id[] = {
    { 0x0200,  "Multiple Profiles - Single Device Supported Scenarios" },
    { 0x0201,  "Multiple Profiles - Multiple Device Supported Scenarios" },
    { 0x0202,  "Supported Profile and Protocol Dependency" },
    { 0, NULL }
};

static const value_string vs_ctn_as_attribute_id[] = {
    { 0x0315,  "Instance ID" },
    { 0x0317,  "Supported Features" },
    { 0, NULL }
};

static const value_string vs_ctn_ns_attribute_id[] = {
    { 0x0317,  "Supported Features" },
    { 0, NULL }
};

static const value_string did_vendor_id_source_vals[] = {
    { 0x0001,   "Bluetooth SIG" },
    { 0x0002,   "USB Implementer's Forum" },
    { 0, NULL }
};
value_string_ext did_vendor_id_source_vals_ext = VALUE_STRING_EXT_INIT(did_vendor_id_source_vals);

static const value_string synch_supported_data_store_vals[] = {
    { 0x01,   "Phonebook" },
    { 0x03,   "Calendar" },
    { 0x05,   "Notes" },
    { 0x06,   "Messages" },
    { 0, NULL }
};

static const value_string ctp_external_network_vals[] = {
    { 0x01,   "Phonebook" },
    { 0x02,   "ISDN" },
    { 0x03,   "GSM" },
    { 0x04,   "CDMA" },
    { 0x05,   "Analogue Cellular" },
    { 0x06,   "Packet-switched" },
    { 0x07,   "Other" },
    { 0, NULL }
};

static const value_string wap_stack_type_vals[] = {
    { 0x01,   "Connectionless" },
    { 0x02,   "Connection Oriented" },
    { 0x03,   "All (Connectionless + Connection Oriented)" },
    { 0, NULL }
};

static const value_string wap_gateway_vals[] = {
    { 0x01,   "Origin Server" },
    { 0x02,   "Proxy" },
    { 0, NULL }
};

static const value_string hdp_data_exchange_specification_vals[] = {
    { 0x01,   "ISO/IEEE 11073-20601 (Health informatics)" },
    { 0, NULL }
};

static const range_string hdp_mdep_id_rvals[] = {
    { 0x00, 0x00,  "Reserved For Echo Test Function" },
    { 0x01, 0x7F,  "Available for use" },
    { 0x80, 0xFF,  "Reserved by MCAP" },
    { 0, 0, NULL }
};

static const value_string hdp_mdep_role_vals[] = {
    { 0x00,   "Source" },
    { 0x01,   "Sink" },
    { 0, NULL }
};

static const value_string pan_security_description_vals[] = {
    { 0x0000,   "None" },
    { 0x0001,   "Service-level Enforced Security" },
    { 0x0002,   "802.1x Security" },
    { 0, NULL }
};

static const value_string opp_supported_format_vals[] = {
    { 0x01,   "vCard 2.1" },
    { 0x02,   "vCard 3.0" },
    { 0x03,   "vCal 1.0" },
    { 0x04,   "iCal 2.0" },
    { 0x05,   "vNote" },
    { 0x06,   "vMessage" },
    { 0xFF,   "AllFormats" },
    { 0, NULL }
};

static const value_string pan_net_access_type_vals[] = {
    { 0x0000,   "PSTN" },
    { 0x0001,   "ISDN" },
    { 0x0002,   "DSL" },
    { 0x0003,   "Cable Modem" },
    { 0x0004,   "10Mb Ethernet" },
    { 0x0005,   "100Mb Ethernet" },
    { 0x0006,   "4Mb Token Ring" },
    { 0x0007,   "16Mb Token Ring" },
    { 0x0008,   "100Mb Token Ring" },
    { 0x0009,   "FDDI" },
    { 0x000A,   "GSM" },
    { 0x000B,   "CDMA" },
    { 0x000c,   "GPRS" },
    { 0x000D,   "3G" },
    { 0xFFFE,   "Other" },
    { 0, NULL }
};

static const value_string hfp_gw_network_vals[] = {
    { 0x00,   "No ability to reject a call" },
    { 0x01,   "Ability to reject a call" },
    { 0, NULL }
};

static const value_string hid_device_subclass_type_vals[] = {
    { 0x00,   "Not Keyboard / Not Pointing Device" },
    { 0x01,   "Keyboard" },
    { 0x02,   "Pointing Device" },
    { 0x03,   "Combo keyboard/pointing device" },
    { 0, NULL }
};

static const value_string hid_device_subclass_subtype_vals[] = {
    { 0x00,   "Uncategorized device" },
    { 0x01,   "Joystick" },
    { 0x02,   "Gamepad" },
    { 0x03,   "Remote control" },
    { 0x04,   "Sensing device" },
    { 0x05,   "Digitizer tablet" },
    { 0x06,   "Card Reader" },
    { 0, NULL }
};

/* USB HID 1.11 bCountryCode */
const value_string hid_country_code_vals[] = {
    {  0,   "Not Supported" },
    {  1,   "Arabic" },
    {  2,   "Belgian" },
    {  3,   "Canadian-Bilingual" },
    {  4,   "Canadian-French" },
    {  5,   "Czech Republic" },
    {  6,   "Danish" },
    {  7,   "Finnish" },
    {  8,   "French" },
    {  9,   "German" },
    { 10,   "Greek" },
    { 11,   "Hebrew" },
    { 12,   "Hungary" },
    { 13,   "International (ISO)" },
    { 14,   "Italian" },
    { 15,   "Japan (Katakana)" },
    { 16,   "Korean" },
    { 17,   "Latin American" },
    { 18,   "Netherlands/Dutch" },
    { 19,   "Norwegian" },
    { 20,   "Persian (Farsi)" },
    { 21,   "Poland" },
    { 22,   "Portuguese" },
    { 23,   "Russia" },
    { 24,   "Slovakia" },
    { 25,   "Spanish" },
    { 26,   "Swedish" },
    { 27,   "Swiss/French" },
    { 28,   "Swiss/German" },
    { 29,   "Switzerland" },
    { 30,   "Taiwan" },
    { 31,   "Turkish-Q" },
    { 32,   "UK" },
    { 33,   "US" },
    { 34,   "Yugoslavia" },
    { 35,   "Turkish-F" },
    { 0, NULL }
};

static const value_string descriptor_list_type_vals[] = {
    { 0x22,  "Report" },
    { 0x23,  "Physical"},
    { 0, NULL }
};

static const value_string vs_error_code[] = {
    { 0x0001,   "Invalid/Unsupported SDP Version" },
    { 0x0002,   "Invalid Service Record Handle" },
    { 0x0003,   "Invalid Request Syntax" },
    { 0x0004,   "Invalid PDU Size" },
    { 0x0005,   "Invalid Continuation State" },
    { 0x0006,   "Insufficient Resources to Satisfy Request" },
    { 0, NULL }
};

static const value_string vs_data_element_size[] = {
    { 0x00,   "1 byte (0 bytes if Nil)" },
    { 0x01,   "2 bytes" },
    { 0x02,   "4 bytes" },
    { 0x03,   "8 bytes" },
    { 0x04,   "16 bytes" },
    { 0x05,   "uint8" },
    { 0x06,   "uint16" },
    { 0x07,   "uint32" },
    { 0, NULL }
};

static const value_string vs_data_element_type[] = {
    { 0x00,   "Nil" },
    { 0x01,   "Unsigned Integer" },
    { 0x02,   "Signed Twos-Complement Integer" },
    { 0x03,   "UUID" },
    { 0x04,   "Text string" },
    { 0x05,   "Boolean" },
    { 0x06,   "Sequence" },
    { 0x07,   "Alternative" },
    { 0x08,   "URL" },
    { 0, NULL }
};

extern value_string_ext ext_psm_vals;
extern value_string_ext usb_langid_vals_ext;

void proto_register_btsdp(void);
void proto_reg_handoff_btsdp(void);

service_info_t* btsdp_get_service_info(wmem_tree_key_t* key)
{
    if (service_infos == NULL)
        return NULL;

    return (service_info_t *)wmem_tree_lookup32_array_le(service_infos, key);
}

static bluetooth_uuid_t
get_specified_uuid(wmem_array_t  *uuid_array)
{
    bluetooth_uuid_t uuid;

/* Try to find UUID that is already use in RFCOMM or L2CAP, otherwise try to
   return last one (most generic).
   NOTE: UUIDs in array are from (most specified) to (most generic) */
    if (uuid_array) {
        guint32  i_uuid;
        guint32  size;
        bluetooth_uuid_t *p_uuid = NULL;

        size = wmem_array_get_count(uuid_array);

        for (i_uuid = 0; i_uuid < size; i_uuid += 1) {
            p_uuid = (bluetooth_uuid_t *) wmem_array_index(uuid_array, i_uuid);
            if (p_uuid->size == 16) /* CustomUUID (UUID128) is always ok */
                break;
            if (p_uuid->size == 0)
                continue;
            if (dissector_get_string_handle(bluetooth_uuid_table, print_numeric_uuid(p_uuid)))
                break;
        }

        if (p_uuid) return *p_uuid;
    }

    memset(&uuid, 0, sizeof(bluetooth_uuid_t));
    return uuid;
}


static wmem_array_t *
get_uuids(packet_info *pinfo, guint32 record_handle, btl2cap_data_t *l2cap_data)
{
    record_handle_service_t  *record_handle_service;
    wmem_tree_key_t           key[7];
    guint32                   k_interface_id;
    guint32                   k_adapter_id;
    guint32                   k_chandle;
    guint32                   k_psm;
    guint32                   k_record_handle;
    guint32                   k_frame_number;
    guint32                   interface_id;
    guint32                   adapter_id;
    guint32                   chandle;
    guint32                   psm;
    guint32                   frame_number;

    interface_id = l2cap_data->interface_id;
    adapter_id   = l2cap_data->adapter_id;
    chandle  = l2cap_data->chandle;
    psm  = l2cap_data->psm;
    frame_number = pinfo->num;

    k_interface_id  = interface_id;
    k_adapter_id    = adapter_id;
    k_chandle   = chandle;
    k_psm   = psm;
    k_record_handle = record_handle;
    k_frame_number  = frame_number;


    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_chandle;
    key[3].length = 1;
    key[3].key    = &k_psm;
    key[4].length = 1;
    key[4].key    = &k_record_handle;
    key[5].length = 1;
    key[5].key    = &k_frame_number;
    key[6].length = 0;
    key[6].key    = NULL;

    record_handle_service = (record_handle_service_t *) wmem_tree_lookup32_array_le(record_handle_services, key);
    if (record_handle_service && record_handle_service->interface_id == interface_id &&
            record_handle_service->adapter_id == adapter_id &&
            record_handle_service->chandle == chandle &&
            record_handle_service->psm == psm &&
            record_handle_service->record_handle == record_handle) {
        return record_handle_service->uuid_array;
    }

    return NULL;
}


static service_info_t *
save_channel(packet_info *pinfo, guint32 type_protocol, guint32 channel,
        gint protocol_order, service_info_t *parent_service_info)
{
    wmem_tree_key_t  key[10];
    guint32          k_interface_id;
    guint32          k_adapter_id;
    guint32          k_sdp_psm;
    guint32          k_direction;
    guint32          k_bd_addr_oui;
    guint32          k_bd_addr_id;
    guint32          k_service_type;
    guint32          k_service_channel;
    guint32          k_frame_number;
    service_info_t  *service_info;

    service_info = (service_info_t *) wmem_new(wmem_file_scope(), service_info_t);
    service_info->interface_id   = parent_service_info->interface_id;
    service_info->adapter_id     = parent_service_info->adapter_id;
    service_info->sdp_psm        = parent_service_info->sdp_psm;
    service_info->direction      = parent_service_info->direction;
    service_info->bd_addr_oui    = parent_service_info->bd_addr_oui;
    service_info->bd_addr_id     = parent_service_info->bd_addr_id;

    service_info->type           = type_protocol;
    service_info->channel        = channel;

    service_info->uuid           = parent_service_info->uuid;

    service_info->protocol       = -1;
    service_info->protocol_order = protocol_order;
    service_info->parent_info    = parent_service_info;
    service_info->data           = parent_service_info->data;


    k_interface_id    = service_info->interface_id;
    k_adapter_id      = service_info->adapter_id;
    k_sdp_psm         = service_info->sdp_psm;
    k_direction       = service_info->direction;
    k_bd_addr_oui     = service_info->bd_addr_oui;
    k_bd_addr_id      = service_info->bd_addr_id;
    k_service_type    = service_info->type;
    k_service_channel = service_info->channel;
    k_frame_number    = pinfo->num;

    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_sdp_psm;
    key[3].length = 1;
    key[3].key = &k_direction;
    key[4].length = 1;
    key[4].key = &k_bd_addr_oui;
    key[5].length = 1;
    key[5].key = &k_bd_addr_id;
    key[6].length = 1;
    key[6].key = &k_service_type;
    key[7].length = 1;
    key[7].key = &k_service_channel;
    key[8].length = 1;
    key[8].key = &k_frame_number;
    key[9].length = 0;
    key[9].key = NULL;

    wmem_tree_insert32_array(service_infos, key, service_info);

    return service_info;
}


static gint
get_type_length(tvbuff_t *tvb, gint offset, gint *length)
{
    gint    size  = 0;
    guint8  byte;

    byte = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (byte & 0x07) {
    case 0:
        size = (byte >> 3) == 0 ? 0 : 1;
        break;
    case 1:
        size = 2;
        break;
    case 2:
        size = 4;
        break;
    case 3:
        size = 8;
        break;
    case 4:
        size = 16;
        break;
    case 5:
        size = tvb_get_guint8(tvb, offset);
        offset += 1;
        break;
    case 6:
        size = tvb_get_ntohs(tvb, offset);
        offset += 2;
        break;
    case 7:
        size = tvb_get_ntohl(tvb, offset);
        offset += 4;
        break;
    }

    if (size < 0) {
        *length = 0; /* Add expert info? */
    }
    else {
        *length = size;
    }

    return offset;
}


static guint32
get_uint_by_size(tvbuff_t *tvb, gint off, gint size)
{
    switch (size) {
    case 0:
        return tvb_get_guint8(tvb, off);
    case 1:
        return tvb_get_ntohs(tvb, off);
    case 2:
        return tvb_get_ntohl(tvb, off);
    default:
        return 0xffffffff;
    }
}


static gint32
get_int_by_size(tvbuff_t *tvb, gint off, gint size)
{
    switch (size) {
    case 0:
        return tvb_get_guint8(tvb, off);
    case 1:
        return tvb_get_ntohs(tvb, off);
    case 2:
        return tvb_get_ntohl(tvb, off);
    default:
        return -1;
    }
}

static gint
dissect_uuid(proto_tree *tree, tvbuff_t *tvb, gint offset, gint size, bluetooth_uuid_t *uuid)
{
    proto_item  *item;

    DISSECTOR_ASSERT(uuid);

    if (size == 2) {
        proto_tree_add_item(tree, hf_data_element_value_uuid_16, tvb, offset, size, ENC_BIG_ENDIAN);
        uuid->bt_uuid = tvb_get_ntohs(tvb, offset);
    } else if (size == 4 && tvb_get_ntohs(tvb, offset) == 0x0000) {
        proto_tree_add_item(tree, hf_data_element_value_uuid_32, tvb, offset, size, ENC_BIG_ENDIAN);
        uuid->bt_uuid = tvb_get_ntohs(tvb, offset + 2);
    } else if (size == 16 && tvb_get_ntohs(tvb, offset) == 0x0000 && tvb_get_ntohl(tvb, offset + 4) == 0x1000 && tvb_get_ntoh64(tvb, offset + 8) == G_GUINT64_CONSTANT(0x800000805F9B34FB)) {
        item = proto_tree_add_item(tree, hf_data_element_value_uuid_128, tvb, offset, size, ENC_NA);
        uuid->bt_uuid = tvb_get_ntohs(tvb, offset + 2);
        proto_item_append_text(item, " (%s)", val_to_str_ext_const(uuid->bt_uuid, &bluetooth_uuid_vals_ext, "Unknown"));
    } else {
        bluetooth_uuid_t  x_uuid;

        item = proto_tree_add_item(tree, hf_data_element_value_uuid, tvb, offset, size, ENC_NA);
        x_uuid = get_uuid(tvb, offset, size);

        proto_item_append_text(item, " (%s)", print_uuid(&x_uuid));

        uuid->bt_uuid = 0;
    }

    if (size == 2 || size == 4 || size == 16) {
        uuid->size = size;
        tvb_memcpy(tvb, uuid->data, offset, size);
    } else {
        uuid->size = 0;
    }

    return offset + size;
}


static gint
dissect_continuation_state(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
        gint offset)
{
    proto_item  *cont_item;
    guint length;

    length = tvb_reported_length_remaining(tvb, offset);
    if (length == 0)  {
        proto_tree_add_expert(tree, pinfo, &ei_btsdp_continuation_state_none, tvb, offset, -1);
    } else if (length > 17) {
        proto_tree_add_expert(tree, pinfo, &ei_btsdp_continuation_state_large, tvb, offset, -1);
    } else if (length == 1 && tvb_get_guint8(tvb, offset) == 0x00) {
        proto_tree_add_none_format(tree, hf_continuation_state, tvb,
                offset, -1, "Continuation State: no (00)");
    } else {
        proto_item  *cont_tree;
        guint        data;
        guint8       i_data;
        guint8       continuation_state_length;

        continuation_state_length = tvb_get_guint8(tvb, offset);
        cont_item = proto_tree_add_none_format(tree, hf_continuation_state, tvb, offset,
                1 + continuation_state_length, "Continuation State: yes (");
        cont_tree = proto_item_add_subtree(cont_item, ett_btsdp_continuation_state);

        proto_tree_add_item(cont_tree, hf_continuation_state_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(cont_tree, hf_continuation_state_value, tvb, offset,
                continuation_state_length, ENC_NA);

        for (i_data = 0; i_data < continuation_state_length - 1; ++i_data) {
            data = tvb_get_guint8(tvb, offset);
            proto_item_append_text(cont_item, "%02X ", data);
            offset += 1;
        }

        data = tvb_get_guint8(tvb, offset);
        proto_item_append_text(cont_item, "%02X)", data);
        offset += 1;
    }

    return offset;
}

static gint
reassemble_continuation_state(tvbuff_t *tvb, packet_info *pinfo,
        gint offset, guint tid, gboolean is_request,
        gint attribute_list_byte_offset, gint attribute_list_byte_count,
        guint32 pdu_type, tvbuff_t **new_tvb, gboolean *is_first,
        gboolean *is_continued, wmem_array_t **uuid_array,
        guint32 *record_handle, btl2cap_data_t *l2cap_data)
{
    guint              length;
    tid_request_t     *tid_request;
    continuation_state_data_t *continuation_state_data;
    wmem_tree_key_t    key[12];
    wmem_tree_t       *subtree;
    guint32            k_interface_id;
    guint32            k_adapter_id;
    guint32            k_chandle;
    guint32            k_psm;
    guint32            k_tid;
    guint32            k_pdu_type;
    guint32            k_frame_number;
    guint32           *k_continuation_state_array;
    guint8            *continuation_state;
    guint32            interface_id;
    guint32            adapter_id;
    guint32            chandle;
    guint32            psm;
    guint32            frame_number;

    if (new_tvb) *new_tvb = NULL;

    interface_id = l2cap_data->interface_id;
    adapter_id   = l2cap_data->adapter_id;
    chandle      = l2cap_data->chandle;
    psm          = l2cap_data->psm;
    frame_number = pinfo->num;

    k_interface_id = interface_id;
    k_adapter_id   = adapter_id;
    k_chandle      = chandle;
    k_psm          = psm;
    k_tid          = tid;
    k_frame_number = frame_number;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_chandle;
    key[3].length = 1;
    key[3].key    = &k_psm;
    key[4].length = 1;
    key[4].key    = &k_tid;
    key[5].length = 1;
    key[5].key    = &k_frame_number;
    key[6].length = 0;
    key[6].key    = NULL;

    if (is_first) *is_first = TRUE;
    if (is_continued) *is_continued = TRUE;

    length = tvb_reported_length_remaining(tvb, offset);
    if (length == 0)  {
        return offset;
    } else if (length > 17) {
        return offset;
    } else if (length == 1 && tvb_get_guint8(tvb, offset) == 0x00) {
        if (is_continued) *is_continued = FALSE;

        if (!pinfo->fd->flags.visited) {
            if (is_request) {
                tid_request = (tid_request_t *) wmem_new(wmem_file_scope(), tid_request_t);
                tid_request->interface_id = interface_id;
                tid_request->adapter_id   = adapter_id;
                tid_request->chandle      = chandle;
                tid_request->psm          = psm;
                tid_request->tid          = tid;

                if (uuid_array)
                    tid_request->uuid_array = *uuid_array;
                else
                    tid_request->uuid_array = NULL;
                if (record_handle)
                    tid_request->record_handle   = *record_handle;
                else
                    tid_request->record_handle = 0;

                tid_request->data         = NULL;
                tid_request->data_length  = 0;

                tid_request->pdu_type = pdu_type;

                tid_request->continuation_state        = NULL;
                tid_request->continuation_state_length = 0;

                wmem_tree_insert32_array(tid_requests, key, tid_request);
            } else {
                tid_request = (tid_request_t *) wmem_tree_lookup32_array_le(tid_requests, key);
                if (tid_request && tid_request->interface_id == interface_id &&
                        tid_request->adapter_id == adapter_id &&
                        tid_request->chandle == chandle &&
                        tid_request->psm == psm &&
                        tid_request->tid == tid) {
                    if (tid_request->continuation_state_length > 0) {
                        /* fetch tid_request->continuation_state */

                        k_continuation_state_array =  (guint32 *) wmem_alloc0(wmem_packet_scope(), 20);
                        continuation_state = (guint8 *) k_continuation_state_array;
                        continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);

                        k_interface_id       = interface_id;
                        k_adapter_id         = adapter_id;
                        k_chandle            = chandle;
                        k_psm                = psm;
                        k_pdu_type           = tid_request->pdu_type;
                        k_frame_number       = frame_number;

                        key[0].length = 1;
                        key[0].key    = &k_interface_id;
                        key[1].length = 1;
                        key[1].key    = &k_adapter_id;
                        key[2].length = 1;
                        key[2].key    = &k_chandle;
                        key[3].length = 1;
                        key[3].key    = &k_psm;
                        key[4].length = 1;
                        key[4].key    = &k_pdu_type;
                        key[5].length = 1;
                        key[5].key    = &k_continuation_state_array[0];
                        key[6].length = 1;
                        key[6].key    = &k_continuation_state_array[1];
                        key[7].length = 1;
                        key[7].key    = &k_continuation_state_array[2];
                        key[8].length = 1;
                        key[8].key    = &k_continuation_state_array[3];
                        key[9].length = 1;
                        key[9].key    = &k_continuation_state_array[4];
                        key[10].length = 1;
                        key[10].key    = &k_frame_number;
                        key[11].length = 0;
                        key[11].key    = NULL;

                        continuation_state_data = (continuation_state_data_t *) wmem_tree_lookup32_array_le(continuation_states, key);
                        if (continuation_state_data && continuation_state_data->interface_id == interface_id &&
                                continuation_state_data->adapter_id == adapter_id &&
                                continuation_state_data->chandle == chandle &&
                                continuation_state_data->psm == psm &&
                                continuation_state_data->pdu_type == tid_request->pdu_type &&
                                continuation_state_data->continuation_state[0] == k_continuation_state_array[0] &&
                                continuation_state_data->continuation_state[1] == k_continuation_state_array[1] &&
                                continuation_state_data->continuation_state[2] == k_continuation_state_array[2] &&
                                continuation_state_data->continuation_state[3] == k_continuation_state_array[3] &&
                                continuation_state_data->continuation_state[4] == k_continuation_state_array[4]) {
                            tid_request->data = (guint8 *) wmem_alloc(wmem_file_scope(), continuation_state_data->data_length + attribute_list_byte_count);
                            tid_request->data_length = continuation_state_data->data_length + attribute_list_byte_count;
                            memcpy(tid_request->data, continuation_state_data->data, continuation_state_data->data_length);
                            tvb_memcpy(tvb, tid_request->data + continuation_state_data->data_length, attribute_list_byte_offset, attribute_list_byte_count);
                        }
                    } else {
                        tid_request->data        = (guint8 *) wmem_alloc(wmem_file_scope(), attribute_list_byte_count);
                        tid_request->data_length = attribute_list_byte_count;

                        tvb_memcpy(tvb, tid_request->data, attribute_list_byte_offset, attribute_list_byte_count);
                    }

                    if (uuid_array) *uuid_array = tid_request->uuid_array;
                    if (record_handle) *record_handle = tid_request->record_handle;
                }
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_psm          = psm;
            k_tid          = tid;
            k_frame_number = frame_number;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_psm;
            key[4].length = 1;
            key[4].key    = &k_tid;
            key[5].length = 1;
            key[5].key    = &k_frame_number;
            key[6].length = 0;
            key[6].key    = NULL;
        }

        /* full reassemble */
        if (!is_request) {
            tid_request = (tid_request_t *) wmem_tree_lookup32_array_le(tid_requests, key);
            if (tid_request && tid_request->interface_id == interface_id &&
                    tid_request->adapter_id == adapter_id &&
                    tid_request->chandle == chandle &&
                    tid_request->psm == psm &&
                    tid_request->tid == tid) {
                tvbuff_t *next_tvb;

                next_tvb = tvb_new_child_real_data(tvb, tid_request->data,
                        tid_request->data_length, tid_request->data_length);

                if (new_tvb) *new_tvb = next_tvb;
                if (tid_request->continuation_state_length && is_first) *is_first = FALSE;

                if (uuid_array) *uuid_array = tid_request->uuid_array;
                if (record_handle) *record_handle = tid_request->record_handle;
            }
        }
    } else {
        guint8      *continuation_state_buffer;
        guint8       continuation_state_length;

        continuation_state_length = tvb_get_guint8(tvb, offset);
        offset++;

        continuation_state_buffer = tvb_bytes_to_str(wmem_file_scope(), tvb, offset, continuation_state_length);

        if (!pinfo->fd->flags.visited) {
            if (is_request) {
                tid_request = (tid_request_t *) wmem_new(wmem_file_scope(), tid_request_t);
                tid_request->interface_id              = interface_id;
                tid_request->adapter_id                = adapter_id;
                tid_request->chandle                   = chandle;
                tid_request->psm                       = psm;
                tid_request->tid                       = tid;

                if (uuid_array)
                    tid_request->uuid_array = *uuid_array;
                else
                    tid_request->uuid_array = NULL;

                if (record_handle)
                    tid_request->record_handle = *record_handle;
                else
                    tid_request->record_handle = 0;

                /* fetch data saved in continuation_state */
                tid_request->data        = NULL;
                tid_request->data_length = 0;

                tid_request->pdu_type = pdu_type;

                tid_request->continuation_state        = continuation_state_buffer;
                tid_request->continuation_state_length = continuation_state_length;

                wmem_tree_insert32_array(tid_requests, key, tid_request);
            } else {
                tid_request = (tid_request_t *) wmem_tree_lookup32_array_le(tid_requests, key);
                if (tid_request && tid_request->interface_id == interface_id &&
                        tid_request->adapter_id == adapter_id &&
                        tid_request->chandle == chandle &&
                        tid_request->psm == psm &&
                        tid_request->tid == tid) {
                    /* data comes from here and saved in previous continuation_state */

                    if (tid_request->continuation_state_length > 0) {
                        /* fetch tid_request->continuation_state */
                        k_continuation_state_array =  (guint32 *) wmem_alloc0(wmem_packet_scope(), 20);
                        continuation_state = (guint8 *) k_continuation_state_array;
                        continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);

                        k_interface_id       = interface_id;
                        k_adapter_id         = adapter_id;
                        k_chandle            = chandle;
                        k_psm                = psm;
                        k_pdu_type           = tid_request->pdu_type;

                        key[0].length = 1;
                        key[0].key    = &k_interface_id;
                        key[1].length = 1;
                        key[1].key    = &k_adapter_id;
                        key[2].length = 1;
                        key[2].key    = &k_chandle;
                        key[3].length = 1;
                        key[3].key    = &k_psm;
                        key[4].length = 1;
                        key[4].key    = &k_pdu_type;
                        key[5].length = 1;
                        key[5].key    = &k_continuation_state_array[0];
                        key[6].length = 1;
                        key[6].key    = &k_continuation_state_array[1];
                        key[7].length = 1;
                        key[7].key    = &k_continuation_state_array[2];
                        key[8].length = 1;
                        key[8].key    = &k_continuation_state_array[3];
                        key[9].length = 1;
                        key[9].key     = &k_continuation_state_array[4];
                        key[10].length = 0;
                        key[10].key    = NULL;

                        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(continuation_states, key);
                        continuation_state_data = (subtree) ? (continuation_state_data_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                        if (continuation_state_data) {
                            tid_request->data = (guint8 *) wmem_alloc(wmem_file_scope(), continuation_state_data->data_length + attribute_list_byte_count);
                            tid_request->data_length = continuation_state_data->data_length + attribute_list_byte_count;
                            memcpy(tid_request->data, continuation_state_data->data, continuation_state_data->data_length);
                            tvb_memcpy(tvb, tid_request->data + continuation_state_data->data_length, attribute_list_byte_offset, attribute_list_byte_count);
                        }
                    } else {
                        tid_request->data        = (guint8 *) wmem_alloc(wmem_file_scope(), attribute_list_byte_count);
                        tid_request->data_length = attribute_list_byte_count;

                        tvb_memcpy(tvb, tid_request->data, attribute_list_byte_offset, attribute_list_byte_count);
                    }

                    if (uuid_array) *uuid_array = tid_request->uuid_array;
                    if (record_handle) *record_handle = tid_request->record_handle;

                    /* save tid_request in continuation_state data */
                    k_continuation_state_array =  (guint32 *) wmem_alloc0(wmem_packet_scope(), 20);
                    continuation_state = (guint8 *) k_continuation_state_array;
                    continuation_state[0] = continuation_state_length;
                    memcpy(&continuation_state[1], continuation_state_buffer, continuation_state_length);

                    k_interface_id       = interface_id;
                    k_adapter_id         = adapter_id;
                    k_chandle            = chandle;
                    k_psm                = psm;
                    k_pdu_type           = pdu_type;
                    k_frame_number       = frame_number;

                    key[0].length = 1;
                    key[0].key    = &k_interface_id;
                    key[1].length = 1;
                    key[1].key    = &k_adapter_id;
                    key[2].length = 1;
                    key[2].key    = &k_chandle;
                    key[3].length = 1;
                    key[3].key    = &k_psm;
                    key[4].length = 1;
                    key[4].key    = &k_pdu_type;
                    key[5].length = 1;
                    key[5].key    = &k_continuation_state_array[0];
                    key[6].length = 1;
                    key[6].key    = &k_continuation_state_array[1];
                    key[7].length = 1;
                    key[7].key    = &k_continuation_state_array[2];
                    key[8].length = 1;
                    key[8].key    = &k_continuation_state_array[3];
                    key[9].length = 1;
                    key[9].key    = &k_continuation_state_array[4];
                    key[10].length = 1;
                    key[10].key    = &k_frame_number;
                    key[11].length = 0;
                    key[11].key    = NULL;

                    continuation_state_data = (continuation_state_data_t *) wmem_new(wmem_file_scope(), continuation_state_data_t);
                    continuation_state_data->interface_id = interface_id;
                    continuation_state_data->adapter_id = adapter_id;
                    continuation_state_data->chandle = chandle;
                    continuation_state_data->psm = psm;
                    continuation_state_data->pdu_type = pdu_type;
                    continuation_state_data->continuation_state[0] = k_continuation_state_array[0];
                    continuation_state_data->continuation_state[1] = k_continuation_state_array[1];
                    continuation_state_data->continuation_state[2] = k_continuation_state_array[2];
                    continuation_state_data->continuation_state[3] = k_continuation_state_array[3];
                    continuation_state_data->continuation_state[4] = k_continuation_state_array[4];
                    continuation_state_data->data = tid_request->data;
                    continuation_state_data->data_length = tid_request->data_length;

                    wmem_tree_insert32_array(continuation_states, key, continuation_state_data);
                }
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_psm          = psm;
            k_tid          = tid;
            k_frame_number = frame_number;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_psm;
            key[4].length = 1;
            key[4].key    = &k_tid;
            key[5].length = 1;
            key[5].key    = &k_frame_number;
            key[6].length = 0;
            key[6].key    = NULL;
        }

        /* partial reassemble */
        if (!is_request) {
            tid_request = (tid_request_t *) wmem_tree_lookup32_array_le(tid_requests, key);
            if (tid_request && tid_request->interface_id == interface_id &&
                    tid_request->adapter_id == adapter_id &&
                    tid_request->chandle == chandle &&
                    tid_request->psm == psm &&
                    tid_request->tid == tid) {
                tvbuff_t *next_tvb;

                next_tvb = tvb_new_child_real_data(tvb, tid_request->data,
                        tid_request->data_length, tid_request->data_length);

                if (new_tvb) *new_tvb = next_tvb;
                if (tid_request->continuation_state_length && is_first) *is_first = FALSE;

                if (uuid_array) *uuid_array = tid_request->uuid_array;
                if (record_handle) *record_handle = tid_request->record_handle;
            }

        }
    }

    return offset;
}

static gint
dissect_data_element(proto_tree *tree, proto_tree **next_tree,
        packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    proto_item  *pitem;
    proto_tree  *ptree;
    gint        new_offset;
    gint        length;
    gint        len;
    guint8      type;
    guint8      size;

    new_offset = get_type_length(tvb, offset, &length) - 1;
    type = tvb_get_guint8(tvb, offset);
    size = type & 0x07;
    type = type >> 3;

    pitem = proto_tree_add_none_format(tree, hf_data_element, tvb, offset, 0, "Data Element: %s %s",
            val_to_str_const(type, vs_data_element_type, "Unknown Type"),
            val_to_str_const(size, vs_data_element_size, "Unknown Size"));
    ptree = proto_item_add_subtree(pitem, ett_btsdp_data_element);

    len = (new_offset - offset) + length;

    proto_item_set_len(pitem, len + 1);

    proto_tree_add_item(ptree, hf_data_element_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ptree, hf_data_element_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (new_offset > offset - 1) {
        proto_tree_add_uint(ptree, hf_data_element_var_size, tvb,
                offset, len - length, length);
        proto_item_append_text(pitem, (length != 1) ? " %u bytes" : " %u byte", length);
        offset += len - length;
    }

    pitem = proto_tree_add_item(ptree, hf_data_element_value, tvb, offset,  0, ENC_NA);
    if (length > tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info(pinfo, pitem, &ei_data_element_value_large);
        length = 0;
    }
    proto_item_set_len(pitem, length);
    if (length == 0)
        proto_item_append_text(pitem, ": MISSING");

    if (next_tree) *next_tree = proto_item_add_subtree(pitem, ett_btsdp_data_element_value);
    offset += length;

    return offset;
}


static gint
findDidVendorIdSource(tvbuff_t *tvb, gint service_offset,
        gint number_of_attributes)
{
    gint result = 0;
    gint search_length;
    gint search_offset;
    gint i_number_of_attributes;
    guint16 attribute;

    search_offset = service_offset;
    i_number_of_attributes = 0;

    while (i_number_of_attributes < number_of_attributes) {
        search_offset = get_type_length(tvb, search_offset, &search_length);
        attribute = tvb_get_ntohs(tvb, search_offset);

        search_offset += search_length;
        search_offset = get_type_length(tvb, search_offset, &search_length);

        if (attribute == 0x205) {
            result = get_uint_by_size(tvb, search_offset, 1);
        }

        search_offset += search_length;
        i_number_of_attributes += 1;
    }

    return result;
}

static gint
findDidVendorId(tvbuff_t *tvb, gint service_offset,
        gint number_of_attributes)
{
    gint result = 0;
    gint search_length;
    gint search_offset;
    gint i_number_of_attributes;
    guint16 attribute;

    search_offset = service_offset;
    i_number_of_attributes = 0;

    while (i_number_of_attributes < number_of_attributes) {
        search_offset = get_type_length(tvb, search_offset, &search_length);
        attribute = tvb_get_ntohs(tvb, search_offset);

        search_offset += search_length;
        search_offset = get_type_length(tvb, search_offset, &search_length);

        if (attribute == 0x201) {
            result = get_uint_by_size(tvb, search_offset, 1);
        }

        search_offset += search_length;
        i_number_of_attributes += 1;
    }

    return result;
}


static void
dissect_protocol_descriptor_list(proto_tree *next_tree, tvbuff_t *tvb,
        packet_info *pinfo, gint offset, gint size, wmem_strbuf_t *info_buf,
        service_info_t  *service_info, gint *protocol_order)
{
    proto_tree      *feature_tree;
    proto_item      *feature_item;
    proto_tree      *entry_tree;
    proto_item      *entry_item;
    proto_tree      *sub_tree;
    proto_tree      *last_tree;
    gint             new_offset;
    gint             list_offset;
    gint             entry_offset;
    gint             entry_length;
    guint32          value;
    gint             length;
    guint32          i_protocol;
    bluetooth_uuid_t uuid;
    service_info_t  *record = NULL;

    list_offset = offset;
    i_protocol = 1;
    while (list_offset - offset < size) {
        const gchar     *uuid_str;

        feature_item = proto_tree_add_none_format(next_tree, hf_sdp_protocol_item, tvb, list_offset, 0, "Protocol #%u", i_protocol);
        feature_tree = proto_item_add_subtree(feature_item, ett_btsdp_protocol);
        entry_offset = get_type_length(tvb, list_offset, &entry_length);
        proto_item_set_len(feature_item, entry_length + (entry_offset - list_offset));

        dissect_data_element(feature_tree, &sub_tree, pinfo, tvb, list_offset);

        entry_item = proto_tree_add_item(sub_tree, hf_sdp_protocol, tvb, entry_offset, entry_length, ENC_NA);
        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_supported_features_mdep_id);
        dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
        new_offset = get_type_length(tvb, entry_offset, &length);
        entry_offset = new_offset;

        dissect_uuid(sub_tree, tvb, entry_offset, length, &uuid);

        uuid_str = print_uuid(&uuid);
        wmem_strbuf_append(info_buf, uuid_str);
        proto_item_append_text(feature_item, ": %s", uuid_str);
        proto_item_append_text(entry_item, ": %s", uuid_str);

        entry_offset += length;

        if (entry_offset - list_offset <= entry_length) {
            dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
            new_offset = get_type_length(tvb, entry_offset, &length);
            entry_offset = new_offset;
            value = get_int_by_size(tvb, entry_offset, length / 2);

            if (uuid.bt_uuid == BTSDP_L2CAP_PROTOCOL_UUID) {
                wmem_strbuf_append_printf(info_buf, ":%u", value);
                proto_item_append_text(feature_item, ", PSM: %u", value);
                proto_item_append_text(entry_item, ", PSM: %u", value);
                proto_tree_add_item(sub_tree, hf_sdp_protocol_psm, tvb, entry_offset, 2, ENC_BIG_ENDIAN);
                if (!pinfo->fd->flags.visited && service_info)
                    record = save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, value, *protocol_order, service_info);
                *protocol_order += 1;
            } else if (uuid.bt_uuid == BTSDP_RFCOMM_PROTOCOL_UUID) {
                wmem_strbuf_append_printf(info_buf, ":%u", value);
                proto_item_append_text(feature_item, ", RFCOMM Channel: %u", value);
                proto_item_append_text(entry_item, ", RFCOMM Channel: %u", value);
                proto_tree_add_item(sub_tree, hf_sdp_protocol_channel, tvb, entry_offset, 1, ENC_BIG_ENDIAN);
                if (!pinfo->fd->flags.visited && service_info)
                    record = save_channel(pinfo, BTSDP_RFCOMM_PROTOCOL_UUID, value, *protocol_order, service_info);
                *protocol_order += 1;
            } else if (uuid.bt_uuid == BTSDP_ATT_PROTOCOL_UUID) {
                proto_item_append_text(feature_item, ", GATT Handle Start: 0x%04x", value);
                proto_item_append_text(entry_item, ", GATT Handle Start: 0x%04x", value);
                wmem_strbuf_append_printf(info_buf, ":0x%04x.", value);
                proto_tree_add_item(sub_tree, hf_sdp_protocol_gatt_handle_start, tvb, entry_offset, 2, ENC_BIG_ENDIAN);

                if ((entry_offset - list_offset) + length <= entry_length) {
                    entry_offset += length;
                    dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
                    new_offset = get_type_length(tvb, entry_offset, &length);
                    entry_offset = new_offset;
                    value = get_int_by_size(tvb, entry_offset, length / 2);

                    wmem_strbuf_append_printf(info_buf, ".0x%04x", value);
                    proto_item_append_text(feature_item, ", GATT Handle End: 0x%04x", value);
                    proto_item_append_text(entry_item, ", GATT Handle End: 0x%04x", value);
                    proto_tree_add_item(sub_tree, hf_sdp_protocol_gatt_handle_end, tvb, entry_offset, 2, ENC_BIG_ENDIAN);
                }
            } else {
                wmem_strbuf_append_printf(info_buf, " (%x.%x)", value >> 8, value & 0xFF);
                proto_item_append_text(feature_item, ", Version %x.%x", value >> 8, value & 0xFF);
                proto_item_append_text(entry_item, ", Version 0x%03x", value);
                proto_tree_add_item(sub_tree, hf_sdp_protocol_version, tvb, entry_offset, 2, ENC_BIG_ENDIAN);
            }

            entry_offset += length;
        }

        while (entry_offset - list_offset <= entry_length) {
            gint value_offset;
            gint len;

            dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
            new_offset = get_type_length(tvb, entry_offset, &length);

            if (uuid.bt_uuid == BTSDP_BNEP_PROTOCOL_UUID) {
                wmem_strbuf_append(info_buf, " (");
                value_offset = new_offset;
                while (value_offset - new_offset < length) {
                    gint next_offset;
                    dissect_data_element(sub_tree, &last_tree, pinfo, tvb, value_offset);
                    next_offset = get_type_length(tvb, value_offset, &len);
                    value = get_int_by_size(tvb, next_offset, len / 2);

                    proto_tree_add_item(last_tree, hf_sdp_protocol_bnep_type, tvb, next_offset, 2, ENC_BIG_ENDIAN);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, etype_vals, "Unknown"));
                    value_offset = next_offset + len;

                    if (value_offset - new_offset < length)
                        wmem_strbuf_append(info_buf, " ");
                }
                wmem_strbuf_append(info_buf, ")");
            }

            entry_offset = new_offset + length;
        }

        i_protocol += 1;
        list_offset = entry_offset;

        if (list_offset - offset < size)
            wmem_strbuf_append(info_buf, " -> ");

        if (record)
            record->protocol = uuid.bt_uuid;
    }

}


static gint
dissect_sdp_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
        gint offset, gint attribute, bluetooth_uuid_t service_uuid,
        gint service_did_vendor_id, gint service_did_vendor_id_source,
        service_info_t  *service_info, wmem_strbuf_t **pinfo_buf)
{
    proto_tree    *feature_tree;
    proto_item    *feature_item;
    proto_tree    *entry_tree;
    proto_item    *entry_item;
    proto_tree    *next_tree;
    proto_tree    *sub_tree;
    proto_tree    *last_tree;
    gint           size;
    guint8         byte;
    guint8         type;
    guint8         size_index;
    gint           start_offset;
    gint           new_offset;
    gint           list_offset;
    gint           list_length;
    gint           entry_offset;
    gint           entry_length;
    gboolean       found;
    guint16        specification_id;
    guint16        vendor_id;
    guint16        product_id;
    guint16        version;
    guint8         primary_record;
    guint8         mdep_id;
    guint16        vendor_id_source;
    const guint8  *str_val;
    guint32        supported_features;
    guint          i_feature;
    guint          i_protocol;
    guint16        psm;
    const guint8  *new_str;
    guint32        value;
    guint64        value_64;
    bluetooth_uuid_t uuid;
    const gchar   *uuid_str;
    gint           length;
    gint           protocol_order;
    wmem_strbuf_t *info_buf;

    info_buf = wmem_strbuf_new_label(wmem_packet_scope());
    *pinfo_buf = info_buf;


    byte         = tvb_get_guint8(tvb, offset);
    type         = (byte >> 3) & 0x1f;
    size_index   = byte & 0x07;

    start_offset = offset;
    new_offset = dissect_data_element(tree, &next_tree, pinfo, tvb, offset);

    offset = get_type_length(tvb, offset, &size);

    found = TRUE;
    switch(service_uuid.bt_uuid) {
        case BTSDP_DID_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_did_specification_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                    specification_id = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%x.%02x (0x%04x)", specification_id >> 8, specification_id & 0xFF, specification_id);
                    break;
                case 0x201:
                    vendor_id = tvb_get_ntohs(tvb, offset);
                    if (service_did_vendor_id_source == DID_VENDOR_ID_SOURCE_BLUETOOTH_SIG) {
                        proto_tree_add_item(next_tree, hf_did_vendor_id_bluetooth_sig, tvb, offset, 2, ENC_BIG_ENDIAN);
                        str_val = val_to_str_ext_const(vendor_id, &bluetooth_company_id_vals_ext, "Unknown");
                    } else if (service_did_vendor_id_source == DID_VENDOR_ID_SOURCE_USB_FORUM) {
                        proto_tree_add_item(next_tree, hf_did_vendor_id_usb_forum, tvb, offset, 2, ENC_BIG_ENDIAN);
                        str_val = val_to_str_ext_const(vendor_id, &ext_usb_vendors_vals, "Unknown");
                    } else {
                        proto_tree_add_item(next_tree, hf_did_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                        str_val = "Unknown";
                    }
                    wmem_strbuf_append_printf(info_buf, "%s (0x%04x)", str_val, vendor_id);
                    break;
                case 0x202:
                    entry_item = proto_tree_add_item(next_tree, hf_did_product_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                    product_id = tvb_get_ntohs(tvb, offset);

                    if (service_did_vendor_id_source == DID_VENDOR_ID_SOURCE_USB_FORUM) {
                        str_val = val_to_str_ext_const(service_did_vendor_id << 16 | product_id, &ext_usb_products_vals, "Unknown");
                        wmem_strbuf_append_printf(info_buf, "%s (0x%04x)", str_val, product_id);
                        proto_item_append_text(entry_item, " (%s)", str_val);
                    } else {
                        wmem_strbuf_append_printf(info_buf, "0x%04x", product_id);
                    }
                    break;
                case 0x203:
                    proto_tree_add_item(next_tree, hf_did_version, tvb, offset, 2, ENC_BIG_ENDIAN);
                    version = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%x.%x.%x (0x%04x)", version >> 8, (version >> 4) & 0xF, version & 0xF, version);
                    break;
                case 0x204:
                    proto_tree_add_item(next_tree, hf_did_primary_record, tvb, offset, 1, ENC_BIG_ENDIAN);
                    primary_record = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, primary_record ? "true" : "false");
                    break;
                case 0x205:
                    proto_tree_add_item(next_tree, hf_did_vendor_id_source, tvb, offset, 2, ENC_BIG_ENDIAN);
                    vendor_id_source = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s (0x%04x)",
                            val_to_str_const(vendor_id_source, did_vendor_id_source_vals, "Unknown"),
                            vendor_id_source);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_A2DP_SINK_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_a2dp_sink_supported_features_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_sink_supported_features_amplifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_sink_supported_features_recorder, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_sink_supported_features_speaker, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_sink_supported_features_headphone, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (supported_features & 0x01) ? "Headphone " : "",
                            (supported_features & 0x02) ? "Speaker " : "",
                            (supported_features & 0x04) ? "Recorder " : "",
                            (supported_features & 0x08) ? "Amplifier " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_A2DP_SOURCE_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_a2dp_source_supported_features_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_source_supported_features_mixer, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_source_supported_features_tuner, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_source_supported_features_microphone, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_a2dp_source_supported_features_player, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (supported_features & 0x01) ? "Player " : "",
                            (supported_features & 0x02) ? "Microphone " : "",
                            (supported_features & 0x04) ? "Tuner " : "",
                            (supported_features & 0x08) ? "Mixer " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_SYNC_SERVICE_UUID:
            switch (attribute) {
                case 0x301:
                    list_offset = offset;
                    while (list_offset - offset < size) {
                        dissect_data_element(next_tree, &entry_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &list_length);
                        proto_tree_add_item(entry_tree, hf_synch_supported_data_store, tvb, list_offset, 1, ENC_BIG_ENDIAN);
                        value = tvb_get_guint8(tvb, list_offset);

                        wmem_strbuf_append_printf(info_buf, "%s ", val_to_str_const(value, synch_supported_data_store_vals, "Unknown"));
                        list_offset += list_length;
                    }
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_CTP_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_ctp_external_network, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);

                    wmem_strbuf_append(info_buf, val_to_str_const(value, ctp_external_network_vals, "Unknown"));
                break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_AVRCP_SERVICE_UUID:
        case BTSDP_AVRCP_CT_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_reserved_7_15, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_browsing, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_reserved_4_5, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_category_4, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_category_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_category_2, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_ct_supported_features_category_1, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s",
                            (supported_features & 0x01) ? "Category1(Player/Recorder) " : "",
                            (supported_features & 0x02) ? "Category2(Monitor/Amplifier) " : "",
                            (supported_features & 0x04) ? "Category3(Tuner) " : "",
                            (supported_features & 0x08) ? "Category4(Menu) " : "",
                            (supported_features & 0x40) ? "Browsing " : "");
                break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_AVRCP_TG_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_reserved_8_15, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_multiple_player, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_browsing, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_group_navigation, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_settings, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_category_4, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_category_3, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_category_2, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_avrcp_tg_supported_features_category_1, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "Category1(Player/Recorder) " : "",
                            (supported_features & 0x02) ? "Category2(Monitor/Amplifier) " : "",
                            (supported_features & 0x04) ? "Category3(Tuner) " : "",
                            (supported_features & 0x08) ? "Category4(Menu) " : "",
                            (supported_features & 0x10) ? "PlayerApplicationSettings " : "",
                            (supported_features & 0x20) ? "GroupNavigation " : "",
                            (supported_features & 0x40) ? "Browsing " : "",
                            (supported_features & 0x80) ? "MultiplePlayers " : "");
                break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HSP_SERVICE_UUID:
        case BTSDP_HSP_HS_SERVICE_UUID:
            switch (attribute) {
                case 0x302:
                    proto_tree_add_item(next_tree, hf_hsp_remote_audio_volume_control, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_GNSS_UUID:
        case BTSDP_GNSS_SERVER_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_gnss_supported_features, tvb, offset, 2, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "reserved (0x%04x)", supported_features);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_PBAP_PSE_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_pbap_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited  && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x314:
                    proto_tree_add_bitmask_with_flags(next_tree, tvb, offset, hf_pbap_pse_supported_repositories, ett_btsdp_supported_features,  hfx_pbap_pse_supported_repositories, ENC_NA, BMT_NO_APPEND);
                    supported_features = tvb_get_guint8(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (supported_features & 0x01) ? "LocalPhonebook " : "",
                            (supported_features & 0x02) ? "SIM " : "",
                            (supported_features & 0x04) ? "SpeedDial " : "",
                            (supported_features & 0x08) ? "Favourites " : "");
                    break;
                case 0x317:
                    proto_tree_add_bitmask_with_flags(next_tree, tvb, offset, hf_pbap_pse_supported_features, ett_btsdp_supported_features,  hfx_pbap_pse_supported_features, ENC_NA, BMT_NO_APPEND);
                    supported_features = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s%s%s%s",
                            (supported_features & 0x001) ? "Download " : "",
                            (supported_features & 0x002) ? "Browsing " : "",
                            (supported_features & 0x004) ? "DatabaseIdentifier " : "",
                            (supported_features & 0x008) ? "FolderVersionCounters " : "",
                            (supported_features & 0x010) ? "vCardSelecting " : "",
                            (supported_features & 0x020) ? "EnhancedMissedCalls " : "",
                            (supported_features & 0x040) ? "X-BT-UCIvCardProperty " : "",
                            (supported_features & 0x080) ? "X-BT-UIDvCardProperty " : "",
                            (supported_features & 0x100) ? "ContactReferencing " : "",
                            (supported_features & 0x200) ? "DefaultContactImageFormat " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_FAX_SERVICE_UUID:
            switch (attribute) {
                case 0x302:
                    proto_tree_add_item(next_tree, hf_fax_support_class_1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, supported_features ? "true" : "false");
                    break;
                case 0x303:
                    proto_tree_add_item(next_tree, hf_fax_support_class_2, tvb, offset, 1, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, supported_features ? "true" : "false");
                    break;
                case 0x304:
                    proto_tree_add_item(next_tree, hf_fax_support_class_2_vendor, tvb, offset, 1, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, supported_features ? "true" : "false");
                    break;
                case 0x305:
                    proto_tree_add_item(next_tree, hf_fax_support_audio_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, supported_features ? "true" : "false");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_FTP_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_ftp_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited  && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_MAP_SERVICE_UUID:
        case BTSDP_MAP_ACCESS_SRV_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_map_mas_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited  && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x315:
                    proto_tree_add_item(next_tree, hf_map_mas_instance_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", value, value);
                    break;
                case 0x316:
                    proto_tree_add_item(next_tree, hf_map_mas_supported_message_types_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_map_mas_supported_message_types_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_map_mas_supported_message_types_sms_cdma, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_map_mas_supported_message_types_sms_gsm, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_map_mas_supported_message_types_email, tvb, offset, 1, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (supported_features & 0x01) ? "Email " : "",
                            (supported_features & 0x02) ? "SMS_GSM " : "",
                            (supported_features & 0x04) ? "SMS_CDMA " : "",
                            (supported_features & 0x08) ? "MMS " : "");
                    break;
                case 0x317:
                    proto_tree_add_bitmask_with_flags(next_tree, tvb, offset, hf_map_supported_features, ett_btsdp_supported_features,  hfx_map_supported_features, ENC_NA, BMT_NO_APPEND);
                    supported_features = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "NotificationRegistration Feature " : "",
                            (supported_features & 0x02) ? "NotificationFeature " : "",
                            (supported_features & 0x04) ? "BrowsingFeature " : "",
                            (supported_features & 0x08) ? "UploadingFeature " : "",
                            (supported_features & 0x10) ? "DeleteFeature " : "",
                            (supported_features & 0x20) ? "InstanceInformationFeature " : "",
                            (supported_features & 0x40) ? "ExtendedEventReport1.1 " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_MAP_NOTIFICATION_SRV_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_map_mns_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited  && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x317:
                    proto_tree_add_bitmask_with_flags(next_tree, tvb, offset, hf_map_supported_features, ett_btsdp_supported_features,  hfx_map_supported_features, ENC_NA, BMT_NO_APPEND);
                    supported_features = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "NotificationRegistration Feature " : "",
                            (supported_features & 0x02) ? "NotificationFeature " : "",
                            (supported_features & 0x04) ? "BrowsingFeature " : "",
                            (supported_features & 0x08) ? "UploadingFeature " : "",
                            (supported_features & 0x10) ? "DeleteFeature " : "",
                            (supported_features & 0x20) ? "InstanceInformationFeature " : "",
                            (supported_features & 0x40) ? "ExtendedEventReport1.1 " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HCRP_SERVICE_UUID:
        case BTSDP_HCRP_PRINT_SERVICE_UUID:
        case BTSDP_HCRP_SCAN_SERVICE_UUID:
            switch (attribute) {
                case 0x300:
                    proto_tree_add_item_ret_string(next_tree, hf_hcrp_1284_id, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x302:
                    proto_tree_add_item_ret_string(next_tree, hf_hcrp_device_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x304:
                    proto_tree_add_item_ret_string(next_tree, hf_hcrp_friendly_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x306:
                    proto_tree_add_item_ret_string(next_tree, hf_hcrp_device_location, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_WAP_SERVICE_UUID:
        case BTSDP_WAP_CLIENT_SERVICE_UUID:
            switch (attribute) {
                case 0x306:
                    proto_tree_add_item(next_tree, hf_wap_network_address, tvb, offset, 4, ENC_BIG_ENDIAN);
                    wmem_strbuf_append(info_buf, tvb_ip_to_str(tvb, offset));
                    break;
                case 0x307:
                    proto_tree_add_item(next_tree, hf_wap_gateway, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, wap_gateway_vals, "Unknown"));
                    break;
                case 0x308:
                    proto_tree_add_item_ret_string(next_tree, hf_wap_homepage_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x309:
                    proto_tree_add_item(next_tree, hf_wap_stack_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, wap_stack_type_vals, "Unknown"));
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HDP_SERVICE_UUID:
        case BTSDP_HDP_SOURCE_SERVICE_UUID:
        case BTSDP_HDP_SINK_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    i_feature = 1;
                    list_offset = offset;
                    while (list_offset - offset < size) {
                        entry_offset = get_type_length(tvb, list_offset, &entry_length);
                        feature_item = proto_tree_add_none_format(next_tree, hf_hdp_supported_features_data, tvb, entry_offset, entry_length, "Supported Feature #%u", i_feature);
                        feature_tree = proto_item_add_subtree(feature_item, ett_btsdp_supported_features);

                        dissect_data_element(feature_tree, &sub_tree, pinfo, tvb, list_offset);

                        entry_item = proto_tree_add_item(sub_tree, hf_hdp_supported_features_data_mdep_id, tvb, entry_offset, 0, ENC_NA);
                        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_supported_features_mdep_id);
                        dissect_data_element(entry_tree, &next_tree, pinfo, tvb, entry_offset);
                        new_offset = get_type_length(tvb, entry_offset, &length);
                        proto_item_set_len(entry_item, (new_offset - entry_offset) + length);
                        entry_offset = new_offset;

                        proto_tree_add_item(next_tree, hf_hdp_supported_features_mdep_id, tvb, entry_offset, 1, ENC_BIG_ENDIAN);
                        mdep_id = tvb_get_guint8(tvb, entry_offset);
                        proto_item_append_text(entry_item, ": %u (0x%02x)", mdep_id, mdep_id);
                        entry_offset += length;

                        entry_item = proto_tree_add_item(sub_tree, hf_hdp_supported_features_data_mdep_data_type, tvb, entry_offset, 0, ENC_NA);
                        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_supported_features_mdep_data_type);

                        dissect_data_element(entry_tree, &next_tree, pinfo, tvb, entry_offset);
                        new_offset = get_type_length(tvb, entry_offset, &length);
                        proto_item_set_len(entry_item, (new_offset - entry_offset) + length);
                        entry_offset = new_offset;
                        proto_tree_add_item(next_tree, hf_hdp_supported_features_mdep_data_type, tvb, entry_offset, 2, ENC_BIG_ENDIAN);
                        value = tvb_get_ntohs(tvb, entry_offset);
                        proto_item_append_text(entry_item, ": %u (0x%04x)", value, value);
                        entry_offset += length;

                        entry_item = proto_tree_add_item(sub_tree, hf_hdp_supported_features_data_mdep_role, tvb, entry_offset, 0, ENC_NA);
                        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_supported_features_mdep_role);

                        dissect_data_element(entry_tree, &next_tree, pinfo, tvb, entry_offset);
                        new_offset = get_type_length(tvb, entry_offset, &length);
                        proto_item_set_len(entry_item, (new_offset - entry_offset) + length);
                        entry_offset = new_offset;
                        proto_tree_add_item(next_tree, hf_hdp_supported_features_mdep_role, tvb, entry_offset, 1, ENC_BIG_ENDIAN);
                        value = tvb_get_guint8(tvb, entry_offset);
                        wmem_strbuf_append_printf(info_buf, "MDEP ID: %u (Role: %s) ", mdep_id, val_to_str_const(value, hdp_mdep_role_vals ,"Unknown"));
                        proto_item_append_text(entry_item, ": %s", val_to_str_const(value, hdp_mdep_role_vals ,"Unknown"));
                        entry_offset += length;

                        if (entry_length - (entry_offset - list_offset) > 0) {
                            const guint8* entry_str;

                            entry_item = proto_tree_add_item(sub_tree, hf_hdp_supported_features_data_mdep_description, tvb, entry_offset, entry_length, ENC_NA);
                            entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_supported_features_mdep_description);

                            dissect_data_element(entry_tree, &next_tree, pinfo, tvb, entry_offset);
                            new_offset = get_type_length(tvb, entry_offset, &length);
                            proto_item_set_len(entry_item, (new_offset - entry_offset) + length);
                            entry_offset = new_offset;
                            proto_tree_add_item_ret_string(next_tree, hf_hdp_supported_features_mdep_description, tvb, entry_offset, length,
                                                            ENC_ASCII | ENC_NA, wmem_packet_scope(), &entry_str);
                            proto_item_append_text(entry_item, ": %s", entry_str);
                            entry_offset += length;
                        }

                        list_offset = entry_offset;
                        i_feature += 1;
                    }
                    break;
                case 0x301:
                    proto_tree_add_item(next_tree, hf_hdp_data_exchange, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, hdp_data_exchange_specification_vals, "Unknown"));
                    break;
                case 0x302:
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_reserved_5_7, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_sync_master_role, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_clock_synchronization_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_reconnect_acceptance, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_reconnect_initiation, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hdp_support_procedure_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (supported_features & 0x02) ? "ReconnectInitiation " : "",
                            (supported_features & 0x04) ? "ReconnectAcceptance " : "",
                            (supported_features & 0x08) ? "ClockSynchronizationProtocol " : "",
                            (supported_features & 0x10) ? "SyncMasterRole " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_PAN_GN_SERVICE_UUID:
            switch (attribute) {
                case 0x30A:
                    proto_tree_add_item(next_tree, hf_pan_sercurity_description, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, pan_security_description_vals, "Unknown"));
                    break;
                case 0x30D:
                case 0x200:
                    proto_tree_add_item_ret_string(next_tree, hf_pan_ipv4_subnet, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x30E:
                    proto_tree_add_item_ret_string(next_tree, hf_pan_ipv6_subnet, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_PAN_NAP_SERVICE_UUID:
            switch (attribute) {
                case 0x30A:
                    proto_tree_add_item(next_tree, hf_pan_sercurity_description, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, pan_security_description_vals, "Unknown"));
                    break;
                case 0x30B:
                    proto_tree_add_item(next_tree, hf_pan_net_access_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, pan_net_access_type_vals, "Unknown"));
                    break;
                case 0x30C:
                    proto_tree_add_item(next_tree, hf_pan_max_net_access_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohl(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%08x)", value, value);
                    break;
                case 0x30D:
                case 0x200:
                    proto_tree_add_item_ret_string(next_tree, hf_pan_ipv4_subnet, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x30E:
                    proto_tree_add_item_ret_string(next_tree, hf_pan_ipv6_subnet, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_PAN_PANU_SERVICE_UUID:
            switch (attribute) {
                case 0x30A:
                    proto_tree_add_item(next_tree, hf_pan_sercurity_description, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, pan_security_description_vals, "Unknown"));
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_OPP_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_opp_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x303:
                    list_offset = offset;
                    while (list_offset - offset < size) {
                        dissect_data_element(next_tree, &entry_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &list_length);
                        proto_tree_add_item(entry_tree, hf_opp_supported_format, tvb, list_offset, 1, ENC_BIG_ENDIAN);
                        value = tvb_get_guint8(tvb, list_offset);

                        wmem_strbuf_append_printf(info_buf, "%s ", val_to_str_const(value, opp_supported_format_vals, "Unknown"));
                        list_offset += list_length;
                    }
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_DUN_SERVICE_UUID:
            switch (attribute) {
                case 0x305:
                    proto_tree_add_item(next_tree, hf_dun_support_audio_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
                    supported_features = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, supported_features ? "true" : "false");
                    break;
                case 0x306:
                    proto_tree_add_item_ret_string(next_tree, hf_dun_escape_sequence, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HFP_SERVICE_UUID:
            switch (attribute) {
                case 0x311:
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_wide_band_speech, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_remote_volume_control, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_voice_recognition_activation, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_cli_presentation_capability, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_call_waiting_or_three_way_calling, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_hf_supported_features_ec_and_or_nr_function, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "(EC and/or Nr Function) " : "",
                            (supported_features & 0x02) ? "(Call Waiting or Three Way Calling) " : "",
                            (supported_features & 0x04) ? "(CLI Presentation Capability) " : "",
                            (supported_features & 0x08) ? "(Voice Recognition Activation) " : "",
                            (supported_features & 0x10) ? "(Remote Volume Control) " : "",
                            (supported_features & 0x20) ? "(Wide Band Speech) " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HFP_GW_SERVICE_UUID:
            switch (attribute) {
                case 0x301:
                    proto_tree_add_item(next_tree, hf_hfp_gw_network, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, hfp_gw_network_vals, "Unknown"));
                    break;
                case 0x311:
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_wide_band_speech, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_attach_phone_number_to_voice_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_inband_ring_tone_capability, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_voice_recognition_function, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_ec_and_or_nr_function, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hfp_gw_supported_features_three_way_calling, tvb, offset, 2, ENC_BIG_ENDIAN);

                    supported_features = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "(Three Way Calling) " : "",
                            (supported_features & 0x02) ? "(EC and/or Nr Function) " : "",
                            (supported_features & 0x04) ? "(Voice Recognition Function) " : "",
                            (supported_features & 0x08) ? "(Inband Ring Tone Capability) " : "",
                            (supported_features & 0x10) ? "(Attach a Phone Number to a Voice Tag) " : "",
                            (supported_features & 0x20) ? "(Wide Band Speech) " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_HID_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_hid_device_release_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    version = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%x.%x.%x (0x%04x)", version >> 8, (version >> 4) & 0xF, version & 0xF, version);
                    break;
                case 0x201:
                    proto_tree_add_item(next_tree, hf_hid_parser_version, tvb, offset, 2, ENC_BIG_ENDIAN);
                    version = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%x.%x.%x (0x%04x)", version >> 8, (version >> 4) & 0xF, version & 0xF, version);
                    break;
                case 0x202:
                    proto_tree_add_item(next_tree, hf_hid_device_subclass_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hid_device_subclass_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_hid_device_subclass_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s, %s",
                            val_to_str_const(value >> 6, hid_device_subclass_type_vals, "Unknown"),
                            val_to_str_const(((value & 0x3C) >> 2) , hid_device_subclass_subtype_vals, "Unknown"));
                    break;
                case 0x203:
                    proto_tree_add_item(next_tree, hf_hid_country_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, val_to_str_const(value, hid_country_code_vals, "Unknown"));
                    break;
                case 0x204:
                    proto_tree_add_item(next_tree, hf_hid_virtual_cable, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x205:
                    proto_tree_add_item(next_tree, hf_hid_reconnect_initiate, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x206:
                    list_offset = offset;
                    i_feature = 1;
                    while (list_offset - offset < size) {
                        entry_item = proto_tree_add_none_format(next_tree, hf_hid_descriptor_list_descriptor_data, tvb, list_offset, size, "Descriptor #%u", i_feature);
                        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_data_element);

                        dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);

                        dissect_data_element(sub_tree, &last_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);
                        proto_tree_add_item(last_tree, hf_hid_descriptor_list_type, tvb, list_offset, 1, ENC_BIG_ENDIAN);
                        value = tvb_get_guint8(tvb, list_offset);
                        wmem_strbuf_append(info_buf, val_to_str_const(value, descriptor_list_type_vals, "Unknown"));
                        proto_item_append_text(entry_item, ": %s", val_to_str_const(value, descriptor_list_type_vals, "Unknown"));
                        list_offset += entry_length;

                        dissect_data_element(sub_tree, &last_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);
                        proto_tree_add_item(last_tree, hf_hid_descriptor_list_descriptor, tvb, list_offset, entry_length, ENC_NA);
                        list_offset += entry_length;

                        i_feature += 1;

                        if (list_offset - offset < size)
                            wmem_strbuf_append(info_buf, ", ");
                    }
                    break;
                case 0x207:
                    list_offset = offset;
                    i_feature = 1;
                    while (list_offset - offset < size) {
                        wmem_strbuf_append(info_buf, "[");
                        entry_item = proto_tree_add_none_format(next_tree, hf_hid_lang, tvb, list_offset, size, "Language #%u", i_feature);
                        entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_data_element);

                        dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);

                        dissect_data_element(sub_tree, &last_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);
                        value = tvb_get_ntohs(tvb, list_offset);
                        wmem_strbuf_append_printf(info_buf, "Lang ID: %s", val_to_str_ext_const(value, &usb_langid_vals_ext, "Unknown"));
                        proto_item_append_text(entry_item, ": Lang ID: %s", val_to_str_ext_const(value, &usb_langid_vals_ext, "Unknown"));
                        proto_tree_add_item(last_tree, hf_sdp_lang_id, tvb, list_offset, entry_length, ENC_BIG_ENDIAN);
                        list_offset += entry_length;

                        dissect_data_element(sub_tree, &last_tree, pinfo, tvb, list_offset);
                        list_offset = get_type_length(tvb, list_offset, &entry_length);
                        value = tvb_get_ntohs(tvb, list_offset);
                        wmem_strbuf_append_printf(info_buf, ", Attribute Base: 0x%04x", value);
                        proto_item_append_text(entry_item, ", Attribute Base: 0x%04x", value);
                        proto_tree_add_item(last_tree, hf_sdp_lang_attribute_base, tvb, list_offset, 2, ENC_BIG_ENDIAN);
                        list_offset += entry_length;
                        i_feature += 1;

                        if (list_offset - offset < size)
                            wmem_strbuf_append(info_buf, "], ");
                        else
                            wmem_strbuf_append(info_buf, "]");
                    }
                    break;
                case 0x208:
                    proto_tree_add_item(next_tree, hf_hid_sdp_disable, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x209:
                    proto_tree_add_item(next_tree, hf_hid_battery_power, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x20A:
                    proto_tree_add_item(next_tree, hf_hid_remote_wake, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x20B:
                    proto_tree_add_item(next_tree, hf_hid_profile_version, tvb, offset, 2, ENC_BIG_ENDIAN);
                    version = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%x.%x.%x (0x%04x)", version >> 8, (version >> 4) & 0xF, version & 0xF, version);
                    break;
                case 0x20C:
                    proto_tree_add_item(next_tree, hf_hid_supervision_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u", value);
                    break;
                case 0x20D:
                    proto_tree_add_item(next_tree, hf_hid_normally_connectable, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x20E:
                    proto_tree_add_item(next_tree, hf_hid_boot_device, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x20F:
                    proto_tree_add_item(next_tree, hf_hid_ssr_host_max_latency, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u", value);
                    break;
                case 0x210:
                    proto_tree_add_item(next_tree, hf_hid_ssr_host_min_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u", value);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_BIP_SERVICE_UUID:
        case BTSDP_BIP_RESPONDER_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_bip_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x310:
                    proto_tree_add_item(next_tree, hf_bip_supported_capabilities_reserved_4_7, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_capabilities_displaying, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_capabilities_printing, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_capabilities_capturing, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_capabilities_genering_imaging, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s",
                            (value & 0x01) ? "GeneringImaging " : "",
                            (value & 0x02) ? "Capturing " : "",
                            (value & 0x04) ? "Printing " : "",
                            (value & 0x08) ? "Displaying " : "");
                    break;
                case 0x311:
                    proto_tree_add_item(next_tree, hf_bip_supported_features_reserved_9_15, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_remote_display, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_remote_camera, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_automatic_archive, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_advanced_image_printing, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_image_pull, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_image_push_display, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_image_push_print, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_image_push_store, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_features_image_push, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s%s%s",
                            (value & 0x001) ? "ImagePush " : "",
                            (value & 0x002) ? "ImagePushStore " : "",
                            (value & 0x004) ? "ImagePushPrint " : "",
                            (value & 0x008) ? "ImagePushDisplay " : "",
                            (value & 0x010) ? "ImagePull " : "",
                            (value & 0x020) ? "AdvancedImagePrinting " : "",
                            (value & 0x040) ? "AutomatingArchive " : "",
                            (value & 0x080) ? "RemoteCamera " : "",
                            (value & 0x100) ? "RemoteDisplay " : "");
                    break;
                case 0x312:
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_17_31, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_status, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_15, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_monitoring_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_start_archive, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_12, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_start_print, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_delete_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_linked_attachment, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_linked_thumbnail, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_image_property, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_images_list, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_remote_display, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_put_linked_thumbnail, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_put_linked_attachment, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_put_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohl(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                            (value & 0x001) ? "GetCapabilities " : "",
                            (value & 0x002) ? "PutImage " : "",
                            (value & 0x004) ? "PutLinkedAttachment " : "",
                            (value & 0x008) ? "PutLinkedThumbnail " : "",
                            (value & 0x010) ? "RemoteDisplay " : "",
                            (value & 0x020) ? "GetImageList " : "",
                            (value & 0x040) ? "GetImageProperty " : "",
                            (value & 0x080) ? "GetImage " : "",
                            (value & 0x100) ? "GetLinkedThumbnail " : "",
                            (value & 0x200) ? "GetLinkedAttachment " : "",
                            (value & 0x400) ? "DeleteImage " : "",
                            (value & 0x800) ? "StartPrint " : "",
                            (value & 0x2000) ? "StartArchive " : "",
                            (value & 0x4000) ? "GetMonitoringImage " : "",
                            (value & 0x10000) ? "GetStatus " : "");
                    break;
                case 0x313:
                    proto_tree_add_item(next_tree, hf_bip_total_imaging_data_capacity, tvb, offset, 8, ENC_BIG_ENDIAN);
                    value_64 = tvb_get_ntoh64(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%"G_GUINT64_FORMAT, value_64);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_BIP_REF_OBJ_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_bip_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited && service_info)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x312:
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_13_31, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_partial_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_1_11, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohl(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s",
                            (value & 0x0001) ? "GetCapabilities " : "",
                            (value & 0x1000) ? "GetPartialImage " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_BIP_AUTO_ARCH_SERVICE_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_item(next_tree, hf_bip_goep_l2cap_psm, tvb, offset, 2, ENC_BIG_ENDIAN);
                    psm = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", psm, psm);
                    if (!pinfo->fd->flags.visited)
                        save_channel(pinfo, BTSDP_L2CAP_PROTOCOL_UUID, psm, -1, service_info);
                    break;
                case 0x312:
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_11_31, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_delete_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_linked_attachment, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_linked_thumbnail, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_image, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_image_property, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_images_list, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_reserved_1_4, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(next_tree, hf_bip_supported_functions_get_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohl(tvb, offset);

                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s",
                            (value & 0x001) ? "GetCapabilities " : "",
                            (value & 0x020) ? "GetImageList " : "",
                            (value & 0x040) ? "GetImageProperty " : "",
                            (value & 0x080) ? "GetImage " : "",
                            (value & 0x100) ? "GetLinkedThumbnail " : "",
                            (value & 0x200) ? "GetLinkedAttachment " : "",
                            (value & 0x400) ? "DeleteImage " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_BPP_SERVICE_UUID:
        case BTSDP_BPP_STATUS_SERVICE_UUID:
        case BTSDP_BPP_DIRECT_PRINTING_SERVICE_UUID:
        case BTSDP_BPP_REFERENCE_PRINTING_SERVICE_UUID:
            switch (attribute) {
                case 0x350:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_document_formats_supported, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x352:
                    proto_tree_add_item(next_tree, hf_bpp_character_repertoires_support, tvb, offset, size, ENC_NA);
                    new_str = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, size);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x354:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_xhtml_print_image_formats_supported, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x356:
                    proto_tree_add_item(next_tree, hf_bpp_color_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x358:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_1284_id, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x35A:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_printer_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x35C:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_printer_location, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x35E:
                    proto_tree_add_item(next_tree, hf_bpp_duplex_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x360:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_media_types_supported, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x362:
                    proto_tree_add_item(next_tree, hf_bpp_max_media_width, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u", value);
                    break;
                case 0x364:
                    proto_tree_add_item(next_tree, hf_bpp_max_media_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    value = tvb_get_ntohs(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u", value);
                    break;
                case 0x366:
                    proto_tree_add_item(next_tree, hf_bpp_enhanced_layout_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x368:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_rui_formats_supported, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x370:
                    proto_tree_add_item(next_tree, hf_bpp_reference_printing_rui_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x372:
                    proto_tree_add_item(next_tree, hf_bpp_direct_printing_rui_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append(info_buf, value ? "true" : "false");
                    break;
                case 0x374:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_reference_printing_top_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x376:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_direct_printing_top_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x37A:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_device_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_BPP_REFLECTED_UI_SERVICE_UUID:
            switch (attribute) {
                case 0x368:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_rui_formats_supported, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                case 0x378:
                    proto_tree_add_item_ret_string(next_tree, hf_bpp_printer_admin_rui_top_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                    wmem_strbuf_append(info_buf, new_str);
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_CTN_ACCESS_SERVICE_UUID:
        case BTSDP_CTN_NOTIFICATION_SERVICE_UUID:
            if (service_uuid.bt_uuid == BTSDP_CTN_NOTIFICATION_SERVICE_UUID && attribute != 0x317) {
                found = FALSE;
                break;
            }
            switch (attribute) {
                case 0x315:
                    proto_tree_add_item(next_tree, hf_ctn_instance_id, tvb, offset, 1, ENC_NA);
                    value = tvb_get_guint8(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%u (0x%02x)", value, value);

                    break;
                case 0x317:
                    proto_tree_add_bitmask(next_tree, tvb, offset, hf_ctn_supported_features, ett_btsdp_supported_features,  hfx_ctn_supported_features, ENC_NA);

                    supported_features = tvb_get_ntohl(tvb, offset);
                    wmem_strbuf_append_printf(info_buf, "%s%s%s%s%s%s%s",
                            (supported_features & 0x01) ? "AccountManager " : "",
                            (supported_features & 0x02) ? "Notification " : "",
                            (supported_features & 0x04) ? "Browsing " : "",
                            (supported_features & 0x08) ? "Downloading " : "",
                            (supported_features & 0x10) ? "Uploading " : "",
                            (supported_features & 0x20) ? "Delete " : "",
                            (supported_features & 0x40) ? "Forward " : "");
                    break;
                default:
                    found = FALSE;
            }
            break;
        case BTSDP_MULTI_PROFILE_UUID:
        case BTSDP_MULTI_PROFILE_SC_UUID:
            switch (attribute) {
                case 0x200:
                    proto_tree_add_bitmask(next_tree, tvb, offset, hf_mps_mpsd_scenarios, ett_btsdp_supported_features,  hfx_mps_mpsd_scenarios, ENC_NA);

                    break;
                case 0x201:
                    proto_tree_add_bitmask(next_tree, tvb, offset, hf_mps_mpmd_scenarios, ett_btsdp_supported_features,  hfx_mps_mpmd_scenarios, ENC_NA);

                    break;
                case 0x202:
                    proto_tree_add_bitmask(next_tree, tvb, offset, hf_mps_supported_profile_and_protocol_dependency, ett_btsdp_supported_features,  hfx_mps_supported_profile_and_protocol_dependency, ENC_NA);

                    break;
                default:
                    found = FALSE;
            }
            break;
        default:
            found = FALSE;
    }

    if  (!found) {
        found = TRUE;
        switch (attribute) {
        case 0x000:
            proto_tree_add_item(next_tree, hf_sdp_service_record_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = tvb_get_ntohl(tvb, offset);
            wmem_strbuf_append_printf(info_buf, "0x%08x (%u)", value, value);
            break;
        case 0x001:
            list_offset = offset;
            while (list_offset - offset < size) {
                dissect_data_element(next_tree, &entry_tree, pinfo, tvb, list_offset);
                list_offset = get_type_length(tvb, list_offset, &list_length);

                dissect_uuid(entry_tree, tvb, list_offset, list_length, &uuid);

                wmem_strbuf_append(info_buf, print_uuid(&uuid));
                list_offset += list_length;

                if (list_offset - offset < size)
                    wmem_strbuf_append(info_buf, " -> ");
            }
            break;
        case 0x002:
            proto_tree_add_item(next_tree, hf_sdp_service_record_state, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = tvb_get_ntohl(tvb, offset);
            wmem_strbuf_append_printf(info_buf, "0x%08x (%u)", value, value);
            break;
        case 0x003:
            dissect_uuid(next_tree, tvb, offset, size, &uuid);
            wmem_strbuf_append(info_buf, print_uuid(&uuid));
            break;
        case 0x004:
            protocol_order = 0;
            dissect_protocol_descriptor_list(next_tree, tvb, pinfo,
                    offset, size, info_buf, service_info, &protocol_order);
            break;
        case 0x005:
            list_offset = offset;
            while (list_offset - offset < size) {
                dissect_data_element(next_tree, &entry_tree, pinfo, tvb, list_offset);
                list_offset = get_type_length(tvb, list_offset, &list_length);

                dissect_uuid(entry_tree, tvb, list_offset, list_length, &uuid);

                wmem_strbuf_append(info_buf, print_uuid(&uuid));
                list_offset += list_length;

                if (list_offset - offset < size)
                    wmem_strbuf_append(info_buf, ", ");
            }
            break;
        case 0x006:
            list_offset = offset;
            i_feature = 1;
            while (list_offset - offset < size) {
                wmem_strbuf_append(info_buf, "(");
                entry_item = proto_tree_add_none_format(next_tree, hf_sdp_lang, tvb, list_offset, size, "Language #%u", i_feature);
                entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_data_element);

                dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, list_offset);
                list_offset = get_type_length(tvb, list_offset, &entry_length);
                proto_tree_add_item_ret_string(sub_tree, hf_sdp_lang_code, tvb, list_offset, entry_length, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
                wmem_strbuf_append_printf(info_buf, "Lang: %s", new_str);
                proto_item_append_text(entry_item, ": Lang: %s", new_str);
                list_offset += entry_length;

                dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, list_offset);
                list_offset = get_type_length(tvb, list_offset, &entry_length);
                value = tvb_get_ntohs(tvb, list_offset);
                wmem_strbuf_append_printf(info_buf, ", Encoding: %s", val_to_str_ext_const(value, &mibenum_vals_character_sets_ext, "Unknown"));
                proto_item_append_text(entry_item, ", Encoding: %s", val_to_str_ext_const(value, &mibenum_vals_character_sets_ext, "Unknown"));
                proto_tree_add_item(sub_tree, hf_sdp_lang_encoding, tvb, list_offset, 2, ENC_BIG_ENDIAN);
                list_offset += entry_length;

                dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, list_offset);
                list_offset = get_type_length(tvb, list_offset, &entry_length);
                value = tvb_get_ntohs(tvb, list_offset);
                wmem_strbuf_append_printf(info_buf, ", Attribute Base: 0x%04x", value);
                proto_item_append_text(entry_item, ", Attribute Base: 0x%04x", value);
                proto_tree_add_item(sub_tree, hf_sdp_lang_attribute_base, tvb, list_offset, 2, ENC_BIG_ENDIAN);
                list_offset += entry_length;
                i_feature += 1;

                if (list_offset - offset < size)
                    wmem_strbuf_append(info_buf, "), ");
                else
                    wmem_strbuf_append(info_buf, ")");
            }
            break;
        case 0x007:
            proto_tree_add_item(next_tree, hf_sdp_service_info_time_to_live, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = tvb_get_ntohl(tvb, offset);
            wmem_strbuf_append_printf(info_buf, "%u (0x%08x)", value, value);
            break;
        case 0x008:
            proto_tree_add_item(next_tree, hf_sdp_service_availability, tvb, offset, 1, ENC_BIG_ENDIAN);
            value = tvb_get_guint8(tvb, offset);
            wmem_strbuf_append_printf(info_buf, "0x%02x (%u)", value, value);
            break;
        case 0x009:
            list_offset = offset;
            i_protocol = 1;
            while (list_offset - offset < size) {
                entry_offset = get_type_length(tvb, list_offset, &entry_length);
                dissect_data_element(next_tree, &sub_tree, pinfo, tvb, list_offset);
                entry_item = proto_tree_add_none_format(sub_tree, hf_profile_descriptor_list, tvb, entry_offset, entry_length, "Profile Descriptor List #%u", i_protocol);
                entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_data_element);

                dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
                entry_offset = get_type_length(tvb, entry_offset, &entry_length);

                dissect_uuid(sub_tree, tvb, entry_offset, entry_length, &uuid);

                uuid_str = print_uuid(&uuid);
                wmem_strbuf_append(info_buf, uuid_str);
                proto_item_append_text(entry_item, ": %s", uuid_str);

                entry_offset += entry_length;

                dissect_data_element(entry_tree, &sub_tree, pinfo, tvb, entry_offset);
                entry_offset = get_type_length(tvb, entry_offset, &entry_length);
                value = tvb_get_ntohs(tvb, entry_offset);

                wmem_strbuf_append_printf(info_buf, " %x.%x", value >> 8, value & 0xFF);
                proto_item_append_text(entry_item, ", Version %x.%x", value >> 8, value & 0xFF);
                proto_tree_add_item(sub_tree, hf_sdp_protocol_version, tvb, entry_offset, 2, ENC_BIG_ENDIAN);

                entry_offset += entry_length;

                list_offset = entry_offset;

                if (list_offset - offset < size)
                    wmem_strbuf_append(info_buf, ", ");
                i_protocol += 1;
            }
            break;
        case 0x00A:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_documentation_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        case 0x00B:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_client_executable_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        case 0x00C:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_icon_url, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        case 0x00D:
            protocol_order = 1;
            list_offset = offset;
            i_protocol = 1;
            while (list_offset - offset < size) {
                entry_offset = get_type_length(tvb, list_offset, &entry_length);
                dissect_data_element(next_tree, &sub_tree, pinfo, tvb, list_offset);
                entry_item = proto_tree_add_none_format(sub_tree, hf_profile_descriptor_list, tvb, entry_offset, entry_length, "Protocol Descriptor List #%u", i_protocol);
                entry_tree = proto_item_add_subtree(entry_item, ett_btsdp_data_element);

                list_offset = get_type_length(tvb, list_offset, &list_length);

                wmem_strbuf_append(info_buf, "[");
                dissect_protocol_descriptor_list(entry_tree, tvb,
                        pinfo, list_offset, list_length, info_buf,
                        service_info, &protocol_order);

                list_offset += list_length;

                wmem_strbuf_append(info_buf, "] ");
                i_protocol += 1;
            }
            break;
        case 0x100:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        case 0x101:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_description, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        case 0x102:
            proto_tree_add_item_ret_string(next_tree, hf_sdp_service_provider_name, tvb, offset, size, ENC_ASCII | ENC_NA, wmem_packet_scope(), &new_str);
            wmem_strbuf_append(info_buf, new_str);
            break;
        default:
            found = FALSE;
        }
    }

    if (!found) switch (type) {
    case 0:
        proto_tree_add_item(next_tree, hf_data_element_value_nil, tvb, offset, size, ENC_NA);
        wmem_strbuf_append(info_buf, "Nil ");
        break;
    case 1: {
        guint32 val = get_uint_by_size(tvb, offset, size_index);
        proto_tree_add_item(next_tree, hf_data_element_value_unsigned_int, tvb, offset, size, ENC_BIG_ENDIAN);
        wmem_strbuf_append_printf(info_buf, "%u ", val);
        break;
    }
    case 2: {
        guint32 val = get_int_by_size(tvb, offset, size_index);
        proto_tree_add_item(next_tree, hf_data_element_value_signed_int, tvb, offset, size, ENC_BIG_ENDIAN);
        wmem_strbuf_append_printf(info_buf, "%d ", val);
        break;
    }
    case 3:
        dissect_uuid(next_tree, tvb, offset, size, &uuid);
        wmem_strbuf_append_printf(info_buf, ": %s", print_uuid(&uuid));
        break;
    case 8: /* fall through */
    case 4: {
        const guint8 *ptr;

        proto_tree_add_item_ret_string(next_tree, (type == 8) ? hf_data_element_value_url : hf_data_element_value_string, tvb, offset, size, ENC_NA | ENC_ASCII, wmem_packet_scope(), &ptr);
        wmem_strbuf_append_printf(info_buf, "%s ", ptr);
        break;
    }
    case 5: {
        guint8 var = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(next_tree, hf_data_element_value_boolean, tvb, offset, size, ENC_BIG_ENDIAN);
        wmem_strbuf_append_printf(info_buf, "%s ", var ? "true" : "false");
        break;
    }
    case 6: /* Data Element sequence */
    case 7: /* Data Element alternative */ {
        proto_tree    *st;
        proto_item    *ti;
        gint           bytes_to_go = size;
        gint           first       = 1;
        wmem_strbuf_t *substr;

        ti = proto_tree_add_item(next_tree, (type == 6) ? hf_data_element_value_sequence : hf_data_element_value_alternative,
                tvb, offset, size, ENC_NA);
        st = proto_item_add_subtree(ti, ett_btsdp_des);

        wmem_strbuf_append(info_buf, "{ ");

        while (bytes_to_go > 0) {
            if (!first) {
                wmem_strbuf_append(info_buf, ", ");
            } else {
                first = 0;
            }

            size = dissect_sdp_type(st, pinfo, tvb, offset, attribute, service_uuid, service_did_vendor_id, service_did_vendor_id_source, service_info, &substr);
            if (size < 1) {
                break;
            }
            wmem_strbuf_append_printf(info_buf, "%s ", wmem_strbuf_get_str(substr));
            offset += size ;
            bytes_to_go -= size;
        }

        wmem_strbuf_append(info_buf, "} ");
        break;
    }
    }

    return new_offset - start_offset;
}


static gint
dissect_sdp_service_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, bluetooth_uuid_t uuid, gint service_offset,
        service_info_t  *service_info, gint number_of_attributes, gboolean attribute_only)
{
    proto_tree          *attribute_tree;
    proto_item          *attribute_item;
    proto_tree          *attribute_id_tree;
    proto_item          *attribute_id_item;
    proto_tree          *attribute_value_tree;
    proto_item          *attribute_value_item;
    proto_tree          *next_tree;
    gint                 size = 0;
    const gchar         *attribute_name;
    wmem_strbuf_t       *attribute_value = NULL;
    guint16              id;
    gint                 service_did_vendor_id = -1;
    gint                 service_did_vendor_id_source = -1;
    gint                 hfx_attribute_id = hf_service_attribute_id_generic;
    const value_string  *name_vals = NULL;
    const guint8        *profile_speficic = "";
    gint                 new_offset;
    gint                 old_offset;
    guint8               type;

    type = tvb_get_guint8(tvb, offset);
    id = tvb_get_ntohs(tvb, offset + 1);

    switch (uuid.bt_uuid) {
        case BTSDP_DID_SERVICE_UUID:
            name_vals = vs_did_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_did;
            profile_speficic = "(DID) ";

            if (number_of_attributes > 1) {
                service_did_vendor_id_source = findDidVendorIdSource(tvb, service_offset, number_of_attributes);
                service_did_vendor_id = findDidVendorId(tvb, service_offset, number_of_attributes);
            }
            break;
        case BTSDP_HID_SERVICE_UUID:
            name_vals = vs_hid_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hid;
            profile_speficic = "(HID) ";
            break;
        case BTSDP_SYNC_SERVICE_UUID:
            name_vals = vs_synch_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_synch;
            profile_speficic = "(SYNCH) ";
            break;
        case BTSDP_PBAP_PSE_SERVICE_UUID:
        case BTSDP_PBAP_SERVICE_UUID:
            name_vals = vs_pbap_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_pbap;
            profile_speficic = "(PBAP) ";
            break;
        case BTSDP_PAN_NAP_SERVICE_UUID:
            name_vals = vs_pan_nap_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_pan_nap;
            profile_speficic = "(PAN NAP) ";
            break;
        case BTSDP_PAN_GN_SERVICE_UUID:
            name_vals = vs_pan_gn_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_pan_gn;
            profile_speficic = "(PAN GN) ";
            break;
        case BTSDP_PAN_PANU_SERVICE_UUID:
            name_vals = vs_pan_panu_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_pan_panu;
            profile_speficic = "(PAN PANU) ";
            break;
        case BTSDP_OPP_SERVICE_UUID:
            name_vals = vs_opp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_opp;
            profile_speficic = "(OPP) ";
            break;
        case BTSDP_MAP_SERVICE_UUID:
        case BTSDP_MAP_ACCESS_SRV_SERVICE_UUID:
            name_vals = vs_map_mas_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_map_mas;
            profile_speficic = "(MAP MAS) ";
            break;
        case BTSDP_MAP_NOTIFICATION_SRV_SERVICE_UUID:
            name_vals = vs_map_mns_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_map_mns;
            profile_speficic = "(MAP MNS) ";
            break;
        case BTSDP_WAP_SERVICE_UUID:
        case BTSDP_WAP_CLIENT_SERVICE_UUID:
            name_vals = vs_wap_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_wap;
            profile_speficic = "(WAP) ";
            break;
        case BTSDP_HDP_SERVICE_UUID:
        case BTSDP_HDP_SOURCE_SERVICE_UUID:
        case BTSDP_HDP_SINK_SERVICE_UUID:
            name_vals = vs_hdp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hdp;
            profile_speficic = "(HDP) ";
            break;
        case BTSDP_HSP_SERVICE_UUID:
        case BTSDP_HSP_HS_SERVICE_UUID:
            name_vals = vs_hsp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hsp;
            profile_speficic = "(HSP) ";
            break;
        case BTSDP_HCRP_SERVICE_UUID:
        case BTSDP_HCRP_PRINT_SERVICE_UUID:
        case BTSDP_HCRP_SCAN_SERVICE_UUID:
            name_vals = vs_hcrp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hcrp;
            profile_speficic = "(HCRP) ";
            break;
        case BTSDP_HFP_SERVICE_UUID:
            name_vals = vs_hfp_gw_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hfp_hf;
            profile_speficic = "(HFP HS) ";
            break;
        case BTSDP_HFP_GW_SERVICE_UUID:
            name_vals = vs_hfp_ag_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_hfp_ag;
            profile_speficic = "(HFP AG) ";
            break;
        case BTSDP_GNSS_UUID:
        case BTSDP_GNSS_SERVER_UUID:
            name_vals = vs_gnss_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_gnss;
            profile_speficic = "(GNSS) ";
            break;
        case BTSDP_FTP_SERVICE_UUID:
            name_vals = vs_ftp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_ftp;
            profile_speficic = "(FTP) ";
            break;
        case BTSDP_FAX_SERVICE_UUID:
            name_vals = vs_fax_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_fax;
            profile_speficic = "(FAX) ";
            break;
        case BTSDP_CTP_SERVICE_UUID:
            name_vals = vs_ctp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_ctp;
            profile_speficic = "(CTP) ";
            break;
        case BTSDP_A2DP_SOURCE_SERVICE_UUID:
        case BTSDP_A2DP_SINK_SERVICE_UUID:
        case BTSDP_A2DP_DISTRIBUTION_SERVICE_UUID:
            name_vals = vs_a2dp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_a2dp;
            profile_speficic = "(A2DP) ";
            break;
        case BTSDP_AVRCP_TG_SERVICE_UUID:
        case BTSDP_AVRCP_SERVICE_UUID:
        case BTSDP_AVRCP_CT_SERVICE_UUID:
            name_vals = vs_avrcp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_avrcp;
            profile_speficic = "(AVRCP) ";
            break;
        case BTSDP_BIP_SERVICE_UUID:
        case BTSDP_BIP_RESPONDER_SERVICE_UUID:
            name_vals = vs_bip_imaging_responder_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_bip_imaging_responder;
            profile_speficic = "(BIP IR) ";
            break;
        case BTSDP_BIP_AUTO_ARCH_SERVICE_UUID:
            name_vals = vs_bip_imaging_other_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_bip_imaging_other;
            profile_speficic = "(BIP IAA) ";
            break;
        case BTSDP_BIP_REF_OBJ_SERVICE_UUID:
            name_vals = vs_bip_imaging_other_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_bip_imaging_other;
            profile_speficic = "(BIP IRO) ";
            break;
        case BTSDP_BPP_SERVICE_UUID:
        case BTSDP_BPP_STATUS_SERVICE_UUID:
        case BTSDP_BPP_DIRECT_PRINTING_SERVICE_UUID:
        case BTSDP_BPP_REFERENCE_PRINTING_SERVICE_UUID:
            name_vals = vs_bpp_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_bpp;
            profile_speficic = "(BPP) ";
            break;
        case BTSDP_BPP_REFLECTED_UI_SERVICE_UUID:
            name_vals = vs_bpp_reflected_ui_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_bpp_rui;
            profile_speficic = "(BPP RUI) ";
            break;
        case BTSDP_DUN_SERVICE_UUID:
            name_vals = vs_dun_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_dun;
            profile_speficic = "(DUN) ";
            break;
        case BTSDP_CTN_ACCESS_SERVICE_UUID:
            name_vals = vs_ctn_as_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_ctn_as;
            profile_speficic = "(CTN AS) ";
            break;
        case BTSDP_CTN_NOTIFICATION_SERVICE_UUID:
            name_vals = vs_ctn_ns_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_ctn_ns;
            profile_speficic = "(CTN NS) ";
            break;
        case BTSDP_MULTI_PROFILE_UUID:
        case BTSDP_MULTI_PROFILE_SC_UUID:
            name_vals = vs_mps_attribute_id;
            hfx_attribute_id = hf_service_attribute_id_mps;
            profile_speficic = "(MPS) ";
            break;
    }

    if (name_vals && try_val_to_str(id, name_vals)) {
        attribute_name = val_to_str(id, name_vals, "Unknown");
    } else {
        attribute_name = val_to_str(id, vs_general_attribute_id, "Unknown");
        profile_speficic = "";
        hfx_attribute_id = hf_service_attribute_id_generic;
    }

    if (!attribute_only) {
        attribute_item = proto_tree_add_none_format(tree, hf_service_attribute, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                        "Service Attribute: %s%s (0x%x)", profile_speficic, attribute_name, id);
        attribute_tree = proto_item_add_subtree(attribute_item, ett_btsdp_attribute);
    } else {
        attribute_tree = tree;
    }

    if (attribute_only && type == 0x0a) {
        dissect_data_element(attribute_tree, &next_tree, pinfo, tvb, offset);
        offset += 1;

        attribute_id_item = proto_tree_add_item(next_tree, hf_attribute_id_range, tvb, offset, 4, ENC_BIG_ENDIAN);
        attribute_id_tree = proto_item_add_subtree(attribute_id_item, ett_btsdp_attribute_id);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Attribute Range (0x%04x - 0x%04x) ",
                            tvb_get_ntohs(tvb, offset), tvb_get_ntohs(tvb, offset + 2));

        proto_tree_add_item(attribute_id_tree, hf_attribute_id_range_from, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(attribute_id_tree, hf_attribute_id_range_to, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        attribute_id_item = proto_tree_add_none_format(attribute_tree, hf_service_attribute_id, tvb, offset, 3, "Attribute ID: %s", attribute_name);
        attribute_id_tree = proto_item_add_subtree(attribute_id_item, ett_btsdp_attribute_id);

        new_offset = dissect_data_element(attribute_id_tree, &next_tree, pinfo, tvb, offset);
        proto_tree_add_item(next_tree, hfx_attribute_id, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        offset = new_offset;

        if (!attribute_only){
            attribute_value_item = proto_tree_add_item(attribute_tree, hf_service_attribute_value, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
            attribute_value_tree = proto_item_add_subtree(attribute_value_item, ett_btsdp_attribute_value);

            dissect_sdp_type(attribute_value_tree, pinfo, tvb, offset, id, uuid,
                    service_did_vendor_id, service_did_vendor_id_source, service_info, &attribute_value);
            old_offset = offset;
            offset = get_type_length(tvb, offset, &size);
            proto_item_append_text(attribute_item, ", value = %s", wmem_strbuf_get_str(attribute_value));

            proto_item_set_len(attribute_item, 3 + size + (offset - old_offset));
            proto_item_set_len(attribute_value_item, size + (offset - old_offset));
        } else {
            proto_item_append_text(attribute_id_item, " %s", profile_speficic);
            col_append_fstr(pinfo->cinfo, COL_INFO, "[%s%s 0x%04x] ", profile_speficic, attribute_name, id);
        }
    }

    return offset + size;
}


static gint
dissect_attribute_id_list(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, bluetooth_uuid_t *uuid)
{
    proto_item  *list_item;
    proto_tree  *list_tree;
    proto_tree  *sub_tree;
    gint         start_offset;
    gint         previous_offset;
    gint         service_offset;
    gint         bytes_to_go;
    bluetooth_uuid_t empty_uuid;

    if (!uuid)
        memset(&empty_uuid, 0, sizeof(bluetooth_uuid_t));

    start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_attribute_id_list, tvb, offset, 0, ENC_NA);
    list_tree = proto_item_add_subtree(list_item, ett_btsdp_attribute_idlist);

    dissect_data_element(list_tree, &sub_tree, pinfo, tvb, offset);

    offset = get_type_length(tvb, offset, &bytes_to_go);
    service_offset = offset;
    proto_item_set_len(list_item, offset - start_offset + bytes_to_go);

    previous_offset = offset;
    while (bytes_to_go > 0) {
        offset = dissect_sdp_service_attribute(sub_tree, tvb, offset, pinfo, (uuid) ? *uuid : empty_uuid, service_offset, NULL, 1, TRUE);
        bytes_to_go -= offset - previous_offset;
        previous_offset = offset;
    }

    return offset - start_offset;
}


static gint
dissect_sdp_error_response(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}


static gint
dissect_sdp_service_attribute_list(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, bluetooth_uuid_t *service_uuid, btl2cap_data_t *l2cap_data)
{
    proto_item      *list_item;
    proto_tree      *list_tree;
    proto_tree      *next_tree;
    gint             start_offset = offset;
    gint             search_offset;
    gint             search_length;
    gint             len;
    guint            number_of_attributes;
    guint16          attribute;
    gint             element_length;
    gint             new_offset;
    gint             service_offset;
    bluetooth_uuid_t uuid;
    wmem_tree_key_t  key[10];
    guint32          k_interface_id;
    guint32          k_adapter_id;
    guint32          k_sdp_psm;
    guint32          k_direction;
    guint32          k_bd_addr_oui;
    guint32          k_bd_addr_id;
    guint32          k_service_type;
    guint32          k_service_channel;
    guint32          k_frame_number;
    service_info_t  *service_info;
    wmem_array_t    *uuid_array;

    uuid_array = wmem_array_new(wmem_packet_scope(), sizeof(bluetooth_uuid_t));

    offset = get_type_length(tvb, offset, &len);
    memset(&uuid, 0, sizeof(bluetooth_uuid_t));

    list_item = proto_tree_add_item(tree, hf_attribute_list, tvb,
            start_offset, len + (offset - start_offset), ENC_NA);
    list_tree = proto_item_add_subtree(list_item, ett_btsdp_attribute);
    dissect_data_element(list_tree, &next_tree, pinfo, tvb, start_offset);

    /* search for main service uuid */
    search_offset = offset;
    number_of_attributes = 0;

    while ((search_offset - start_offset) < len) {
        search_offset = get_type_length(tvb, search_offset, &search_length);
        attribute = tvb_get_ntohs(tvb, search_offset);

        search_offset += search_length;
        search_offset = get_type_length(tvb, search_offset, &search_length);

        if (attribute == 0x01) {
            new_offset = 0;
            while (new_offset <= search_offset) {
                new_offset = get_type_length(tvb, search_offset, &element_length);
                dissect_uuid(NULL, tvb, new_offset, element_length, &uuid);
                wmem_array_append_one(uuid_array, uuid);
                new_offset += element_length;
            }
        }

        search_offset += search_length;
        number_of_attributes += 1;
    }

    uuid = get_specified_uuid(uuid_array);
    if (uuid.size == 0 && service_uuid)
        uuid = *service_uuid;

    if (!pinfo->fd->flags.visited) {
        service_info = (service_info_t *) wmem_new(wmem_file_scope(), service_info_t);
        service_info->interface_id   = l2cap_data->interface_id;
        service_info->adapter_id     = l2cap_data->adapter_id;
        service_info->sdp_psm        = l2cap_data->psm;
        service_info->direction      = pinfo->p2p_dir;
        if (service_info->direction == P2P_DIR_RECV) {
            service_info->bd_addr_oui = l2cap_data->remote_bd_addr_oui;
            service_info->bd_addr_id  = l2cap_data->remote_bd_addr_id;
        } else {
            service_info->bd_addr_oui = 0;
            service_info->bd_addr_id  = 0;
        }

        service_info->uuid           = uuid;

        service_info->type           = 0;
        service_info->channel        = 0;
        service_info->protocol_order = 0;
        service_info->protocol       = -1;
        service_info->parent_info    = NULL;
    } else {
        service_info = NULL;
    }

    service_offset = offset;
    while ((offset - start_offset) < len) {
        offset = dissect_sdp_service_attribute(next_tree, tvb, offset, pinfo,
                uuid, service_offset, service_info, number_of_attributes, FALSE);
    }

    if (!pinfo->fd->flags.visited && service_info) {
        k_interface_id    = l2cap_data->interface_id;
        k_adapter_id      = l2cap_data->adapter_id;
        k_sdp_psm         = l2cap_data->psm;
        k_direction       = service_info->direction;
        k_bd_addr_oui     = service_info->bd_addr_oui;
        k_bd_addr_id      = service_info->bd_addr_id;
        k_service_type    = service_info->type;
        k_service_channel = service_info->channel;
        k_frame_number    = pinfo->num;

        key[0].length = 1;
        key[0].key = &k_interface_id;
        key[1].length = 1;
        key[1].key = &k_adapter_id;
        key[2].length = 1;
        key[2].key = &k_sdp_psm;
        key[3].length = 1;
        key[3].key = &k_direction;
        key[4].length = 1;
        key[4].key = &k_bd_addr_oui;
        key[5].length = 1;
        key[5].key = &k_bd_addr_id;
        key[6].length = 1;
        key[6].key = &k_service_type;
        key[7].length = 1;
        key[7].key = &k_service_channel;
        key[8].length = 1;
        key[8].key = &k_frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        wmem_tree_insert32_array(service_infos, key, service_info);
    }

    proto_item_set_len(list_item, offset - start_offset);

    if (uuid.size)
        proto_item_append_text(list_tree, " [count = %2u] (%s%s)",
                number_of_attributes, (uuid.bt_uuid) ? "" : "CustomUUID: ", print_uuid(&uuid));
    else
        proto_item_append_text(list_tree, " [count = %2u]",
                number_of_attributes);

    return offset;
}


static gint
dissect_sdp_service_attribute_list_array(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, gint attribute_list_byte_count,
        bluetooth_uuid_t *service_uuid, btl2cap_data_t *l2cap_data)
{
    proto_item   *lists_item;
    proto_tree   *lists_tree;
    proto_tree   *next_tree;
    gint          start_offset;
    gint          len;
    guint         number_of_attributes;

    start_offset = offset;

    offset = get_type_length(tvb, offset, &len);

    lists_item = proto_tree_add_item(tree, hf_attribute_lists, tvb, start_offset,
            attribute_list_byte_count, ENC_NA);
    lists_tree = proto_item_add_subtree(lists_item, ett_btsdp_attribute);
    dissect_data_element(lists_tree, &next_tree, pinfo, tvb, start_offset);

    number_of_attributes = 0;

    while (offset - start_offset < attribute_list_byte_count) {
        number_of_attributes += 1;

        offset = dissect_sdp_service_attribute_list(next_tree, tvb, offset,
                pinfo, service_uuid, l2cap_data);
    }

    proto_item_append_text(lists_tree, " [count = %2u]", number_of_attributes);

    return offset;
}


static gint
dissect_sdp_service_search_request(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    gint         start_offset;
    gint         bytes_to_go;
    gint         size;
    proto_item   *ti;
    proto_tree   *st;
    proto_tree   *sub_tree = NULL;
    bluetooth_uuid_t empty_uuid;
    wmem_array_t *uuid_array = NULL;

    start_offset = offset;
    memset(&empty_uuid, 0, sizeof(bluetooth_uuid_t));
    if (!pinfo->fd->flags.visited)
        uuid_array = wmem_array_new(wmem_file_scope(), sizeof(bluetooth_uuid_t));

    ti = proto_tree_add_item(tree, hf_service_search_pattern, tvb, offset, 0, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btsdp_service_search_pattern);

    dissect_data_element(st, &sub_tree, pinfo, tvb, offset);
    offset = get_type_length(tvb, offset, &bytes_to_go);
    proto_item_set_len(ti, offset - start_offset + bytes_to_go);

    while (bytes_to_go > 0) {
        wmem_strbuf_t  *str = NULL;
        gint            entry_offset;
        gint            entry_size;
        bluetooth_uuid_t uuid;

        size = dissect_sdp_type(sub_tree, pinfo, tvb, offset, -1, empty_uuid, 0, 0, NULL, &str);

        entry_offset = get_type_length(tvb, offset, &entry_size);
        dissect_uuid(NULL, tvb, entry_offset, entry_size, &uuid);
        if (uuid_array)
            wmem_array_append_one(uuid_array, uuid);

        proto_item_append_text(ti, " %s", wmem_strbuf_get_str(str));
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", wmem_strbuf_get_str(str));

        if (size < 1)
            break;

        offset      += size;
        bytes_to_go -= size;
    }

    proto_tree_add_item(tree, hf_maximum_service_record_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_SEARCH, NULL, NULL, NULL, &uuid_array, NULL, l2cap_data);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_search_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    proto_tree   *st;
    proto_item   *ti;
    guint16       current_count;
    gboolean      is_first;
    gboolean      is_continued;
    tvbuff_t     *new_tvb;
    guint         i_record;
    wmem_array_t *uuid_array = NULL;
    wmem_array_t *record_handle_array = NULL;

    proto_tree_add_item(tree, hf_ssr_total_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    current_count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssr_current_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ti = proto_tree_add_none_format(tree, hf_service_record_handle_list, tvb, offset,
                 current_count * 4, "Service Record Handle List [count = %u]", current_count);
    st = proto_item_add_subtree(ti, ett_btsdp_ssr);

    if (!pinfo->fd->flags.visited)
        record_handle_array = wmem_array_new(wmem_packet_scope(), sizeof(guint32));

    while (current_count > 0) {
        proto_tree_add_item(st, hf_sdp_service_record_handle, tvb, offset, 4, ENC_BIG_ENDIAN);

        if (record_handle_array) {
            guint32 value;

            value = tvb_get_ntohl(tvb, offset);
            wmem_array_append_one(record_handle_array, value);
        }

        offset += 4;
        current_count -= 1;
    }

    reassemble_continuation_state(tvb, pinfo, offset, tid, FALSE,
            offset - current_count * 4, current_count * 4, PDU_TYPE_SERVICE_SEARCH,
            &new_tvb, &is_first, &is_continued, &uuid_array, NULL, l2cap_data);

    if (is_continued)
        col_append_str(pinfo->cinfo, COL_INFO, "(fragment)");

    if (!pinfo->fd->flags.visited) {
        record_handle_service_t  *record_handle_service;
        wmem_tree_key_t           key[7];
        guint32                   k_interface_id;
        guint32                   k_adapter_id;
        guint32                   k_chandle;
        guint32                   k_psm;
        guint32                   k_record_handle;
        guint32                   k_frame_number;
        guint32                   interface_id;
        guint32                   adapter_id;
        guint32                   chandle;
        guint32                   psm;
        guint32                   record_handle;
        guint32                   frame_number;

        interface_id = l2cap_data->interface_id;
        adapter_id   = l2cap_data->adapter_id;
        chandle      = l2cap_data->chandle;
        psm          = l2cap_data->psm;
        frame_number = pinfo->num;

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_psm          = psm;
        k_frame_number = frame_number;

        for (i_record = 0; i_record < wmem_array_get_count(record_handle_array); ++i_record) {

            record_handle = *((guint32 *)wmem_array_index(record_handle_array, i_record));
            k_record_handle = record_handle;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_psm;
            key[4].length = 1;
            key[4].key    = &k_record_handle;
            key[5].length = 1;
            key[5].key    = &k_frame_number;
            key[6].length = 0;
            key[6].key    = NULL;

            record_handle_service = (record_handle_service_t *) wmem_new(wmem_file_scope(), record_handle_service_t);
            record_handle_service->interface_id  = interface_id;
            record_handle_service->adapter_id    = adapter_id;
            record_handle_service->chandle       = chandle;
            record_handle_service->psm           = psm;
            record_handle_service->record_handle = record_handle;

            record_handle_service->uuid_array   = uuid_array;

            wmem_tree_insert32_array(record_handle_services, key, record_handle_service);
        }
    }

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;
        gint        new_offset = 0;
        gint        new_length;

        new_length = tvb_reported_length(new_tvb);

        reassembled_item = proto_tree_add_item(tree, (is_continued) ? hf_partial_record_handle_list : hf_reassembled_record_handle_list,new_tvb, 0, new_length, ENC_NA);
        proto_item_append_text(reassembled_item, " [count = %u]", new_length / 4);
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        while (new_length > 0) {
            proto_tree_add_item(reassembled_tree, hf_sdp_service_record_handle, new_tvb,
                    new_offset, 4, ENC_BIG_ENDIAN);
            new_offset  += 4;
            new_length -= 4;
        }
    }

    return offset;
}


static gint
dissect_sdp_service_attribute_request(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    guint32        record_handle;
    wmem_array_t  *uuid_array;
    bluetooth_uuid_t uuid;

    proto_tree_add_item(tree, hf_sdp_service_record_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
    record_handle = tvb_get_ntohl(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ": 0x%08x - ", record_handle);
    offset += 4;

    proto_tree_add_item(tree, hf_maximum_attribute_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uuid_array = get_uuids(pinfo, record_handle, l2cap_data);
    uuid = get_specified_uuid(uuid_array);

    offset += dissect_attribute_id_list(tree, tvb, offset, pinfo, &uuid);

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_ATTRIBUTE, NULL, NULL, NULL, NULL, &record_handle, l2cap_data);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_attribute_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    gint           attribute_list_byte_count;
    gboolean       is_first;
    gboolean       is_continued;
    tvbuff_t      *new_tvb;
    guint32        record_handle = 0;
    bluetooth_uuid_t uuid;

    proto_tree_add_item(tree, hf_attribute_list_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    attribute_list_byte_count = tvb_get_ntohs(tvb, offset);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo,
            offset + attribute_list_byte_count, tid, FALSE,
            offset, attribute_list_byte_count,
            PDU_TYPE_SERVICE_ATTRIBUTE, &new_tvb, &is_first,
            &is_continued, NULL, &record_handle, l2cap_data);

    if (!is_continued) {
        wmem_array_t  *uuid_array;

        uuid_array = get_uuids(pinfo, record_handle, l2cap_data);
        uuid = get_specified_uuid(uuid_array);
    } else {
        memset(&uuid, 0, sizeof(bluetooth_uuid_t));
    }

    if (is_first && !is_continued) {
        dissect_sdp_service_attribute_list(tree, tvb, offset, pinfo, &uuid, l2cap_data);
    } else {
        proto_tree_add_item(tree, hf_fragment, tvb, offset,
                attribute_list_byte_count, ENC_NA);
    }

    if (is_continued)
        col_append_str(pinfo->cinfo, COL_INFO, "(fragment)");

    offset = dissect_continuation_state(tvb, tree, pinfo, offset + attribute_list_byte_count);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;

        add_new_data_source(pinfo, new_tvb, (is_continued) ? "Partial Reassembled SDP" : "Reassembled SDP");

        reassembled_item = proto_tree_add_item(tree,
                (is_continued) ? hf_partial_attribute_list : hf_reassembled_attribute_list,
                new_tvb, 0, tvb_reported_length(new_tvb), ENC_NA);
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        if (!is_continued) {
            dissect_sdp_service_attribute_list(reassembled_tree, new_tvb, 0,
                pinfo, &uuid, l2cap_data);
        }
    }

    return offset;
}


static gint
dissect_sdp_service_search_attribute_request(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    proto_tree     *ptree;
    proto_item     *pitem;
    proto_tree     *next_tree;
    gint            start_offset;
    gint            size;
    gint            bytes_to_go;
    wmem_strbuf_t  *info_buf = NULL;
    bluetooth_uuid_t empty_uuid;
    wmem_array_t   *uuid_array = NULL;
    bluetooth_uuid_t uuid;

    memset(&empty_uuid, 0, sizeof(bluetooth_uuid_t));
    if (!pinfo->fd->flags.visited)
        uuid_array = wmem_array_new(wmem_file_scope(), sizeof(bluetooth_uuid_t));
    else
        uuid_array = wmem_array_new(wmem_packet_scope(), sizeof(bluetooth_uuid_t));

    start_offset = offset;
    pitem = proto_tree_add_item(tree, hf_service_search_pattern, tvb, offset, 0, ENC_NA);
    ptree = proto_item_add_subtree(pitem, ett_btsdp_attribute);

    dissect_data_element(ptree, &next_tree, pinfo, tvb, offset);
    offset = get_type_length(tvb, offset, &bytes_to_go);
    proto_item_set_len(pitem, bytes_to_go + (offset - start_offset));

    while (bytes_to_go > 0) {
        gint            entry_offset;
        gint            entry_size;
        bluetooth_uuid_t a_uuid;

        memset(&a_uuid, 0, sizeof(bluetooth_uuid_t));

        size = dissect_sdp_type(next_tree, pinfo, tvb, offset, -1, empty_uuid, 0, 0, NULL, &info_buf);
        proto_item_append_text(pitem,"%s", wmem_strbuf_get_str(info_buf));
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", wmem_strbuf_get_str(info_buf));

        entry_offset = get_type_length(tvb, offset, &entry_size);
        dissect_uuid(NULL, tvb, entry_offset, entry_size, &a_uuid);
        if (uuid_array)
            wmem_array_append_one(uuid_array, a_uuid);

        offset      += size;
        bytes_to_go -= size;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ": ");

    proto_tree_add_item(tree, hf_maximum_attribute_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uuid = get_specified_uuid(uuid_array);

    offset += dissect_attribute_id_list(tree, tvb, offset, pinfo, &uuid);

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE, NULL, NULL, NULL, &uuid_array, NULL, l2cap_data);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_search_attribute_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid, btl2cap_data_t *l2cap_data)
{
    gint           attribute_list_byte_count;
    gboolean       is_first;
    gboolean       is_continued;
    tvbuff_t      *new_tvb;
    bluetooth_uuid_t uuid;
    wmem_array_t  *uuid_array = NULL;

    proto_tree_add_item(tree, hf_attribute_list_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    attribute_list_byte_count = tvb_get_ntohs(tvb, offset);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo,
            offset + attribute_list_byte_count, tid, FALSE,
            offset, attribute_list_byte_count,
            PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE, &new_tvb, &is_first,
            &is_continued, &uuid_array, NULL, l2cap_data);

    uuid = get_specified_uuid(uuid_array);

    if (is_first && !is_continued) {
        dissect_sdp_service_attribute_list_array(tree, tvb, offset, pinfo,
                attribute_list_byte_count, &uuid, l2cap_data);
    } else {
        proto_tree_add_item(tree, hf_fragment, tvb, offset,
                attribute_list_byte_count, ENC_NA);
    }

    if (is_continued)
        col_append_str(pinfo->cinfo, COL_INFO, "(fragment)");

    offset = dissect_continuation_state(tvb, tree, pinfo, offset + attribute_list_byte_count);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;

        add_new_data_source(pinfo, new_tvb, (is_continued) ? "Partial Reassembled SDP" : "Reassembled SDP");

        reassembled_item = proto_tree_add_item(tree,
                (is_continued) ? hf_partial_attribute_list : hf_reassembled_attribute_list,
                new_tvb, 0, tvb_reported_length(new_tvb), ENC_NA);
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        if (!is_continued)
            dissect_sdp_service_attribute_list_array(reassembled_tree, new_tvb, 0,
                    pinfo, tvb_reported_length(new_tvb), &uuid, l2cap_data);
    }

    return offset;
}


static gint
dissect_btsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item    *ti;
    proto_tree    *st;
    gint          offset = 0;
    guint8        pdu_id;
    guint16       tid;
    btl2cap_data_t   *l2cap_data;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    l2cap_data = (btl2cap_data_t *) data;

    ti = proto_tree_add_item(tree, proto_btsdp, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    st = proto_item_add_subtree(ti, ett_btsdp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    proto_tree_add_item(st, hf_pdu_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    pdu_id = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str_const(pdu_id, vs_pduid, "Unknown"));

    proto_tree_add_item(st, hf_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
    tid = tvb_get_ntohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(st, hf_parameter_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (pdu_id) {
        case 0x01:
            offset = dissect_sdp_error_response(st, tvb, offset);
            break;
        case 0x02:
            offset = dissect_sdp_service_search_request(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
        case 0x03:
            offset = dissect_sdp_service_search_response(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
        case 0x04:
            offset = dissect_sdp_service_attribute_request(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
        case 0x05:
            offset = dissect_sdp_service_attribute_response(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
        case 0x06:
            offset = dissect_sdp_service_search_attribute_request(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
        case 0x07:
            offset = dissect_sdp_service_search_attribute_response(st, tvb, offset, pinfo, tid, l2cap_data);
            break;
    }

    return offset;
}

void
proto_register_btsdp(void)
{
    module_t *module;
    expert_module_t *expert_btsdp;

    static hf_register_info hf[] = {
        { &hf_pdu_id,
            { "PDU",                             "btsdp.pdu",
            FT_UINT8, BASE_HEX, VALS(vs_pduid), 0,
            "PDU type", HFILL }
        },
        { &hf_tid,
            { "Transaction Id",                  "btsdp.tid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_parameter_length,
          { "Parameter Length",                  "btsdp.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_error_code,
            { "Error Code",                      "btsdp.error_code",
            FT_UINT16, BASE_HEX, VALS(vs_error_code), 0,
            NULL, HFILL}
        },
        { &hf_ssr_total_count,
            { "Total Service Record Count",      "btsdp.ssr.total_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Total count of service records", HFILL}
        },
        { &hf_ssr_current_count,
            { "Current Service Record Count",    "btsdp.ssr.current_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Count of service records in this message", HFILL}
        },
        { &hf_attribute_id_list,
            { "Attribute ID List",               "btsdp.attribute_id_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_id_range,
            { "Attribute Range",                 "btsdp.attribute_range",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_id_range_from,
            { "Attribute Range From",            "btsdp.attribute_range.from",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_id_range_to,
            { "Attribute Range To",              "btsdp.attribute_range.to",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_list_byte_count,
            { "Attribute List Byte Count",       "btsdp.attribute_list_byte_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Count of bytes in attribute list response", HFILL}
        },
        { &hf_maximum_service_record_count,
            {"Maximum Service Record Count",     "btsdp.maximum_service_record_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_maximum_attribute_byte_count,
            {"Maximum Attribute Byte Count",     "btsdp.maximum_attribute_byte_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_service_attribute,
            { "Service Attribute",               "btsdp.service_attribute",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id,
            { "Attribute",                       "btsdp.service_attribute.attribute",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_value,
            { "Value",                           "btsdp.service_attribute.value",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_profile_descriptor_list,
            { "Profile Descriptor List",         "btsdp.profile_descriptor_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_list,
            { "Attribute List",                  "btsdp.attribute_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_attribute_lists,
            { "Attribute Lists",                  "btsdp.attribute_lists",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_search_pattern,
            { "Service Search Pattern",          "btsdp.service_search_pattern",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_record_handle_list,
            { "Service Record Handle List",      "btsdp.service_record_handle_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_continuation_state,
            { "Continuation State",              "btsdp.continuation_state",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_continuation_state_length,
            { "Continuation State Length",       "btsdp.continuation_state.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_continuation_state_value,
            { "Continuation State Value",        "btsdp.continuation_state.value",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element,
            { "Data Element",                    "btsdp.data_element",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_type,
            { "Data Element Type",               "btsdp.data_element.type",
            FT_UINT8, BASE_DEC, VALS(vs_data_element_type), 0xF8,
            NULL, HFILL }
        },
        { &hf_data_element_size,
            { "Data Element Size",               "btsdp.data_element.size",
            FT_UINT8, BASE_DEC, VALS(vs_data_element_size), 0x07,
            NULL, HFILL }
        },
        { &hf_data_element_var_size,
            { "Data Element Var Size",           "btsdp.data_element.var_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value,
            { "Data Value",                      "btsdp.data_element.value",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_nil,
            { "Value: Nil",                      "btsdp.data_element.value.nil",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_signed_int,
            { "Value: Signed Int",               "btsdp.data_element.value.signed_int",
            FT_INT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_unsigned_int,
            { "Value: Unsigned Int",             "btsdp.data_element.value.unsigned_int",
            FT_UINT64, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_boolean,
            { "Value: Boolean",                  "btsdp.data_element.value.boolean",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_string,
            { "Value: String",                   "btsdp.data_element.value.string",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_url,
            { "Value: URL",                      "btsdp.data_element.value.url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_uuid_16,
            { "Value: UUID",                     "btsdp.data_element.value.uuid_16",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_uuid_32,
            { "Value: UUID",                     "btsdp.data_element.value.uuid_32",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_uuid_128,
            { "Value: UUID",                     "btsdp.data_element.value.uuid_128",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_uuid,
            { "Value: Custom UUID",              "btsdp.data_element.value.custom_uuid",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_sequence,
            { "Value: Sequence",                 "btsdp.data_element.value.sequence",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value_alternative,
            { "Value: Alternative",              "btsdp.data_element.value.alternative",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fragment,
            { "Data Fragment",                   "btsdp.fragment",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_partial_attribute_list,
            { "Partial Attribute List",          "btsdp.partial_attribute_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_reassembled_attribute_list,
            { "Reassembled Attribute List",      "btsdp.reassembled_attribute_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_partial_record_handle_list,
            { "Partial Record Handle List",      "btsdp.partial_record_handle_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_reassembled_record_handle_list,
            { "Reassembled Record Handle List",  "btsdp.reassembled_attribute_list",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_generic,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_general_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_a2dp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_a2dp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_avrcp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_avrcp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_bip_imaging_responder,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_bip_imaging_responder_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_bip_imaging_other,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_bip_imaging_other_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_bpp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_bpp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_bpp_rui,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_bpp_reflected_ui_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_ctp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_ctp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_did,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_did_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_dun,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_dun_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_fax,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_fax_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_ftp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_ftp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_gnss,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_gnss_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hfp_hf,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hfp_gw_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hfp_ag,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hfp_ag_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hcrp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hcrp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hsp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hsp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hdp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hdp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_hid,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_hid_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_wap,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_wap_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_map_mas,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_map_mas_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_map_mns,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_map_mns_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_opp,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_opp_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_pan_nap,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_pan_nap_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_pan_gn,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_pan_gn_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_pan_panu,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_pan_panu_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_pbap,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_pbap_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_synch,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_synch_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_ctn_as,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_ctn_as_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_ctn_ns,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_ctn_ns_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_mps,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_mps_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_did_specification_id,
            { "Specification ID",                "btsdp.service.did.specification_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_did_vendor_id,
            { "Vendor ID",                       "btsdp.service.did.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_did_vendor_id_bluetooth_sig,
            { "Vendor ID",                       "btsdp.service.did.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_did_vendor_id_usb_forum,
            { "Vendor ID",                       "btsdp.service.did.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ext_usb_vendors_vals, 0,
            NULL, HFILL }
        },
        { &hf_did_product_id,
            { "Product ID",                      "btsdp.service.did.product_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_did_primary_record,
            { "Primary Record",                  "btsdp.service.did.primary_record",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_did_version,
            { "Version",                         "btsdp.service.did.version",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_did_vendor_id_source,
            { "Vendor ID Source",                "btsdp.service.did.vendor_id_source",
            FT_UINT16, BASE_HEX, VALS(did_vendor_id_source_vals), 0,
            NULL, HFILL }
        },
        { &hf_a2dp_sink_supported_features_reserved,
            { "Supported Features: Reserved",    "btsdp.service.a2dp.sink.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_a2dp_sink_supported_features_amplifier,
            { "Supported Features: Amplifier",   "btsdp.service.a2dp.sink.supported_features.amplifier",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_a2dp_sink_supported_features_recorder,
            { "Supported Features: Recorder",    "btsdp.service.a2dp.sink.supported_features.recorder",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_a2dp_sink_supported_features_speaker,
            { "Supported Features: Speaker",     "btsdp.service.a2dp.sink.supported_features.speaker",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_a2dp_sink_supported_features_headphone,
            { "Supported Features: Headphone",   "btsdp.service.a2dp.sink.supported_features.headphone",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_a2dp_source_supported_features_reserved,
            { "Supported Features: Reserved",    "btsdp.service.a2dp.source.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_a2dp_source_supported_features_mixer,
            { "Supported Features: Mixer",       "btsdp.service.a2dp.source.supported_features.mixer",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_a2dp_source_supported_features_tuner,
            { "Supported Features: Tuner",       "btsdp.service.a2dp.source.supported_features.tuner",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_a2dp_source_supported_features_microphone,
            { "Supported Features: Microphone",  "btsdp.service.a2dp.source.supported_features.microphone",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_a2dp_source_supported_features_player,
            { "Supported Features: Player",      "btsdp.service.a2dp.source.supported_features.player",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_synch_supported_data_store,
            { "Supported Data Store",            "btsdp.service.synch.supported_data_store",
            FT_UINT8, BASE_HEX, VALS(synch_supported_data_store_vals), 0,
            NULL, HFILL }
        },
        { &hf_ctp_external_network,
            { "External Network",                "btsdp.service.ctp.external_network",
            FT_UINT8, BASE_HEX, VALS(ctp_external_network_vals), 0,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_reserved_7_15,
            { "Supported Features: Reserved",      "btsdp.service.avrcp.ct.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFF80,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_browsing,
            { "Supported Features: Browsing",      "btsdp.service.avrcp.ct.supported_features.browsing",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_reserved_4_5,
            { "Supported Features: Reserved",      "btsdp.service.avrcp.ct.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0030,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_category_4,
            { "Supported Features: Category 4: Menu",                "btsdp.service.avrcp.ct.supported_features.category_4",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_category_3,
            { "Supported Features: Category 3: Tuner",               "btsdp.service.avrcp.ct.supported_features.category_3",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_category_2,
            { "Supported Features: Category 2: Monitor/Amplifier",   "btsdp.service.avrcp.ct.supported_features.category_2",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_avrcp_ct_supported_features_category_1,
            { "Supported Features: Category 1: Player/Recorder",     "btsdp.service.avrcp.ct.supported_features.category_1",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_reserved_8_15,
            { "Supported Features: Reserved",                        "btsdp.service.avrcp.tg.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_multiple_player,
            { "Supported Features: Multiple Player",                 "btsdp.service.avrcp.tg.supported_features.multiple_player",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_browsing,
            { "Supported Features: Browsing",                        "btsdp.service.avrcp.tg.supported_features.browsing",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_group_navigation,
            { "Supported Features: Group Navigation",                "btsdp.service.avrcp.tg.supported_features.group_navigation",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_settings,
            { "Supported Features: Settings",                        "btsdp.service.avrcp.tg.supported_features.settings",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_category_4,
            { "Supported Features: Category 4: Menu",                "btsdp.service.avrcp.tg.supported_features.category_4",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_category_3,
            { "Supported Features: Category 3: Tuner",               "btsdp.service.avrcp.tg.supported_features.category_3",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_category_2,
            { "Supported Features: Category 2: Monitor/Amplifier",   "btsdp.service.avrcp.tg.supported_features.category_2",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_avrcp_tg_supported_features_category_1,
            { "Supported Features: Category 1: Player/Recorder",     "btsdp.service.avrcp.tg.supported_features.category_1",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_hsp_remote_audio_volume_control,
            { "Remote Audio Volume Control",     "btsdp.service.hsp.remote_audio_volume_control",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gnss_supported_features,
            { "Supported Features: Reserved",    "btsdp.service.gnss.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFF,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories,
            { "Supported Repositories",     "btsdp.service.pbap.pse.supported_repositories",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories_reserved,
            { "Reserved",                   "btsdp.service.pbap.pse.supported_repositories.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories_favourites,
            { "Favourites",                 "btsdp.service.pbap.pse.supported_repositories.favourites",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories_speed_dial,
            { "Speed Dial",                 "btsdp.service.pbap.pse.supported_repositories.speed_dial",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories_sim_card,
            { "SIM Card",                   "btsdp.service.pbap.pse.supported_repositories.sim_card",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_repositories_local_phonebook,
            { "Local Phonebook",            "btsdp.service.pbap.pse.supported_repositories.local_phonebook",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features,
            { "Supported Features",              "btsdp.service.pbap.pse.supported_features",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_reserved,
            { "Reserved",                        "btsdp.service.pbap.pse.supported_features.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_default_contact_image_format,
            { "Default Contact Image Format",    "btsdp.service.pbap.pse.supported_features.default_contact_image_format",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_contact_referencing,
            { "Contact Referencing",             "btsdp.service.pbap.pse.supported_features.contact_referencing",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_x_bt_uid_vcard_property,
            { "X-BT-UID vCard Property",         "btsdp.service.pbap.pse.supported_features.x_bt_uid_vcard_property",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_x_bt_uci_vcard_property,
            { "X-BT-UCI vCard Property",         "btsdp.service.pbap.pse.supported_features.x_bt_uci_vcard_property",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_enhanced_missed_calls,
            { "Enhanced Missed Calls",           "btsdp.service.pbap.pse.supported_features.enhanced_missed_calls",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_vcard_selecting,
            { "vCard Selecting",                 "btsdp.service.pbap.pse.supported_features.vcard_selecting",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_folder_version_counters,
            { "Folder Version Counters",         "btsdp.service.pbap.pse.supported_features.folder_version_counters",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_database_identifier,
            { "Database Identifier",             "btsdp.service.pbap.pse.supported_features.database_identifier",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_browsing,
            { "Browsing",                        "btsdp.service.pbap.pse.supported_features.browsing",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_pbap_pse_supported_features_download,
            { "Download",                        "btsdp.service.pbap.pse.supported_features.download",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_pbap_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.pbap.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_dun_support_audio_feedback,
            { "Support: Audio Feedback",         "btsdp.dun.support.audio_feedback",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_dun_escape_sequence,
            { "Escape Sequence",                 "btsdp.dun.support.escape_sequence",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fax_support_class_1,
            { "Support: Fax Class 1",            "btsdp.fax.support.class_1",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fax_support_class_2,
            { "Support: Fax Class 2.0",          "btsdp.fax.support.class_2",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fax_support_class_2_vendor,
            { "Support: Fax Class 2 Vendor",     "btsdp.fax.support.class_2_vendor",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fax_support_audio_feedback,
            { "Support: Audio Feedback",         "btsdp.fax.support.audio_feedback",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ftp_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.ftp.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_map_mas_instance_id,
            { "MAS Instance ID",                 "btsdp.map.mas.instance_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_map_mas_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.map.mas.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_map_mns_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.map.mns.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_map_mas_supported_message_types_reserved,
            { "Supported Message Types: Reserved",         "btsdp.map.mas.supported_message_types.reserved",
            FT_UINT8, BASE_DEC_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_map_mas_supported_message_types_mms,
            { "Supported Message Types: MMS",              "btsdp.map.mas.supported_message_types.mms",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_map_mas_supported_message_types_sms_cdma,
            { "Supported Message Types: SMS CDMA",         "btsdp.map.mas.supported_message_types.sms_cdma",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_map_mas_supported_message_types_sms_gsm,
            { "Supported Message Types: SMS GSM",          "btsdp.map.mas.supported_message_types.sms_gsm",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_map_mas_supported_message_types_email,
            { "Supported Message Types: Email",              "btsdp.map.mas.supported_message_types.email",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_hcrp_1284_id,
            { "1284 ID",                         "btsdp.hcrp.1284_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hcrp_device_location,
            { "Service Location",                 "btsdp.hcrp.device_location",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hcrp_device_name,
            { "Device Name",                     "btsdp.hcrp.device_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hcrp_friendly_name,
            { "Friendly Name",                   "btsdp.hcrp.friendly_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_wap_network_address,
            { "Network Address",                 "btsdp.wap.network_address",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_wap_homepage_url,
            { "Homepage URL",                    "btsdp.wap.homepage_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_wap_gateway,
            { "Gateway",                         "btsdp.wap.gateway",
            FT_UINT8, BASE_HEX, VALS(wap_gateway_vals), 0,
            NULL, HFILL }
        },
        { &hf_wap_stack_type,
            { "Stack Type",                      "btsdp.wap.stack_type",
            FT_UINT8, BASE_HEX, VALS(wap_stack_type_vals), 0,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_reserved_5_7,
            { "Support: Reserved_5_7",           "btsdp.hdp.support.reserved_5_7",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_sync_master_role,
            { "Support: SyncMaster Role",        "btsdp.hdp.support.sync_master_role",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_clock_synchronization_protocol,
            { "Support: Clock Synchronization Protocol",   "btsdp.hdp.support.clock_synchronization_protocol",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_reconnect_acceptance,
            { "Support: Reconnect Acceptance",   "btsdp.hdp.support.reconnect_acceptance",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_reconnect_initiation,
            { "Support: Reconnect Initiation",   "btsdp.hdp.support.reconnect_initiation",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_hdp_support_procedure_reserved,
            { "Support: Reserved",               "btsdp.hdp.support.reserved",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_hdp_data_exchange,
            { "Data Exchange Specification",     "btsdp.hdp.data_exchange_specification",
            FT_UINT8, BASE_HEX, VALS(hdp_data_exchange_specification_vals), 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_data,
            { "Supported Features",              "btsdp.hdp.supported_features_data",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_data_mdep_id,
            { "MDEP ID",                         "btsdp.hdp.supported_features_data.mdep_id",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_data_mdep_data_type,
            { "MDEP Data Type",                  "btsdp.hdp.supported_features_data.mdep_data_type",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_data_mdep_role,
            { "MDEP Role",                       "btsdp.hdp.supported_features_data.mdep_role",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_data_mdep_description,
            { "MDEP Description",                "btsdp.hdp.supported_features_data.mdep_description",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_mdep_id,
            { "MDEP ID",                         "btsdp.hdp.supported_features.mdep_id",
            FT_UINT8, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(hdp_mdep_id_rvals), 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_mdep_data_type,
            { "MDEP Data Type",                  "btsdp.hdp.supported_features.mdep_data_type",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_mdep_role,
            { "MDEP Role",                       "btsdp.hdp.supported_features.mdep_role",
            FT_UINT8, BASE_HEX, VALS(hdp_mdep_role_vals), 0,
            NULL, HFILL }
        },
        { &hf_hdp_supported_features_mdep_description,
            { "MDEP Description",                "btsdp.hdp.supported_features.mdep_description",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pan_sercurity_description,
            { "Security Description",            "btsdp.pan.security_description",
            FT_UINT16, BASE_HEX, VALS(pan_security_description_vals), 0,
            NULL, HFILL }
        },
        { &hf_pan_ipv4_subnet,
            { "IPv4 Subnet",                     "btsdp.pan.ipv4_subnet",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pan_ipv6_subnet,
            { "IPv6 Subnet",                     "btsdp.pan.ipv6_subnet",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pan_net_access_type,
            { "Net Access Type",                 "btsdp.pan.net_access_type",
            FT_UINT16, BASE_HEX, VALS(pan_net_access_type_vals), 0,
            NULL, HFILL }
        },
        { &hf_pan_max_net_access_rate,
            { "Max Net Access Rate",             "btsdp.pan.max_net_access_rate",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_opp_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.opp.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_opp_supported_format,
            { "Supported Format",                  "btsdp.opp.supported_format",
            FT_UINT8, BASE_HEX, VALS(opp_supported_format_vals), 0,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_reserved,
            { "Supported Features: Reserved",                             "btsdp.service.hfp.hf.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFC0,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_wide_band_speech,
            { "Supported Features: Wide Band Speech",                     "btsdp.service.hfp.hf.supported_features.wide_band_speech",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_remote_volume_control,
            { "Supported Features: Remote Volume Control",                "btsdp.service.hfp.hf.supported_features.remote_volume_control",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_voice_recognition_activation,
            { "Supported Features: Voice Recognition Activation",         "btsdp.service.hfp.hf.supported_features.voice_recognition_activation",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_cli_presentation_capability,
            { "Supported Features: CLI Presentation Capability",          "btsdp.service.hfp.hf.supported_features.cli_presentation_capability",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_call_waiting_or_three_way_calling,
            { "Supported Features: Call Waiting or Three Way Calling",    "btsdp.service.hfp.hf.supported_features.call_waiting_or_three_way_calling",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_hfp_hf_supported_features_ec_and_or_nr_function,
            { "Supported Features: EC and/or Nr Function",                "btsdp.service.hfp.hf.supported_features.ec_and_or_nr_function",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_reserved,
            { "Supported Features: Reserved",                             "btsdp.service.hfp.gw.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFC0,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_wide_band_speech,
            { "Supported Features: Wide Band Speech",                     "btsdp.service.hfp.gw.supported_features.wide_band_speech",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_attach_phone_number_to_voice_tag,
            { "Supported Features: Attach a Phone Number to a Voice Tag", "btsdp.service.hfp.gw.supported_features.attach_a_phone_number_to_a_voice_tag",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_inband_ring_tone_capability,
            { "Supported Features: Inband Ring Tone Capability",          "btsdp.service.hfp.gw.supported_features.inband_ring_tone_capability",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_voice_recognition_function,
            { "Supported Features: Voice Recognition Function",           "btsdp.service.hfp.gw.supported_features.voice_recognition_function",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_ec_and_or_nr_function,
            { "Supported Features: EC and/or Nr Function",                "btsdp.service.hfp.gw.supported_features.ec_and_or_nr_function",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_hfp_gw_supported_features_three_way_calling,
            { "Supported Features: Three Way Calling",                    "btsdp.service.hfp.gw.supported_features.three_way_calling",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_hfp_gw_network,
            { "Network",                                                  "btsdp.service.hfp.gw.network",
            FT_UINT8, BASE_HEX, VALS(hfp_gw_network_vals), 0,
            NULL, HFILL }
        },
        { &hf_ctn_instance_id,
            { "Instance ID",                     "btsdp.ctn.instance_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features,
            { "Supported Features",              "btsdp.ctn.supported_features",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_reserved,
            { "Reserved",                        "btsdp.ctn.supported_features.reserved",
            FT_BOOLEAN, 32, NULL, 0xFFFFFF80,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_forward,
            { "Forward",                         "btsdp.ctn.supported_features.forward",
            FT_BOOLEAN, 32, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_delete,
            { "Delete",                          "btsdp.ctn.supported_features.delete",
            FT_BOOLEAN, 32, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_uploading,
            { "Uploading",                       "btsdp.ctn.supported_features.uploading",
            FT_BOOLEAN, 32, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_downloading,
            { "Downloading",                     "btsdp.ctn.supported_features.downloading",
            FT_BOOLEAN, 32, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_browsing,
            { "Browsing",                        "btsdp.ctn.supported_features.browsing",
            FT_BOOLEAN, 32, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_notification,
            { "Notification",                    "btsdp.ctn.supported_features.notification",
            FT_BOOLEAN, 32, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_ctn_supported_features_account_management,
            { "Account Management",              "btsdp.ctn.supported_features.account_management",
            FT_BOOLEAN, 32, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios,
            { "Supported Profile and Protocol Dependency",                                                   "btsdp.mps.mpsd_scenarios",
            FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_reserved,
            { "Reserved",                                                                                    "btsdp.mps.mpsd_scenarios.reserved",
            FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xFFFFFFC000000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_37,
            { "Phonebook Download during Audio Streaming (A2DP-SNK_PBAP-Client)",                            "btsdp.mps.mpsd_scenarios.37",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000002000000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_36,
            { "Phonebook Download during Audio Streaming (A2DP-SRC_PBAP-Server)",                            "btsdp.mps.mpsd_scenarios.36",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000001000000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_35,
            { "Data communication establishment in Personal Area Network during Audio Streaming (A2DP-SNK_PAN_PANU)",  "btsdp.mps.mpsd_scenarios.35",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000800000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_34,
            { "Data communication establishment in Personal Area Network during Audio Streaming (A2DP-SRC_PAN-NAP)",   "btsdp.mps.mpsd_scenarios.34",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000400000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_33,
            { "Start Audio Streaming during Data communication in Personal Area Network (A2DP-SNK_PAN-PANU)",          "btsdp.mps.mpsd_scenarios.33",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000200000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_32,
            { "Start Audio Streaming during Data communication in Personal Area Network (A2DP-SRC_PAN-NAP)",           "btsdp.mps.mpsd_scenarios.32",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000100000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_31,
            { "Incoming voice call during Data communication in Personal Area Network (HFP-HF_PAN-PANU)",              "btsdp.mps.mpsd_scenarios.31",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000080000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_30,
            { "Incoming voice call during Data communication in Personal Area Network (HFP-AG_PAN-NAP)",               "btsdp.mps.mpsd_scenarios.30",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000040000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_29,
            { "Outgoing voice call during Data communication in Personal Area Network (HFP-HF_PAN-PANU)",              "btsdp.mps.mpsd_scenarios.29",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000020000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_28,
            { "Outgoing voice call during Data communication in Personal Area Network (HFP-AG_PAN-NAP)",               "btsdp.mps.mpsd_scenarios.28",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000010000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_27,
            { "Data communication in Personal Area Network during active voice call (HFP-HF_PAN-PANU)",                "btsdp.mps.mpsd_scenarios.27",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000008000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_26,
            { "Data communication in Personal Area Network during active voice call (HFP-AG_PAN-NAP)",                 "btsdp.mps.mpsd_scenarios.26",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000004000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_25,
            { "Terminate voice call / data call during data communication and voice call (HFP-HF_DUN-DT)",             "btsdp.mps.mpsd_scenarios.25",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000002000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_24,
            { "Terminate voice call / data call during data communication and voice call (HFP-AG_DUN-GW)",             "btsdp.mps.mpsd_scenarios.24",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000001000000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_23,
            { "Data communication establishment under PSDM (DUN) during Audio Streaming (A2DP-SNK_DUN-DT)",            "btsdp.mps.mpsd_scenarios.23",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000800000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_22,
            { "Data communication establishment under PSDM (DUN) during Audio Streaming (A2DP-SRC_DUN-GW)",            "btsdp.mps.mpsd_scenarios.22",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000400000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_21,
            { "Start Audio Streaming during Data communication under PSDM (DUN) (A2DP-SNK_DUN-DT)",                    "btsdp.mps.mpsd_scenarios.21",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000200000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_20,
            { "Start Audio Streaming during Data communication under PSDM (DUN) (A2DP-SRC_DUN-GW)",                    "btsdp.mps.mpsd_scenarios.20",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000100000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_19,
            { "Incoming voice call during Data communication under PSDM (DUN) (HFP-HF_DUN-DT)",                        "btsdp.mps.mpsd_scenarios.19",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000080000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_18,
            { "Incoming voice call during Data communication under PSDM (DUN) (HFP-AG_DUN-GW)",                        "btsdp.mps.mpsd_scenarios.18",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000040000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_17,
            { "Outgoing voice call during Data communication under PSDM (DUN) (HFP-HF_DUN-DT)",                        "btsdp.mps.mpsd_scenarios.17",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000020000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_16,
            { "Outgoing voice call during Data communication under PSDM (DUN) (HFP-AG_DUN-GW)",                        "btsdp.mps.mpsd_scenarios.16",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000010000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_15,
            { "Data communication under PSDM (DUN) during active voice call (HFP-HF_DUN-DT)",                          "btsdp.mps.mpsd_scenarios.15",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000008000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_14,
            { "Data communication under PSDM (DUN) during active voice call (HFP-AG_DUN-GW)",                          "btsdp.mps.mpsd_scenarios.14",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000004000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_13,
            { "Suspend Audio Streaming after AVRCP Pause/Stop (HFP-HF_A2DP-SNK)",                            "btsdp.mps.mpsd_scenarios.13",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000002000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_12,
            { "Suspend Audio Streaming after AVRCP Pause/Stop (HFP-AG_A2DP-SRC)",                            "btsdp.mps.mpsd_scenarios.12",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000001000),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_11,
            { "Start Audio Streaming after AVRCP Play Command (HFP-HF_A2DP-SNK)",                            "btsdp.mps.mpsd_scenarios.11",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000800),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_10,
            { "Start Audio Streaming after AVRCP Play Command (HFP-AG_A2DP-SRC)",                            "btsdp.mps.mpsd_scenarios.10",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000400),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_9,
            { "Press Play on Audio Player during active call (HFP-HF_A2DP-SNK)",                             "btsdp.mps.mpsd_scenarios.9",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000200),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_8,
            { "Press Play on Audio Player during active call (HFP-AG_A2DP-SRC)",                             "btsdp.mps.mpsd_scenarios.8",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000100),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_7,
            { "HFP call termination during AVP connection (HFP-HF_A2DP-SNK)",                                "btsdp.mps.mpsd_scenarios.7",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000080),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_6,
            { "HFP call termination during AVP connection (HFP-AG_A2DP-SRC)",                                "btsdp.mps.mpsd_scenarios.6",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000040),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_5,
            { "Reject/Ignore Incoming Call during Audio Streaming (HFP-HF_A2DP-SNK)",                        "btsdp.mps.mpsd_scenarios.5",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000020),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_4,
            { "Reject/Ignore Incoming Call during Audio Streaming (HFP-AG_A2DP-SRC)",                        "btsdp.mps.mpsd_scenarios.4",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000010),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_3,
            { "Outgoing Call during Audio Streaming (HFP-HF_A2DP-SNK)",                                      "btsdp.mps.mpsd_scenarios.3",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000008),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_2,
            { "Outgoing Call during Audio Streaming (HFP-AG_A2DP-SRC)",                                      "btsdp.mps.mpsd_scenarios.2",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000004),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_1,
            { "Answer Incoming Call during Audio Streaming (HFP-HF_A2DP-SNK)",                               "btsdp.mps.mpsd_scenarios.1",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000002),
            NULL, HFILL }
        },
        { &hf_mps_mpsd_scenarios_0,
            { "Answer Incoming Call during Audio Streaming (HFP-AG_A2DP-SRC)",                               "btsdp.mps.mpsd_scenarios.0",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000001),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios,
            { "Supported Profile and Protocol Dependency",                                                   "btsdp.mps.mpmd_scenarios",
            FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_reserved,
            { "Reserved",                                                                                    "btsdp.mps.mpmd_scenarios.reserved",
            FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xFFFFFFFFFFF80000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_18,
            { "Start Packet data communication during Audio streaming (A2DP-SNK_AVRCP-CT_DUN-DT)",           "btsdp.mps.mpmd_scenarios.18",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000040000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_17,
            { "Start Packet data communication during Audio streaming (A2DP-SRC_AVRCP-TG)",                  "btsdp.mps.mpmd_scenarios.17",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000020000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_16,
            { "Start Audio streaming during Data communication under PSDM (A2DP-SNK_AVRCP-CT_DUN-DT)",       "btsdp.mps.mpmd_scenarios.16",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000010000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_15,
            { "Start Audio streaming during Data communication under PSDM (A2DP-SRC_AVRCP-TG)",              "btsdp.mps.mpmd_scenarios.15",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000008000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_14,
            { "Suspend Audio Streaming after AVRCP Pause/Stop (A2DP-SRC_AVRCP-TG)",                          "btsdp.mps.mpmd_scenarios.14",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000004000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_13,
            { "Suspend Audio Streaming after AVRCP Pause/Stop (AVRCP-CT where the same device does not carry out the role of an A2DP SNK)",     "btsdp.mps.mpmd_scenarios.13",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000002000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_12,
            { "Start Audio Streaming after AVRCP Play Command (A2DP-SRC_AVRCP-TG)",                                                             "btsdp.mps.mpmd_scenarios.12",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000001000),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_11,
            { "Start Audio Streaming after AVRCP Play Command (AVRCP-CT where the same device does not carry out the role of an A2DP SNK)",     "btsdp.mps.mpmd_scenarios.11",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000800),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_10,
            { "Press Play on Audio Player during active call (A2DP-SRC_AVRCP-TG)",                 "btsdp.mps.mpmd_scenarios.10",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000400),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_9,
            { "Press Play on Audio Player during active call (HFP-HF_A2DP-SNK_AVRCP-CT)",          "btsdp.mps.mpmd_scenarios.9",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000200),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_8,
            { "HFP Call termination during AVP connection (A2DP-SRC_AVRCP-TG)",                    "btsdp.mps.mpmd_scenarios.8",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000100),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_7,
            { "HFP Call termination during AVP connection (HFP-HF_ A2DP-SNK_AVRCP-CT)",            "btsdp.mps.mpmd_scenarios.7",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000080),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_6,
            { "HFP Call termination during AVP connection (HFP-AG)",                               "btsdp.mps.mpmd_scenarios.6",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000040),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_5,
            { "Reject/Ignore Incoming Call during Audio Streaming (A2DP-SRC_AVRCP-TG)",            "btsdp.mps.mpmd_scenarios.5",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000020),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_4,
            { "Reject/Ignore Incoming Call during Audio Streaming (HFP-HF_A2DP-SNK_AVRCP-CT)",     "btsdp.mps.mpmd_scenarios.4",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000010),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_3,
            { "Outgoing Call during Audio Streaming (A2DP-SRC_AVRCP-TG)",                          "btsdp.mps.mpmd_scenarios.3",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000008),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_2,
            { "Outgoing Call during Audio Streaming (HFP-HF_A2DP-SNK_AVRCP-CT)",                   "btsdp.mps.mpmd_scenarios.2",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000004),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_1,
            { "Answer Incoming Call during Audio Streaming (A2DP-SRC_AVRCP-TG)",                   "btsdp.mps.mpmd_scenarios.1",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000002),
            NULL, HFILL }
        },
        { &hf_mps_mpmd_scenarios_0,
            { "Answer Incoming Call during Audio Streaming (HFP-HF_A2DP-SNK_AVRCP-CT)",            "btsdp.mps.mpmd_scenarios.0",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000000000000001),
            NULL, HFILL }
        },
        { &hf_mps_supported_profile_and_protocol_dependency,
            { "Supported Profile and Protocol Dependency",           "btsdp.mps.supported_profile_and_protocol_dependency",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_mps_supported_profile_and_protocol_dependency_reserved,
            { "Reserved",                                  "btsdp.mps.supported_profile_and_protocol_dependency.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFF8,
            NULL, HFILL }
        },
        { &hf_mps_supported_profile_and_protocol_dependency_dis_connection_order_behaviour,
            { "(Dis)Connection Order/Behaviour",           "btsdp.mps.supported_profile_and_protocol_dependency.dis_connection_order_behaviour",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_mps_supported_profile_and_protocol_dependency_gavdp_requirements,
            { "GAVDP Requirements",                        "btsdp.mps.supported_profile_and_protocol_dependency.gavdp_requirements",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_mps_supported_profile_and_protocol_dependency_sniff_mode_during_streaming,
            { "Sniff Mode During Streaming",               "btsdp.mps.supported_profile_and_protocol_dependency.sniff_mode_during_streaming",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_map_supported_features,
            { "Supported Features",    "btsdp.map.supported_features",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_map_supported_features_reserved,
            { "Reserved",              "btsdp.map.supported_features.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFF80,
            NULL, HFILL }
        },
        { &hf_map_supported_features_extended_event_report_1_1,
            { "Extended Event Report 1.1",  "btsdp.map.supported_features.extended_event_report_1_1",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }
        },
        { &hf_map_supported_features_instance_information_feature,
            { "Instance Information Feature",  "btsdp.map.supported_features.instance_information_feature",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_map_supported_features_delete_feature,
            { "Delete Feature",  "btsdp.map.supported_features.delete_feature",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_map_supported_features_uploading_feature,
            { "Uploading Feature",  "btsdp.map.supported_features.uploading_feature",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_map_supported_features_browsing_feature,
            { "Browsing Feature",  "btsdp.map.supported_features.browsing_feature",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_map_supported_features_notification_feature,
            { "Notification Feature",  "btsdp.map.supported_features.notification_feature",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_map_supported_features_notification_registration_feature,
            { "Notification Registration Feature",  "btsdp.map.supported_features.notification_registration_feature",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_item,
            { "Protocol",                        "btsdp.protocol_item",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol,
            { "Protocol Entry",                  "btsdp.protocol",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_psm,
            { "L2CAP PSM",                       "btsdp.protocol.psm",
            FT_UINT16, BASE_DEC_HEX | BASE_EXT_STRING, &ext_psm_vals, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_channel,
            { "RFCOMM Channel",                  "btsdp.protocol.channel",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_gatt_handle_start,
            { "GATT Handle Start",               "btsdp.protocol.gatt_handle_start",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_gatt_handle_end,
            { "GATT Handle Start",               "btsdp.protocol.gatt_handle_end",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_version,
            { "Protocol Version",                "btsdp.protocol.version",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_protocol_bnep_type,
            { "BNEP Type",                       "btsdp.protocol.bnep_type",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_record_handle,
            { "Service Record Handle",           "btsdp.service_record_handle",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_record_state,
            { "Service Record State",            "btsdp.service_record_state",
            FT_UINT32, BASE_HEX_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_sdp_service_info_time_to_live,
            { "Service Info Time to Live",       "btsdp.service_info_time_to_live",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_availability,
            { "Service Availability",            "btsdp.service_availability",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_documentation_url,
            { "Documentation URL",               "btsdp.documentation_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_client_executable_url,
            { "Service Client Executable URL",   "btsdp.service_client_executable_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_icon_url,
            { "Icon URL",                        "btsdp.icon_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_name,
            { "Service Name",                    "btsdp.service_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_description,
            { "Service Description",             "btsdp.service_description",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_provider_name,
            { "Provider Name",                   "btsdp.provider_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_lang,
            { "Language",                        "btsdp.lang",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_lang_code,
            { "Language Code",                   "btsdp.lang.code",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_sdp_lang_id,
            { "Language ID",                     "btsdp.lang.id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &usb_langid_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_sdp_lang_encoding,
            { "Language Encoding",               "btsdp.lang.encoding",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &mibenum_vals_character_sets_ext, 0,
            NULL, HFILL }
        },
        { &hf_sdp_lang_attribute_base,
            { "Attribute Base",                  "btsdp.lang.attribute_base",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_device_release_number,
            { "Device Release Number",           "btsdp.service.hid.device_release_number",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_parser_version,
            { "Parser Version",                  "btsdp.service.hid.parser_version",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_device_subclass_type,
            { "Device Subclass: Type",           "btsdp.service.hid.device_subclass.type",
            FT_UINT8, BASE_HEX, VALS(hid_device_subclass_type_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_hid_device_subclass_subtype,
            { "Device Subclass: SubType",        "btsdp.service.hid.device_subclass.subtype",
            FT_UINT8, BASE_HEX, VALS(hid_device_subclass_subtype_vals), 0x3C,
            NULL, HFILL }
        },
        { &hf_hid_device_subclass_reserved,
            { "Device Subclass: Reserved",       "btsdp.service.hid.device_subclass.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_hid_country_code,
            { "Country Code",                    "btsdp.service.hid.country_code",
            FT_UINT8, BASE_DEC_HEX, VALS(hid_country_code_vals), 0,
            NULL, HFILL }
        },
        { &hf_hid_virtual_cable,
            { "Virtual Cable",                   "btsdp.service.hid.virtual_cable",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_reconnect_initiate,
            { "Reconnect Initiate",              "btsdp.service.hid.reconnect_initiate",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_sdp_disable,
            { "SDP Disable",                     "btsdp.service.hid.sdp_disable",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_battery_power,
            { "Battery Power",                    "btsdp.service.hid.battery_power",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_remote_wake,
            { "Remote Wake",                     "btsdp.service.hid.remote_wake",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_normally_connectable,
            { "Normally Connectable",            "btsdp.service.hid.normally_connectable",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_boot_device,
            { "Boot Device",                     "btsdp.service.hid.boot_device",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_profile_version,
            { "Profile Version",                 "btsdp.service.hid.profile_version",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_supervision_timeout,
            { "Supervision Timeout",             "btsdp.service.hid.supervision_timeout",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_ssr_host_max_latency,
            { "SSR Host Max Latency",            "btsdp.service.hid.ssr_host_max_latency",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_ssr_host_min_timeout,
            { "SSR Host Min Timeout",            "btsdp.service.hid.ssr_host_min_timeout",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_descriptor_list_type,
            { "Descriptor Type",                 "btsdp.service.hid.descriptor.type",
            FT_UINT8, BASE_HEX, VALS(descriptor_list_type_vals), 0,
            NULL, HFILL }
        },
        { &hf_hid_lang,
            { "Language",                        "btsdp.service.hid.lang",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_descriptor_list_descriptor_data,
            { "Descriptor",                      "btsdp.service.hid.descriptor_list.descriptor_data",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hid_descriptor_list_descriptor,
            { "Descriptor",                      "btsdp.service.hid.descriptor_list.descriptor",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bip_supported_capabilities_reserved_4_7,
            { "Supported Capabilities: Reserved",          "btsdp.service.bip.supported_capabilities.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_bip_supported_capabilities_displaying,
            { "Supported Capabilities: Displaying",        "btsdp.service.bip.supported_capabilities.displaying",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bip_supported_capabilities_printing,
            { "Supported Capabilities: Printing",          "btsdp.service.bip.supported_capabilities.printing",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bip_supported_capabilities_capturing,
            { "Supported Capabilities: Capturing",         "btsdp.service.bip.supported_capabilities.capturing",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bip_supported_capabilities_genering_imaging,
            { "Supported Capabilities: Genering Imaging",  "btsdp.service.bip.supported_capabilities.genering_imaging",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_reserved_9_15,
            { "Supported Features: Reserved",              "btsdp.service.bip.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_remote_display,
            { "Supported Features: Remote Display",        "btsdp.service.bip.supported_features.remote_display",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_remote_camera,
            { "Supported Features: Remote Camera",         "btsdp.service.bip.supported_features.remote_camera",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_automatic_archive,
            { "Supported Features: Automatic Archive",     "btsdp.service.bip.supported_features.automatic_archive",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_advanced_image_printing,
            { "Supported Features: Advanced Image Printing","btsdp.service.bip.supported_features.advanced_image_printing",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_image_pull,
            { "Supported Features: Image Pull",            "btsdp.service.bip.supported_features.image_pull",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_image_push_display,
            { "Supported Features: Image Push Display",    "btsdp.service.bip.supported_features.image_push_display",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_image_push_print,
            { "Supported Features: Image Push Print",     "btsdp.service.bip.supported_features.image_push_print",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_image_push_store,
            { "Supported Features: Image Push Store",      "btsdp.service.bip.supported_features.image_push_store",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_bip_supported_features_image_push,
            { "Supported Features: Image Push",            "btsdp.service.bip.supported_features.image_push",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_17_31,
            { "Supported Functions: Reserved",            "btsdp.service.bip.supported_functions.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFE0000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_13_31,
            { "Supported Functions: Reserved",            "btsdp.service.bip.supported_functions.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFE000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_11_31,
            { "Supported Functions: Reserved",            "btsdp.service.bip.supported_functions.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFF800,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_1_11,
            { "Supported Functions: Reserved",            "btsdp.service.bip.supported_functions.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x00000FFE,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_1_4,
            { "Supported Functions: Reserved",            "btsdp.service.bip.supported_functions.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0000001E,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_status,
            { "Supported Functions: Get Status",           "btsdp.service.bip.supported_functions.get_status",
            FT_BOOLEAN, 32, NULL, 0x00010000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_15,
            { "Supported Functions: Reserved",             "btsdp.service.bip.supported_functions.reserved_15",
            FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_monitoring_image,
            { "Supported Functions: Get Monitoring Image", "btsdp.service.bip.supported_functions.get_monitoring_image",
            FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_start_archive,
            { "Supported Functions: Start Archive",        "btsdp.service.bip.supported_functions.start_archive",
            FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_reserved_12,
            { "Supported Functions: Reserved",             "btsdp.service.bip.supported_functions.reserved_12",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_partial_image,
            { "Supported Functions: Get Partial Image",    "btsdp.service.bip.supported_functions.get_partial_image",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_start_print,
            { "Supported Functions: Start Print",          "btsdp.service.bip.supported_functions.start_print",
            FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_delete_image,
            { "Supported Functions: Delete Image",         "btsdp.service.bip.supported_functions.delete_image",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_linked_attachment,
            { "Supported Functions: Get Linked Attachment","btsdp.service.bip.supported_functions.get_linked_attachment",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_linked_thumbnail,
            { "Supported Functions: Get Linked Thumbnail", "btsdp.service.bip.supported_functions.get_linked_thumbnail",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_image,
            { "Supported Functions: Get Image",            "btsdp.service.bip.supported_functions.get_image",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_image_property,
            { "Supported Functions: Get Image Property",   "btsdp.service.bip.supported_functions.get_image_property",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_images_list,
            { "Supported Functions: Get Images List",      "btsdp.service.bip.supported_functions.get_images_list",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_remote_display,
            { "Supported Functions: Remote Display",       "btsdp.service.bip.supported_functions.remote_display",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_put_linked_thumbnail,
            { "Supported Functions: Put Linked Thumbnail", "btsdp.service.bip.supported_functions.put_linked_thumbnail",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_put_linked_attachment,
            { "Supported Functions: Put Linked Attachment","btsdp.service.bip.supported_functions.put_linked_attachment",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_put_image,
            { "Supported Functions: Put Image",            "btsdp.service.bip.supported_functions.put_image",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_bip_supported_functions_get_capabilities,
            { "Supported Functions: Get Capabilities",     "btsdp.service.bip.supported_functions.get_capabilities",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_bip_total_imaging_data_capacity,
            { "Total Imaging Data Capacity",     "btsdp.bip.total_imaging_data_capacity",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bip_goep_l2cap_psm,
            { "GOEP L2CAP PSM",                  "btsdp.bip.goep_l2cap_psm",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_document_formats_supported,
            { "Document Formats Supported",       "btsdp.service.bpp.document_formats_supported",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_character_repertoires_support,
            { "Character Repertoires Support",   "btsdp.service.bpp.character_repertoires_support",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_xhtml_print_image_formats_supported,
            { "XHTML Print Image Formats Supported",       "btsdp.service.bpp.xhtml_print_image_formats_supported",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_color_supported,
            { "Color Supported",                 "btsdp.service.bpp.color_supported",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_1284_id,
            { "1284 ID",                         "btsdp.service.bpp.1284_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_printer_name,
            { "Printer Name",                    "btsdp.service.bpp.printer_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_printer_location,
            { "Printer Location",                "btsdp.service.bpp.location",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_duplex_supported,
            { "Duplex Supported",                "btsdp.service.bpp.duplex_supported",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_media_types_supported,
            { "Media Types Supported",           "btsdp.service.bpp.media_types_supported",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_max_media_width,
            { "Max Media Width",                 "btsdp.service.bpp.max_media_width",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_max_media_length,
            { "Max Media Length",                "btsdp.service.bpp.max_media_length",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_enhanced_layout_supported,
            { "Enhanced Layout Supported",       "btsdp.service.bpp.enhanced_layout_supported",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_rui_formats_supported,
            { "RUI Formats Supported",           "btsdp.service.bpp.rui_formats_supported",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_reference_printing_rui_supported,
            { "Reference Printing RUI Supported","btsdp.service.bpp.reference_printing_rui_supported",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_direct_printing_rui_supported,
            { "Direct Printing RUI Supported",   "btsdp.service.bpp.direct_printing_rui_supported",
            FT_BOOLEAN, 8, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_reference_printing_top_url,
            { "Reference Printing Top URL",      "btsdp.service.bpp.reference_printing_top_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_direct_printing_top_url,
            { "Direct Printing Top URL",         "btsdp.service.bpp.direct_printing_top_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_device_name,
            { "Device Name",                     "btsdp.service.bpp.device_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bpp_printer_admin_rui_top_url,
            { "Printer Admin RUI Top URL",       "btsdp.service.bpp.printer_admin_rui_top_url",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btsdp,
        &ett_btsdp_ssr,
        &ett_btsdp_des,
        &ett_btsdp_attribute,
        &ett_btsdp_attribute_id,
        &ett_btsdp_attribute_value,
        &ett_btsdp_service_search_pattern,
        &ett_btsdp_attribute_idlist,
        &ett_btsdp_continuation_state,
        &ett_btsdp_data_element,
        &ett_btsdp_data_element_value,
        &ett_btsdp_reassembled,
        &ett_btsdp_supported_features,
        &ett_btsdp_supported_features_mdep_id,
        &ett_btsdp_supported_features_mdep_data_type,
        &ett_btsdp_supported_features_mdep_role,
        &ett_btsdp_supported_features_mdep_description,
        &ett_btsdp_protocol
    };

    static ei_register_info ei[] = {
        { &ei_btsdp_continuation_state_none,  { "btsdp.expert.continuation_state_none",  PI_MALFORMED, PI_WARN,      "There is no Continuation State", EXPFILL }},
        { &ei_btsdp_continuation_state_large, { "btsdp.expert.continuation_state_large", PI_MALFORMED, PI_WARN,      "Continuation State data is longer then 16", EXPFILL }},
        { &ei_data_element_value_large,       { "btsdp.expert.data_element.value.large", PI_MALFORMED, PI_WARN,      "Data size exceeds the length of payload", EXPFILL }},
    };

    proto_btsdp = proto_register_protocol("Bluetooth SDP Protocol", "BT SDP", "btsdp");
    btsdp_handle = register_dissector("btsdp", dissect_btsdp, proto_btsdp);

    proto_register_field_array(proto_btsdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btsdp = expert_register_protocol(proto_btsdp);
    expert_register_field_array(expert_btsdp, ei, array_length(ei));

    tid_requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    continuation_states = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    record_handle_services = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    service_infos = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol(proto_btsdp, NULL);
    prefs_register_static_text_preference(module, "bnep.version",
            "Bluetooth Protocol SDP version from Core 4.0",
            "Version of protocol supported by this dissector.");
}


void
proto_reg_handoff_btsdp(void)
{
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_SDP, btsdp_handle);
    dissector_add_for_decode_as("btl2cap.cid", btsdp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
