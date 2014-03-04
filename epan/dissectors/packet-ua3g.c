/* packet-ua3g.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <ctype.h>

#include <glib.h>

#include "epan/packet.h"
#include "epan/wmem/wmem.h"
#include "packet-uaudp.h"

void proto_register_ua3g(void);
void proto_reg_handoff_ua3g(void);
/*-----------------------------------------------------------------------------
    Globals
    ---------------------------------------------------------------------------*/

#if 0
static dissector_table_t ua3g_opcode_dissector_table;
#endif


static int  proto_ua3g          = -1;
static gint ett_ua3g            = -1;
static gint ett_ua3g_body       = -1;
static gint ett_ua3g_param      = -1;
static gint ett_ua3g_param_sub  = -1;
static gint ett_ua3g_option     = -1;

static int  hf_ua3g_length                  = -1;
static int  hf_ua3g_opcode_sys              = -1;
static int  hf_ua3g_opcode_term             = -1;
static int  hf_ua3g_opcode_production_test  = -1;
static int  hf_ua3g_opcode_subservice_reset = -1;
static int  hf_ua3g_opcode_are_you_there    = -1;
static int  hf_ua3g_opcode_set_speaker_vol  = -1;
static int  hf_ua3g_opcode_trace_on         = -1;
static int  hf_ua3g_ip                      = -1;
static int  hf_ua3g_ip_cs                   = -1;
static int  hf_ua3g_command_led             = -1;
static int  hf_ua3g_command_lcd_line        = -1;
static int  hf_ua3g_main_voice_mode         = -1;
static int  hf_ua3g_command_set_clck        = -1;
static int  hf_ua3g_external_ringing_command= -1;
static int  hf_ua3g_lcd_cursor              = -1;
static int  hf_ua3g_command_beep            = -1;
static int  hf_ua3g_command_sidetone        = -1;
static int  hf_ua3g_command_mute            = -1;
static int  hf_ua3g_command_feedback        = -1;
static int  hf_ua3g_command_audio_config    = -1;
static int  hf_ua3g_command_key_release     = -1;
static int  hf_ua3g_command_amplified_handset = -1;
static int  hf_ua3g_command_loudspeaker     = -1;
static int  hf_ua3g_command_announce        = -1;
static int  hf_ua3g_command_ring            = -1;
static int  hf_ua3g_command_ua_dwl_protocol = -1;
static int  hf_ua3g_command_unsolicited_msg = -1;
static int  hf_ua3g_ip_device_routing_stop_rtp_parameter = -1;
static int  hf_ua3g_ip_device_routing_stop_rtp_parameter_length = -1;
static int  hf_ua3g_ip_device_routing_stop_rtp_parameter_value_num = -1;
static int  hf_ua3g_ip_device_routing_stop_rtp_parameter_value_bytes = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_ua3g_ip_device_routing_start_tone_direction = -1;
static int hf_ua3g_ip_device_routing_start_tone_num_entries = -1;
static int hf_ua3g_ip_device_routing_def_tones_num_entries = -1;
static int hf_ua3g_cs_ip_device_routing_cmd00_characteristic_number = -1;
static int hf_ua3g_subdevice_msg_subdev_type = -1;
static int hf_ua3g_unsolicited_msg_next_byte_of_bad_segment = -1;
static int hf_ua3g_ip_device_routing_start_tone_identification = -1;
static int hf_ua3g_ip_device_routing_def_tones_level_2 = -1;
static int hf_ua3g_r_w_peripheral_content = -1;
static int hf_ua3g_subdevice_metastate_subchannel_address = -1;
static int hf_ua3g_subdevice_parameter_bytes = -1;
static int hf_ua3g_subdevice_msg_parameter_bytes = -1;
static int hf_ua3g_set_clck_timer_pos_call_timer_column_number = -1;
static int hf_ua3g_unsolicited_msg_segment_failure_s = -1;
static int hf_ua3g_ip_device_routing_reset_parameter = -1;
static int hf_ua3g_ip_device_routing_get_param_req_parameter = -1;
static int hf_ua3g_set_lcd_contrast_driver_number = -1;
static int hf_ua3g_dwl_special_char_character_number = -1;
static int hf_ua3g_cs_ip_device_routing_cmd00_vta_type = -1;
static int hf_ua3g_ua_dwl_protocol_cause = -1;
static int hf_ua3g_audio_padded_path_emission_padded_level = -1;
static int hf_ua3g_set_clck_timer_pos_clock_column_number = -1;
static int hf_ua3g_segment_msg_num_remaining = -1;
static int hf_ua3g_ip_device_routing_digit_value = -1;
static int hf_ua3g_super_msg_data = -1;
static int hf_ua3g_unsolicited_msg_hardware_version = -1;
static int hf_ua3g_voice_channel_announce = -1;
static int hf_ua3g_ring_silent = -1;
static int hf_ua3g_audio_config_handsfree_return = -1;
static int hf_ua3g_dwl_dtmf_clck_format_inter_digit_pause_time = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_length = -1;
static int hf_ua3g_unsolicited_msg_opcode_bad_segment = -1;
static int hf_ua3g_unsolicited_msg_firmware_version_loader = -1;
static int hf_ua3g_debug_in_line = -1;
static int hf_ua3g_voice_channel_b_microphones = -1;
static int hf_ua3g_beep_beep_number = -1;
static int hf_ua3g_main_voice_mode_tune = -1;
static int hf_ua3g_super_msg_length = -1;
static int hf_ua3g_ip_device_routing_redirect_parameter = -1;
static int hf_ua3g_unsolicited_msg_next_byte_of_bad_command = -1;
static int hf_ua3g_unsolicited_msg_self_test_result = -1;
static int hf_ua3g_beep_on_off = -1;
static int hf_ua3g_ua_dwl_protocol_binary_length = -1;
static int hf_ua3g_ring_speaker_level = -1;
static int hf_ua3g_voice_channel_channel_mode = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_length = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter = -1;
static int hf_ua3g_subdevice_metastate_new_metastate = -1;
static int hf_ua3g_unsolicited_msg_other_information_2 = -1;
static int hf_ua3g_set_lcd_contrast_contrast_value = -1;
static int hf_ua3g_unsolicited_msg_vta_type = -1;
static int hf_ua3g_ua_dwl_protocol_packet_number = -1;
static int hf_ua3g_unsolicited_msg_segment_failure_l = -1;
static int hf_ua3g_voice_channel_b_ear_piece = -1;
static int hf_ua3g_subdevice_msg_subdev_address = -1;
static int hf_ua3g_ring_progressive = -1;
static int hf_ua3g_ua_dwl_protocol_item_version = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_length = -1;
static int hf_ua3g_dwl_dtmf_clck_format_minimum_on_time = -1;
static int hf_ua3g_ring_melody = -1;
static int hf_ua3g_ua_dwl_protocol_item_identifier = -1;
static int hf_ua3g_main_voice_mode_speaker_volume = -1;
static int hf_ua3g_ip_device_routing_listen_rtp_parameter_length = -1;
static int hf_ua3g_ringing_cadence_length = -1;
static int hf_ua3g_software_reset = -1;
static int hf_ua3g_feedback_level = -1;
static int hf_ua3g_ip_phone_warmstart = -1;
static int hf_ua3g_subdevice_opcode = -1;
static int hf_ua3g_unsolicited_msg_device_event = -1;
static int hf_ua3g_segment_message_data = -1;
static int hf_ua3g_main_voice_mode_sending_level = -1;
static int hf_ua3g_subdevice_msg_subdevice_opcode = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter = -1;
static int hf_ua3g_audio_padded_path_reception_padded_level = -1;
static int hf_ua3g_ua_dwl_protocol_force_mode = -1;
static int hf_ua3g_lcd_line_cmd_starting_column = -1;
static int hf_ua3g_subdevice_address = -1;
static int hf_ua3g_ip_device_routing_pause_restart_rtp_parameter = -1;
static int hf_ua3g_audio_config_ignored = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options = -1;
static int hf_ua3g_main_voice_mode_cadence = -1;
static int hf_ua3g_segment_msg_length = -1;
static int hf_ua3g_ua_dwl_protocol_acknowledge = -1;
static int hf_ua3g_command_led_number = -1;
static int hf_ua3g_set_clck_timer_pos_call_timer_line_number = -1;
static int hf_ua3g_unsolicited_msg_segment_failure_t = -1;
static int hf_ua3g_ip_device_routing_start_tone_duration = -1;
static int hf_ua3g_unsolicited_msg_other_information_1 = -1;
static int hf_ua3g_unsolicited_msg_firmware_datas_patch_version = -1;
static int hf_ua3g_ring_beep_number = -1;
static int hf_ua3g_feedback_duration = -1;
static int hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_length = -1;
static int hf_ua3g_audio_config_law = -1;
static int hf_ua3g_ua_dwl_protocol_checksum = -1;
static int hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_value = -1;
static int hf_ua3g_audio_config_handsfree_handsfree = -1;
static int hf_ua3g_ringing_cadence_cadence = -1;
static int hf_ua3g_lcd_cursor_line_number = -1;
static int hf_ua3g_ip_device_routing_def_tones_level_1 = -1;
static int hf_ua3g_unsolicited_msg_opcode_of_bad_command = -1;
static int hf_ua3g_ua_dwl_protocol_download_ack_status = -1;
static int hf_ua3g_voice_channel_main_voice = -1;
static int hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_length = -1;
static int hf_ua3g_icon_cmd_segment = -1;
static int hf_ua3g_cs_ip_device_routing_cmd01_incident_0 = -1;
static int hf_ua3g_beep_destination = -1;
static int hf_ua3g_ip_device_routing_def_tones_frequency_1 = -1;
static int hf_ua3g_unsolicited_msg_datas_version = -1;
static int hf_ua3g_dwl_dtmf_clck_format_dtmf_country_adaptation = -1;
static int hf_ua3g_ringing_cadence_on_off = -1;
static int hf_ua3g_audio_config_volume_level = -1;
static int hf_ua3g_voice_channel_b_general = -1;
static int hf_ua3g_beep_terminator = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter = -1;
static int hf_ua3g_unsolicited_msg_firmware_version_bootloader = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter = -1;
static int hf_ua3g_ip_device_routing_start_rtp_direction = -1;
static int hf_ua3g_set_clck_timer_pos_clock_line_number = -1;
static int hf_ua3g_voice_channel_b_loud_speaker = -1;
static int hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter = -1;
static int hf_ua3g_on_off_level_level_on_loudspeaker = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_length = -1;
static int hf_ua3g_main_voice_mode_microphone_volume = -1;
static int hf_ua3g_sidetone_level = -1;
static int hf_ua3g_beep_number_of_notes = -1;
static int hf_ua3g_unsolicited_msg_segment_failure_num = -1;
static int hf_ua3g_dwl_special_char_byte = -1;
static int hf_ua3g_ring_cadence = -1;
static int hf_ua3g_unsolicited_msg_device_type = -1;
static int hf_ua3g_voice_channel_codec = -1;
static int hf_ua3g_ip_device_routing_redirect_parameter_length = -1;
static int hf_ua3g_ip_device_routing_listen_rtp_parameter = -1;
static int hf_ua3g_beep_cadence = -1;
static int hf_ua3g_voice_channel_voice_channel = -1;
static int hf_ua3g_unsolicited_msg_other_information = -1;
static int hf_ua3g_ip_device_routing_def_tones_frequency_2 = -1;
static int hf_ua3g_digit_dialed_digit_value = -1;
static int hf_ua3g_unsolicited_msg_subdevice_address = -1;
static int hf_ua3g_ua_dwl_protocol_packet_download_end_ack_ok_status = -1;
static int hf_ua3g_r_w_peripheral_address = -1;
static int hf_ua3g_icon_cmd_icon_number = -1;
static int hf_ua3g_dwl_dtmf_clck_format_clock_time_format = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_length = -1;
static int hf_ua3g_i_m_here_id_code = -1;
static int hf_ua3g_ua_dwl_protocol_item_version_nc = -1;
static int hf_ua3g_unsolicited_msg_firmware_version = -1;
static int hf_ua3g_segment_msg_segment = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_bootloader = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_data = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_customization = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_localization = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_code = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_noe_update_sip = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_value = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_bad_sec_mode = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_cust_name = -1;
static int hf_ua3g_ip_device_routing_reset_parameter_l10n_name = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_ip = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_compressor = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_value = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_enabler = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_send_qos = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_dtmf_sending = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_rfc2198 = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_srtp_encryption = -1;
static int hf_ua3g_ip_device_routing_start_rtp_parameter_uint = -1;
static int hf_ua3g_ip_device_routing_redirect_parameter_ip = -1;
static int hf_ua3g_ip_device_routing_redirect_parameter_uint = -1;
static int hf_ua3g_ip_device_routing_redirect_parameter_value = -1;
static int hf_ua3g_ip_device_routing_listen_rtp_parameter_ip = -1;
static int hf_ua3g_ip_device_routing_listen_rtp_parameter_port = -1;
static int hf_ua3g_ip_device_routing_listen_rtp_parameter_value = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_compressor = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_err_string = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_tftp_backup_ip = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_set_pc_port_status = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_record_rtp_auth = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_security_flag_filter = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_uint = -1;
static int hf_ua3g_ip_device_routing_set_param_req_parameter_value = -1;
static int hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_uint = -1;
static int hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_remote_ip = -1;
static int hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_uint = -1;
static int hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_value = -1;
static int hf_ua3g_main_voice_mode_handset_level = -1;
static int hf_ua3g_main_voice_mode_headset_level = -1;
static int hf_ua3g_main_voice_mode_handsfree_level = -1;
static int hf_ua3g_audio_config_dpi_chan_ua_tx1 = -1;
static int hf_ua3g_audio_config_dpi_chan_ua_tx2 = -1;
static int hf_ua3g_audio_config_dpi_chan_gci_tx1 = -1;
static int hf_ua3g_audio_config_dpi_chan_gci_tx2 = -1;
static int hf_ua3g_audio_config_dpi_chan_cod_tx = -1;
static int hf_ua3g_audio_config_audio_circuit_dth = -1;
static int hf_ua3g_audio_config_audio_circuit_dtr = -1;
static int hf_ua3g_audio_config_audio_circuit_dtf = -1;
static int hf_ua3g_audio_config_audio_circuit_str = -1;
static int hf_ua3g_audio_config_audio_circuit_ahp1 = -1;
static int hf_ua3g_audio_config_audio_circuit_ahp2 = -1;
static int hf_ua3g_audio_config_audio_circuit_ath = -1;
static int hf_ua3g_audio_config_audio_circuit_atr = -1;
static int hf_ua3g_audio_config_audio_circuit_atf = -1;
static int hf_ua3g_audio_config_audio_circuit_alm = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_group_listen = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_attenuation = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_stay_in_send = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mtx = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mrc = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_trans_threshold = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_trans_threshold = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_recv_threshold = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_recv_threshold = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_med_recv_threshold = -1;
static int hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_high_recv_threshold = -1;
static int hf_ua3g_ua_dwl_protocol_files_inc_boot_binary = -1;
static int hf_ua3g_ua_dwl_protocol_files_inc_loader_binary = -1;
static int hf_ua3g_ua_dwl_protocol_files_inc_appli_binary = -1;
static int hf_ua3g_ua_dwl_protocol_files_inc_data_binary = -1;
static int hf_ua3g_ua_dwl_protocol_model_selection_a = -1;
static int hf_ua3g_ua_dwl_protocol_model_selection_b = -1;
static int hf_ua3g_ua_dwl_protocol_model_selection_c = -1;
static int hf_ua3g_ua_dwl_protocol_model_selection_country_ver = -1;
static int hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe1 = -1;
static int hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe2 = -1;
static int hf_ua3g_ua_dwl_protocol_memory_sizes_flash = -1;
static int hf_ua3g_ua_dwl_protocol_memory_sizes_ext_ram = -1;
static int hf_ua3g_unsolicited_msg_char_num_vta_subtype = -1;
static int hf_ua3g_unsolicited_msg_char_num_generation = -1;
static int hf_ua3g_unsolicited_msg_char_num_design = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_vta_type = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_design = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_subtype = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_hard_config_chip = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_hard_config_flash = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_config_ram = -1;
static int hf_ua3g_unsolicited_msg_hardware_config_hard_config_ip = -1;
static int hf_ua3g_unsolicited_msg_hook_status = -1;
static int hf_ua3g_special_key_shift = -1;
static int hf_ua3g_special_key_ctrl = -1;
static int hf_ua3g_special_key_alt = -1;
static int hf_ua3g_special_key_cmd = -1;
static int hf_ua3g_special_key_shift_prime = -1;
static int hf_ua3g_special_key_ctrl_prime = -1;
static int hf_ua3g_special_key_alt_prime = -1;
static int hf_ua3g_special_key_cmd_prime = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_call_timer = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_blink = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_call_timer_control = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_call_timer_display = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_time_of_day_display = -1;
static int hf_ua3g_lcd_line_cmd_lcd_options_suspend_display_refresh = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_firmware_version = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_ip = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_uint = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_bytes = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_mac_address = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_uint = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_value = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_speed = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_duplex = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_speed = -1;
static int hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_duplex = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip1 = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip2 = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_ip = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_string = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_default_codec = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_vad = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_ece = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_voice_mode = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_delay_distribution = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_bfi = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021Q_used = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021P_priority = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_vlan_id = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_diffserv = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution_200ms = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_rtp_lost = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_uint = -1;
static int hf_ua3g_cs_ip_device_routing_cmd03_parameter_jitter_depth_distribution = -1;

/* Definition of opcodes */
/* System To Terminal */
#define SC_NOP                     0x00
#define SC_PRODUCTION_TEST         0x01    /* IP Phone */
#define SC_SUBDEVICE_ESCAPE        0x02    /* IP Phone */
#define SC_SOFT_RESET              0x03
#define SC_IP_PHONE_WARMSTART      0x04    /* IP Phone */
#define SC_HE_ROUTING              0x05    /* IP Phone - NOT EXPECTED */
#define SC_SUBDEVICE_RESET         0x06
#define SC_LOOPBACK_ON             0x07    /* IP Phone & UA NOE */
#define SC_LOOPBACK_OFF            0x08    /* IP Phone & UA NOE */
#define SC_VIDEO_ROUTING           0x09    /* IP Phone - NOT EXPECTED */
#define SC_SUPER_MSG               0x0B
#define SC_SEGMENT_MSG             0x0C
#define SC_REMOTE_UA_ROUTING       0x0D    /* IP Phone - NOT EXPECTED */
#define SC_VERY_REMOTE_UA_ROUTING  0x0E    /* IP Phone - NOT EXPECTED */
#define SC_OSI_ROUTING             0x0F    /* IP Phone - NOT EXPECTED */
#define SC_ABC_A_ROUTING           0x11    /* IP Phone - NOT EXPECTED */
#define SC_IBS_ROUTING             0x12    /* IP Phone - NOT EXPECTED */
#define SC_IP_DEVICE_ROUTING       0x13
#define SC_M_REFLEX_HUB_ROUTING    0x14    /* IP Phone - NOT EXPECTED */
#if 0
#define SC_NOE_CS_ROUTING          0x15    /* Decoded by packet-noe.c */
#define SC_NOE_PS_ROUTING          0x16    /* Decoded by packet-noe.c */
#endif
#define SC_SUPER_MSG_2             0x17
#define SC_DEBUG_IN_LINE           0x18
#define SC_LED_COMMAND             0x21    /* IP Phone */
#define SC_START_BUZZER            0x22    /* VTA */
#define SC_STOP_BUZZER             0x23    /* VTA */
#define SC_ENABLE_DTMF             0x24    /* Only IP NOE */
#define SC_DISABLE_DTMF            0x25    /* Only IP NOE */
#define SC_CLEAR_LCD_DISP          0x26    /* IP Phone */
#define SC_LCD_LINE_1_CMD          0x27    /* IP Phone */
#define SC_LCD_LINE_2_CMD          0x28    /* IP Phone */
#define SC_MAIN_VOICE_MODE         0x29
#define SC_VERSION_INQUIRY         0x2A
#define SC_ARE_YOU_THERE           0x2B    /* IP Phone & UA NOE */
#define SC_SUBDEVICE_METASTATE     0x2C
#define SC_VTA_STATUS_INQUIRY      0x2D    /* IP Phone */
#define SC_SUBDEVICE_STATE         0x2E
#define SC_DWL_DTMF_CLCK_FORMAT    0x30    /* IP Phone */
#define SC_SET_CLCK                0x31    /* IP Phone */
#define SC_VOICE_CHANNEL           0x32    /* IP Phone & UA NOE */
#define SC_EXTERNAL_RINGING        0x33
#define SC_LCD_CURSOR              0x35    /* IP Phone */
#define SC_DWL_SPECIAL_CHAR        0x36    /* IP Phone */
#define SC_SET_CLCK_TIMER_POS      0x38    /* IP Phone */
#define SC_SET_LCD_CONTRAST        0x39    /* IP Phone */
#define SC_AUDIO_IDLE              0x3A
#define SC_SET_SPEAKER_VOL         0x3B    /* IP Phone */
#define SC_BEEP                    0x3C
#define SC_SIDETONE                0x3D
#define SC_RINGING_CADENCE         0x3E
#define SC_MUTE                    0x3F
#define SC_FEEDBACK                0x40
#define SC_KEY_RELEASE             0x41    /* IP Phone */
#define SC_TRACE_ON                0x42    /* IP Phone - NOT EXPECTED */
#define SC_TRACE_OFF               0x43    /* IP Phone - NOT EXPECTED */
#define SC_READ_PERIPHERAL         0x44    /* IP Phone - NOT EXPECTED */
#define SC_WRITE_PERIPHERAL        0x45    /* IP Phone - NOT EXPECTED */
#define SC_ALL_ICONS_OFF           0x46    /* IP Phone */
#define SC_ICON_CMD                0x47    /* IP Phone */
#define SC_AMPLIFIED_HANDSET       0x48    /* IP Phone */
#define SC_AUDIO_CONFIG            0x49
#define SC_AUDIO_PADDED_PATH       0x4A    /* IP Phone */
#define SC_RELEASE_RADIO_LINK      0x4B    /* IP Phone - NOT EXPECTED */
#define SC_DECT_HANDOVER           0x4C    /* IP Phone - NOT EXPECTED */
#define SC_LOUDSPEAKER             0x4D
#define SC_ANNOUNCE                0x4E
#define SC_RING                    0x4F
#define SC_UA_DWL_PROTOCOL         0x50    /* Only UA NOE */

/* Terminal To System */
#define CS_NOP_ACK              0x00
#define CS_HANDSET_OFFHOOK      0x01    /* IP Phone */
#define CS_HANDSET_ONHOOK       0x02    /* IP Phone */
#define CS_DIGIT_DIALED         0x03    /* IP Phone */
#define CS_SUBDEVICE_MSG        0x04
#define CS_HE_ROUTING           0x05    /* IP Phone - NOT EXPECTED */
#define CS_LOOPBACK_ON          0x06    /* IP Phone & UA NOE */
#define CS_LOOPBACK_OFF         0x07    /* IP Phone & UA NOE */
#define CS_VIDEO_ROUTING        0x09    /* IP Phone - NOT EXPECTED */
#define CS_WARMSTART_ACK        0x0A    /* IP Phone */
#define CS_SUPER_MSG            0x0B    /* IP Phone - NOT EXPECTED */
#define CS_SEGMENT_MSG          0x0C
#define CS_REMOTE_UA_ROUTING    0x0D    /* IP Phone - NOT EXPECTED */
#define CS_VERY_REMOTE_UA_R     0x0E    /* IP Phone - NOT EXPECTED */
#define CS_OSI_ROUTING          0x0F    /* IP Phone - NOT EXPECTED */
#define CS_ABC_A_ROUTING        0x11    /* IP Phone - NOT EXPECTED */
#define CS_IBS_ROUTING          0x12    /* IP Phone - NOT EXPECTED */
#define CS_IP_DEVICE_ROUTING    0x13
#if 0
#define CS_NOE_CS_ROUTING       0x15    /* Decoded by packet-noe.c */
#define CS_NOE_PS_ROUTING       0x16    /* Decoded by packet-noe.c */
#endif
#define CS_SUPER_MSG_2          0x17
#define CS_DEBUG_IN_LINE        0x18
#define CS_NON_DIGIT_KEY_PUSHED 0x20    /* IP Phone */
#define CS_VERSION_RESPONSE     0x21
#define CS_I_M_HERE             0x22
#define CS_RSP_STATUS_INQUIRY   0x23    /* IP Phone */
#define CS_SUBDEVICE_STATE      0x24
#define CS_DIGIT_KEY_RELEASED   0x26    /* IP Phone */
#define CS_TRACE_ON_ACK         0x27    /* IP Phone */
#define CS_TRACE_OFF_ACK        0x28    /* IP Phone */
#define CS_SPECIAL_KEY_STATUS   0x29    /* IP Phone */
#define CS_KEY_RELEASED         0x2A    /* IP Phone */
#define CS_PERIPHERAL_CONTENT   0x2B    /* IP Phone */
#define CS_TM_KEY_PUSHED        0x2D    /* IP Phone */
#define CS_UA_DWL_PROTOCOL      0x50    /* Only UA NOE */
#define CS_UNSOLICITED_MSG      0x9F

/* System To Terminal Opcodes */
static const value_string opcodes_vals_sys[] =
{
    {SC_NOP                    , "NOP"},
    {SC_PRODUCTION_TEST        , "Production Test"},                     /* IP Phone */
    {SC_SUBDEVICE_ESCAPE       , "Subdevice Escape To Subdevice"},       /* IP Phone */
    {SC_SOFT_RESET             , "Software Reset"},
    {SC_IP_PHONE_WARMSTART     , "IP-Phone Warmstart"},                  /* IP Phone */
    {SC_HE_ROUTING             , "HE Routing Code"},                     /* IP Phone - NOT EXPECTED */
    {SC_SUBDEVICE_RESET        , "Subdevice Reset"},
    {SC_LOOPBACK_ON            , "Loopback On"},
    {SC_LOOPBACK_OFF           , "Loopback Off"},
    {SC_VIDEO_ROUTING          , "Video Routing Code"},                  /* IP Phone - NOT EXPECTED */
    {SC_SUPER_MSG              , "Super Message"},
    {SC_SEGMENT_MSG            , "Segment Message"},
    {SC_REMOTE_UA_ROUTING      , "Remote UA Routing Code"},              /* IP Phone - NOT EXPECTED */
    {SC_VERY_REMOTE_UA_ROUTING , "Very Remote UA Routing Code"},         /* IP Phone - NOT EXPECTED */
    {SC_OSI_ROUTING            , "OSI Routing Code"},                    /* IP Phone - NOT EXPECTED */
    {SC_ABC_A_ROUTING          , "ABC-A Routing Code"},                  /* IP Phone - NOT EXPECTED */
    {SC_IBS_ROUTING            , "IBS Routing Code"},                    /* IP Phone - NOT EXPECTED */
    {SC_IP_DEVICE_ROUTING      , "IP Device Routing"},
    {SC_M_REFLEX_HUB_ROUTING   , "Mutli-Reflex Hub Routing Code"},       /* IP Phone - NOT EXPECTED */
    {SC_SUPER_MSG_2            , "Super Message 2"},
    {SC_DEBUG_IN_LINE          , "Debug In Line"},
    {SC_LED_COMMAND            , "Led Command"},                         /* IP Phone */
    {SC_START_BUZZER           , "Start Buzzer"},                        /* VTA */
    {SC_STOP_BUZZER            , "Stop Buzzer"},                         /* VTA */
    {SC_ENABLE_DTMF            , "Enable DTMF"},
    {SC_DISABLE_DTMF           , "Disable DTMF"},
    {SC_CLEAR_LCD_DISP         , "Clear LCD Display"},                   /* IP Phone */
    {SC_LCD_LINE_1_CMD         , "LCD Line 1 Commands"},                 /* IP Phone */
    {SC_LCD_LINE_2_CMD         , "LCD Line 2 Commands"},                 /* IP Phone */
    {SC_MAIN_VOICE_MODE        , "Main Voice Mode"},
    {SC_VERSION_INQUIRY        , "Version Inquiry"},
    {SC_ARE_YOU_THERE          , "Are You There?"},
    {SC_SUBDEVICE_METASTATE    , "Subdevice Metastate"},
    {SC_VTA_STATUS_INQUIRY     , "VTA Status Inquiry"},                  /* IP Phone */
    {SC_SUBDEVICE_STATE        , "Subdevice State?"},
    {SC_DWL_DTMF_CLCK_FORMAT   , "Download DTMF & Clock Format"},        /* IP Phone */
    {SC_SET_CLCK               , "Set Clock"},                           /* IP Phone */
    {SC_VOICE_CHANNEL          , "Voice Channel"},                       /* IP Phone & UA NOE */
    {SC_EXTERNAL_RINGING       , "External Ringing"},
    {SC_LCD_CURSOR             , "LCD Cursor"},                          /* IP Phone */
    {SC_DWL_SPECIAL_CHAR       , "Download Special Character"},          /* IP Phone */
    {SC_SET_CLCK_TIMER_POS     , "Set Clock/Timer Position"},            /* IP Phone */
    {SC_SET_LCD_CONTRAST       , "Set LCD Contrast"},                    /* IP Phone */
    {SC_AUDIO_IDLE             , "Audio Idle"},
    {SC_SET_SPEAKER_VOL        , "Set Speaker Volume"},                  /* IP Phone */
    {SC_BEEP                   , "Beep"},
    {SC_SIDETONE               , "Sidetone"},
    {SC_RINGING_CADENCE        , "Set Programmable Ringing Cadence"},
    {SC_MUTE                   , "Mute"},
    {SC_FEEDBACK               , "Feedback"},
    {SC_KEY_RELEASE            , "Key Release"},                         /* IP Phone */
    {SC_TRACE_ON               , "Trace On"},                            /* IP Phone - NOT EXPECTED */
    {SC_TRACE_OFF              , "Trace Off"},                           /* IP Phone - NOT EXPECTED */
    {SC_READ_PERIPHERAL        , "Read Peripheral"},                     /* IP Phone - NOT EXPECTED */
    {SC_WRITE_PERIPHERAL       , "Write Peripheral"},                    /* IP Phone - NOT EXPECTED */
    {SC_ALL_ICONS_OFF          , "All Icons Off"},                       /* IP Phone */
    {SC_ICON_CMD               , "Icon Command"},                        /* IP Phone */
    {SC_AMPLIFIED_HANDSET      , "Amplified Handset (Boost)"},           /* IP Phone */
    {SC_AUDIO_CONFIG           , "Audio Config"},
    {SC_AUDIO_PADDED_PATH      , "Audio Padded Path"},                   /* IP Phone */
    {SC_RELEASE_RADIO_LINK     , "Release Radio Link"},                  /* IP Phone - NOT EXPECTED */
    {SC_DECT_HANDOVER          , "DECT External Handover Routing Code"}, /* IP Phone - NOT EXPECTED */
    {SC_LOUDSPEAKER            , "Loudspeaker"},
    {SC_ANNOUNCE               , "Announce"},
    {SC_RING                   , "Ring"},
    {SC_UA_DWL_PROTOCOL        , "UA Download Protocol"},
    {0, NULL}
};
static value_string_ext opcodes_vals_sys_ext = VALUE_STRING_EXT_INIT(opcodes_vals_sys);

/* Terminal To System Opcodes */
static const value_string opcodes_vals_term[] =
{
    {CS_NOP_ACK              , "NOP Acknowledge"},
    {CS_HANDSET_OFFHOOK      , "Handset Offhook"},                      /* IP Phone */
    {CS_HANDSET_ONHOOK       , "Hansdet Onhook"},                       /* IP Phone */
    {CS_DIGIT_DIALED         , "Digital Dialed"},                       /* IP Phone */
    {CS_SUBDEVICE_MSG        , "Subdevice Message"},
    {CS_HE_ROUTING           , "HE Routing Response Code"},             /* IP Phone - NOT EXPECTED */
    {CS_LOOPBACK_ON          , "Loopback On Acknowledge"},              /* Same as CS To Terminal */
    {CS_LOOPBACK_OFF         , "Loopback Off Acknowledge"},             /* Same as CS To Terminal */
    {CS_VIDEO_ROUTING        , "Video Routing Response Code"},          /* IP Phone - NOT EXPECTED */
    {CS_WARMSTART_ACK        , "Warmstart Acknowledge"},                /* IP Phone */
    {CS_SUPER_MSG            , "Super Message"},                        /* IP Phone - NOT EXPECTED */
    {CS_SEGMENT_MSG          , "Segment Message"},                      /* Same as CS To Terminal */
    {CS_REMOTE_UA_ROUTING    , "Remote UA Routing Response Code"},      /* IP Phone - NOT EXPECTED */
    {CS_VERY_REMOTE_UA_R     , "Very Remote UA Routing Response Code"}, /* IP Phone - NOT EXPECTED */
    {CS_OSI_ROUTING          , "OSI Response Code"},                    /* IP Phone - NOT EXPECTED */
    {CS_ABC_A_ROUTING        , "ABC-A Routing Response Code"},          /* IP Phone - NOT EXPECTED */
    {CS_IBS_ROUTING          , "IBS Routing Response Code"},            /* IP Phone - NOT EXPECTED */
    {CS_IP_DEVICE_ROUTING    , "IP Device Routing"},
    {CS_SUPER_MSG_2          , "Super Message 2"},                      /* Same as CS To Terminal */
    {CS_DEBUG_IN_LINE        , "Debug Message"},
    {CS_NON_DIGIT_KEY_PUSHED , "Non-Digit Key Pushed"},                 /* IP Phone */
    {CS_VERSION_RESPONSE     , "Version Information"},
    {CS_I_M_HERE             , "I'm Here Response"},
    {CS_RSP_STATUS_INQUIRY   , "Response To Status Inquiry"},           /* IP Phone */
    {CS_SUBDEVICE_STATE      , "Subdevice State Response"},
    {CS_DIGIT_KEY_RELEASED   , "Digit Key Released"},                   /* IP Phone */
    {CS_TRACE_ON_ACK         , "Trace On Acknowledge"},                 /* IP Phone - NOT EXPECTED */
    {CS_TRACE_OFF_ACK        , "Trace Off Acknowledge"},                /* IP Phone - NOT EXPECTED */
    {CS_SPECIAL_KEY_STATUS   , "Special Key Status"},                   /* IP Phone */
    {CS_KEY_RELEASED         , "Key Released"},                         /* IP Phone */
    {CS_PERIPHERAL_CONTENT   , "Peripheral Content"},                   /* IP Phone - NOT EXPECTED */
    {CS_TM_KEY_PUSHED        , "TM Key Pushed"},                        /* IP Phone - NOT EXPECTED */
    {CS_UA_DWL_PROTOCOL      , "Download Protocol"},
    {CS_UNSOLICITED_MSG      , "Unsolicited Message"},
    {0, NULL}
};
static value_string_ext opcodes_vals_term_ext = VALUE_STRING_EXT_INIT(opcodes_vals_term);

static const value_string str_digit[] = {
    { 0, "0"},
    { 1, "1"},
    { 2, "2"},
    { 3, "3"},
    { 4, "4"},
    { 5, "5"},
    { 6, "6"},
    { 7, "7"},
    { 8, "8"},
    { 9, "9"},
    {10, "*"},
    {11, "#"},
    {12, "A"},
    {13, "B"},
    {14, "C"},
    {15, "D"},
    {16, "Flash"},
    {0, NULL}
};
static value_string_ext str_digit_ext = VALUE_STRING_EXT_INIT(str_digit);

#define STR_ON_OFF(arg) ((arg) ? "On" : "Off")
#define STR_YES_NO(arg) ((arg) ? "Yes" : "No")


static const value_string str_device_type[] = {
    {0x00, "Voice Terminal Adaptor"},
    {0, NULL}
};


/*-----------------------------------------------------------------------------
    VERSION NUMBER COMPUTER - This function computes a version number (S.SZ.AB) from a 16 bits number
    ---------------------------------------------------------------------------*/
static void
version_number_computer( gchar *result, guint32 hexa_version )
{
    int   release, vers, fix;

    release = (int)(hexa_version / 10000);
    vers    = (int)((hexa_version % 10000) / 100);
    fix     = (hexa_version % 10000) % 100;
    g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%02d.%02d", release, vers, fix);
}


/*-----------------------------------------------------------------------------
    Function for UA3G message with opcode and one parameter

    PRODUCTION TEST    - 01h (MESSAGE FROM THE SYSTEM)
    SUBDEVICE RESET    - 06h (MESSAGE FROM THE SYSTEM)
    ARE YOU THERE      - 2Bh - IPhone & UA NOE (MESSAGE FROM THE SYSTEM)
    SET SPEAKER VOLUME - 3Bh (MESSAGE FROM THE SYSTEM)
    TRACE ON           - 42h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_with_one_parameter(proto_tree *tree, tvbuff_t *tvb,
              packet_info *pinfo _U_, guint offset, guint length,
              int hf_opcode)
{
    if (length == 0)
        return;

    proto_tree_add_item(tree, hf_opcode, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SUBDEVICE ESCAPE TO SUBDEVICE - 02h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_escape(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
            guint offset, guint length)
{
    proto_tree_add_item(tree, hf_ua3g_subdevice_address, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_subdevice_opcode, tvb, offset+1, 1, ENC_NA);
    if (length > 2) {
        proto_tree_add_item(tree, hf_ua3g_subdevice_parameter_bytes, tvb, offset+2, length-2, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    SOFTWARE RESET - 03h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string software_reset_verswitch_vals[] = {
    {0x00, "Reset Without Version Switch"},
    {0x01, "Reset With Version Switch"},
    {0, NULL}
};

static void
decode_software_reset(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                      guint offset, guint length)
{
    if (length == 0)
        return;

    proto_tree_add_item(tree, hf_ua3g_software_reset, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    IP-PHONE WARMSTART - 04h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_ip_phone_warmstart[] = {
    {0x00, "Run In UA2G Emulation Mode"},
    {0x01, "Run In Full UA3G Mode"},
    {0, NULL}
};

static void
decode_ip_phone_warmstart(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
              guint offset, guint length)
{
    if (length == 0)
        return;

    proto_tree_add_item(tree, hf_ua3g_ip_phone_warmstart, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SUPER MESSAGE - 0Bh (MESSAGE FROM THE SYSTEM)
    SUPER MESSAGE 2 - 17h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_super_msg(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
         guint offset, guint length, guint8 opcode)
{
    proto_tree *ua3g_body_tree = tree;
    int         j = 0, parameter_length;

    if (!ua3g_body_tree)
        return;

    while (length > 0) {
        if (opcode == 0x17) {
            parameter_length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_super_msg_length, tvb, offset, 2,
                parameter_length, "Length %d: %d", j++, parameter_length);
            offset += 2;
            length -= 2;
        } else {
            parameter_length = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_super_msg_length, tvb, offset, 1,
                parameter_length, "Length %d: %d", j++, parameter_length);
            offset++;
            length--;
        }

        if (parameter_length > 0) {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_super_msg_data, tvb, offset, parameter_length, ENC_NA);
            offset += parameter_length;
            length -= parameter_length;
        }
    }
}


/*-----------------------------------------------------------------------------
    SEGMENT MESSAGE - 0Ch (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
const true_false_string tfs_segment_msg_segment = { "First Segment", "Subsequent Segment" };

static void
decode_segment_msg(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
           guint offset, guint length)
{
    guint8      val;

    if (!tree)
        return;

    val = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ua3g_segment_msg_segment, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_segment_msg_num_remaining, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    if (val & 0x80) {
        proto_tree_add_item(tree, hf_ua3g_segment_msg_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        length -= 2;
    }

    if (length > 0) {
        proto_tree_add_item(tree, hf_ua3g_segment_message_data, tvb, offset, length, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    IP DEVICE ROUTING - 13h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_ip_device_routing[] = {
    {0x00, "Reset"},
    {0x01, "Start RTP"},
    {0x02, "Stop RTP"},
    {0x03, "Redirect"},
    {0x04, "Tone Definition"},
    {0x05, "Start Tone"},
    {0x06, "Stop Tone"},
    {0x07, "Start Listen RTP"},
    {0x08, "Stop Listen RTP"},
    {0x09, "Get Parameters Value"},
    {0x0A, "Set Parameters Value"},
    {0x0B, "Send Digit"},
    {0x0C, "Pause RTP"},
    {0x0D, "Restart RTP"},
    {0x0E, "Start Record RTP"},
    {0x0F, "Stop Record RTP"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_reset_vals[] = {
    {0x00, "Update Mode"},
    {0x01, "Bad Sec Mode"},
    {0x02, "Customization Name"},
    {0x03, "Localization Name"},
    {0, NULL}
};

static const value_string reset_param_bad_sec_mode[] = {
    {0x01, "Binary is full, CS is secured, but terminal running in clear mode"},
    {0, NULL}
};

static const value_string start_rtp_str_direction[] = {
    {0x00, "Terminal Input"},
    {0x01, "Terminal Output"},
    {0x02, "Terminal Input/Output (Both Directions)"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_start_rtp_vals[] = {
    {0x00, "Local UDP Port"},
    {0x01, "Remote IP Address"},
    {0x02, "Remote UDP Port"},
    {0x03, "Type Of Service"},
    {0x04, "Compressor"},
    {0x05, "Payload Concatenation (ms)"},
    {0x06, "Echo Cancellation Enabler"},
    {0x07, "Silence Suppression Enabler"},
    {0x08, "802.1 Q User Priority"},
    {0x09, "Reserved"},
    {0x0a, "Post Filtering Enabler"},
    {0x0b, "High Pass Filtering Enabler"},
    {0x0c, "Remote SSRC"},
    {0x0d, "Must Send QOS Tickets"},
    {0x0e, "Local Identifier"},
    {0x0f, "Distant Identifier"},
    {0x10, "Destination For RTCP Sender Reports - Port Number"},
    {0x11, "Destination For RTCP Sender Reports - IP Address"},
    {0x12, "Destination For RTCP Receiver Reports - Port Number"},
    {0x13, "Destination For RTCP Receiver Reports - IP Address"},
    {0x14, "Channel Number"},
    {0x15, "DTMF Sending"},
    {0x16, "Payload Type Of Redundancy"},
    {0x17, "Payload Type Of DTMF Events"},
    {0x18, "Enable / Disable RFC 2198"},
    {0x31, "SRTP Encryption Enable For This Communication"},
    {0x32, "Master Key For SRTP Session"},
    {0x33, "Master Salt Key For SRTP Session"},
    {0x34, "Master key for output stream of SRTP session"},
    {0x35, "Master salt key for output stream of SRTP session"},
    {0x36, "Integrity checking enabled for this communication"},
    {0x37, "MKI value for SRTP packets in input stream"},
    {0x38, "MKI value for SRTP packets in output stream"},
    {0x50, "MD5 Authentication"},
    {0, NULL}
};
static value_string_ext ip_device_routing_cmd_start_rtp_vals_ext = VALUE_STRING_EXT_INIT(ip_device_routing_cmd_start_rtp_vals);

static const val64_string str_start_rtp_compressor[] = {
    {0x00, "G.711 A-law"},
    {0x01, "G.711 mu-law"},
    {0x0F, "G.723.1 5.3kbps"},
    {0x10, "G.723.1 6.3kbps"},
    {0x11, "G.729A 8 kbps"},
    {0, NULL}
};

static const value_string str_set_param_req_compressor[] = {
    {0x00, "G.711 A-law"},
    {0x01, "G.711 mu-law"},
    {0x0F, "G.723.1 5.3kbps"},
    {0x10, "G.723.1 6.3kbps"},
    {0x11, "G.729A 8 kbps"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_stop_rtp_vals[] = {
    {0x0E, "Local Identifier"},
    {0x0F, "Distant Identifier"},
    {0x14, "Canal Identifier"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_redirect_vals[] = {
    {0x00, "Remote MainCPU Server IP Address"},
    {0x01, "Remote MainCPU Server Port"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_listen_rtp_vals[] = {
    {0x00, "Remote IP Address    "},
    {0x01, "Remote UDP Port In   "},
    {0x02, "Remote UDP Port Out  "},
    {0x03, "Remote IP Address Out"},
    {0x04, "Canal Number"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_set_param_req_vals[] = {
    {0x00   , "QOS IP TOS"},
    {0x01   , "QOS 8021 VLID"},
    {0x02   , "QOS 8021 PRI"},
    {0x03   , "SNMP MIB2 SysContact"},
    {0x04   , "SNMP MIB2 SysName"},
    {0x05   , "SNMP MIB2 SysLocation"},
    {0x06   , "Default Compressor"},
    {0x07   , "Error String Net Down"},
    {0x08   , "Error String Cable PB"},
    {0x09   , "Error String Try Connect"},
    {0x0A   , "Error String Connected"},
    {0x0B   , "Error String Reset"},
    {0x0C   , "Error String Duplicate IP Address"},
    {0x0D   , "SNMP MIB Community"},
    {0x0E   , "TFTP Backup Sec Mode"},
    {0x0F   , "TFTP Backup IP Address"},
    {0x10   , "Set MMI Password"},
    {0x11   , "Set PC Port Status"},
    {0x12   , "Record RTP Authorization"},
    {0x13   , "Security Flags"},
    {0x14   , "ARP Spoofing"},
    {0x15   , "Session Param"},
    {0x30   , "MD5 Authentication"},
    {0, NULL}
};
static value_string_ext ip_device_routing_cmd_set_param_req_vals_ext = VALUE_STRING_EXT_INIT(ip_device_routing_cmd_set_param_req_vals);

static const value_string ip_device_routing_cmd_pause_restart_vals[] = {
    {0x14, "Canal Identifier"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_record_rtp_vals[] = {
    {0x00   , "Recorder Index"},
    {0x01   , "Remote IP Address"},
    {0x02   , "Remote UDP Port In"},
    {0x03   , "Remote UDP Port Out"},
    {0x04   , "Remote IP Address Out"},
    {0x05   , "Local UDP Port In"},
    {0x06   , "Local UDP Port Out"},
    {0x07   , "Type Of Service"},
    {0x08   , "Master Key For SRTP Session"},
    {0x09   , "Master Salt Key For SRTP Session"},
    {0x30   , "MD5 Authentication"},
    {0, NULL}
};

static const value_string ip_device_routing_tone_direction_vals[] = {
    {0x00, "On The Phone"},
    {0x40, "To The Network"},
    {0x80, "On The Phone and To The Network"},
    {0, NULL}
};

static const value_string ip_device_routing_cmd_get_param_req_vals[] = {
    {0x00   , "Firmware Version"},
    {0x01   , "Firmware Version"},
    {0x02   , "DHCP IP Address"},
    {0x03   , "Local IP Address"},
    {0x04   , "Subnetwork Mask"},
    {0x05   , "Router IP Address"},
    {0x06   , "TFTP IP Address"},
    {0x07   , "MainCPU IP Address"},
    {0x08   , "Default Codec"},
    {0x09   , "Ethernet Drivers Config"},
    {0x0A   , "MAC Address"},
    {0, NULL}
};

static const value_string str_set_pc_port_status[] = {
    {0x00, "No PC Port Security"},
    {0x01, "Block PC Port"},
    {0x02, "Filter VLAN"},
    {0, NULL}
};

static const value_string str_enable_feature[] = {
    {0x00, "Disable Feature"},
    {0x01, "Enable Feature"},
    {0, NULL}
};

static void
decode_ip_device_routing(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
             guint offset, guint length)
{
    guint8         command;
    proto_tree    *ua3g_body_tree = tree, *ua3g_param_tree, *ua3g_param_subtree;
    proto_item    *ua3g_param_item;
    int parameter_length, parameter_id;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_ip_device_routing, "Unknown"));

    if (!ua3g_body_tree)
        return;

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    switch (command) {
    case 0x00: /* RESET */
        {
            if (length > 0) {
                parameter_id     = tvb_get_guint8(tvb, offset);
                parameter_length = tvb_get_guint8(tvb, offset + 1);

                ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter, tvb, offset,
                    parameter_length + 2, parameter_id, "%s",
                    val_to_str_const(parameter_id, ip_device_routing_cmd_reset_vals, "Unknown"));
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_length, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                if (parameter_length > 0) {
                    guint8 param;
                    switch (parameter_id) {
                    case 0x00: /* Update Mode */

                        param = tvb_get_guint8(tvb, offset);
                        if ((param & 0x80) == 0x00) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_noe_update, tvb, offset, 1, ENC_NA);
                            ua3g_param_subtree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param_sub);

                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_bootloader, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_data, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_customization, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_localization, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_code, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_subtree, hf_ua3g_ip_device_routing_reset_parameter_noe_update_sip, tvb, offset, 1, ENC_NA);

                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }

                        break;
                    case 0x01: /* Bad_Sec_Mode */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_bad_sec_mode, tvb, offset, 1, ENC_NA);
                        break;
                    case 0x02: /* Cust_Name */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_cust_name, tvb, offset, parameter_length, ENC_NA|ENC_ASCII);
                        break;
                    case 0x03: /* L10N_Name */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_l10n_name, tvb, offset, parameter_length, ENC_NA|ENC_ASCII);
                        break;
                    default:
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_reset_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        break;
                    }

                    /*offset += parameter_length;
                    length -= parameter_length;*/
                }
            }
            break;
        }
    case 0x01: /* START RTP */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_start_rtp_direction, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            while (length > 0) {
                parameter_id     = tvb_get_guint8(tvb, offset);
                parameter_length = tvb_get_guint8(tvb, offset + 1);

                ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_start_rtp_parameter, tvb, offset,
                        parameter_length + 2, parameter_id, "%s",
                        val_to_str_ext_const(parameter_id, &ip_device_routing_cmd_start_rtp_vals_ext, "Unknown"));

                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_length, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                if (parameter_length > 0) {
                    switch (parameter_id) {
                    case 0x01: /* Remote IP Address */
                    case 0x11: /* Destination For RTCP Sender Reports - IP Address */
                    case 0x13: /* Destination For RTCP Receiver Reports - IP Address */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                            break;
                    case 0x04: /* Compressor */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_compressor, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x06: /* Echo Cancelation Enabler */
                    case 0x07: /* Silence Suppression Enabler */
                    case 0x0A: /* Post Filtering Enabler */
                    case 0x0B: /* High Pass Filtering Enabler */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_enabler, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x0D: /* Must Send QOS Tickets */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_send_qos, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x0E: /* Local Identifier */
                    case 0x0F: /* Distant Identifier */
                        break;
                    case 0x15: /* DTMF Sending */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_dtmf_sending, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x18: /* Enable / Disable RFC 2198 */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_rfc2198, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x31: /* SRTP Encryption Enable For This Communication */
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_srtp_encryption, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    case 0x00: /* Local UDP Port */
                    case 0x02: /* Remote UDP Port */
                    case 0x03: /* Type Of Service */
                    case 0x05: /* Payload Concatenation */
                    case 0x08: /* 802.1 Q User Priority */
                    case 0x09: /* Reserved */
                    case 0x0C: /* Remote SSRC */
                    case 0x10: /* Destination For RTCP Sender Reports - Port Number */
                    case 0x12: /* Destination For RTCP Receiver Reports - Port Number */
                    case 0x14: /* Channel Number */
                    case 0x16: /* Payload Type For Redundancy */
                    case 0x17: /* Payload Type For DTMF Events */
                    case 0x32: /* Master Key For SRTP Session */
                    case 0x33: /* Master Salt Key For SRTP Session */
                    case 0x34: /* Master key for output stream of SRTP session */
                    case 0x35: /* Master salt key for output stream of SRTP session */
                    case 0x36: /* Integrity checking enabled for this communication */
                    case 0x37: /* MKI value for SRTP packets in input stream */
                    case 0x38: /* MKI value for SRTP packets in output stream */
                    case 0x50: /* MD5 Authentication */
                    default:
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    }

                    offset += parameter_length;
                    length -= parameter_length;
                }
            }
            break;
        }
    case 0x02: /* STOP_RTP */
        while (length > 0) {
            parameter_id     = tvb_get_guint8(tvb, offset);
            parameter_length = tvb_get_guint8(tvb, offset + 1);

            ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter, tvb, offset,
                parameter_length + 2, parameter_id, "%s",
                val_to_str_const(parameter_id, ip_device_routing_cmd_stop_rtp_vals, "Unknown"));
            ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter_length, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            if (parameter_length > 0) {
                if (parameter_length <= 8) {
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter_value_num, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_stop_rtp_parameter_value_bytes, tvb, offset, parameter_length, ENC_NA);
                }

                offset += parameter_length;
                length -= parameter_length;
            }
        }
        break;
    case 0x03: /* REDIRECT */
        while (length > 0) {
            parameter_id = tvb_get_guint8(tvb, offset);
            parameter_length = tvb_get_guint8(tvb, offset + 1);

            ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_redirect_parameter,
                    tvb, offset, parameter_length + 2, parameter_id,
                    "%s", val_to_str_const(parameter_id, ip_device_routing_cmd_redirect_vals, "Unknown"));
            ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_redirect_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_redirect_parameter_length, tvb, offset, 1, ENC_NA);
            offset++;
            length--;


            if (parameter_length > 0) {
                switch (parameter_id) {
                case 0x00: /* Remote MainCPU Server IP Address */
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_redirect_parameter_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                    break;
                case 0x01: /* Remote MainCPU Server Port */
                default:
                    if (parameter_length <= 8) {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_redirect_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                    } else {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_redirect_parameter_value, tvb, offset, parameter_length, ENC_NA);
                    }
                    break;
                }

                offset += parameter_length;
                length -= parameter_length;
            }
        }
        break;
    case 0x04: /* DEF_TONES */
        {
            int         i, tone_nb_entries;
            guint16     frequency_1, frequency_2;
            signed char level_1, level_2;

            tone_nb_entries = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_def_tones_num_entries, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            while (length > 0 && tone_nb_entries) {
                for (i = 1; i <= tone_nb_entries; i++) {
                    frequency_1 = tvb_get_ntohs(tvb, offset);
                    level_1 = (signed char)(tvb_get_guint8(tvb, offset + 2)) / 2;
                    frequency_2 = tvb_get_ntohs(tvb, offset + 3);
                    level_2 = (signed char)(tvb_get_guint8(tvb, offset + 5)) / 2;

                    ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 6,
                        "Tone Pair %d: %d Hz at %d dB / %d Hz at %d dB",
                        i, frequency_1, level_1, frequency_2, level_2);
                    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_def_tones_frequency_1, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    length -= 2;

                    proto_tree_add_int(ua3g_param_tree, hf_ua3g_ip_device_routing_def_tones_level_1, tvb, offset, 1, level_1);
                    offset++;
                    length--;

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_def_tones_frequency_2, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    length -= 2;

                    proto_tree_add_int(ua3g_param_tree, hf_ua3g_ip_device_routing_def_tones_level_2, tvb, offset, 1, level_2);
                    offset++;
                    length--;
                }
            }
            break;
        }
    case 0x05: /* START TONE */
        {
            guint8 ii, tone_nb_entries, tone_id;
#if 0
            guint8 tone_direction, tone_id, tone_duration tone_silence;
#endif
            int tone_duration;

            tone_nb_entries = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_start_tone_direction, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_start_tone_num_entries, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            while (length > 0 && tone_nb_entries) {
                for (ii = 0; ii < tone_nb_entries; ii++) {
                    tone_id = tvb_get_guint8(tvb, offset);
                    tone_duration = tvb_get_ntohs(tvb, offset + 1);
#if 0
                    tone_duration = tvb_get_guint8(tvb, offset + 1);
                    tone_silence = tvb_get_guint8(tvb, offset + 2);
#endif

                    ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 6,
#if 0
                        "Tone Pair %d: Id: %d, Duration: %d ms, Silence: %d ms",
                        ii+1, tone_id, tone_duration, tone_silence);
#endif
                        "Tone Pair %d: Id: %d, Duration: %d ms",
                        ii+1, tone_id, tone_duration);
                    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_tone_identification, tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_tone_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    length -= 2;

#if 0
                    proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
                        "Duration: %d ms", tone_duration);
                    offset++;
                    length--;

                    proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
                        "Silence: %d ms", tone_silence);
                    offset++;
                    length--;
#endif
                }
            }
            break;
        }
    case 0x07: /* START LISTEN RTP */
    case 0x08: /* STOP LISTEN RTP */
        while (length > 0) {
            parameter_id     = tvb_get_guint8(tvb, offset);
            parameter_length = tvb_get_guint8(tvb, offset + 1);

            ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter, tvb, offset,
                parameter_length + 2, parameter_id, "%s",
                val_to_str_const(parameter_id, ip_device_routing_cmd_listen_rtp_vals, "Unknown"));
            ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter_length, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            if (parameter_length > 0) {
                switch (parameter_id) {
                case 0x00: /* Remote IP Address - Not for start listening rtp */
                case 0x03: /* Remote IP Address Out - Not for start listening rtp */
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter_ip, tvb, offset, 1, ENC_NA);
                    break;
                case 0x01: /* Remote UDP Port In - Not for start listening rtp */
                case 0x02: /* Remote UDP Port Out - Not for start listening rtp */
                case 0x04: /* Canal Number */
                default:
                    if (parameter_length <= 8) {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter_port, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                    } else {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_listen_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                    }
                    break;
                }

                offset += parameter_length;
                length -= parameter_length;
            }
        }
        break;
    case 0x09: /* GET_PARAM_REQ */
        while (length > 0) {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_get_param_req_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;
        }
        break;

    case 0x0A: /* SET_PARAM_REQ */
        {
            while (length > 0) {
                parameter_id     = tvb_get_guint8(tvb, offset);
                parameter_length = tvb_get_guint8(tvb, offset + 1);

                ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_set_param_req_parameter, tvb, offset,
                    parameter_length + 2, parameter_id, "%s",
                    val_to_str_ext_const(parameter_id, &ip_device_routing_cmd_set_param_req_vals_ext, "Unknown"));
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_length, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                if (parameter_length > 0) {
                    switch (parameter_id) {
                    case 0x06: /* Compressor */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_compressor, tvb, offset, 1, ENC_NA);
                        break;
                    case 0x07: /* ERR STRING NET DOWN */
                    case 0x08: /* ERR STRING CABLE PB */
                    case 0x09: /* ERR STRING TRY CONNECT */
                    case 0x0A: /* ERR STRING CONNECTED */
                    case 0x0B: /* ERR STRING RESET */
                    case 0x0C: /* ERR STRING DUPLICATE IP ADDRESS */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_err_string, tvb, offset, parameter_length, ENC_NA|ENC_ASCII);
                        break;
                    case 0x0F: /* TFTP BACKUP IP ADDR */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_tftp_backup_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                        break;
                    case 0x11: /* Set PC Port status */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_set_pc_port_status, tvb, offset, 1, ENC_NA);
                        break;
                    case 0x12: /* Record RTP Authorization */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_record_rtp_auth, tvb, offset, 1, ENC_NA);
                        break;
                    case 0x13: /* Security Flags */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_security_flag_filter, tvb, offset, 1, ENC_NA);
                        break;
                    case 0x00: /* QOS IP TOS */
                    case 0x01: /* QOS 8021 VLID */
                    case 0x02: /* QOS 8021 PRI */
                    case 0x03: /* SNMP MIB2 SYSCONTACT */
                    case 0x04: /* SNMP MIB2 SYSNAME */
                    case 0x05: /* SNMP MIB2 SYSLOCATION */
                    case 0x0D: /* SNMP MIB COMMUNITY */
                    case 0x0E: /* TFTP BACKUP SEC MODE */
                    case 0x10: /* SET MMI PASSWORD */
                    case 0x14: /* ARP Spoofing */
                    case 0x15: /* Session Param */
                    case 0x30: /* MD5 Authentication */
                    default:
                        if ((parameter_length > 0) && (parameter_length <= 8)) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else if (parameter_length > 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_set_param_req_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    }

                    offset += parameter_length;
                    length -= parameter_length;
                }
            }
            break;
        }
    case 0x0B: /* SEND_DIGIT */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_device_routing_digit_value, tvb, offset, 1, ENC_NA);
        break;

    case 0x0C: /* PAUSE_RTP */
    case 0x0D: /* RESTART_RTP */
        while (length > 0) {
            parameter_id     = tvb_get_guint8(tvb, offset);
            parameter_length = tvb_get_guint8(tvb, offset + 1);

            ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_pause_restart_rtp_parameter, tvb, offset,
                parameter_length + 2, parameter_id, "%s",
                val_to_str_const(parameter_id, ip_device_routing_cmd_pause_restart_vals, "Unknown"));
            ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_pause_restart_rtp_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_length, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            if (parameter_length > 0) {
                if (parameter_length <= 8) {
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                }

                offset += parameter_length;
                length -= parameter_length;
            }
        }
        break;
    case 0x0E: /* START_RECORD_RTP */
    case 0x0F: /* STOP RECORD RTP */
        while (length > 0) {

            parameter_id     = tvb_get_guint8(tvb, offset);
            parameter_length = tvb_get_guint8(tvb, offset + 1);

            ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter, tvb, offset,
                parameter_length + 2, parameter_id, "%s",
                val_to_str_const(parameter_id, ip_device_routing_cmd_record_rtp_vals, "Unknown"));
            ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_length, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            if (parameter_length > 0) {
                switch (parameter_id) {
                case 0x01: /* Remote IP Address */
                case 0x04: /* Remote IP Address Out */
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_remote_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                    break;
                case 0x00: /* Recorder Index */
                case 0x02: /* Remote UDP Port In */
                case 0x03: /* Remote UDP Port Out */
                case 0x05: /* Local UDP Port In */
                case 0x06: /* Local UDP Port Out */
                case 0x07: /* Type Of Service */
                case 0x08: /* Master Key For SRTP Session */
                case 0x09: /* Master Salt Key For SRTP Session */
                case 0x30: /* MD5 Authentication */
                default:
                    if (parameter_length <= 8) {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                    } else {
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_value, tvb, offset, parameter_length, ENC_NA);
                    }
                    break;
                }

                offset += parameter_length;
                length -= parameter_length;
            }
        }
        break;
    case 0x06: /* STOP TONE */
    default:
        {
            break;
        }
    }
}


/*-----------------------------------------------------------------------------
    DEBUG IN LINE - 18h (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_debug_in_line(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
             guint offset, guint length)
{
    proto_tree_add_item(tree, hf_ua3g_debug_in_line, tvb, offset, length, ENC_NA|ENC_ASCII);
}


/*-----------------------------------------------------------------------------
    LED COMMAND - 21h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_led[] = {
    {0x00, "Led Off"},
    {0x01, "Led On"},
    {0x02, "Red Led Fast Flash"},
    {0x03, "Red Led Slow Flash"},
    {0x04, "Green Led On"},
    {0x05, "Green Led Fast Flash"},
    {0x06, "Green Led Slow Flash"},
    {0x07, "All Led Off"},
    {0, NULL}
};

static void
decode_led_command(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
           guint offset)
{
    int         command;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_led, "Unknown"));

    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_command_led, tvb, offset, 1, ENC_NA);

    if ((command >= 0) && (command < 7)) {
        proto_tree_add_item(tree, hf_ua3g_command_led_number, tvb, offset+1, 1, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    LCD LINE 1 COMMANDS - 27h (MESSAGE FROM THE SYSTEM)
    LCD LINE 2 COMMANDS - 28h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_lcd_line[] = {
    {0, "Clear Line & Write From Column"},
    {1, "Write From Column"},
    {2, "Append To Current Line"},
    {0, NULL}
};

static const value_string str_call_timer_ctrl[] = {
    {0x00, "Call Timer Status Not Changed"},
    {0x01, "Stop Call Timer"},
    {0x02, "Start Call Timer From Current Value"},
    {0x03, "Initialize And Call Timer"},
    {0, NULL}
};

static void
decode_lcd_line_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
            guint offset, guint length)
{
    guint8         command, column_n;
    const gchar*  command_str;
    proto_tree    *ua3g_body_tree = tree, *ua3g_param_tree, *ua3g_option_tree;
    proto_item    *ua3g_param_item, *ua3g_option_item;
    wmem_strbuf_t *strbuf;

    command     = tvb_get_guint8(tvb, offset) & 0x03;
    column_n    = tvb_get_guint8(tvb, offset + 1);
    command_str = val_to_str_const(command, str_command_lcd_line, "Unknown");

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s %d", command_str, column_n);

    if (!ua3g_body_tree)
        return;

    strbuf  = wmem_strbuf_new_label(wmem_packet_scope());

    wmem_strbuf_append_printf(strbuf, "\"%s\"", tvb_format_text(tvb, offset + 2, length - 2));

    ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
        length, "%s %d: %s",
        command_str, column_n, wmem_strbuf_get_str(strbuf));
    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_command_lcd_line, tvb, offset, 1, ENC_NA);
    ua3g_option_item = proto_tree_add_item(ua3g_param_tree, hf_ua3g_lcd_line_cmd_lcd_options, tvb, offset, 1, ENC_NA);
    ua3g_option_tree = proto_item_add_subtree(ua3g_option_item, ett_ua3g_option);

    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_call_timer, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_blink, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_call_timer_control, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_call_timer_display, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_time_of_day_display, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ua3g_option_tree, hf_ua3g_lcd_line_cmd_lcd_options_suspend_display_refresh, tvb, offset, 1, ENC_NA);

    offset++;
    length--;

    if (command != 3)
        proto_tree_add_item(ua3g_param_tree, hf_ua3g_lcd_line_cmd_starting_column, tvb, offset, 1, ENC_NA);
    else
        proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Unused");

    offset++;
    length--;
    proto_tree_add_text(ua3g_param_tree, tvb, offset, length, "ASCII Char: %s", wmem_strbuf_get_str(strbuf));
}


/*-----------------------------------------------------------------------------
    MAIN VOICE MODE - 29h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_main_voice_mode[] = {
    {0x00, "Idle"},
    {0x01, "Handset"},
    {0x02, "Group Listening"},
    {0x03, "On Hook Dial"},
    {0x04, "Handsfree"},
    {0x05, "Announce Loudspeaker"},
    {0x06, "Ringing"},
    {0x10, "Idle"},
    {0x11, "Handset"},
    {0x12, "Headset"},
    {0x13, "Handsfree"},
    {0, NULL}
};

static const value_string str_cadence[] = {
    {0x00, "Standard Ringing"},
    {0x01, "Double Burst"},
    {0x02, "Triple Burst"},
    {0x03, "Continuous Ringing"},
    {0x04, "Priority Attendant Ringing"},
    {0x05, "Regular Attendant Ringing"},
    {0x06, "Programmable Cadence"},
    {0x07, "Programmable Cadence"},
    {0, NULL}
};

static void
decode_main_voice_mode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
               guint offset, guint length)
{
    guint8      mode;
    proto_tree *ua3g_body_tree = tree;

    mode  = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(mode, str_main_voice_mode, "Unknown"));

    if (!ua3g_body_tree)
        return;

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_main_voice_mode, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    switch (mode) {
    case 0x06: /* Ringing */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_main_voice_mode_tune, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_main_voice_mode_cadence, tvb, offset, 1, ENC_NA);
            offset++;
            length--;
        }
        /* FALLTHROUGH */
    case 0x02: /* Group Listening */
    case 0x03: /* On Hook Dial */
    case 0x04: /* Handsfree */
    case 0x05: /* Announce Loudspeaker */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_main_voice_mode_speaker_volume, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            if (length > 0) {
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_main_voice_mode_microphone_volume, tvb, offset, 1, ENC_NA);
            }
            break;
        }
    case 0x11: /* Handset */
        {
            signed char level;

            level = (signed char)(tvb_get_guint8(tvb, offset)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_handset_level, tvb, offset, 1, level);

            level = (signed char)(tvb_get_guint8(tvb, offset+1)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_sending_level, tvb, offset+1, 1, level);
            break;
        }
    case 0x12: /* Headset */
        {
            signed char level;

            level = (signed char)(tvb_get_guint8(tvb, offset)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_headset_level, tvb, offset, 1, level);

            level = (signed char)(tvb_get_guint8(tvb, offset+1)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_sending_level, tvb, offset+1, 1, level);
            break;
        }
    case 0x13: /* Handsfree */
        {
            signed char level;

            level = (signed char)(tvb_get_guint8(tvb, offset)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_handsfree_level, tvb, offset, 1, level);

            level = (signed char)(tvb_get_guint8(tvb, offset+1)) / 2;
            proto_tree_add_int(ua3g_body_tree, hf_ua3g_main_voice_mode_sending_level, tvb, offset+1, 1, level);
            break;
        }
    case 0x00: /* Idle */
    case 0x01: /* Handset */
    case 0x10: /* Idle */
    default:
        {
            break;
        }
    }
}


/*-----------------------------------------------------------------------------
    SUBDEVICE METASTATE - 2Ch (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_new_metastate[] = {
    {0x00, "Disable"},
    {0x01, "Active"},
    {0x02, "Wake Up"},
    {0, NULL}
};

static void
decode_subdevice_metastate(proto_tree *tree, tvbuff_t *tvb,
               packet_info *pinfo _U_, guint offset)
{
    proto_tree_add_item(tree, hf_ua3g_subdevice_metastate_subchannel_address, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_subdevice_metastate_new_metastate, tvb, offset+1, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    Download DTMF & CLOCK FORMAT - 30h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_clock_format[] = {
    {0, "Europe"},
    {1, "US"},
    {0, NULL}
};

static void
decode_dwl_dtmf_clck_format(proto_tree *tree, tvbuff_t *tvb,
                packet_info *pinfo _U_, guint offset, guint length)
{
    proto_tree_add_item(tree, hf_ua3g_dwl_dtmf_clck_format_minimum_on_time, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_dwl_dtmf_clck_format_inter_digit_pause_time, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_dwl_dtmf_clck_format_clock_time_format, tvb, offset+2, 1, ENC_NA);

    if (length > 2)
        proto_tree_add_item(tree, hf_ua3g_dwl_dtmf_clck_format_dtmf_country_adaptation, tvb, offset+3, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SET CLOCK - 31h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_set_clck[] = {
    {0x00, "Set Current Time/Call Timer"},
    {0x01, "Set Current Time"},
    {0x02, "Set Call Timer"},
    {0, NULL}
};

static const value_string str_call_timer[] = {
    {1, "Call Timer "},
    {0, NULL}
};

static void
decode_set_clck(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        guint offset, guint length)
{
    guint8      command;
    int         hour, minute, second, call_timer;

    command  = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_set_clck, "Unknown"));

    proto_tree_add_item(tree, hf_ua3g_command_set_clck, tvb, offset, 1, ENC_NA);
    offset++;
    length--;
    call_timer = 0;

    switch (command) {
    case 0x02: /* Timer Form */
        {
            call_timer = 1;
        }
        /* FALLTHROUGH */
    case 0x00: /* Set Current Time/Call Timer */
    case 0x01: /* Set Current Time */
        {
            while (length > 0) {
                hour   = tvb_get_guint8(tvb, offset);
                minute = tvb_get_guint8(tvb, offset + 1);
                second = tvb_get_guint8(tvb, offset + 2);

                proto_tree_add_text(tree, tvb, offset, 3,
                    "%s: %d:%d:%d",
                    val_to_str_const(call_timer, str_call_timer, "Current Time"), hour, minute, second);
                offset += 3;
                length -= 3;

                call_timer = 1;
            }
        }
    default:
        {
            break;
        }
    }

}


/*-----------------------------------------------------------------------------
    VOICE CHANNEL - 32h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_voice_channel[] = {
    {0x00, "No"},
    {0x01, "B1"},
    {0x02, "B2"},
    {0x03, "B3"},
    {0, NULL}
};

static const true_false_string tfs_voice_channel_channel_mode = { "Write 00 to Voice Channel", "Normal Voice Channel Mode" };
static const true_false_string tfs_voice_channel_codec = { "Write Quiet To Codec", "Normal Codec Operation" };
static const true_false_string tfs_voice_channel_voice_channel = { "Use B3 As Voice Channel", "Use B1 As Voice Channel" };

static void
decode_voice_channel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
             guint offset, guint length)
{
    if (length == 1) {
        proto_tree_add_item(tree, hf_ua3g_voice_channel_channel_mode, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_codec, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_voice_channel, tvb, offset, 1, ENC_NA);
    } else if (length == 2) {
        proto_tree_add_item(tree, hf_ua3g_voice_channel_main_voice, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_announce, tvb, offset+1, 1, ENC_NA);
    } else if (length == 4) {
        proto_tree_add_item(tree, hf_ua3g_voice_channel_b_general, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_b_loud_speaker, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_b_ear_piece, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_voice_channel_b_microphones, tvb, offset+3, 1, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    EXTERNAL RINGING - 33h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_ext_ring_cmd[] = {
    {0x00, "Turn Off"},
    {0x01, "Turn On"},
    {0x02, "Follow The Normal Ringing"},
    {0, NULL}
};

static void
decode_external_ringing(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
            guint offset)
{
    guint8      command;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_ext_ring_cmd, "Unknown"));

    proto_tree_add_item(tree, hf_ua3g_external_ringing_command, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    LCD CURSOR - 35h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_lcd_cursor(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo, guint offset)
{
    const gchar* str_on_off_val = STR_ON_OFF(tvb_get_guint8(tvb, offset + 1) & 0x02);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", str_on_off_val);

    proto_tree_add_item(tree, hf_ua3g_lcd_cursor_line_number, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_lcd_cursor, tvb, offset+1, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    DOWNLOAD SPECIAL CHARACTER - 36h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_dwl_special_char(proto_tree *tree, tvbuff_t *tvb,
            packet_info *pinfo _U_, guint offset, guint length)
{
    int            i;

    while (length > 0) {
        proto_tree_add_item(tree, hf_ua3g_dwl_special_char_character_number, tvb, offset, 1, ENC_NA);
        offset++;
        length--;
        for (i = 1; i <= 8; i++) {
            proto_tree_add_item(tree, hf_ua3g_dwl_special_char_byte, tvb, offset, 1, ENC_NA);
            offset++;
            length--;
        }
    }
}


/*-----------------------------------------------------------------------------
    SET CLOCK/TIMER POSITION - 38h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_set_clck_timer_pos(proto_tree *tree, tvbuff_t *tvb,
              packet_info *pinfo _U_, guint offset)
{
    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_set_clck_timer_pos_clock_line_number, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_set_clck_timer_pos_clock_column_number, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_set_clck_timer_pos_call_timer_line_number, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_set_clck_timer_pos_call_timer_column_number, tvb, offset+3, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SET LCD CONTRAST - 39h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_driver_number[] = {
    {0x00, "Display"},
    {0x01, "Icon"},
    {0, NULL}
};

static void
decode_set_lcd_contrast(proto_tree *tree, tvbuff_t *tvb,
            packet_info *pinfo _U_, guint offset)
{
    proto_tree_add_item(tree, hf_ua3g_set_lcd_contrast_driver_number, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_set_lcd_contrast_contrast_value, tvb, offset+1, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    BEEP - 3Ch (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_beep[] = {
    {0x01, "Beep Once"},
    {0x02, "Beep Start"},
    {0x03, "Stop Beep"},
    {0x04, "Start Beep"},
    {0x05, "Define Beep"},
    {0, NULL}
};

static const value_string str_beep_start_destination[] = {
    {0x01, "Ear-Piece"},
    {0x02, "Loudspeaker"},
    {0x03, "Ear-Piece and Loudspeaker"},
    {0, NULL}
};

static const value_string str_start_beep_destination[] = {
    {0x01, "Handset"},
    {0x02, "Headset"},
    {0x04, "Loudspeaker"},
    {0x08, "Announce Loudspeaker"},
    {0x10, "Handsfree"},
    {0, NULL}
};

static const value_string str_beep_freq_sample_nb[] = {
    {0x00, "Frequency"},
    {0xFF, "Audio Sample Number"},
    {0, NULL}
};
static const value_string str_beep_duration[] = {
    {0x00, "Duration "},
    {0xFF, "Duration (Ignored)"},
    {0, NULL}
};
static const value_string str_beep_terminator[] = {
    {0xFD, "Stop"},
    {0xFE, "Loop"},
    {0xFF, "Infinite"},
    {0, NULL}
};

static void
decode_beep(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        guint offset, guint length)
{
    if (length > 0) { /* All cases except classical beep */
        guint8      command;
        proto_tree *ua3g_body_tree = tree;

        command = tvb_get_guint8(tvb, offset);

        /* add text to the frame "INFO" column */
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_beep, "Unknown"));

        proto_tree_add_item(ua3g_body_tree, hf_ua3g_command_beep, tvb, offset, 1, ENC_NA);
        offset++;
        length--;

        switch (command) {
        case 0x01: /* Beep Once */
        case 0x02: /* Beep Start */
            {
                int i =  0;

                proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_destination, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                while (length > 0) {
                    guint8 val;

                    i++;
                    val = (tvb_get_guint8(tvb, offset) & 0x7F) * 10;
                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_on_off, tvb, offset, 1, ENC_NA);
                    proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_beep_cadence, tvb, offset, 1, val,
                        "Cadence T%d: %d ms", i, val);
                    offset++;
                    length--;
                }
                break;
            }
        case 0x04: /* Start Beep */
            {
                guint8         beep_dest;
                wmem_strbuf_t *strbuf;
                int            i;

                beep_dest = tvb_get_guint8(tvb, offset);

                strbuf = wmem_strbuf_new_label(wmem_packet_scope());

                for (i = 0; i < 5; i++) {
                    wmem_strbuf_append(strbuf,
                        val_to_str_const(beep_dest & (0x01 << i), str_start_beep_destination, ""));
                }

                proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                    "Destination: %s", wmem_strbuf_get_str(strbuf));
                offset++;

                proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_beep_number, tvb, offset, 1, ENC_NA);
                break;
            }
        case 0x05:
            {
                int i, nb_of_notes, beep_number;

                beep_number = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_beep_number, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                if (beep_number <= 0x44)
                    beep_number = 0x00;
                else
                    beep_number = 0xFF;

                nb_of_notes = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_number_of_notes, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                while (length > 0) {
                    for (i = 1; i <= nb_of_notes; i++) {
                        proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s %d: %d",
                            val_to_str_const(beep_number, str_beep_freq_sample_nb, "Unknown"),
                            i, tvb_get_guint8(tvb, offset));
                        offset++;
                        length--;
                        proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Level %d: %d",
                            i, tvb_get_guint8(tvb, offset));
                        offset++;
                        length--;
                        proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s %d: %x",
                            val_to_str_const(beep_number, str_beep_duration, "Unknown"),
                            i, tvb_get_guint8(tvb, offset));
                        offset++;
                        length--;
                    }
                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_beep_terminator, tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;
                }
                break;
            }
        case 0x03: /* Stop Beep */
        default:
            {
                break;
            }
        }
    } else { /* Classical Beep */
        /* add text to the frame "INFO" column */
        col_append_str(pinfo->cinfo, COL_INFO, ": Classical Beep");
    }
}


/*-----------------------------------------------------------------------------
    SIDETONE ON / OFF - 3Dh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_sidetone(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint offset)
{
    guint8      command;
    const gchar* command_str;

    command = tvb_get_guint8(tvb, offset);
    command_str = STR_ON_OFF(command);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", command_str);

    proto_tree_add_item(tree, hf_ua3g_command_sidetone, tvb, offset, 1, ENC_NA);

    if (command == 0x01) {
        proto_tree_add_int(tree, hf_ua3g_sidetone_level, tvb, offset+1, 1,
            (signed char)(tvb_get_guint8(tvb, offset+1) / 2));
    }
}


/*-----------------------------------------------------------------------------
    SET PROGRAMMABLE RINGING CADENCE - 3Eh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ringing_cadence(proto_tree *tree, tvbuff_t *tvb,
               packet_info *pinfo _U_, guint offset, guint length)
{
    int         i = 0;
    guint16     cadence_length;

    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_ringing_cadence_cadence, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    while (length > 0) {
        i++;
        proto_tree_add_item(tree, hf_ua3g_ringing_cadence_on_off, tvb, offset, 1, ENC_NA);
        cadence_length = ((tvb_get_guint8(tvb, offset) & 0x7F) * 10);
        proto_tree_add_uint_format(tree, hf_ua3g_ringing_cadence_length, tvb, offset, 1, cadence_length,
            "Length %d : %d ms", i, cadence_length);
        offset++;
        length--;
    }
}


/*-----------------------------------------------------------------------------
    MUTE ON / OFF - 3Fh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_mute[] = {
    {0x00, "Microphone Disable"},
    {0x01, "Microphone Enable"},
    {0, NULL}
};

static void
decode_mute(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint offset)
{
    guint8      command;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_mute, "Unknown"));

    proto_tree_add_item(tree, hf_ua3g_command_mute, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    FEEDBACK ON / OFF - 40h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_feedback(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        guint offset, guint length)
{
    guint8      command;
    const gchar* command_str;

    command = tvb_get_guint8(tvb, offset);
    command_str = STR_ON_OFF(command);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", command_str);

    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_command_feedback, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    if (command == 0x01) {
        proto_tree_add_int(tree, hf_ua3g_feedback_level, tvb, offset, 1,
            (signed char)(tvb_get_guint8(tvb, offset) / 2));
        offset++;
        length--;

        if (length > 0) {
            proto_tree_add_uint_format_value(tree, hf_ua3g_feedback_duration, tvb, offset, 1,
                tvb_get_guint8(tvb, offset) * 10, "%d ms", tvb_get_guint8(tvb, offset) * 10);
        }
    }
}


/*-----------------------------------------------------------------------------
    READ PERIPHERAL - 44h (MESSAGE FROM THE SYSTEM)
    WRITE PERIPHERAL - 45h (MESSAGE FROM THE SYSTEM)
    PERIPHERAL CONTENT - 2Bh (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_r_w_peripheral(proto_tree *tree, tvbuff_t *tvb,
              packet_info *pinfo _U_, guint offset, guint length)
{
    proto_tree_add_item(tree, hf_ua3g_r_w_peripheral_address, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (length > 2) {
        proto_tree_add_item(tree, hf_ua3g_r_w_peripheral_content, tvb, offset+2, 1, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    ICON COMMAND - 47h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_icon_cmd_state[] = {
    {0x00, "Off"},
    {0x01, "Slow Flash"},
    {0x02, "Not Used"},
    {0x03, "Steady On"},
    {0, NULL}
};

static void
decode_icon_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    guint8 byte0, byte1, bytex;
    int i;

    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_icon_cmd_icon_number, tvb, offset, 1, ENC_NA);

    byte0 = tvb_get_guint8(tvb, offset+1);
    byte1 = tvb_get_guint8(tvb, offset+2);

    for (i = 0; i < 8; i++) {
        bytex =
            ((byte0 >> i) & 0x01) * 2 +
            ((byte1 >> i) & 0x01);
        proto_tree_add_uint_format(tree, hf_ua3g_icon_cmd_segment, tvb, offset+1, 2, bytex,
                            "Segment %d: %s (%d)", i, val_to_str_const(bytex, str_icon_cmd_state, "Unknown"), bytex);
    }
}


/*-----------------------------------------------------------------------------
    AUDIO CONFIGURATION - 49h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_audio_config[] = {
    {0x00, "Audio Coding"},
    {0x01, "DPI Channel Allocations"},
    {0x02, "Loudspeaker Volume Adjust"},
    {0x03, "Audio Circuit Configuration"},
    {0x04, "Handsfree Parameters"},
    {0x05, "Loudspeaker Acoustic Parameters"},
    {0x06, "Device Configuration"},
    {0, NULL}
};

static const value_string str_audio_coding_law[] = {
    {0x00, "A Law"},
    {0x01, "m Law"},
    {0, NULL}
};

static const value_string str_device_configuration[] = {
    { 0, "Handset Device             "},
    { 1, "Headset Device             "},
    { 2, "Loudspeaker Device         "},
    { 3, "Announce Loudspeaker Device"},
    { 4, "Handsfree Device           "},
    { 0, NULL }
};

const true_false_string tfs_audio_config_handsfree_return = { "Return Loss Active", "Return Loss Normal" };
const true_false_string tfs_audio_config_handsfree_handsfree = { "More Full Duplex", "Handsfree Normal" };

static void
decode_audio_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
            guint offset, guint length)
{
    guint8      command;
    proto_tree *ua3g_body_tree = tree;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_audio_config, "Unknown"));

    if (!ua3g_body_tree)
        return;

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_command_audio_config, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    switch (command) {
    case 0x00: /* Audio Coding */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_ignored, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_law, tvb, offset+1, 1, ENC_NA);
        break;
    case 0x01: /* DPI Channel Allocations */

        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_dpi_chan_ua_tx1, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_dpi_chan_ua_tx2, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_dpi_chan_gci_tx1, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_dpi_chan_gci_tx2, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_dpi_chan_cod_tx, tvb, offset+4, 1, ENC_NA);
        break;
    case 0x02: /* Loudspeaker Volume Adjust */
        {
            int i;
            for (i = 1; i < 8; i++) {
                proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_audio_config_volume_level, tvb, offset,
                    1, tvb_get_guint8(tvb, offset), "Volume Level %d: %d",
                    i, tvb_get_guint8(tvb, offset));
                offset++;
                length--;
            }
            break;
        }
    case 0x03: /* Audio Circuit Configuration */

        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_dth, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_dtr, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_dtf, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_str, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_ahp1, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_ahp2, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_ath, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_atr, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_atf, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_audio_circuit_alm, tvb, offset+9, 1, ENC_NA);
        break;
    case 0x04: /* Handsfree Parameters */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_handsfree_return, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_handsfree_handsfree, tvb, offset, 1, ENC_NA);
        break;
    case 0x05: /* Loudspeaker Acoustic Parameters */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_group_listen, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_attenuation, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_stay_in_send, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mtx, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mrc, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_trans_threshold, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_trans_threshold, tvb, offset+6, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_recv_threshold, tvb, offset+7, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_recv_threshold, tvb, offset+8, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_med_recv_threshold, tvb, offset+9, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_high_recv_threshold, tvb, offset+10, 1, ENC_NA);
        break;
    case 0x06: /* Device Configuration */
        {
            static const gchar *str_device_values[] = {
                " Internal",
                " Rj9 Plug",
                " Jack Plug",
                " Bluetooth Link",
                " USB Link"
            };
            wmem_strbuf_t *strbuf;
            guint8 device_values;
            int j;
            int device_index = 0;

            strbuf = wmem_strbuf_new_label(wmem_packet_scope());

            while (length > 0) {

                device_values = tvb_get_guint8(tvb, offset);

                wmem_strbuf_truncate(strbuf, 0);

                if (device_values != 0) {
                    for (j = 0; j < 5; j++) {
                        if (device_values & (0x01 << j)) {
                            wmem_strbuf_append(strbuf, str_device_values[j]);
                        }
                    }
                } else {
                    wmem_strbuf_append(strbuf, " None");
                }

                proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                                    "%s:%s",
                                    val_to_str_const(device_index, str_device_configuration, "Unknown"),
                                    wmem_strbuf_get_str(strbuf));
                offset++;
                length--;
                device_index++;
            }
            break;
        }
    default:
        {
            break;
        }
    }
}


/*-----------------------------------------------------------------------------
    AUDIO PADDED PATH - 4Ah (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_audio_padded_path(proto_tree *tree, tvbuff_t *tvb,
             packet_info *pinfo _U_, guint offset)
{
    proto_tree_add_item(tree, hf_ua3g_audio_padded_path_emission_padded_level, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_audio_padded_path_reception_padded_level, tvb, offset+1, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    KEY RELEASE ON / OFF - 41h (MESSAGE FROM THE SYSTEM)
    AMPLIFIED HANDSET (BOOST) - 48h (MESSAGE FROM THE SYSTEM)
    LOUDSPEAKER ON / OFF - 4Dh (MESSAGE FROM THE SYSTEM)
    ANNOUNCE ON / OFF - 4Eh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_on_off_level(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
            guint offset, guint length, int hf_opcode)
{
    guint8      command;
    const gchar* command_str;

    command = tvb_get_guint8(tvb, offset);
    command_str = STR_ON_OFF(command);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", command_str);

    proto_tree_add_item(tree, hf_opcode, tvb, offset, 1, ENC_NA);

    if (length > 1) {
        if (command == 0x01) {
            proto_tree_add_item(tree, hf_ua3g_on_off_level_level_on_loudspeaker, tvb, offset+1, 1, ENC_NA);
        }
    }
}


/*-----------------------------------------------------------------------------
    RING ON / OFF - 4Fh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ring(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint offset)
{
    guint8      command;
    const gchar* command_str;

    command = tvb_get_guint8(tvb, offset);
    command_str = STR_ON_OFF(command);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", command_str);

    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_command_ring, tvb, offset, 1, ENC_NA);

    if (command == 0x01) {
        proto_tree_add_item(tree, hf_ua3g_ring_melody, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_ring_cadence, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_ring_speaker_level, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_ring_beep_number, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_ring_silent, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ua3g_ring_progressive, tvb, offset+5, 1, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    UA DOWNLOAD PROTOCOL - 50h - Only for UA NOE (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static const value_string str_command_ua_dwl_protocol[] = {
    {0x00, "Downloading Suggest"},
    {0x01, "Downloading Request"},
    {0x02, "Downloading Acknowledge"},
    {0x03, "Downloading Data"},
    {0x04, "Downloading End"},
    {0x05, "Downloading End Acknowledge"},
    {0x06, "Downloading ISO Checksum"},
    {0x07, "Downloading ISO Checksum Acknowledge"},
    {0, NULL}
};

static const value_string str_download_req_force_mode[] = {
    {0x00, "System Accept All Refusals"},
    {0x01, "Force Software Lock"},
    {0, NULL}
};
#if 0
static const value_string str_download_req_item_id[] = {
    {0x00, "Patches File"},
    {0x01, "Application Binary"},
    {0x02, "Datas Binary"},
    {0, NULL}
};
#endif
static const value_string str_download_req_mode_selection_country[] = {
    {0x00, "No Check"},
    {0x01, "For All Countries Except Chinese"},
    {0x02, "For Chinese"},
    {0, NULL}
};

static const value_string str_download_ack_status[] = {
    {0x00, "Ok (Binary Item Downloading In \"Normal\" Progress)"},
    {0x01, "Hardware Failure: Flash Failure"},
    {0x02, "Not Enough Place To Store The Downloaded Binary"},
    {0x03, "Wrong Seq Number On Latest Received Download_Data Message"},
    {0x04, "Wrong Packet Number On Latest Received Download_Data Message"},
    {0x05, "Download Refusal Terminal (Validation Purpose)"},
    {0x06, "Download Refusal Terminal (Development Purpose)"},
    {0x10, "Download Refusal: Hardware Cause (Unknown Flash Device, Incompatible Hardware)"},
    {0x11, "Download Refusal: No Loader Available Into The Terminal"},
    {0x12, "Download Refusal: Software Lock"},
    {0x13, "Download Refusal: Wrong Parameter Into Download Request"},
    {0x20, "Wrong Packet Number On Latest Received Downloading_Data Message"},
    {0x21, "Compress Header Invalid"},
    {0x22, "Decompress Error"},
    {0x23, "Binary Header Invalid"},
    {0x24, "Binary Check Error: Flash Write Error Or Binary Is Invalid"},
    {0x25, "Error Already Signaled - No More Data Accepted"},
    {0x26, "No Downloading In Progress"},
    {0x27, "Too Many Bytes Received (More Than Size Given Into The Download_Req Message)"},
    {0xFF, "Undefined Error"},
    {0, NULL}
};
static value_string_ext str_download_ack_status_ext = VALUE_STRING_EXT_INIT(str_download_ack_status);

static const value_string str_download_end_ack_ok[] = {
    {0x00, "Ok"},
    {0x01, "Hardware Failure: Flash Problems"},
    {0x02, "Not Enough Place To Store The Downloaded Binary"},
    {0, NULL}
};

static const value_string str_iso_checksum_ack_status[] = {
    {0x00, "The Checksum Matches"},
    {0x25, "Error Detected And Already Signaled"},
    {0x30, "Checksum Error (All Bytes Received)"},
    {0x31, "Checksum Error (Bytes Missing)"},
    {0, NULL}
};

static const value_string str_mem_size[] = {
    {0x00, "No Check"},
    {0x01, "128 Kbytes"},
    {0x02, "256 Kbytes"},
    {0x03, "512 Kbytes"},
    {0x04, "1 Mbytes"},
    {0x05, "2 Mbytes"},
    {0x06, "4 Mbytes"},
    {0x07, "8 Mbytes"},
    {0, NULL}
};


static void
decode_ua_dwl_protocol(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
               guint offset, guint length)
{
    guint8      command;
    proto_tree    *ua3g_body_tree = tree, *ua3g_param_tree;
    proto_item    *ua3g_param_item;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_ua_dwl_protocol, "Unknown"));

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_command_ua_dwl_protocol, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    switch (command) {
    case 0x00:  /* Downloading Suggest (MESSAGE FROM THE TERMINAL) */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_item_identifier, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_item_version_nc, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_cause, tvb, offset+3, 1, ENC_NA);
        break;
    case 0x01:  /* Downloading Request (MESSAGE FROM THE SYSTEM) */
        {
            static const gchar *str_bin_info[] = {
                "Uncompressed Binary",
                "LZO Compressed Binary"
            };

            if (length > 7) { /* Not R1 */
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_force_mode, tvb, offset, 1, ENC_NA);
                offset++;
                length--;
            }

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_item_identifier, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_item_version, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            length -= 2;

            if (length > 2) { /* Not R1 */
                ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Files Included");
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_files_inc_boot_binary,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_files_inc_loader_binary,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_files_inc_appli_binary,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_files_inc_data_binary,
                        tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Model Selection");
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_model_selection_a,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_model_selection_b,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_model_selection_c,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_model_selection_country_ver,
                        tvb, offset, 1, ENC_NA);
                offset++;
                length--;
                ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Hardware Selection");
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe1,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe2,
                        tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Memory Sizes Required");
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_memory_sizes_flash,
                        tvb, offset, 1, ENC_NA);
                proto_tree_add_item(ua3g_param_tree, hf_ua3g_ua_dwl_protocol_memory_sizes_ext_ram,
                        tvb, offset, 1, ENC_NA);
                offset++;
                length--;
            } else { /* R1 */
                proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                    "Binary Information: %s, Country/Operator/CLient Identifier ?",
                    str_bin_info[tvb_get_guint8(tvb, offset) & 0x01]);
                offset++;
                length--;
            }

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_binary_length, tvb, offset, 3, ENC_BIG_ENDIAN);
            break;
        }
    case 0x02:  /* Downloading Acknowledge (MESSAGE FROM THE TERMINAL) */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_packet_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_download_ack_status, tvb, offset+2, 1, ENC_NA);
        break;
    case 0x03:  /* Downloading Data (MESSAGE FROM THE SYSTEM) */
        {
            int i = 1;

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_packet_number, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            length -= 2;

            while (length > 0) {
                proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                    "Packet Number %3d: %d", i, tvb_get_guint8(tvb, offset));
                offset++;
                length--;
                i++;
            }
            break;
        }
    case 0x05:  /* Downloading End Acknowledge (MESSAGE FROM THE TERMINAL) */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_packet_download_end_ack_ok_status, tvb, offset, 1, ENC_NA);
        break;
    case 0x06:  /* Downloading Iso Checksum (MESSAGE FROM THE SYSTEM) */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case 0x07:  /* Downloading ISO Checksum Acknowledge (MESSAGE FROM THE TERMINAL) */
        proto_tree_add_item(ua3g_body_tree, hf_ua3g_ua_dwl_protocol_acknowledge, tvb, offset, 1, ENC_NA);
        break;
    case 0x04:  /* Downloading End (MESSAGE FROM THE SYSTEM) */
    default:
        break;
    }
}


/*-----------------------------------------------------------------------------
    DIGIT DIALED - 03h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_digit_dialed(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    proto_tree_add_item(tree, hf_ua3g_digit_dialed_digit_value, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SUBDEVICE_MSG - 04h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_msg(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
             guint offset, guint length)
{
    if (!tree)
        return;

    proto_tree_add_item(tree, hf_ua3g_subdevice_msg_subdev_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_subdevice_msg_subdev_address, tvb, offset, 1, ENC_NA);

    proto_tree_add_item(tree, hf_ua3g_subdevice_msg_subdevice_opcode, tvb, offset+1, 1, ENC_NA);

    if (length > 2) {
        proto_tree_add_item(tree, hf_ua3g_subdevice_msg_parameter_bytes, tvb, offset+2, length-2, ENC_NA);
    }
}


/*-----------------------------------------------------------------------------
    IP DEVICE ROUTING - 13h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static const value_string str_command_cs_ip_device_routing[] = {
    {0x00, "Init"},
    {0x01, "Incident"},
    {0x02, "Get Parameters Value Response"},
    {0x03, "QOS Ticket RSP"},
    {0, NULL}
};

static const value_string str_cs_ip_device_routing_vta_type[] = {
    {0x20, "NOE A"},
    {0x21, "NOE B"},
    {0x22, "NOE C"},
    {0x23, "NOE D"},
    {0, NULL}
};

#if 0
static const value_string str_cs_ip_device_routing_08_compressor[] = {
    {0x00, "G.711 A-law"},
    {0x01, "G.711 mu-law"},
    {0x0F, "G.723.1 5.3kbps"},
    {0x10, "G.723.1 6.3kbps"},
    {0x11, "G.729A 8 kbps"},
    {0, NULL}
};
#endif

static const val64_string str_cs_ip_device_routing_0F_compressor[] = {
    {0x00, "G.711 A-law"},
    {0x01, "G.711 mu-law"},
    {0x02, "G.723.1 6.3kbps"},
    {0x03, "G.729"},
    {0x04, "G.723.1 5.3kbps"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_03_parameter_id_vals[] = {
    {0x01, "Date Of End Of Communication"},
    {0x02, "Node Number"},
    {0x03, "Ticket Protocol Version"},
    {0x06, "Equipment Type"},
    {0x08, "Local IP Address"},
    {0x09, "Distant IP Address"},
    {0x0A, "Local ID"},
    {0x0B, "Distant ID"},
    {0x0C, "Call Duration (second)"},
    {0x0D, "Local SSRC"},
    {0x0E, "Distant SSRC"},
    {0x0F, "Codec"},
    {0x10, "VAD"},
    {0x11, "ECE"},
    {0x12, "Voice Mode"},
    {0x13, "Transmitted Framing (ms)"},
    {0x14, "Received Framing (ms)"},
    {0x15, "Framing Changes"},
    {0x16, "Number Of RTP Packets Received"},
    {0x17, "Number Of RTP Packets Sent"},
    {0x18, "Number Of RTP Packets Lost"},
    {0x19, "Total Silence Detected (second)"},
    {0x1A, "Number Of SID Received"},
    {0x1B, "Delay Distribution"},
    {0x1C, "Maximum Delay (ms)"},
    {0x1D, "Number Of DTMF Received"},
    {0x1E, "Consecutive BFI"},
    {0x1F, "BFI Distribution"},
    {0x20, "Jitter Depth Distribution"},
    {0x21, "Number Of ICMP Host Unreachable"},
    {0x26, "Firmware Version"},
    {0x29, "DSP Framing (ms)"},
    {0x2A, "Transmitter SID"},
    {0x2D, "Minimum Delay (ms)"},
    {0x2E, "802.1 Q Used"},
    {0x2F, "802.1p Priority"},
    {0x30, "VLAN Id"},
    {0x31, "DiffServ"},
    {0x3D, "200 ms BFI Distribution"},
    {0x3E, "Consecutive RTP Lost"},
    {0, NULL}
};
static value_string_ext cs_ip_device_routing_03_parameter_id_vals_ext = VALUE_STRING_EXT_INIT(cs_ip_device_routing_03_parameter_id_vals);

static const value_string cs_ip_device_routing_03_parameter_id_tab_vals[] = {
    {0x1B, "Range: Value"},
    {0x1F, "Range: Value"},
    {0x20, "Jitter: Value"},
    {0x3D, "Contents: Value"},
    {0x3E, "Contents: Value"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_cmd03_first_byte_vals[] = {
    {0x01, "IP-Phone"},
    {0x02, "Appli-PC"},
    {0x03, "Coupler OmniPCX Enterprise"},
    {0x04, "Coupler OmniPCX Office"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_cmd03_second_byte_vals[] = {
    {0x0101, "IP-Phone V2"},
    {0x0102, "NOE-IP"},
    {0x0200, "4980 Softphone (PCMM2)"},
    {0x0201, "WebSoftphoneIP"},
    {0x0300, "INTIP"},
    {0x0301, "GD"},
    {0x0302, "eVA"},
    {0, NULL}
};

static const val64_string cs_ip_device_routing_cmd03_voice_mode_vals[] = {
    {0x50, "Idle"},
    {0x51, "Handset"},
    {0x52, "Group Listening"},
    {0x53, "On Hook Dial"},
    {0x54, "Handsfree"},
    {0x55, "Headset"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_delay_distribution_range_vals[] = {
    {0, "0-40     "},
    {1, "40-80    "},
    {2, "80-150   "},
    {3, "150-250  "},
    {4, "250 and +"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_consecutive_bfi_range_vals[] = {
    {0, "0"},
    {1, "1"},
    {2, "2"},
    {3, "3"},
    {4, "4"},
    {5, "5"},
    {6, "5"},
    {7, "7"},
    {8, "8"},
    {9, "9"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_bfi_distribution_range_vals[] = {
    {0, "0      "},
    {1, "0-1    "},
    {2, "1-2    "},
    {3, "2-3    "},
    {4, "3 and +"},
    {0, NULL}
};

static const value_string cs_ip_device_routing_200ms_bfi_distribution_range_vals[] = {
    {0, "< 10 %  "},
    {1, "< 20 %  "},
    {2, "< 40 %  "},
    {3, "< 60 %  "},
    {4, ">= 60 % "},
    {0, NULL}
};

static const value_string cs_ip_device_routing_consecutive_rtp_lost_range_vals[] = {
    {0, "1         "},
    {1, "2         "},
    {2, "3         "},
    {3, "4         "},
    {4, "5 and more"},
    {0, NULL}
};

static void
decode_cs_ip_device_routing(proto_tree *tree _U_, tvbuff_t *tvb,
                packet_info *pinfo, guint offset, guint length)
{
    guint8 command;
    proto_tree *ua3g_body_tree = tree, *ua3g_param_tree;
    proto_item *ua3g_param_item;
    int i, parameter_id, parameter_length;

    command = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_cs_ip_device_routing, "Unknown"));

    if (!ua3g_body_tree)
        return;

    proto_tree_add_item(ua3g_body_tree, hf_ua3g_ip_cs, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    switch (command) {
        case 0x00:
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_cs_ip_device_routing_cmd00_vta_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_cs_ip_device_routing_cmd00_characteristic_number, tvb, offset+1, 1, ENC_NA);
            break;
        case 0x01:
            {
                int j = 0;
                if (length == 1) {
                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_cs_ip_device_routing_cmd01_incident_0, tvb, offset, 1, ENC_NA);
                } else {
                    while (length >0) {
                        j++;
                        proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                            "Parameter %d Identifier: %d",
                            j, tvb_get_guint8(tvb, offset));
                        offset++;
                        length--;
                    }
                }
                break;
            }
        case 0x02:
            while (length > 0) {
                parameter_id = tvb_get_guint8(tvb, offset);
                parameter_length = tvb_get_guint8(tvb, offset + 1);

                ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter, tvb, offset,
                    parameter_id, parameter_length + 2,
                    "%s", val_to_str_const(parameter_id, ip_device_routing_cmd_get_param_req_vals, "Unknown"));
                ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_length, tvb, offset, 1, ENC_NA);
                offset++;
                length--;

                if (parameter_length > 0) {
                    switch (parameter_id) {
                    case 0x00: /* Firmware Version */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_firmware_version, tvb, offset, 2, ENC_BIG_ENDIAN);
                        break;
                    case 0x01: /* Firmware Version */
                    case 0x02: /* DHCP IP Address */
                    case 0x03: /* Local IP Address */
                    case 0x04: /* Subnetwork Mask */
                    case 0x05: /* Router IP Address */
                    case 0x06: /* TFTP IP Address */
                    case 0x07: /* Main CPU Address */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                        break;
                    case 0x08: /* Default Codec */
                        {
                            if (parameter_length <= 8) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                            } else {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_bytes, tvb, offset, parameter_length, ENC_NA);
                            }
                            break;
                        }
                    case 0x09: /* Ethernet Drivers Config */
                        {
                            if (parameter_length == 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_speed, tvb, offset, 1, ENC_NA);
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_duplex, tvb, offset+1, 1, ENC_NA);
                            } else if (parameter_length == 4) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_speed, tvb, offset, 1, ENC_NA);
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_duplex, tvb, offset+1, 1, ENC_NA);
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_speed, tvb, offset+2, 1, ENC_NA);
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_duplex, tvb, offset+3, 1, ENC_NA);
                            } else {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_value, tvb, offset, parameter_length, ENC_NA);
                            }
                            break;
                        }
                    case 0x0A: /* MAC Address */
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_mac_address, tvb, offset, 6, ENC_NA);
                        break;
                    default:
                        if (parameter_length <= 8) {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                        } else {
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd02_parameter_value, tvb, offset, parameter_length, ENC_NA);
                        }
                        break;
                    }

                    offset += parameter_length;
                    length -= parameter_length;
                }
            }
            break;
        case 0x03:
            {
                int  framing_rtp    = 0;

                while (length > 0) {
                    parameter_id     = tvb_get_guint8(tvb, offset);
                    parameter_length = tvb_get_ntohs(tvb, offset + 1);

                    ua3g_param_item = proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter, tvb, offset,
                        parameter_length+3, parameter_id, "%s",
                        val_to_str_const(parameter_id, cs_ip_device_routing_03_parameter_id_tab_vals, "Unknown"));
                    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter, tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;

                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    length -= 2;

                    if (parameter_length > 0) {
                        switch (parameter_id) {
                        case 0x06: /* Type Of Equipment */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip1, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip2, tvb, offset, 2, ENC_BIG_ENDIAN);
                            break;
                        case 0x08: /* Local IP Address */
                        case 0x09: /* Distant IP Address */
                        case 0x26: /* Firmware Version */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                            break;
                        case 0x0A:
                        case 0x0B:
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_string, tvb, offset, parameter_length, ENC_NA|ENC_ASCII);
                            break;
                        case 0x0F: /* Default Codec */
                            if (parameter_length <= 8) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_default_codec, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                            } else {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_default_codec, tvb, offset, 8, ENC_BIG_ENDIAN);
                                /* XXX - add as expert info wmem_strbuf_append(strbuf, "Parameter Value Too Long (more than 64 bits)"); */
                            }
                            break;
                        case 0x10: /* VAD */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_vad, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x11: /* ECE */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_ece, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x12: /* Voice Mode */
                            if (parameter_length <= 8) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_voice_mode, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                            } else {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_voice_mode, tvb, offset, 8, ENC_BIG_ENDIAN);
                                /* XXX - add as expert info wmem_strbuf_append(strbuf, "Parameter Value Too Long (more than 64 bits)"); */
                            }
                            break;
                        case 0x1B: /* Delay Distribution */
                            for (i = 0; i < parameter_length; i += 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_delay_distribution, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                            }
                            break;
                        case 0x1E: /* Consecutive BFI */
                            for (i = 0; i < parameter_length; i += 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_bfi, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                            }
                            break;
                        case 0x1F: /* BFI Distribution */
                            for (i = 0; i < parameter_length; i += 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                            }
                            break;
                        case 0x20: /* Jitter Depth Distribution */
                            for (i = 0; i < parameter_length / 4; i+=4) {
                                proto_tree_add_uint_format_value(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_jitter_depth_distribution,
                                        tvb, offset+i, 4, tvb_get_ntohl(tvb, offset+i), "+/- %3d ms: %d",
                                        ((2 * i/4) + 1) * framing_rtp / 2, tvb_get_ntohl(tvb, offset+i));
                            }
                            break;
                        case 0x2E: /* 802.1 Q Used */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021Q_used, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x2F: /* 802.1p Priority */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021P_priority, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x30: /* VLAN Id */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                            break;
                        case 0x31: /* DiffServ */
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_diffserv, tvb, offset, 1, ENC_NA);
                            break;
                        case 0x3D: /* 200 ms BFI Distribution */
                            for (i = 0; i < parameter_length; i += 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution_200ms, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                            }
                            break;
                        case 0x3E: /* Consecutive RTP Lost */
                            for (i = 0; i < parameter_length; i += 2) {
                                proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_rtp_lost, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                            }
                            break;
                        case 0x14: /* Received Framing (ms) */
                            {
                                /* XXX: What is the point of this assignment? */
                                framing_rtp = tvb_get_guint8(tvb, offset + 3);
                                /* FALLTHROUGH */
                            }
                        case 0x01: /* Date Of End Of Communication */
                        case 0x02: /* Node Number */
                        case 0x03: /* Ticket Protocol Version */
                        case 0x0C: /* Call Duration (second) */
                        case 0x0D: /* Local SSRC */
                        case 0x0E: /* Distant SSRC */
                        case 0x13: /* Transmitted Framing (ms) */
                        case 0x15: /* Framing Changes */
                        case 0x16: /* Number Of RTP Packets Received */
                        case 0x17: /* Number Of RTP Packets Sent */
                        case 0x18: /* Number Of RTP Packets Lost */
                        case 0x19: /* Total Silence Detected (second) */
                        case 0x1A: /* Number Of SID Received */
                        case 0x1C: /* Maximum Delay (ms) */
                        case 0x1D: /* Number Of DTMF Received */
                        case 0x21: /* Number Of ICMP Host Unreachable */
                        case 0x29: /* DSP Framing (ms) */
                        case 0x2A: /* Transmitter SID */
                        case 0x2D: /* Minimum Delay (ms) */
                        default:
                            proto_tree_add_item(ua3g_param_tree, hf_ua3g_cs_ip_device_routing_cmd03_parameter_uint, tvb, offset, parameter_length, ENC_BIG_ENDIAN);
                            break;
                        }

                        offset += parameter_length;
                        length -= parameter_length;
                    }
                }
                break;
            }
        default:
            break;
    }
}


/*-----------------------------------------------------------------------------
    UNSOLICITED MESSAGE - 9Fh/1Fh (MESSAGE FROM THE TERMINAL)
    VERSION RESPONSE - 21h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static const value_string str_command_unsolicited_msg[] = {
    {0x00, "Hardware Reset Acknowledge"},
    {0x01, "Software Reset Acknowledge"},
    {0x02, "Illegal Command Received"},
    {0x05, "Subdevice Down"},
    {0x06, "Segment Failure"},
    {0x07, "UA Device Event"},
    {0, NULL}
};

static const value_string str_unsolicited_msg_vta_type[] = {
    {0x03, "4035"},
    {0x04, "4020"},
    {0x05, "4010"},
    {0x20, "NOE A"},
    {0x21, "NOE B"},
    {0x22, "NOE C"},
    {0x23, "NOE D"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_other_info_1[] = {
    {0x00, "Link Is TDM"},
    {0x01, "Link Is IP"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_other_info_2[] = {
    {0x00, "Download Allowed"},
    {0x01, "Download Refused"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_config_ip[] = {
    {0x00, "Export Binary (No Thales)"},
    {0x01, "Full Binary (Thales)"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_config_chip[] = {
    {0x01, "Ivanoe 1"},
    {0x02, "Ivanoe 2"},
    {0x03, "Reserved"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_config_flash[] = {
    {0x00, "No Flash"},
    {0x01, "128 Kbytes"},
    {0x02, "256 Kbytes"},
    {0x03, "512 Kbytes"},
    {0x04, "1 Mbytes"},
    {0x05, "2 Mbytes"},
    {0x06, "4 Mbytes"},
    {0x07, "8 Mbytes"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_config_ram[] = {
    {0x00, "No External RAM"},
    {0x01, "128 Kbytes"},
    {0x02, "256 Kbytes"},
    {0x03, "512 Kbytes"},
    {0x04, "1 Mbytes"},
    {0x05, "2 Mbytes"},
    {0x06, "4 Mbytes"},
    {0x07, "8 Mbytes"},
    {0, NULL}
};

static const value_string str_unsolicited_msg_subtype[] = {
    {0x03, "2x40"},
    {0x04, "1x20"},
    {0x05, "1x20"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_generation[] = {
    {0x02, "3"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_design[] = {
    {0x00, "Alpha"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_vta_type[] = {
    {0x03, "MR2 (4035)"},
    {0x05, "VLE (4010)"},
    {0x07, "LE (4020)"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_design[] = {
    {0x06, "Alpha"},
    {0, NULL}
};
static const value_string str_unsolicited_msg_hard_subtype[] = {
    {0x06, "2x40"},
    {0x07, "1x20"},
    {0x08, "1x20"},
    {0, NULL}
};

static void
decode_unsolicited_msg(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
               guint offset, guint length, guint8 opcode)
{
    guint8      command;
    proto_tree *ua3g_body_tree = tree, *ua3g_param_tree;
    proto_item *ua3g_param_item;

    command = tvb_get_guint8(tvb, offset);

    if (opcode != 0x21) {
        /* add text to the frame "INFO" column */
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(command, str_command_unsolicited_msg, "Unknown"));

        proto_tree_add_item(ua3g_body_tree, hf_ua3g_command_unsolicited_msg, tvb, offset, 1, ENC_NA);
        offset++;
        length--;
    } else {
        command = 0xFF; /* Opcode = 0x21 */
    }

    switch (command)
    {
    case 0x00: /* Hardware Reset Acknowledge */
    case 0x01: /* Software Reset Acknowledge */
    case 0xFF: /* Opcode = 0x21 : Version Response */
        {
            int link, vta_type;

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_device_type, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_firmware_version, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            length -= 2;

            if (opcode != 0x21) {
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_self_test_result, tvb, offset, 1, ENC_NA);
                offset++;
                length--;
            }

            vta_type = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_vta_type, tvb, offset, 1, ENC_NA);
            offset++;
            length--;

            switch (vta_type)
            {
            case 0x03:
            case 0x04:
            case 0x05:
                {
                    ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Characteristic Number");
                    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_char_num_vta_subtype,
                            tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_char_num_generation,
                            tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_char_num_design,
                            tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;
                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_other_information, tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;

                    ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Hardware Configuration");
                    ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_vta_type,
                            tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_design,
                            tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_subtype,
                            tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;

                    if (opcode != 0x21) {
                        proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
                            "Hook Status/BCM Version: %s Hook",
                            STR_ON_OFF(tvb_get_guint8(tvb, offset)));
                        offset++;
                        length--;

                    }
                    break;
                }
            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            default:
                {
                    link = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_other_information_1, tvb, offset, 1, ENC_NA);
                    offset++;
                    length--;

                    if (link == 0x00) {
                        proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_hardware_version, tvb, offset, 1, ENC_NA);
                        offset++;
                        length--;

                        ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Hardware Configuration");
                        ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_hard_config_chip,
                                tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_hard_config_flash,
                                tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(ua3g_param_tree, hf_ua3g_unsolicited_msg_hardware_config_config_ram,
                                tvb, offset, 1, ENC_NA);
                        offset++;
                        length--;
                    } else {
                        proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_other_information_2, tvb, offset, 1, ENC_NA);
                        offset++;
                        length--;

                        proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_hardware_config_hard_config_ip,
                                tvb, offset, 1, ENC_NA);
                        offset++;
                        length--;
                    }

                    if (opcode != 0x21) {
                        proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_hook_status,
                                tvb, offset, 1, ENC_NA);
                        offset++;
                        length--;

                        if (length > 0) {
                            if (link == 0x00) {
                                proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_firmware_datas_patch_version,
                                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                                if (length > 2) {
                                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_firmware_version_loader, tvb,
                                                         offset+2, 2, ENC_BIG_ENDIAN);
                                }
                            } else {
                                proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_datas_version, tvb, offset, 2, ENC_BIG_ENDIAN);

                                if (length > 2) {
                                    proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_firmware_version_bootloader,
                                        tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                }
                            }
                        }
                    }
                    break;
                }
            }
            break;
        }
    case 0x02: /* Illegal Command Received */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_opcode_of_bad_command, tvb, offset, 1, ENC_NA);

            if (length > 1) {
                proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_next_byte_of_bad_command, tvb, offset+1, length-1, ENC_NA);
            }
            break;
        }
    case 0x05: /* Subdevice Down */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_subdevice_address, tvb, offset, 1, ENC_NA);
            break;
        }
    case 0x06: /* Segment Failure */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_segment_failure_t, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_segment_failure_num, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_segment_failure_s, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_segment_failure_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_opcode_bad_segment, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_next_byte_of_bad_segment, tvb, offset+2, 1, ENC_NA);
            break;
        }
    case 0x07: /* UA Device Event */
        {
            proto_tree_add_item(ua3g_body_tree, hf_ua3g_unsolicited_msg_device_event, tvb, offset, 1, ENC_NA);
            break;
        }
    default:
        {
            break;
        }
    }
}


/*-----------------------------------------------------------------------------
    NON-DIGIT KEY PUSHED - 20h (MESSAGE FROM THE TERMINAL)
    DIGIT KEY RELEASED - 26h (MESSAGE FROM THE TERMINAL)
    KEY RELEASED - 2Ah (MESSAGE FROM THE TERMINAL)
    TM KEY PUSHED - 2Dh (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_key_number(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
          guint offset, guint length)
{
#if 0
    proto_tree *ua3g_body_tree;
    static const value_string str_first_parameter[] = {
        {0x01, "Production Test Command"},
        {0x06, "Reserved For Compatibility"},
        {0x3B, "Volume"},
        {0x42, "Subdevice Address"},
        {0, NULL}
    };
#endif

    if (!tree)
        return;

    if (length > 0) {
        proto_tree_add_text(tree, tvb, offset, length,
            "Key Number: Row %d, Column %d",
            (tvb_get_guint8(tvb, offset) & 0xF0), (tvb_get_guint8(tvb, offset) & 0x0F));
    }
}


/*-----------------------------------------------------------------------------
    I'M HERE - 22h - Only for UA NOE (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_i_m_here(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    proto_tree_add_item(tree, hf_ua3g_i_m_here_id_code, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    RESPONSE STATUS INQUIRY - 23h (MESSAGE FROM THE TERMINAL)
    SPECIAL KEY STATUS - 29h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static const value_string str_special_key_parameters[] = {
    {0x00, "Not Received Default In Effect"},
    {0x02, "Downloaded Values In Effect"},
    {0, NULL}
};

const true_false_string tfs_released_pressed = { "Released", "Pressed" };

static void
decode_special_key(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
           guint offset, guint8 opcode)
{
    if (!tree)
        return;

    if (opcode == 0x23) {
        proto_tree_add_text(tree, tvb, offset, 1,
            "Parameters Received for DTMF: %s",
            val_to_str_const((tvb_get_guint8(tvb, offset) & 0x02), str_special_key_parameters, "Unknown"));
        proto_tree_add_text(tree, tvb, offset, 1,
            "Hookswitch Status: %shook",
            STR_ON_OFF(tvb_get_guint8(tvb, offset) & 0x01));
        offset++;
    }

    proto_tree_add_item(tree, hf_ua3g_special_key_shift, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_ctrl, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_alt, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_cmd, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_shift_prime, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_ctrl_prime, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_alt_prime, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ua3g_special_key_cmd_prime, tvb, offset, 1, ENC_NA);
}


/*-----------------------------------------------------------------------------
    SUBDEVICE STATE ENQUIRY - 24h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_state(proto_tree *tree, tvbuff_t *tvb,
               packet_info *pinfo _U_, guint offset)
{
    guint8      info;
    int         i;

    for (i = 0; i <= 7; i++) {
        info = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1,
            "Subdevice %d State: %d",
            i, info & 0x0F);
        i++;
        proto_tree_add_text(tree, tvb, offset, 1,
            "Subdevice %d State: %d",
            i, (info & 0xF0) >> 4);
        offset++;
    }
}


/*-----------------------------------------------------------------------------
    UA3G DISSECTOR
    ---------------------------------------------------------------------------*/
static int
dissect_ua3g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint              offset         = 0;
    proto_item       *ua3g_item, *ua3g_body_item;
    proto_tree       *ua3g_tree, *ua3g_body_tree;
    gint              length;
    guint8            opcode;
    const gchar*      opcode_str;
    e_ua_direction   *message_direction;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    message_direction = (e_ua_direction *)data;

    ua3g_item = proto_tree_add_item(tree, proto_ua3g, tvb, 0, -1, ENC_NA);
    ua3g_tree = proto_item_add_subtree(ua3g_item, ett_ua3g);

    /* Length of the UA Message */
    length = tvb_get_letohs(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_str(pinfo->cinfo, COL_INFO, " - UA3G Message:");

    proto_tree_add_uint(ua3g_tree, hf_ua3g_length, tvb, offset, 2, length);
    offset += 2;

    /* Opcode of the UA Message */
    opcode = tvb_get_guint8(tvb, offset);
    if (opcode != 0x9f)
        opcode = (opcode & 0x7f);

    /* Useful for a research in wireshark */
    if (*message_direction == SYS_TO_TERM) {
        proto_tree_add_uint(ua3g_tree, hf_ua3g_opcode_sys, tvb, offset, 1, opcode);
        opcode_str = val_to_str_ext_const(opcode, &opcodes_vals_sys_ext, "Unknown");
    } else {
        proto_tree_add_uint(ua3g_tree, hf_ua3g_opcode_term, tvb, offset, 1, opcode);
        opcode_str = val_to_str_ext_const(opcode, &opcodes_vals_term_ext, "Unknown");
    }

    offset++;
    length--;

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", opcode_str);

    proto_item_append_text(ua3g_item, ", %s", opcode_str);

    ua3g_body_item = proto_tree_add_text(ua3g_tree, tvb, offset, length, "UA3G Body");
    ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

    if (*message_direction == SYS_TO_TERM) {
        switch (opcode) {
        case SC_PRODUCTION_TEST: /* 0x01 */
            {
                decode_with_one_parameter(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_opcode_production_test);
                break;
            }
        case SC_SUBDEVICE_RESET: /* 0x06 */
            {
                decode_with_one_parameter(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_opcode_subservice_reset);
                break;
            }
        case SC_ARE_YOU_THERE:   /* 0x2B */
            {
                decode_with_one_parameter(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_opcode_are_you_there);
                break;
            }
        case SC_SET_SPEAKER_VOL: /* 0x3B */
            {
                decode_with_one_parameter(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_opcode_set_speaker_vol);
                break;
            }
        case SC_TRACE_ON:        /* 0x42 */
            {
                decode_with_one_parameter(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_opcode_trace_on);
                break;
            }
        case SC_SUBDEVICE_ESCAPE: /* 0x02 */
            {
                decode_subdevice_escape(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SOFT_RESET: /* 0x03 */
            {
                decode_software_reset(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_IP_PHONE_WARMSTART: /* 0x04 */
            {
                decode_ip_phone_warmstart(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SUPER_MSG:   /* 0x0B */
        case SC_SUPER_MSG_2: /* 0x17 */
            {
                decode_super_msg(ua3g_body_tree, tvb, pinfo, offset, length, opcode);
                break;
            }
        case SC_SEGMENT_MSG: /* 0x0C */
            {
                decode_segment_msg(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_IP_DEVICE_ROUTING: /* 0x13 */
            {
            decode_ip_device_routing(ua3g_body_tree, tvb, pinfo, offset, length);
            break;
            }
        case SC_DEBUG_IN_LINE: /* 0x18 */
            {
                decode_debug_in_line(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_LED_COMMAND: /* 0x21 */
            {
                decode_led_command(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_LCD_LINE_1_CMD: /* 0x27 */
        case SC_LCD_LINE_2_CMD: /* 0x28 */
            {
                decode_lcd_line_cmd(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_MAIN_VOICE_MODE: /* 0x29 */
            {
                decode_main_voice_mode(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SUBDEVICE_METASTATE: /* 0x2C */
            {
                decode_subdevice_metastate(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_DWL_DTMF_CLCK_FORMAT: /* 0x30 */
            {
                decode_dwl_dtmf_clck_format(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SET_CLCK: /* 0x31 */
            {
                decode_set_clck(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_VOICE_CHANNEL: /* 0x32 */
            {
                decode_voice_channel(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_EXTERNAL_RINGING: /* 0x33 */
            {
                decode_external_ringing(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_LCD_CURSOR: /* 0x35 */
            {
                decode_lcd_cursor(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_DWL_SPECIAL_CHAR: /* 0x36 */
            {
                decode_dwl_special_char(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SET_CLCK_TIMER_POS: /* 0x38 */
            {
                decode_set_clck_timer_pos(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_SET_LCD_CONTRAST: /* 0x39 */
            {
                decode_set_lcd_contrast(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_BEEP: /* 0x3C */
            {
                decode_beep(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_SIDETONE: /* 0x3D */
            {
                decode_sidetone(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_RINGING_CADENCE: /* 0x3E */
            {
                decode_ringing_cadence(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_MUTE: /* 0x3F */
            {
                decode_mute(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_FEEDBACK: /* 0x40 */
            {
                decode_feedback(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_READ_PERIPHERAL:  /* 0x44 */
        case SC_WRITE_PERIPHERAL: /* 0x45 */
            {
            decode_r_w_peripheral(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_ICON_CMD: /* 0x47 */
            {
                decode_icon_cmd(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_AUDIO_CONFIG: /* 0x49 */
            {
                decode_audio_config(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case SC_AUDIO_PADDED_PATH: /* 0x4A */
            {
                decode_audio_padded_path(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_KEY_RELEASE:       /* 0x41 */
            {
                decode_on_off_level(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_command_key_release);
                break;
            }
        case SC_AMPLIFIED_HANDSET: /* 0x48 */
            {
                decode_on_off_level(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_command_amplified_handset);
                break;
            }
        case SC_LOUDSPEAKER:       /* 0x4D */
            {
                decode_on_off_level(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_command_loudspeaker);
                break;
            }
        case SC_ANNOUNCE:          /* 0x4E */
            {
                decode_on_off_level(ua3g_body_tree, tvb, pinfo, offset, length, hf_ua3g_command_announce);
                break;
            }
        case SC_RING: /* 0x4F */
            {
                decode_ring(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case SC_UA_DWL_PROTOCOL: /* 0x50 */
            {
                decode_ua_dwl_protocol(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        /* Case for UA3G message with only opcode (No body) */
        case SC_NOP:                    /* 0x00 */
        case SC_HE_ROUTING:             /* 0x05 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_LOOPBACK_ON:            /* 0x07 */
        case SC_LOOPBACK_OFF:           /* 0x08 */
        case SC_VIDEO_ROUTING:          /* 0x09 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_REMOTE_UA_ROUTING:      /* 0x0D NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_VERY_REMOTE_UA_ROUTING: /* 0x0E NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_OSI_ROUTING:            /* 0x0F NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_ABC_A_ROUTING:          /* 0x11 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_IBS_ROUTING:            /* 0x12 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_M_REFLEX_HUB_ROUTING:   /* 0x14 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case SC_START_BUZZER:           /* 0x22 */
        case SC_STOP_BUZZER:            /* 0x23 */
        case SC_ENABLE_DTMF:            /* 0x24 */
        case SC_DISABLE_DTMF:           /* 0x25 */
        case SC_CLEAR_LCD_DISP:         /* 0x26 */
        case SC_VERSION_INQUIRY:        /* 0x2A */
        case SC_VTA_STATUS_INQUIRY:     /* 0x2D */
        case SC_SUBDEVICE_STATE:        /* 0x2E */
        case SC_AUDIO_IDLE:             /* 0x3A */
        case SC_TRACE_OFF:              /* 0x43 */
        case SC_ALL_ICONS_OFF:          /* 0x46 */
        case SC_RELEASE_RADIO_LINK:     /* 0x4B */
        case SC_DECT_HANDOVER:          /* 0x4C NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        default:
            {
                break;
            }
        }
    }
    if (*message_direction == TERM_TO_SYS) {
        switch (opcode) {
        case CS_DIGIT_DIALED: /* 0x03 */
            {
                decode_digit_dialed(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case CS_SUBDEVICE_MSG: /* 0x04 */
            {
                decode_subdevice_msg(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case CS_SUPER_MSG:   /* 0x0B */
        case CS_SUPER_MSG_2: /* 0x17 */
            {
                decode_super_msg(ua3g_body_tree, tvb, pinfo, offset, length, opcode);
                break;
            }
        case CS_SEGMENT_MSG: /* 0x0C */
            {
            decode_segment_msg(ua3g_body_tree, tvb, pinfo, offset, length);
            break;
            }
        case CS_IP_DEVICE_ROUTING: /* 0x13 */
            {
                decode_cs_ip_device_routing(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case CS_DEBUG_IN_LINE: /* 0x18 */
            {
                decode_debug_in_line(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case CS_NON_DIGIT_KEY_PUSHED: /* 0x20 Key translation not sure */
        case CS_DIGIT_KEY_RELEASED:   /* 0x26 Key translation not sure */
        case CS_KEY_RELEASED:         /* 0x2A */
        case CS_TM_KEY_PUSHED:        /* 0x2D Key translation not sure */
            {
                decode_key_number(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case CS_UNSOLICITED_MSG: /* 0x9F (0x1F) */
        case CS_VERSION_RESPONSE: /* 0x21 */
            {
                decode_unsolicited_msg(ua3g_body_tree, tvb, pinfo, offset, length, opcode);
                break;
            }
        case CS_I_M_HERE: /* 0x22 */
            {
                decode_i_m_here(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case CS_RSP_STATUS_INQUIRY: /* 0x23 */
        case CS_SPECIAL_KEY_STATUS: /* 0x29 */
            {
                decode_special_key(ua3g_body_tree, tvb, pinfo, offset, opcode);
                break;
            }
        case CS_SUBDEVICE_STATE: /* 0x24 */
            {
                decode_subdevice_state(ua3g_body_tree, tvb, pinfo, offset);
                break;
            }
        case CS_PERIPHERAL_CONTENT: /* 0x2B */
            {
                decode_r_w_peripheral(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        case CS_UA_DWL_PROTOCOL: /* 0x50 */
            {
                decode_ua_dwl_protocol(ua3g_body_tree, tvb, pinfo, offset, length);
                break;
            }
        /* Case for UA3G message with only opcode (No body) */
        case CS_NOP_ACK:           /* 0x00 */
        case CS_HANDSET_OFFHOOK:   /* 0x01 */
        case CS_HANDSET_ONHOOK:    /* 0x02 */
        case CS_HE_ROUTING:        /* 0x05 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_LOOPBACK_ON:       /* 0x06 */
        case CS_LOOPBACK_OFF:      /* 0x07 */
        case CS_VIDEO_ROUTING:     /* 0x09 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_WARMSTART_ACK:     /* 0x0A */
        case CS_REMOTE_UA_ROUTING: /* 0x0D NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_VERY_REMOTE_UA_R:  /* 0x0E NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_OSI_ROUTING:       /* 0x0F NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_ABC_A_ROUTING:     /* 0x11 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_IBS_ROUTING:       /* 0x12 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
        case CS_TRACE_ON_ACK:      /* 0x27 */
        case CS_TRACE_OFF_ACK:     /* 0x28 */
        default:
            {
                break;
            }
        }
    }

    return tvb_length(tvb);
}


/*-----------------------------------------------------------------------------
    DISSECTORS REGISTRATION FUNCTIONS
    ---------------------------------------------------------------------------*/
void
proto_register_ua3g(void)
{
    static hf_register_info hf[] =
    {
        { &hf_ua3g_length,
            { "Length", "ua3g.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_sys,
            { "Opcode", "ua3g.opcode",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &opcodes_vals_sys_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_term,
            { "Opcode", "ua3g.opcode",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &opcodes_vals_term_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_production_test,
            { "Production Test Command", "ua3g.production_test",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_subservice_reset,
            { "Reserved For Compatibility", "ua3g.subservice_reset",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_are_you_there,
            { "Temporization", "ua3g.are_you_there",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_set_speaker_vol,
            { "Volume", "ua3g.set_speaker_vol",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_opcode_trace_on,
            { "Subdevice Address", "ua3g.trace_on",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip,
            { "IP Device Routing", "ua3g.ip",
            FT_UINT8, BASE_HEX, VALS(str_command_ip_device_routing), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip_cs,
            { "IP Device Routing", "ua3g.ip.cs",
            FT_UINT8, BASE_HEX, VALS(str_command_cs_ip_device_routing), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_led,
            { "Led Command", "ua3g.command.led",
            FT_UINT8, BASE_HEX, VALS(str_command_led), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_lcd_line,
            { "LCD Line Command", "ua3g.command.lcd_line",
            FT_UINT8, BASE_HEX, VALS(str_command_lcd_line), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_main_voice_mode,
            { "Voice Mode", "ua3g.command.main_voice_mode",
            FT_UINT8, BASE_HEX, VALS(str_main_voice_mode), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_set_clck,
            { "Set Clock", "ua3g.command.set_clck",
            FT_UINT8, BASE_HEX, VALS(str_command_set_clck), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_external_ringing_command,
            { "External Ringing Command", "ua3g.command.external_ringing",
            FT_UINT8, BASE_HEX, VALS(str_ext_ring_cmd), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_lcd_cursor,
            { "Cursor", "ua3g.lcd_cursor",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x02,
            NULL, HFILL }
        },
        { &hf_ua3g_command_beep,
            { "Beep", "ua3g.command.beep",
            FT_UINT8, BASE_HEX, VALS(str_command_beep), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_sidetone,
            { "Sidetone", "ua3g.command.sidetone",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_mute,
            { "Microphone", "ua3g.command.mute",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01,
            NULL, HFILL }
        },
        { &hf_ua3g_command_feedback,
            { "Feedback", "ua3g.command.feedback",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_audio_config,
            { "Audio Config", "ua3g.command.audio_config",
            FT_UINT8, BASE_HEX, VALS(str_command_audio_config), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_key_release,
            { "Key Release", "ua3g.command.key_release",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_amplified_handset,
            { "Amplified Handset (Boost)", "ua3g.command.amplified_handset",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_loudspeaker,
            { "Loudspeaker", "ua3g.command.loudspeaker",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_announce,
            { "Announce", "ua3g.command.announce",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_ring,
            { "Ring", "ua3g.command.ring",
            FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_ua_dwl_protocol,
            { "UA Download Protocol", "ua3g.command.ua_dwl_protocol",
            FT_UINT8, BASE_HEX, VALS(str_command_ua_dwl_protocol), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_command_unsolicited_msg,
            { "Unsolicited Message", "ua3g.command.unsolicited_msg",
            FT_UINT8, BASE_HEX, VALS(str_command_unsolicited_msg), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip_device_routing_stop_rtp_parameter,
            { "Parameter", "ua3g.ip.stop_rtp.parameter",
            FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_stop_rtp_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip_device_routing_stop_rtp_parameter_length,
            { "Length", "ua3g.ip.stop_rtp.parameter.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip_device_routing_stop_rtp_parameter_value_num,
            { "Value", "ua3g.ip.stop_rtp.parameter.value.num",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ua3g_ip_device_routing_stop_rtp_parameter_value_bytes,
            { "Value", "ua3g.ip.stop_rtp.parameter.value.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_ua3g_subdevice_address, { "Subdevice Address", "ua3g.subdevice.address", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
        { &hf_ua3g_subdevice_opcode, { "Subdevice Opcode", "ua3g.subdevice.opcode", FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},
        { &hf_ua3g_subdevice_parameter_bytes, { "Parameter Bytes", "ua3g.subdevice.parameter_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_software_reset, { "Software Reset", "ua3g.software_reset", FT_UINT8, BASE_DEC, VALS(software_reset_verswitch_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_phone_warmstart, { "IP Phone Warmstart", "ua3g.ip_phone_warmstart", FT_UINT8, BASE_DEC, VALS(str_command_ip_phone_warmstart), 0x0, NULL, HFILL }},
        { &hf_ua3g_super_msg_length, { "Length", "ua3g.super_msg.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_super_msg_data, { "Data", "ua3g.super_msg.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_segment_msg_num_remaining, { "Number Of Remaining Segments", "ua3g.segment_msg.num_remaining", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
        { &hf_ua3g_segment_msg_length, { "Length", "ua3g.segment_msg.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_segment_message_data, { "Segment Message Data", "ua3g.segment_message.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter, { "Parameter", "ua3g.ip.reset.parameter", FT_UINT8, BASE_DEC, VALS(ip_device_routing_cmd_reset_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_length, { "Length", "ua3g.ip.reset.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_direction, { "Direction", "ua3g.ip.start_rtp.direction", FT_UINT8, BASE_DEC, VALS(start_rtp_str_direction), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter, { "Parameter", "ua3g.ip.start_rtp.parameter", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ip_device_routing_cmd_start_rtp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_length, { "Length", "ua3g.ip.start_rtp.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_redirect_parameter, { "Parameter", "ua3g.ip.redirect.parameter", FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_redirect_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_redirect_parameter_length, { "Length", "ua3g.ip.redirect.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_def_tones_num_entries, { "Number Of Entries", "ua3g.ip.def_tones.num_entries", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_def_tones_frequency_1, { "Frequency 1 (Hz)", "ua3g.ip.def_tones.frequency_1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_def_tones_level_1, { "Level 1 (dB)", "ua3g.ip.def_tones.level_1", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_def_tones_frequency_2, { "Frequency 2 (Hz)", "ua3g.ip.def_tones.frequency_2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_def_tones_level_2, { "Level 2 (dB)", "ua3g.ip.def_tones.level_2", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_tone_direction, { "Direction", "ua3g.ip.start_tone.direction", FT_UINT8, BASE_DEC, VALS(ip_device_routing_tone_direction_vals), 0xC0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_tone_num_entries, { "Number of entries", "ua3g.ip.start_tone.num_entries", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_tone_identification, { "Identification", "ua3g.ip.start_tone.identification", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_tone_duration, { "Duration (ms)", "ua3g.ip.start_tone.duration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_listen_rtp_parameter, { "Parameter", "ua3g.ip.listen_rtp.parameter", FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_listen_rtp_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_listen_rtp_parameter_length, { "Length", "ua3g.ip.listen_rtp.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_get_param_req_parameter, { "Parameter", "ua3g.ip.get_param_req.parameter", FT_UINT8, BASE_DEC, VALS(ip_device_routing_cmd_get_param_req_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter, { "Parameter", "ua3g.ip.set_param_req.parameter", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ip_device_routing_cmd_set_param_req_vals_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_length, { "Length", "ua3g.ip.set_param_req.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_digit_value, { "Digit Value", "ua3g.ip.digit_value", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &str_digit_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_pause_restart_rtp_parameter, { "Parameter", "ua3g.ip.pause_restart_rtp.parameter", FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_pause_restart_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_length, { "Length", "ua3g.ip.pause_restart_rtp.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_value, { "Value", "ua3g.ip.pause_restart_rtp.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter, { "Parameter", "ua3g.ip.start_stop_record_rtp.parameter", FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_record_rtp_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_length, { "Length", "ua3g.ip.start_stop_record_rtp.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_debug_in_line, { "Text String With Debug", "ua3g.debug_in_line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_command_led_number, { "Led Number", "ua3g.command.led.number", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options, { "LCD Options", "ua3g.command.lcd_line.lcd_options", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_starting_column, { "Starting Column", "ua3g.command.lcd_line.starting_column", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_tune, { "Tune", "ua3g.main_voice_mode.tune", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_cadence, { "Cadence", "ua3g.main_voice_mode.cadence", FT_UINT8, BASE_DEC, VALS(str_cadence), 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_speaker_volume, { "Speaker Volume", "ua3g.main_voice_mode.speaker_volume", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_microphone_volume, { "Microphone Volume", "ua3g.main_voice_mode.microphone_volume", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_sending_level, { "Sending Level (dB)", "ua3g.main_voice_mode.sending_level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_handset_level, { "Receiving Level (dB)", "ua3g.main_voice_mode.handset_level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_headset_level, { "Receiving Level (dB)", "ua3g.main_voice_mode.headset_level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_main_voice_mode_handsfree_level, { "Sending Level (dB)", "ua3g.main_voice_mode.handsfree_level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_metastate_subchannel_address, { "Subchannel Address", "ua3g.subdevice_metastate.subchannel_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_metastate_new_metastate, { "New Metastate", "ua3g.subdevice_metastate.new_metastate", FT_UINT8, BASE_DEC, VALS(str_new_metastate), 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_dtmf_clck_format_minimum_on_time, { "Minimum 'ON' Time (ms)", "ua3g.dwl_dtmf_clck_format.minimum_on_time", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_dtmf_clck_format_inter_digit_pause_time, { "Inter-Digit Pause Time (ms)", "ua3g.dwl_dtmf_clck_format.inter_digit_pause_time", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_dtmf_clck_format_clock_time_format, { "Clock Time Format", "ua3g.dwl_dtmf_clck_format.clock_time_format", FT_UINT8, BASE_DEC, VALS(str_clock_format), 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_dtmf_clck_format_dtmf_country_adaptation, { "DTMF Country Adaptation", "ua3g.dwl_dtmf_clck_format.dtmf_country_adaptation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_channel_mode, { "Channel Mode", "ua3g.voice_channel.channel_mode", FT_BOOLEAN, 8, TFS(&tfs_voice_channel_channel_mode), 0x01, NULL, HFILL }},
        { &hf_ua3g_voice_channel_codec, { "Codec", "ua3g.voice_channel.codec", FT_BOOLEAN, 8, TFS(&tfs_voice_channel_codec), 0x02, NULL, HFILL }},
        { &hf_ua3g_voice_channel_voice_channel, { "Voice Channel", "ua3g.voice_channel.voice_channel", FT_BOOLEAN, 8, TFS(&tfs_voice_channel_voice_channel), 0x04, NULL, HFILL }},
        { &hf_ua3g_voice_channel_main_voice, { "Main Voice", "ua3g.voice_channel.main_voice", FT_UINT8, BASE_DEC, VALS(str_voice_channel), 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_announce, { "Announce", "ua3g.voice_channel.announce", FT_UINT8, BASE_DEC, VALS(str_voice_channel), 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_b_general, { "B General", "ua3g.voice_channel.b_general", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_b_loud_speaker, { "B Loud Speaker", "ua3g.voice_channel.b_loud_speaker", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_b_ear_piece, { "B Ear Piece", "ua3g.voice_channel.b_ear_piece", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_voice_channel_b_microphones, { "B Microphones", "ua3g.voice_channel.b_microphones", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_lcd_cursor_line_number, { "Line Number", "ua3g.lcd_cursor.line_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_special_char_character_number, { "Character Number", "ua3g.dwl_special_char.character_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_dwl_special_char_byte, { "Byte", "ua3g.dwl_special_char.byte", FT_UINT8, BASE_DEC, NULL, 0xFF, NULL, HFILL }},
        { &hf_ua3g_set_clck_timer_pos_clock_line_number, { "Clock Line Number", "ua3g.set_clck_timer_pos.clock_line_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_set_clck_timer_pos_clock_column_number, { "Clock Column Number", "ua3g.set_clck_timer_pos.clock_column_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_set_clck_timer_pos_call_timer_line_number, { "Call Timer Line Number", "ua3g.set_clck_timer_pos.call_timer_line_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_set_clck_timer_pos_call_timer_column_number, { "Call Timer Column Number", "ua3g.set_clck_timer_pos.call_timer_column_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_set_lcd_contrast_driver_number, { "Driver Number", "ua3g.set_lcd_contrast.driver_number", FT_UINT8, BASE_DEC, VALS(str_driver_number), 0x0, NULL, HFILL }},
        { &hf_ua3g_set_lcd_contrast_contrast_value, { "Contrast Value", "ua3g.set_lcd_contrast.contrast_value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_beep_destination, { "Destination", "ua3g.command.beep.destination", FT_UINT8, BASE_DEC, VALS(str_beep_start_destination), 0x0, NULL, HFILL }},
        { &hf_ua3g_beep_on_off, { "On / Off", "ua3g.command.beep.on_off", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80, NULL, HFILL }},
        { &hf_ua3g_beep_cadence, { "Cadence", "ua3g.command.beep.cadence", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_beep_beep_number, { "Beep Number", "ua3g.command.beep.beep_number", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_beep_number_of_notes, { "Number Of Notes", "ua3g.command.beep.number_of_notes", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_beep_terminator, { "Terminator", "ua3g.command.beep.terminator", FT_UINT8, BASE_DEC, VALS(str_beep_terminator), 0x0, NULL, HFILL }},
        { &hf_ua3g_sidetone_level, { "Level", "ua3g.command.sidetone.level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ringing_cadence_cadence, { "Cadence", "ua3g.ringing_cadence.cadence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ringing_cadence_on_off, { "On / Off", "ua3g.ringing_cadence.on_off", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80, NULL, HFILL }},
        { &hf_ua3g_ringing_cadence_length, { "Length (ms)", "ua3g.ringing_cadence.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_feedback_level, { "Level (dB)", "ua3g.command.feedback.level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_feedback_duration, { "Duration (ms)", "ua3g.command.feedback.duration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_r_w_peripheral_address, { "Address", "ua3g.r_w_peripheral.address", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_r_w_peripheral_content, { "Content", "ua3g.r_w_peripheral.content", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_icon_cmd_icon_number, { "Icon Number", "ua3g.icon_cmd.icon_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_icon_cmd_segment, { "Segment", "ua3g.icon_cmd.segment", FT_UINT16, BASE_DEC, VALS(str_icon_cmd_state), 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_ignored, { "Ignored", "ua3g.command.audio_config.ignored", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_law, { "Law", "ua3g.command.audio_config.law", FT_UINT8, BASE_DEC, VALS(str_audio_coding_law), 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_volume_level, { "Volume Level", "ua3g.command.audio_config.volume_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_handsfree_return, { "Return", "ua3g.command.audio_config.handsfree_return", FT_BOOLEAN, 8, TFS(&tfs_audio_config_handsfree_return), 0x01, NULL, HFILL }},
        { &hf_ua3g_audio_config_handsfree_handsfree, { "Handsfree", "ua3g.command.audio_config.handsfree", FT_BOOLEAN, 8, TFS(&tfs_audio_config_handsfree_handsfree), 0x02, NULL, HFILL }},
        { &hf_ua3g_audio_padded_path_emission_padded_level, { "Emission Padded Level", "ua3g.audio_padded_path.emission_padded_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_padded_path_reception_padded_level, { "Reception Padded Level", "ua3g.audio_padded_path.reception_padded_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_on_off_level_level_on_loudspeaker, { "Level on Loudspeaker (dB)", "ua3g.on_off_level.level_on_loudspeaker", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ring_melody, { "Melody", "ua3g.command.ring.melody", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ring_cadence, { "Cadence", "ua3g.command.ring.cadence", FT_UINT8, BASE_DEC, VALS(str_cadence), 0x0, NULL, HFILL }},
        { &hf_ua3g_ring_speaker_level, { "Speaker level (dB)", "ua3g.command.ring.speaker_level", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ring_beep_number, { "Beep number", "ua3g.command.ring.beep_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ring_silent, { "Silent", "ua3g.command.ring.silent", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80, NULL, HFILL }},
        { &hf_ua3g_ring_progressive, { "Progressive", "ua3g.command.ring.progressive", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_item_identifier, { "Item Identifier", "ua3g.ua_dwl_protocol.item_identifier", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_cause, { "Cause", "ua3g.ua_dwl_protocol.cause", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_force_mode, { "Force Mode", "ua3g.ua_dwl_protocol.force_mode", FT_UINT8, BASE_DEC, VALS(str_download_req_force_mode), 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_item_version, { "Item Version", "ua3g.ua_dwl_protocol.item_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_item_version_nc, { "Item Version", "ua3g.ua_dwl_protocol.item_version", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_binary_length, { "Binary Length", "ua3g.ua_dwl_protocol.binary_length", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_packet_number, { "Packet Number", "ua3g.ua_dwl_protocol.packet_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_download_ack_status, { "Status", "ua3g.ua_dwl_protocol.download_ack_status", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &str_download_ack_status_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_packet_download_end_ack_ok_status, { "Status", "ua3g.ua_dwl_protocol_packet.download_end_ack_ok_status", FT_UINT8, BASE_DEC, VALS(str_download_end_ack_ok), 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_checksum, { "Checksum", "ua3g.ua_dwl_protocol.checksum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_acknowledge, { "Acknowledge", "ua3g.ua_dwl_protocol.acknowledge", FT_UINT8, BASE_DEC, VALS(str_iso_checksum_ack_status), 0x0, NULL, HFILL }},
        { &hf_ua3g_digit_dialed_digit_value, { "Digit Value", "ua3g.digit_dialed.digit_value", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &str_digit_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_msg_subdev_type, { "Subdev Type", "ua3g.subdevice_msg.subdev_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_msg_subdev_address, { "Subdev Address", "ua3g.subdevice_msg.subdev_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_msg_subdevice_opcode, { "Subdevice Opcode", "ua3g.subdevice_msg.subdevice_opcode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_subdevice_msg_parameter_bytes, { "Parameter Bytes", "ua3g.subdevice_msg.parameter_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd00_vta_type, { "VTA Type", "ua3g.ip.cs.cmd00.vta_type", FT_UINT8, BASE_DEC, VALS(str_cs_ip_device_routing_vta_type), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd00_characteristic_number, { "Characteristic Number", "ua3g.ip.cs.cmd00.characteristic_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd01_incident_0, { "Incident 0", "ua3g.ip.cs.cmd01.incident_0", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter, { "Parameter", "ua3g.ip.cs.cmd02.parameter", FT_UINT8, BASE_HEX, VALS(ip_device_routing_cmd_get_param_req_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_length, { "Length", "ua3g.ip.cs.cmd02.parameter.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter, { "Parameter", "ua3g.ip.cs.cmd03.parameter", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cs_ip_device_routing_03_parameter_id_vals_ext, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_length, { "Length", "ua3g.ip.cs.cmd03.parameter.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_device_type, { "Device Type", "ua3g.unsolicited_msg.device_type", FT_UINT8, BASE_DEC, VALS(str_device_type), 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_self_test_result, { "Self-Test Result", "ua3g.unsolicited_msg.self_test_result", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_vta_type, { "VTA Type", "ua3g.unsolicited_msg.vta_type", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_vta_type), 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_other_information, { "Other Information", "ua3g.unsolicited_msg.other_information", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_other_info_2), 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_other_information_1, { "Other Information 1", "ua3g.unsolicited_msg.other_information_1", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_other_info_1), 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_version, { "Hardware Version", "ua3g.unsolicited_msg.hardware_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_other_information_2, { "Other Information 2", "ua3g.unsolicited_msg.other_information_2", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_other_info_2), 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_firmware_datas_patch_version, { "Firmware Datas Patch Version", "ua3g.unsolicited_msg.firmware_datas_patch_version", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_firmware_version_loader, { "Firmware Version (Loader)", "ua3g.unsolicited_msg.firmware_version_loader", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_firmware_version, { "Firmware Version", "ua3g.unsolicited_msg.firmware_version", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_datas_version, { "Datas Version", "ua3g.unsolicited_msg.datas_version", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_firmware_version_bootloader, { "Firmware Version (Bootloader)", "ua3g.unsolicited_msg.firmware_version_bootloader", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_opcode_of_bad_command, { "Opcode Of Bad Command", "ua3g.unsolicited_msg.opcode_of_bad_command", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_next_byte_of_bad_command, { "Next Byte Of Bad Command", "ua3g.unsolicited_msg.next_byte_of_bad_command", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_subdevice_address, { "Subdevice Address", "ua3g.unsolicited_msg.subdevice_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_segment_failure_t, { "T", "ua3g.unsolicited_msg.segment_failure.t", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_segment_failure_num, { "Num", "ua3g.unsolicited_msg.segment_failurenum", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_segment_failure_s, { "/S", "ua3g.unsolicited_msg.segment_failure.s", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_segment_failure_l, { "L", "ua3g.unsolicited_msg.segment_failure.l", FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_opcode_bad_segment, { "Opcode Bad Segment", "ua3g.unsolicited_msg.opcode_bad_segment", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_next_byte_of_bad_segment, { "Next Byte Of Bad Segment", "ua3g.unsolicited_msg.next_byte_of_bad_segment", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_device_event, { "Device Event", "ua3g.unsolicited_msg.device_event", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_i_m_here_id_code, { "Id Code", "ua3g.i_m_here.id_code", FT_UINT8, BASE_DEC, VALS(str_device_type), 0x0, NULL, HFILL }},
        { &hf_ua3g_segment_msg_segment, { "F/S", "ua3g.segment_msg.segment", FT_BOOLEAN, 8, TFS(&tfs_segment_msg_segment), 0x80, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update, { "NOE Update Mode", "ua3g.ip.reset.parameter.noe_update", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_bootloader, { "Bootloader", "ua3g.ip.reset.parameter.noe_update.bootloader", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_data, { "Data", "ua3g.ip.reset.parameter.noe_update.data", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_customization, { "Customization", "ua3g.ip.reset.parameter.noe_update.customization", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_localization, { "Localization", "ua3g.ip.reset.parameter.noe_update.localization", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_code, { "Code", "ua3g.ip.reset.parameter.noe_update.code", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_noe_update_sip, { "SIP", "ua3g.ip.reset.parameter.noe_update.sip", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_bad_sec_mode, { "Bad Sec Mode", "ua3g.ip.reset.parameter.bad_sec_mode", FT_UINT8, BASE_DEC, VALS(reset_param_bad_sec_mode), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_value, { "Value", "ua3g.ip.reset.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_cust_name, { "Cust_Name", "ua3g.ip.reset.parameter.cust_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_reset_parameter_l10n_name, { "L10N_Name", "ua3g.ip.reset.parameter.l10n_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_value, { "Value", "ua3g.ip.start_rtp.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_ip, { "IP", "ua3g.ip.start_rtp.parameter.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_compressor, { "Compressor", "ua3g.ip.start_rtp.parameter.compressor", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(str_start_rtp_compressor), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_enabler, { "Enabler", "ua3g.ip.start_rtp.parameter.enabler", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_send_qos, { "Must Send QOS Tickets", "ua3g.ip.start_rtp.parameter.enabler", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_uint, { "Value", "ua3g.ip.start_rtp.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_dtmf_sending, { "Send DTMF", "ua3g.ip.start_rtp.parameter.dtmf_sending", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_rfc2198, { "Enable RFC 2198", "ua3g.ip.start_rtp.parameter.rfc2198", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_rtp_parameter_srtp_encryption, { "Enable SRTP Encryption", "ua3g.ip.start_rtp.parameter.srtp_encryption", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_redirect_parameter_value, { "Value", "ua3g.ip.redirect.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_redirect_parameter_ip, { "IP", "ua3g.ip.redirect.parameter.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_redirect_parameter_uint, { "Value", "ua3g.ip.redirect.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_listen_rtp_parameter_value, { "Value", "ua3g.ip.listen_rtp.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_listen_rtp_parameter_ip, { "IP", "ua3g.ip.listen_rtp.parameter.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_listen_rtp_parameter_port, { "Port", "ua3g.ip.listen_rtp.parameter.port", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_value, { "Value", "ua3g.ip.set_param_req.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_tftp_backup_ip, { "TFTP Backup IP", "ua3g.ip.set_param_req.parameter.tftp_backup_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_uint, { "Value", "ua3g.ip.set_param_req.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_err_string, { "Value", "ua3g.ip.set_param_req.parameter.err_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_compressor, { "Compressor", "ua3g.ip.set_param_req.parameter.compressor", FT_UINT8, BASE_DEC, VALS(str_set_param_req_compressor), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_set_pc_port_status, { "Set PC Port status", "ua3g.ip.set_param_req.parameter.set_pc_port_status", FT_UINT8, BASE_DEC, VALS(str_set_pc_port_status), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_record_rtp_auth, { "Record RTP Authorization", "ua3g.ip.set_param_req.parameter.record_rtp_auth", FT_UINT8, BASE_DEC, VALS(str_enable_feature), 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_set_param_req_parameter_security_flag_filter, { "Filtering", "ua3g.ip.set_param_req.parameter.security_flag.filter", FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x01, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_pause_restart_rtp_parameter_uint, { "Value", "ua3g.ip.pause_restart_rtp.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_value, { "Value", "ua3g.ip.start_stop_record_rtp.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_remote_ip, { "Remote IP", "ua3g.ip.start_stop_record_rtp.parameter.remote_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ip_device_routing_start_stop_record_rtp_parameter_uint, { "Value", "ua3g.ip.start_stop_record_rtp.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_dpi_chan_ua_tx1, { "UA Channel UA-TX1", "ua3g.command.audio_config.dpi_chan.ua_tx1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_dpi_chan_ua_tx2, { "UA Channel UA-TX2", "ua3g.command.audio_config.dpi_chan.ua_tx2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_dpi_chan_gci_tx1, { "GCI Channel GCI-TX1", "ua3g.command.audio_config.dpi_chan.gci_tx1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_dpi_chan_gci_tx2, { "GCI Channel GCI-TX2", "ua3g.command.audio_config.dpi_chan.gci_tx2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_dpi_chan_cod_tx, { "Codec Channel COD-TX", "ua3g.command.audio_config.dpi_chan.cod_tx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_dth, { "Anti-Distortion Coeff 1(DTH)", "ua3g.command.audio_config.audio_circuit.dth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_dtr, { "Anti-Distortion Coeff 2(DTR)", "ua3g.command.audio_config.audio_circuit.dtr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_dtf, { "Anti-Distortion Coeff 3(DTF)", "ua3g.command.audio_config.audio_circuit.dtf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_str, { "Sidetone Attenuation (STR)", "ua3g.command.audio_config.audio_circuit.str", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_ahp1, { "Anti-Larsen Coeff 1 (AHP1)", "ua3g.command.audio_config.audio_circuit.ahp1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_ahp2, { "Anti-Larsen Coeff 2 (AHP2)", "ua3g.command.audio_config.audio_circuit.ahp2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_ath, { "Anti-Larsen Coeff 3 (ATH)", "ua3g.command.audio_config.audio_circuit.ath", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_atr, { "Anti-Larsen Coeff 4 (ATR)", "ua3g.command.audio_config.audio_circuit.atr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_atf, { "Anti-Larsen Coeff 5 (ATF)", "ua3g.command.audio_config.audio_circuit.atf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_audio_circuit_alm, { "Anti-Larsen Coeff 6 (ALM)", "ua3g.command.audio_config.audio_circuit.alm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_group_listen, { "Group Listening Attenuation Constant", "ua3g.command.audio_config.loudspeaker_aco_param.group_listen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_attenuation, { "Handsfree Attenuation Constant", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_attenuation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_stay_in_send, { "Handsfree Number Of ms To Stay In Send State Before Going To Another State", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_stay_in_send", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mtx, { "Handsfree Number Of Positions To Shift Right MTx", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_shift_right_mtx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_shift_right_mrc, { "Handsfree Number Of Positions To Shift Right MRc", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_shift_right_mrc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_trans_threshold, { "Handsfree Idle Transmission Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_idle_trans_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_trans_threshold, { "Handsfree Low Transmission Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_low_trans_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_idle_recv_threshold, { "Handsfree Idle Reception Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_idle_recv_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_low_recv_threshold, { "Handsfree Low Reception Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_low_recv_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_med_recv_threshold, { "Handsfree Medium Reception Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_med_recv_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_audio_config_loudspeaker_aco_param_handsfree_high_recv_threshold, { "Handsfree High Reception Threshold", "ua3g.command.audio_config.loudspeaker_aco_param.handsfree_high_recv_threshold", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_files_inc_boot_binary, { "Boot Binary Included", "ua3g.ua_dwl_protocol.files_inc.boot_binary", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_files_inc_loader_binary, { "Loader Binary Included", "ua3g.ua_dwl_protocol.files_inc.loader_binary", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_files_inc_appli_binary, { "Appli Binary Included", "ua3g.ua_dwl_protocol.files_inc.appli_binary", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_files_inc_data_binary, { "Datas Binary Included", "ua3g.ua_dwl_protocol.files_inc.data_binary", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_model_selection_a, { "For A Model", "ua3g.ua_dwl_protocol.model_selection.a", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_model_selection_b, { "For B Model", "ua3g.ua_dwl_protocol.model_selection.b", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_model_selection_c, { "For C Model", "ua3g.ua_dwl_protocol.model_selection.c", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_model_selection_country_ver, { "Country Version", "ua3g.ua_dwl_protocol.model_selection.country_ver", FT_UINT8, BASE_DEC, VALS(str_download_req_mode_selection_country), 0xE0, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe1, { "For Ivanoe 1", "ua3g.ua_dwl_protocol.hardware_selection.ivanoe1", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_hardware_selection_ivanoe2, { "For Ivanoe 2", "ua3g.ua_dwl_protocol.hardware_selection.ivanoe2", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_memory_sizes_flash, { "Flash Min Size", "ua3g.ua_dwl_protocol.memory_sizes.flash", FT_UINT8, BASE_DEC, VALS(str_mem_size), 0x07, NULL, HFILL }},
        { &hf_ua3g_ua_dwl_protocol_memory_sizes_ext_ram, { "External Ram Min Size", "ua3g.ua_dwl_protocol.memory_sizes.ext_ram", FT_UINT8, BASE_DEC, VALS(str_mem_size), 0x38, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_char_num_vta_subtype, { "VTA SubType", "ua3g.unsolicited_msg.char_num.vta_subtype", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_subtype), 0xC0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_char_num_generation, { "Generation", "ua3g.unsolicited_msg.char_num.generation", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_generation), 0x38, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_char_num_design, { "Design", "ua3g.unsolicited_msg.char_num.design", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_design), 0x07, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_vta_type, { "VTA Type", "ua3g.unsolicited_msg.hardware_config.vta_type", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_vta_type), 0xE0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_design, { "Design", "ua3g.unsolicited_msg.hardware_config.design", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_design), 0x1C, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_subtype, { "VTA SubType", "ua3g.unsolicited_msg.hardware_config.subtype", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_subtype), 0x03, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_hard_config_chip, { "Chip Id", "ua3g.unsolicited_msg.hardware_config.hard_config_chip", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_config_chip), 0x03, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_hard_config_flash, { "Flash Size", "ua3g.unsolicited_msg.hardware_config.hard_config_flash", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_config_flash), 0x1C, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_config_ram, { "External RAM Size", "ua3g.unsolicited_msg.hardware_config.config_ram", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_config_ram), 0xE0, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hardware_config_hard_config_ip, { "Hardware Configuration", "ua3g.unsolicited_msg.hardware_config.ip", FT_UINT8, BASE_DEC, VALS(str_unsolicited_msg_hard_config_ip), 0x01, NULL, HFILL }},
        { &hf_ua3g_unsolicited_msg_hook_status, { "Hook Status", "ua3g.unsolicited_msg.hook_status", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x00, NULL, HFILL }},
        { &hf_ua3g_special_key_shift, { "Shift", "ua3g.special_key.shift", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x01, NULL, HFILL }},
        { &hf_ua3g_special_key_ctrl, { "Ctrl", "ua3g.special_key.ctrl", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x02, NULL, HFILL }},
        { &hf_ua3g_special_key_alt, { "Alt", "ua3g.special_key.alt", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x04, NULL, HFILL }},
        { &hf_ua3g_special_key_cmd, { "Cmd", "ua3g.special_key.cmd", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x08, NULL, HFILL }},
        { &hf_ua3g_special_key_shift_prime, { "Shift'", "ua3g.special_key.shift_prime", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x10, NULL, HFILL }},
        { &hf_ua3g_special_key_ctrl_prime, { "Ctrl'", "ua3g.special_key.ctrl_prime", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x20, NULL, HFILL }},
        { &hf_ua3g_special_key_alt_prime, { "Alt'", "ua3g.special_key.alt_prime", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x40, NULL, HFILL }},
        { &hf_ua3g_special_key_cmd_prime, { "Cmd'", "ua3g.special_key.cmd_prime", FT_BOOLEAN, 8, TFS(&tfs_released_pressed), 0x80, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_call_timer, { "Call Timer", "ua3g.lcd_line_cmd.lcd_options.call_timer", FT_UINT8, BASE_DEC, VALS(str_call_timer_ctrl), 0x03, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_blink, { "Blink", "ua3g.lcd_line_cmd.lcd_options.blink", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_call_timer_control, { "Call Timer Control", "ua3g.lcd_line_cmd.lcd_options.call_timer_control", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_call_timer_display, { "Call Timer Display", "ua3g.lcd_line_cmd.lcd_options.call_timer_display", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_time_of_day_display, { "Time Of Day Display", "ua3g.lcd_line_cmd.lcd_options.time_of_day_display", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL }},
        { &hf_ua3g_lcd_line_cmd_lcd_options_suspend_display_refresh, { "Suspend Display Refresh", "ua3g.lcd_line_cmd.lcd_options.suspend_display_refresh", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_value, { "Value", "ua3g.ip.cs.cmd02.parameter.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_ip, { "IP", "ua3g.ip.cs.cmd02.parameter.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_mac_address, { "MAC Address", "ua3g.ip.cs.cmd02.parameter.mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_uint, { "Value", "ua3g.ip.cs.cmd02.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_bytes, { "Default Codec", "ua3g.ip.cs.cmd02.parameter.default_codec.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_default_codec_uint, { "Default Codec", "ua3g.ip.cs.cmd02.parameter.default_codec.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_firmware_version, { "Firmware Version", "ua3g.ip.cs.cmd02.parameter.firmware_version", FT_UINT16, BASE_CUSTOM, version_number_computer, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_speed, { "Port Lan Speed", "ua3g.ip.cs.cmd02.parameter.eth_driver_config.port_lan_speed", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_lan_duplex, { "Port Lan Duplex", "ua3g.ip.cs.cmd02.parameter.eth_driver_config.port_lan_duplex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_speed, { "Port PC Speed", "ua3g.ip.cs.cmd02.parameter.eth_driver_config.port_pc_speed", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd02_parameter_eth_driver_config_port_pc_duplex, { "Port PC Duplex", "ua3g.ip.cs.cmd02.parameter.eth_driver_config.port_pc_duplex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_ip, { "IP", "ua3g.ip.cs.cmd03.parameter.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_string, { "IP", "ua3g.ip.cs.cmd03.parameter.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip1, { "Type Of Equipment (first byte)", "ua3g.ip.cs.cmd03.parameter.type_of_equip1", FT_UINT8, BASE_DEC, VALS(cs_ip_device_routing_cmd03_first_byte_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_type_of_equip2, { "Type Of Equipment (second byte)", "ua3g.ip.cs.cmd03.parameter.type_of_equip2", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_cmd03_second_byte_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_default_codec, { "Default Codec", "ua3g.ip.cs.cmd03.parameter.default_codec", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(str_cs_ip_device_routing_0F_compressor), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_vad, { "VAD", "ua3g.ip.cs.cmd03.parameter.vad", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_ece, { "ECE", "ua3g.ip.cs.cmd03.parameter.ece", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_voice_mode, { "Voice Mode", "ua3g.ip.cs.cmd03.parameter.voice_mode", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(cs_ip_device_routing_cmd03_voice_mode_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_delay_distribution, { "Delay Distribution", "ua3g.ip.cs.cmd03.parameter.delay_distribution", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_delay_distribution_range_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_bfi, { "Consecutive BFI", "ua3g.ip.cs.cmd03.parameter.consecutive_bfi", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_consecutive_bfi_range_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution, { "BFI Distribution", "ua3g.ip.cs.cmd03.parameter.bfi_distribution", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_bfi_distribution_range_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021Q_used, { "802.1 Q Used", "ua3g.ip.cs.cmd03.parameter.8021Q_used", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_8021P_priority, { "802.1p Priority", "ua3g.ip.cs.cmd03.parameter.8021P_priority", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_vlan_id, { "VLAN Id", "ua3g.ip.cs.cmd03.parameter.vlan_id", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_diffserv, { "DiffServ", "ua3g.ip.cs.cmd03.parameter.diffserv", FT_UINT8, BASE_DEC, NULL, 0xFC, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_bfi_distribution_200ms, { "200 ms BFI Distribution", "ua3g.ip.cs.cmd03.parameter.bfi_distribution_200ms", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_200ms_bfi_distribution_range_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_uint, { "Value", "ua3g.ip.cs.cmd03.parameter.uint", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_consecutive_rtp_lost, { "Consecutive RTP Lost", "ua3g.ip.cs.cmd03.parameter.consecutive_rtp_lost", FT_UINT16, BASE_DEC, VALS(cs_ip_device_routing_consecutive_rtp_lost_range_vals), 0x0, NULL, HFILL }},
        { &hf_ua3g_cs_ip_device_routing_cmd03_parameter_jitter_depth_distribution, { "Jitter Depth Distribution", "ua3g.ip.cs.cmd03.parameter.jitter_depth_distribution", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] =
    {
        &ett_ua3g,
        &ett_ua3g_body,
        &ett_ua3g_param,
        &ett_ua3g_param_sub,
        &ett_ua3g_option,
    };

    /* UA3G dissector registration */
    proto_ua3g = proto_register_protocol("UA3G Message", "UA3G", "ua3g");

    proto_register_field_array(proto_ua3g, hf, array_length(hf));

    new_register_dissector("ua3g", dissect_ua3g, proto_ua3g);

    /* Common subtree array registration */
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ua3g(void)
{
#if 0 /* Future */
	dissector_handle_t handle_ua3g = find_dissector("ua3g");

	/* hooking of UA3G on UA */

	dissector_add_uint("ua.opcode", 0x15, handle_ua3g);
#endif
}
