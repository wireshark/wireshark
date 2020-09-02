/* packet-gryphon.c
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: http://www.dgtech.com/product/gryphon/manual/html/GCprotocol/
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include "packet-gryphon.h"

/*
 * See
 *
 *     https://www.dgtech.com/product/gryphon/manual/html/GCprotocol/
 */

void proto_register_gryphon(void);
void proto_reg_handoff_gryphon(void);

#define GRYPHON_TCP_PORT 7000 /* Not IANA registed */

static int proto_gryphon = -1;

static int hf_gryphon_src = -1;
static int hf_gryphon_srcchan = -1;
static int hf_gryphon_srcchanclient = -1;
static int hf_gryphon_dest = -1;
static int hf_gryphon_destchan = -1;
static int hf_gryphon_destchanclient = -1;
static int hf_gryphon_type = -1;
static int hf_gryphon_cmd = -1;
static int hf_gryphon_cmd_context = -1;
static int hf_gryphon_cmd_ioctl_context = -1;
static int hf_gryphon_data = -1;
static int hf_gryphon_data_length = -1;
static int hf_gryphon_reserved = -1;
static int hf_gryphon_padding = -1;
static int hf_gryphon_ignored = -1;
static int hf_gryphon_wait_flags = -1;
static int hf_gryphon_wait_resp = -1;
static int hf_gryphon_wait_prev_resp = -1;
static int hf_gryphon_status = -1;
static int hf_gryphon_response_in = -1;
static int hf_gryphon_response_to = -1;
static int hf_gryphon_response_time = -1;
static int hf_gryphon_data_header_length = -1;
static int hf_gryphon_data_header_length_bits = -1;
static int hf_gryphon_data_data_length = -1;
static int hf_gryphon_data_extra_data_length = -1;
static int hf_gryphon_data_mode = -1;
static int hf_gryphon_data_mode_transmitted = -1;
static int hf_gryphon_data_mode_receive = -1;
static int hf_gryphon_data_mode_local = -1;
static int hf_gryphon_data_mode_remote = -1;
static int hf_gryphon_data_mode_oneshot = -1;
static int hf_gryphon_data_mode_combined = -1;
static int hf_gryphon_data_mode_nomux = -1;
static int hf_gryphon_data_mode_internal = -1;
static int hf_gryphon_data_priority = -1;
static int hf_gryphon_data_error_status = -1;
static int hf_gryphon_data_time = -1;
static int hf_gryphon_data_context = -1;
static int hf_gryphon_data_header_data = -1;
static int hf_gryphon_data_data = -1;
static int hf_gryphon_data_extra_data = -1;
static int hf_gryphon_data_padding = -1;
static int hf_gryphon_event_id = -1;
static int hf_gryphon_event_context = -1;
static int hf_gryphon_event_time = -1;
static int hf_gryphon_event_data = -1;
static int hf_gryphon_event_padding = -1;
static int hf_gryphon_misc_text = -1;
static int hf_gryphon_misc_padding = -1;
static int hf_gryphon_eventnum = -1;
static int hf_gryphon_resp_time = -1;
static int hf_gryphon_setfilt = -1;
static int hf_gryphon_setfilt_length = -1;
static int hf_gryphon_setfilt_discard_data = -1;
static int hf_gryphon_setfilt_padding = -1;
static int hf_gryphon_ioctl = -1;
static int hf_gryphon_ioctl_nbytes = -1;
static int hf_gryphon_ioctl_data = -1;
static int hf_gryphon_addfilt_pass = -1;
static int hf_gryphon_addfilt_active = -1;
static int hf_gryphon_addfilt_blocks = -1;
static int hf_gryphon_addfilt_handle = -1;
static int hf_gryphon_modfilt = -1;
static int hf_gryphon_modfilt_action = -1;
static int hf_gryphon_filthan = -1;
static int hf_gryphon_filthan_id = -1;
static int hf_gryphon_filthan_padding = -1;
static int hf_gryphon_dfiltmode = -1;
static int hf_gryphon_filtmode = -1;
static int hf_gryphon_event_name = -1;
static int hf_gryphon_register_username = -1;
static int hf_gryphon_register_password = -1;
static int hf_gryphon_register_client_id = -1;
static int hf_gryphon_register_privileges = -1;
static int hf_gryphon_getspeeds_set_ioctl = -1;
static int hf_gryphon_getspeeds_get_ioctl = -1;
static int hf_gryphon_getspeeds_size = -1;
static int hf_gryphon_getspeeds_preset = -1;
static int hf_gryphon_getspeeds_data = -1;
static int hf_gryphon_cmd_sort = -1;
static int hf_gryphon_cmd_optimize = -1;
static int hf_gryphon_config_device_name = -1;
static int hf_gryphon_config_device_version = -1;
static int hf_gryphon_config_device_serial_number = -1;
static int hf_gryphon_config_num_channels = -1;
static int hf_gryphon_config_name_version_ext = -1;
static int hf_gryphon_config_driver_name = -1;
static int hf_gryphon_config_driver_version = -1;
static int hf_gryphon_config_device_security = -1;
static int hf_gryphon_config_max_data_length = -1;
static int hf_gryphon_config_min_data_length = -1;
static int hf_gryphon_config_hardware_serial_number = -1;
static int hf_gryphon_config_protocol_type = -1;
static int hf_gryphon_config_channel_id = -1;
static int hf_gryphon_config_card_slot_number = -1;
static int hf_gryphon_config_max_extra_data = -1;
static int hf_gryphon_config_min_extra_data = -1;
static int hf_gryphon_sched_num_iterations = -1;
static int hf_gryphon_sched_flags = -1;
static int hf_gryphon_sched_flags_scheduler = -1;
static int hf_gryphon_sched_sleep = -1;
static int hf_gryphon_sched_transmit_count = -1;
static int hf_gryphon_sched_transmit_period = -1;
static int hf_gryphon_sched_transmit_flags = -1;
static int hf_gryphon_sched_skip_transmit_period = -1;
static int hf_gryphon_sched_skip_sleep = -1;
static int hf_gryphon_sched_channel = -1;
static int hf_gryphon_sched_channel0 = -1;
static int hf_gryphon_sched_rep_id = -1;
static int hf_gryphon_sched_rep_message_index = -1;
static int hf_gryphon_blm_data_time = -1;
static int hf_gryphon_blm_data_bus_load = -1;
static int hf_gryphon_blm_data_current_bus_load = -1;
static int hf_gryphon_blm_data_peak_bus_load = -1;
static int hf_gryphon_blm_data_historic_peak_bus_load = -1;
static int hf_gryphon_blm_stat_receive_frame_count = -1;
static int hf_gryphon_blm_stat_transmit_frame_count = -1;
static int hf_gryphon_blm_stat_receive_dropped_frame_count = -1;
static int hf_gryphon_blm_stat_transmit_dropped_frame_count = -1;
static int hf_gryphon_blm_stat_receive_error_count = -1;
static int hf_gryphon_blm_stat_transmit_error_count = -1;
static int hf_gryphon_addresp_flags = -1;
static int hf_gryphon_addresp_flags_active = -1;
static int hf_gryphon_addresp_blocks = -1;
static int hf_gryphon_addresp_responses = -1;
static int hf_gryphon_addresp_old_handle = -1;
static int hf_gryphon_addresp_action = -1;
static int hf_gryphon_addresp_action_period = -1;
static int hf_gryphon_addresp_action_deact_on_event = -1;
static int hf_gryphon_addresp_action_deact_after_period = -1;
static int hf_gryphon_addresp_action_period_type = -1;
static int hf_gryphon_addresp_handle = -1;
static int hf_gryphon_ldf_list = -1;
static int hf_gryphon_ldf_number = -1;
static int hf_gryphon_ldf_nodenumber = -1;
static int hf_gryphon_ldf_remaining = -1;
static int hf_gryphon_ldf_name = -1;
static int hf_gryphon_ldf_info_pv = -1;
static int hf_gryphon_ldf_info_lv = -1;
static int hf_gryphon_ldf_ui = -1;
static int hf_gryphon_lin_nodename = -1;
static int hf_gryphon_lin_data_length = -1;
static int hf_gryphon_lin_slave_table_enable = -1;
static int hf_gryphon_lin_slave_table_cs = -1;
static int hf_gryphon_lin_slave_table_data = -1;
static int hf_gryphon_lin_slave_table_datacs = -1;
static int hf_gryphon_lin_masterevent = -1;
static int hf_gryphon_lin_numdata = -1;
static int hf_gryphon_lin_numextra = -1;
static int hf_gryphon_ldf_description = -1;
static int hf_gryphon_ldf_size = -1;
static int hf_gryphon_ldf_exists = -1;
static int hf_gryphon_ldf_blockn = -1;
static int hf_gryphon_ldf_file = -1;
static int hf_gryphon_ldf_desc_pad = -1;
static int hf_gryphon_ldf_restore_session = -1;
static int hf_gryphon_ldf_schedule_name = -1;
static int hf_gryphon_ldf_schedule_msg_dbytes = -1;
static int hf_gryphon_ldf_schedule_flags = -1;
static int hf_gryphon_ldf_schedule_event = -1;
static int hf_gryphon_ldf_schedule_sporadic = -1;
static int hf_gryphon_ldf_ioctl_setflags = -1;
static int hf_gryphon_ldf_numb_ids = -1;
static int hf_gryphon_ldf_bitrate = -1;
static int hf_gryphon_ldf_ioctl_setflags_flags = -1;
static int hf_gryphon_ldf_sched_size_place = -1;
static int hf_gryphon_ldf_sched_numb_place = -1;
static int hf_gryphon_ldf_sched_size = -1;
static int hf_gryphon_ldf_num_node_names = -1;
static int hf_gryphon_ldf_num_frames = -1;
static int hf_gryphon_ldf_num_signal_names = -1;
static int hf_gryphon_ldf_num_schedules = -1;
static int hf_gryphon_ldf_num_encodings = -1;
static int hf_gryphon_ldf_encoding_value = -1;
static int hf_gryphon_ldf_encoding_min = -1;
static int hf_gryphon_ldf_encoding_max = -1;
static int hf_gryphon_ldf_master_node_name = -1;
static int hf_gryphon_ldf_slave_node_name = -1;
static int hf_gryphon_ldf_node_name = -1;
static int hf_gryphon_ldf_signal_name = -1;
static int hf_gryphon_ldf_signal_encoding_name = -1;
static int hf_gryphon_ldf_signal_encoding_type = -1;
static int hf_gryphon_ldf_signal_encoding_logical = -1;
static int hf_gryphon_ldf_signal_offset = -1;
static int hf_gryphon_ldf_signal_length = -1;
static int hf_gryphon_ldf_get_frame = -1;
static int hf_gryphon_ldf_get_frame_num = -1;
static int hf_gryphon_ldf_get_frame_pub = -1;
static int hf_gryphon_ldf_get_frame_num_signals = -1;
static int hf_gryphon_cnvt_valuef = -1;
static int hf_gryphon_cnvt_valuei = -1;
static int hf_gryphon_cnvt_values = -1;
static int hf_gryphon_cnvt_units = -1;
static int hf_gryphon_cnvt_flags_getvalues = -1;
static int hf_gryphon_dd_stream = -1;
static int hf_gryphon_dd_value = -1;
static int hf_gryphon_dd_time = -1;
static int hf_gryphon_modresp_handle = -1;
static int hf_gryphon_modresp_action = -1;
static int hf_gryphon_num_resphan = -1;
static int hf_gryphon_handle = -1;
static int hf_gryphon_transmit_sched_id = -1;
static int hf_gryphon_desc_program_size = -1;
static int hf_gryphon_desc_program_name = -1;
static int hf_gryphon_desc_program_description = -1;
static int hf_gryphon_desc_flags = -1;
static int hf_gryphon_desc_flags_program = -1;
static int hf_gryphon_desc_handle = -1;
static int hf_gryphon_upload_block_number = -1;
static int hf_gryphon_upload_handle = -1;
static int hf_gryphon_upload_data = -1;
static int hf_gryphon_delete = -1;
static int hf_gryphon_list_block_number = -1;
static int hf_gryphon_list_num_programs = -1;
static int hf_gryphon_list_num_remain_programs = -1;
static int hf_gryphon_list_name = -1;
static int hf_gryphon_list_description = -1;
static int hf_gryphon_start_arguments = -1;
static int hf_gryphon_start_channel = -1;
static int hf_gryphon_status_num_running_copies = -1;
static int hf_gryphon_options_handle = -1;
static int hf_gryphon_files = -1;
static int hf_gryphon_usdt_flags_register = -1;
static int hf_gryphon_usdt_action_flags = -1;
static int hf_gryphon_usdt_action_flags_non_legacy = -1;
static int hf_gryphon_usdt_action_flags_register = -1;
static int hf_gryphon_usdt_action_flags_action = -1;
static int hf_gryphon_usdt_transmit_options_flags = -1;
static int hf_gryphon_usdt_transmit_options_flags_echo = -1;
static int hf_gryphon_usdt_transmit_options_done_event = -1;
static int hf_gryphon_usdt_transmit_options_echo_short = -1;
static int hf_gryphon_usdt_transmit_options_rx_nth_fc = -1;
static int hf_gryphon_usdt_transmit_options_action = -1;
static int hf_gryphon_usdt_transmit_options_send_done = -1;
static int hf_gryphon_usdt_receive_options_flags = -1;
static int hf_gryphon_usdt_receive_options_action = -1;
static int hf_gryphon_usdt_receive_options_firstframe_event = -1;
static int hf_gryphon_usdt_receive_options_lastframe_event = -1;
static int hf_gryphon_usdt_receive_options_tx_nth_fc = -1;
static int hf_gryphon_usdt_length_options_flags = -1;
static int hf_gryphon_usdt_length_control_j1939 = -1;
static int hf_gryphon_usdt_stmin_fc = -1;
static int hf_gryphon_usdt_bsmax_fc = -1;
static int hf_gryphon_usdt_stmin_override = -1;
static int hf_gryphon_usdt_stmin_override_active = -1;
static int hf_gryphon_usdt_stmin_override_activate = -1;
static int hf_gryphon_usdt_set_stmin_mul = -1;
static int hf_gryphon_usdt_receive_options_firstframe = -1;
static int hf_gryphon_usdt_receive_options_lastframe = -1;
static int hf_gryphon_usdt_ext_address = -1;
static int hf_gryphon_usdt_ext_address_id = -1;
static int hf_gryphon_usdt_block_size = -1;
static int hf_gryphon_bits_in_input1 = -1;
static int hf_gryphon_bits_in_input2 = -1;
static int hf_gryphon_bits_in_input3 = -1;
static int hf_gryphon_bits_in_pushbutton = -1;
static int hf_gryphon_bits_out_output1 = -1;
static int hf_gryphon_bits_out_output2 = -1;
static int hf_gryphon_init_strat_reset_limit = -1;
static int hf_gryphon_init_strat_delay = -1;
static int hf_gryphon_speed_baud_rate_index = -1;
static int hf_gryphon_filter_block_filter_start = -1;
static int hf_gryphon_filter_block_filter_length = -1;
static int hf_gryphon_filter_block_filter_type = -1;
static int hf_gryphon_filter_block_filter_operator = -1;
static int hf_gryphon_filter_block_filter_value1 = -1;
static int hf_gryphon_filter_block_filter_value2 = -1;
static int hf_gryphon_filter_block_filter_value4 = -1;
static int hf_gryphon_filter_block_filter_value_bytes = -1;
static int hf_gryphon_blm_mode = -1;
static int hf_gryphon_blm_mode_avg_period = -1;
static int hf_gryphon_blm_mode_avg_frames = -1;
static int hf_gryphon_command = -1;
static int hf_gryphon_cmd_mode = -1;
static int hf_gryphon_option = -1;
static int hf_gryphon_option_data = -1;
static int hf_gryphon_cmd_file = -1;
static int hf_gryphon_bit_in_digital_data = -1;
static int hf_gryphon_bit_out_digital_data = -1;
static int hf_gryphon_filter_block_pattern = -1;
static int hf_gryphon_filter_block_mask = -1;
static int hf_gryphon_usdt_request = -1;
static int hf_gryphon_usdt_request_ext = -1;
static int hf_gryphon_usdt_nids = -1;
static int hf_gryphon_usdt_response = -1;
static int hf_gryphon_usdt_response_ext = -1;
static int hf_gryphon_uudt_response = -1;
static int hf_gryphon_uudt_response_ext = -1;
static int hf_gryphon_more_filenames = -1;
static int hf_gryphon_filenames = -1;
static int hf_gryphon_program_channel_number = -1;
static int hf_gryphon_valid_header_length = -1;

static gint ett_gryphon = -1;
static gint ett_gryphon_header = -1;
static gint ett_gryphon_body = -1;
static gint ett_gryphon_command_data = -1;
static gint ett_gryphon_response_data = -1;
static gint ett_gryphon_data_header = -1;
static gint ett_gryphon_flags = -1;
static gint ett_gryphon_data_body = -1;
static gint ett_gryphon_cmd_filter_block = -1;
static gint ett_gryphon_cmd_events_data = -1;
static gint ett_gryphon_cmd_config_device = -1;
static gint ett_gryphon_cmd_sched_data = -1;
static gint ett_gryphon_cmd_sched_cmd = -1;
static gint ett_gryphon_cmd_response_block = -1;
static gint ett_gryphon_pgm_list = -1;
static gint ett_gryphon_pgm_status = -1;
static gint ett_gryphon_pgm_options = -1;
static gint ett_gryphon_valid_headers = -1;
static gint ett_gryphon_usdt_data = -1;
static gint ett_gryphon_usdt_action_flags = -1;
static gint ett_gryphon_usdt_tx_options_flags = -1;
static gint ett_gryphon_usdt_rx_options_flags = -1;
static gint ett_gryphon_usdt_len_options_flags = -1;
static gint ett_gryphon_usdt_data_block = -1;
static gint ett_gryphon_lin_emulate_node = -1;
static gint ett_gryphon_ldf_block = -1;
static gint ett_gryphon_ldf_schedule_name = -1;
static gint ett_gryphon_lin_schedule_msg = -1;
static gint ett_gryphon_cnvt_getflags = -1;
static gint ett_gryphon_digital_data = -1;
static gint ett_gryphon_blm_mode = -1;

static expert_field ei_gryphon_type = EI_INIT;

/* desegmentation of Gryphon */
static gboolean gryphon_desegment = TRUE;

/*
* Length of the frame header.
*/
#define GRYPHON_FRAME_HEADER_LEN    8

static int dissect_gryphon_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_msgresp_add);
static int cmd_ioctl(tvbuff_t*, int, proto_tree*, guint32 ui_command);
static int cmd_ioctl_resp(tvbuff_t*, int, proto_tree*, guint32 ui_command);

static const value_string action_vals[] = {
    { FR_RESP_AFTER_EVENT,
        "Send response(s) for each conforming message" },
    { FR_RESP_AFTER_PERIOD,
        "Send response(s) after the specified period expires following a conforming message" },
    { FR_IGNORE_DURING_PER,
        "Send response(s) for a conforming message and ignore further messages until the specified period expires" },
    { 0,
        NULL }
};

static const value_string deact_on_event_vals[] = {
    { FR_DEACT_ON_EVENT,
        "Deactivate this response for a conforming message" },
    { FR_DELETE|FR_DEACT_ON_EVENT,
        "Delete this response for a conforming message" },
    { 0,
        NULL }
};

static const value_string deact_after_per_vals[] = {
    { FR_DEACT_AFTER_PER,
        "Deactivate this response after the specified period following a conforming message" },
    { FR_DELETE|FR_DEACT_AFTER_PER,
        "Delete this response after the specified period following a conforming message" },
    { 0,
        NULL }
};

static const value_string cmd_optimize_type[] = {
    {0,         "Optimize for throughput (Nagle algorithm enabled)"},
    {1,         "Optimize for latency (Nagle algorithm disabled)"},
    {0,         NULL}
};

static const value_string usdt_action_vals[] = {
    { 0, "Use 11 bit headers only" },
    { 1, "Use 29 bit headers only" },
    { 2, "Use both 11 & 29 bit headers" },
    { 3, "undefined" },
    { 0, NULL }
};

static const value_string xmit_opt_nth_fc_event[] = {
    { 0, "Do not send a USDT_RX_NTH_FLOWCONTROL event when the 1st, 2nd, 3rd, etc. flow control message is received" },
    { 1, "Send a USDT_RX_NTH_FLOWCONTROL event when the 1st, 2nd, 3rd, etc. flow control message is received" },
    { 0, NULL }
};

static const value_string xmit_opt_echo_short[] = {
    { 0, "Do not Echo short transmitted messages back to the client (message less than 8 bytes)" },
    { 1, "Echo short transmitted messages back to the client (message less than 8 bytes)" },
    { 0, NULL }
};

static const value_string xmit_opt_done[] = {
    { 0, "Do not send a USDT_DONE event when the last frame of a multi-frame message is transmitted" },
    { 1, "Send a USDT_DONE event when the last frame of a multi-frame message is transmitted" },
    { 0, NULL }
};

static const value_string xmit_opt_vals[] = {
    { 0, "Pad messages with less than 8 data bytes with 0x00's" },
    { 1, "Pad messages with less than 8 data bytes with 0xFF's" },
    { 2, "Do not pad messages with less than 8 data bytes" },
    { 3, "undefined" },
    { 0, NULL }
};

static const value_string xmit_opt_echo_long[] = {
    { 0, "Do not Echo long transmitted messages back to the client (message longer than 6 or 7 bytes)" },
    { 1, "Echo long transmitted messages back to the client (message longer than 6 or 7 bytes)" },
    { 0, NULL }
};


static const value_string recv_opt_nth_fc_event[] = {
    { 0, "Do not send a USDT_TX_NTH_FLOWCONTROL event when the 1st, 2nd, 3rd, etc. flow control message is sent" },
    { 1, "Send a USDT_TX_NTH_FLOWCONTROL event when the 1st, 2nd, 3rd, etc. flow control message is sent" },
    { 0, NULL }
};
static const value_string recv_opt_lastframe_event[] = {
    { 0, "Do not send a USDT_LASTFRAME event when the last frame of a multi-frame message is received" },
    { 1, "Send a USDT_LASTFRAME event when the last frame of a multi-frame message is received" },
    { 0, NULL }
};
static const value_string recv_opt_firstframe_event[] = {
    { 0, "Do not send a USDT_FIRSTFRAME event when the first frame of a multi-frame message is received" },
    { 1, "Send a USDT_FIRSTFRAME event when the first frame of a multi-frame message is received" },
    { 0, NULL }
};

static const value_string recv_opt_j1939[] = {
    { 0, "Treat the length as a regular 4-byte size in calculating the multi-ID block range (not J1939-style)" },
    { 1, "Use J1939-style length (the source and destination bytes are swapped in response (for 29-bit ID/headers only))" },
    { 2, "undefined" },
    { 0, NULL }
};

static const value_string recv_opt_vals[] = {
    { 0, "Do not verify the integrity of long received messages and do not send them to the client" },
    { 1, "Verify the integrity of long received messages and send them to the client" },
    { 2, "Verify the integrity of long received messages but do not send them to the client" },
    { 3, "undefined" },
    { 0, NULL }
};

static const value_string register_unregister [] = {
    { 0, "Unregister" },
    { 1, "Register" },
    { 0, NULL }
};

static const value_string ldf_exists[] = {
    { 0, "Name is OK, does not already exist" },
    { 1, "*** Warning ***: LDF file with same name already exists" },
    { 0, NULL }
};

static const value_string lin_slave_table_enable[] = {
    { 0, "Disabled" },
    { 1, "Enabled" },
    { 2, "One-shot enabled" },
    { 0, NULL }
};

static const value_string lin_slave_table_cs[] = {
    { 0, "Good" },
    { 1, "Bad" },
    { 0, NULL }
};

static const value_string lin_ldf_ioctl_setflags[] = {
    {0,         "Clear all flags first"},
    {1,         "Leave existing flags intact"},
    {0,         NULL}
};
static const value_string lin_cnvt_getflags[] = {
    {1,         "Float value"},
    {2,         "Int value"},
    {3,         "Float and Int value"},
    {4,         "String value"},
    {5,         "Float and String value"},
    {6,         "Int and String value"},
    {7,         "Float, Int, and String value"},
    {0,         NULL}
};

static const value_string lin_ioctl_masterevent[] = {
    {0,         "LIN driver will not send an event on master schedule start-of-cycle"},
    {1,         "LIN driver will send an event on master schedule start-of-cycle"},
    {0,         NULL}
};

static const value_string blm_mode_vals[] = {
    { 0, "Off" },
    { 1, "Average over time" },
    { 2, "Average over frame count" },
    { 0, NULL }
};

static const value_string dmodes[] = {
    {DEFAULT_FILTER_BLOCK,          "Block"},
    {DEFAULT_FILTER_PASS,           "Pass"},
    {0,                 NULL},
};

static const value_string frame_type[] = {
    {0,         ""},
    {1,         "Command request"},
    {2,         "Command response"},
    {3,         "Network (vehicle) data"},
    {4,         "Event"},
    {5,         "Miscellaneous"},
    {6,         "Text string"},
    {7,         "Signal (vehicle) network"},
    {0,         NULL}
};

static const value_string src_dest[] = {
    {SD_CARD,       "Card"},
    {SD_SERVER,     "Server"},
    {SD_CLIENT,     "Client"},
    {SD_SCHED,      "Scheduler"},
    {SD_SCRIPT,     "Script Processor"},
    {SD_PGM,        "Program Loader"},
    {SD_USDT,       "USDT Server"},
    {SD_BLM,        "Bus Load Monitoring"},
    {SD_LIN,        "LIN LDF Server"}, /* 20171031 mc */
    {SD_FLIGHT,     "Flight Recorder / Data Logger"},
    {SD_RESP,       "Message Responder"},
    {SD_IOPWR,      "I/O and power"},
    {SD_UTIL,       "Utility/Miscellaneous"},
    {SD_CNVT,       "Signal Conversion Utility"}, /* 20171031 mc */
    {0,         NULL}
};

/* 20180305 use with BASE_SPECIAL_VALS */
static const value_string channel_or_broadcast[] = {
    {CH_BROADCAST, "Broadcast"},
    {0,            NULL}
};

static const value_string cmd_vals[] = {
    { CMD_INIT,                      "Initialize" },
    { CMD_GET_STAT,                  "Get status" },
    { CMD_GET_CONFIG,                "Get configuration" },
    { CMD_EVENT_ENABLE,              "Enable event" },
    { CMD_EVENT_DISABLE,             "Disable event" },
    { CMD_GET_TIME,                  "Get time" },
    { CMD_GET_RXDROP,                "Get number of dropped RX messages" },
    { CMD_RESET_RXDROP,              "Clear number of dropped RX messages" },
    { CMD_BCAST_ON,                  "Set broadcasts on" },
    { CMD_BCAST_OFF,                 "Set broadcasts off" },
    { CMD_SET_TIME,                  "Set time" },
    { CMD_CARD_SET_SPEED,            "Set channel baud rate" },
    { CMD_CARD_GET_SPEED,            "Get channel baud rate" },
    { CMD_CARD_SET_FILTER,           "Set filter (deprecated)" },
    { CMD_CARD_GET_FILTER,           "Get filter" },
    { CMD_CARD_TX,                   "Transmit message" },
    { CMD_CARD_TX_LOOP_ON,           "Set transmit loopback on" },
    { CMD_CARD_TX_LOOP_OFF,          "Set transmit loopback off" },
    { CMD_CARD_IOCTL,                "IOCTL pass-through" },
    { CMD_CARD_ADD_FILTER,           "Add a filter" },
    { CMD_CARD_MODIFY_FILTER,        "Modify a filter" },
    { CMD_CARD_GET_FILTER_HANDLES,   "Get filter handles" },
    { CMD_CARD_SET_DEFAULT_FILTER,   "Set default filter" },
    { CMD_CARD_GET_DEFAULT_FILTER,   "Get default filter mode" },
    { CMD_CARD_SET_FILTER_MODE,      "Set filter mode" },
    { CMD_CARD_GET_FILTER_MODE,      "Get filter mode" },
    { CMD_CARD_GET_EVNAMES,          "Get event names" },
    { CMD_CARD_GET_SPEEDS,           "Get defined speeds" },
    { CMD_SERVER_REG,                "Register with server" },
    { CMD_SERVER_SET_SORT,           "Set the sorting behavior" },
    { CMD_SERVER_SET_OPT,            "Set the type of optimization" },
    { CMD_PGM_START2,                "Start an uploaded program" },
    { CMD_SCHED_TX,                  "Schedule transmission of messages" },
    { CMD_SCHED_KILL_TX,             "Stop and destroy a message schedule transmission" },
    { CMD_SCHED_MSG_REPLACE,         "Replace a scheduled message" },
    { CMD_PGM_DESC,                  "Describe program to to uploaded" },
    { CMD_PGM_UPLOAD,                "Upload a program to the Gryphon" },
    { CMD_PGM_DELETE,                "Delete an uploaded program" },
    { CMD_PGM_LIST,                  "Get a list of uploaded programs" },
    { CMD_PGM_START,                 "Start an uploaded program" },
    { CMD_PGM_STOP,                  "Stop an uploaded program" },
    { CMD_PGM_STATUS,                "Get status of an uploaded program" },
    { CMD_PGM_OPTIONS,               "Set program upload options" },
    { CMD_PGM_FILES,                 "Get a list of files & directories" },
    { CMD_USDT_REGISTER,             "Register/Unregister with USDT server (deprecated)" },
    { CMD_USDT_SET_FUNCTIONAL,       "Set IDs to use extended addressing (deprecated)" },
    { CMD_USDT_SET_STMIN_MULT,       "Set USDT STMIN multiplier" },
    { CMD_USDT_SET_STMIN_FC,         "Set USDT STMIN flow control (new command July 2017)" },
    { CMD_USDT_GET_STMIN_FC,         "Get USDT STMIN flow control (new command July 2017)" },
    { CMD_USDT_SET_BSMAX_FC,         "Set USDT BSMAX flow control (new command July 2017)" },
    { CMD_USDT_GET_BSMAX_FC,         "Get USDT BSMAX flow control (new command July 2017)" },
    { CMD_USDT_REGISTER_NON_LEGACY,  "Register/Unregister with USDT (ISO-15765) server, non-legacy (new command July 2017)" },
    { CMD_USDT_SET_STMIN_OVERRIDE,   "Set USDT STMIN override (new command July 2017)" },
    { CMD_USDT_GET_STMIN_OVERRIDE,   "Get USDT STMIN override (new command July 2017)" },
    { CMD_USDT_ACTIVATE_STMIN_OVERRIDE, "Activate/deactivate USDT STMIN override (new command July 2017)" },
    { CMD_BLM_SET_MODE,              "Set Bus Load Monitoring mode" },
    { CMD_BLM_GET_MODE,              "Get Bus Load Monitoring mode" },
    { CMD_BLM_GET_DATA,              "Get Bus Load data" },
    { CMD_BLM_GET_STATS,             "Get Bus Load statistics" },
    { CMD_GET_FRAMES,                "Get frames defined in the LIN LDF file" },
    { CMD_LDF_DESC,                  "Set Name and description of LIN LDF file" },
    { CMD_LDF_UPLOAD,                "Upload a LIN LDF file to the Gryphon" },
    { CMD_LDF_LIST,                  "Get list of loaded LIN LDFs" },
    { CMD_LDF_DELETE,                "Delete LIN LDF" },
    { CMD_LDF_PARSE,                 "Parse an uploaded LIN LDF file" },
    { CMD_GET_LDF_INFO,              "Get info of a parsed LDF file" },
    { CMD_GET_NODE_NAMES,            "Get names of nodes defined in the LIN LDF file" },
    { CMD_EMULATE_NODES,             "Emulate LIN nodes" },
    { CMD_GET_FRAME_INFO,            "Get info from a frame defined in the LIN LDF file" },
    { CMD_GET_SIGNAL_INFO,           "Get info from a signal defined in the LIN LDF file" },
    { CMD_GET_SIGNAL_DETAIL,         "Get details from a signal defined in the LIN LDF file" },
    { CMD_GET_ENCODING_INFO,         "Get details from an encoding name defined in the LIN LDF file" },
    { CMD_GET_SCHEDULES,             "Get schedules of the LIN LDF file" },
    { CMD_START_SCHEDULE,            "Start a LIN schedule from the LIN LDF file" },
    { CMD_SAVE_SESSION,              "Save an internal representation of the LIN LDF file" },
    { CMD_RESTORE_SESSION,           "Restore a previously saved LIN LDF session" },
    { CMD_GET_NODE_SIGNALS,          "Get signal names of the node defined in the LIN LDF file" },
    { CMD_FLIGHT_GET_CONFIG,         "Get flight recorder channel info" },
    { CMD_FLIGHT_START_MON,          "Start flight recorder monitoring" },
    { CMD_FLIGHT_STOP_MON,           "Stop flight recorder monitoring"  },
    { CMD_MSGRESP_ADD,               "Add response message" },
    { CMD_MSGRESP_GET,               "Get response message" },
    { CMD_MSGRESP_MODIFY,            "Modify response message state" },
    { CMD_MSGRESP_GET_HANDLES,       "Get response message handles" },
    { CMD_IOPWR_GETINP,              "Read current digital inputs" },
    { CMD_IOPWR_GETLATCH,            "Read latched digital inputs" },
    { CMD_IOPWR_CLRLATCH,            "Read & clear latched digital inputs" },
    { CMD_IOPWR_GETOUT,              "Read digital outputs" },
    { CMD_IOPWR_SETOUT,              "Write digital outputs" },
    { CMD_IOPWR_SETBIT,              "Set indicated output bits" },
    { CMD_IOPWR_CLRBIT,              "Clear indicated output bits" },
    { CMD_IOPWR_GETPOWER,            "Read digital inputs at power on time" },
    { CMD_UTIL_SET_INIT_STRATEGY,    "Set initialization strategy" },
    { CMD_UTIL_GET_INIT_STRATEGY,    "Get initialization strategy" },
    { CMD_CNVT_GET_VALUES,           "Read one or more signal values from LIN Signal Conversion" },
    { CMD_CNVT_GET_UNITS,            "Read one or more signal units from LIN Signal Conversion" },
    { CMD_CNVT_SET_VALUES,           "Write one or more signal values for LIN Signal Conversion" },
    { CMD_CNVT_DESTROY_SESSION,      "Destroy internal LIN Signal Conversion info" },
    { CMD_CNVT_SAVE_SESSION,         "Save an internal representation of the LIN Signal Conversion" },
    { CMD_CNVT_RESTORE_SESSION,      "Restore a previously saved LIN Signal Conversion session" },
    { CMD_CNVT_GET_NODE_SIGNALS,     "Get signal names of the node defined in the LIN Signal Conversion Session" },
    { 0, NULL},
};

static value_string_ext cmd_vals_ext = VALUE_STRING_EXT_INIT(cmd_vals);

static const value_string responses_vs[] = {
    {RESP_OK,                       "OK - no error"},
    {RESP_UNKNOWN_ERR,              "Unknown error"},
    {RESP_UNKNOWN_CMD,              "Unrecognised command"},
    {RESP_UNSUPPORTED,              "Unsupported command"},
    {RESP_INVAL_CHAN,               "Invalid channel specified"},
    {RESP_INVAL_DST,                "Invalid destination"},
    {RESP_INVAL_PARAM,              "Invalid parameter(s)"},
    {RESP_INVAL_MSG,                "Invalid message"},
    {RESP_INVAL_LEN,                "Invalid length field"},
    {RESP_TX_FAIL,                  "Transmit failed"},
    {RESP_RX_FAIL,                  "Receive failed"},
    {RESP_AUTH_FAIL,                "Authorization failed"},
    {RESP_MEM_ALLOC_ERR,            "Memory allocation error"},
    {RESP_TIMEOUT,                  "Command timed out"},
    {RESP_UNAVAILABLE,              "Unavailable"},
    {RESP_BUF_FULL,                 "Buffer full"},
    {RESP_NO_SUCH_JOB,              "No such job"},
    {0,                 NULL},
};

static const value_string filter_data_types[] = {
    {FILTER_DATA_TYPE_HEADER_FRAME, "frame header"},
    {FILTER_DATA_TYPE_HEADER,       "data message header"},
    {FILTER_DATA_TYPE_DATA,         "data message data"},
    {FILTER_DATA_TYPE_EXTRA_DATA,   "data message extra data"},
    {FILTER_EVENT_TYPE_HEADER,      "event message header"},
    {FILTER_EVENT_TYPE_DATA,        "event message"},
    {0,                         NULL},
};

static const value_string operators[] = {
    {BIT_FIELD_CHECK,               "Bit field check"},
    {SVALUE_GT,                     "Greater than (signed)"},
    {SVALUE_GE,                     "Greater than or equal to (signed)"},
    {SVALUE_LT,                     "Less than (signed)"},
    {SVALUE_LE,                     "Less than or equal to (signed)"},
    {VALUE_EQ,                      "Equal to"},
    {VALUE_NE,                      "Not equal to"},
    {UVALUE_GT,                     "Greater than (unsigned)"},
    {UVALUE_GE,                     "Greater than or equal to (unsigned)"},
    {UVALUE_LT,                     "Less than (unsigned)"},
    {UVALUE_LE,                     "Less than or equal to (unsigned)"},
    {DIG_LOW_TO_HIGH,               "Digital, low to high transition"},
    {DIG_HIGH_TO_LOW,               "Digital, high to low transition"},
    {DIG_TRANSITION,                "Digital, change of state"},
    {0,                 NULL},
};

static const value_string modes[] = {
    {FILTER_OFF_PASS_ALL,           "Filter off, pass all messages"},
    {FILTER_OFF_BLOCK_ALL,          "Filter off, block all messages"},
    {FILTER_ON,                     "Filter on"},
    {0,                 NULL},
};

static const value_string filtacts[] = {
    {DELETE_FILTER,                 "Delete"},
    {ACTIVATE_FILTER,               "Activate"},
    {DEACTIVATE_FILTER,             "Deactivate"},
    {0,                 NULL},
};

static const value_string ioctls[] = {
    {GINIT,                         "GINIT: Initialize"},
    {GLOOPON,                       "GLOOPON: Loop on"},
    {GLOOPOFF,                      "GLOOPOFF: Loop off"},
    {GGETHWTYPE,                    "GGETHWTYPE: Get hardware type"},
    {GGETREG,                       "GGETREG: Get register"},
    {GSETREG,                       "GSETREG: Set register"},
    {GGETRXCOUNT,                   "GGETRXCOUNT: Get the receive message counter"},
    {GSETRXCOUNT,                   "GSETRXCOUNT: Set the receive message counter"},
    {GGETTXCOUNT,                   "GGETTXCOUNT: Get the transmit message counter"},
    {GSETTXCOUNT,                   "GSETTXCOUNT: Set the transmit message counter"},
    {GGETRXDROP,                    "GGETRXDROP: Get the number of dropped receive messages"},
    {GSETRXDROP,                    "GSETRXDROP: Set the number of dropped receive messages"},
    {GGETTXDROP,                    "GGETTXDROP: Get the number of dropped transmit messages"},
    {GSETTXDROP,                    "GSETTXDROP: Set the number of dropped transmit messages"},
    {GGETRXBAD,                     "GGETRXBAD: Get the number of bad receive messages"},
    {GGETTXBAD,                     "GGETTXBAD: Get the number of bad transmit messages"},
    {GGETCOUNTS,                    "GGETCOUNTS: Get total message counter"},
    {GGETBLMON,                     "GGETBLMON: Get bus load monitoring status"},
    {GSETBLMON,                     "GSETBLMON: Set bus load monitoring status (turn on/off)"},
    {GGETERRLEV,                    "GGETERRLEV: Get error level"},
    {GSETERRLEV,                    "GSETERRLEV: Set error level"},
    {GGETBITRATE,                   "GGETBITRATE: Get bit rate"},
    {GGETRAM,                       "GGETRAM: Read value from RAM"},
    {GSETRAM,                       "GSETRAM: Write value to RAM"},
    {GCANGETBTRS,                   "GCANGETBTRS: Read CAN bit timing registers"},
    {GCANSETBTRS,                   "GCANSETBTRS: Write CAN bit timing registers"},
    {GCANGETBC,                     "GCANGETBC: Read CAN bus configuration register"},
    {GCANSETBC,                     "GCANSETBC: Write CAN bus configuration register"},
    {GCANGETMODE,                   "GCANGETMODE"},
    {GCANSETMODE,                   "GCANSETMODE"},
    {GCANGETTRANS,                  "GCANGETTRANS"},
    {GCANSETTRANS,                  "GCANSETTRANS"},
    {GCANSENDERR,                   "GCANSENDERR"},
    {GCANRGETOBJ,                   "GCANRGETOBJ"},
    {GCANRSETSTDID,                 "GCANRSETSTDID"},
    {GCANRSETEXTID,                 "GCANRSETEXTID"},
    {GCANRSETDATA,                  "GCANRSETDATA"},
    {GCANRENABLE,                   "GCANRENABLE"},
    {GCANRDISABLE,                  "GCANRDISABLE"},
    {GCANRGETMASKS,                 "GCANRGETMASKS"},
    {GCANRSETMASKS,                 "GCANRSETMASKS"},
    {GCANSWGETMODE,                 "GCANSWGETMODE"},
    {GCANSWSETMODE,                 "GCANSWSETMODE"},
    {GDLCGETFOURX,                  "GDLCGETFOURX"},
    {GDLCSETFOURX,                  "GDLCSETFOURX"},
    {GDLCGETLOAD,                   "GDLCGETLOAD"},
    {GDLCSETLOAD,                   "GDLCSETLOAD"},
    {GDLCSENDBREAK,                 "GDLCSENDBREAK"},
    {GDLCABORTTX,                   "GDLCABORTTX"},
    {GDLCGETHDRMODE,                "DLCGETHDRMODE"},
    {GDLCSETHDRMODE,                "GDLCSETHDRMODE"},
    {GHONSLEEP,                     "GHONSLEEP"},
    {GHONSILENCE,                   "GHONSILENCE"},
    {GKWPSETPTIMES,                 "GKWPSETPTIMES"},
    {GKWPSETWTIMES,                 "GKWPSETWTIMES"},
    {GKWPDOWAKEUP,                  "GKWPDOWAKEUP"},
    {GKWPGETBITTIME,                "GKWPGETBITTIME"},
    {GKWPSETBITTIME,                "GKWPSETBITTIME"},
    {GKWPSETNODEADDR,               "GKWPSETNODEADDR"},
    {GKWPGETNODETYPE,               "GKWPGETNODETYPE"},
    {GKWPSETNODETYPE,               "GKWPSETNODETYPE"},
    {GKWPSETWAKETYPE,               "GKWPSETWAKETYPE"},
    {GKWPSETTARGADDR,               "GKWPSETTARGADDR"},
    {GKWPSETKEYBYTES,               "GKWPSETKEYBYTES"},
    {GKWPSETSTARTREQ,               "GKWPSETSTARTREQ"},
    {GKWPSETSTARTRESP,              "GKWPSETSTARTRESP"},
    {GKWPSETPROTOCOL,               "GKWPSETPROTOCOL"},
    {GKWPGETLASTKEYBYTES,           "GKWPGETLASTKEYBYTES"},
    {GKWPSETLASTKEYBYTES,           "GKWPSETLASTKEYBYTES"},
    {GSCPGETBBR,                    "GSCPGETBBR"},
    {GSCPSETBBR,                    "GSCPSETBBR"},
    {GSCPGETID,                     "GSCPGETID"},
    {GSCPSETID,                     "GSCPSETID"},
    {GSCPADDFUNCID,                 "GSCPADDFUNCID"},
    {GSCPCLRFUNCID,                 "GSCPCLRFUNCID"},
    {GUBPGETBITRATE,                "GUBPGETBITRATE"},
    {GUBPSETBITRATE,                "GUBPSETBITRATE"},
    {GUBPGETINTERBYTE,              "GUBPGETINTERBYTE"},
    {GUBPSETINTERBYTE,              "GUBPSETINTERBYTE"},
    {GUBPGETNACKMODE,               "GUBPGETNACKMODE"},
    {GUBPSETNACKMODE,               "GUBPSETNACKMODE"},
    {GUBPGETRETRYDELAY,             "GUBPGETRETRYDELAY"},
    {GUBPSETRETRYDELAY,             "GUBPSETRETRYDELAY"},
    {GRESETHC08,                    "GRESETHC08: Reset the HC08 processor"},
    {GTESTHC08COP,                  "GTESTHC08COP: Stop updating the HC08 watchdog timer"},
    {GSJAGETLISTEN,                 "GSJAGETLISTEN"},
    {GSJASETLISTEN,                 "GSJASETLISTEN"},
    {GSJAGETSELFTEST,               "GSJAGETSELFTEST"},
    {GSJASETSELFTEST,               "GSJASETSELFTEST"},
    {GSJAGETXMITONCE,               "GSJAGETXMITONCE"},
    {GSJASETXMITONCE,               "GSJASETXMITONCE"},
    {GSJAGETTRIGSTATE,              "GSJAGETTRIGSTATE"},
    {GSJASETTRIGCTRL,               "GSJASETTRIGCTRL"},
    {GSJAGETTRIGCTRL,               "GSJAGETTRIGCTRL"},
    {GSJAGETOUTSTATE,               "GSJAGETOUTSTATE"},
    {GSJASETOUTSTATE,               "GSJASETOUTSTATE"},
    {GSJAGETFILTER,                 "GSJAGETFILTER"},
    {GSJASETFILTER,                 "GSJASETFILTER"},
    {GSJAGETMASK,                   "GSJAGETMASK"},
    {GSJASETMASK,                   "GSJASETMASK"},
    {GSJAGETINTTERM,                "GSJAGETINTTERM"},
    {GSJASETINTTERM,                "GSJASETINTTERM"},
    {GSJAGETFTTRANS,                "GSJAGETFTTRANS"},
    {GSJASETFTTRANS,                "GSJASETFTTRANS"},
    {GSJAGETFTERROR,                "GSJAGETFTERROR"},
    {GLINGETBITRATE,                "GLINGETBITRATE: Get the current bit rate"},
    {GLINSETBITRATE,                "GLINSETBITRATE: Set the bit rate"},
    {GLINGETBRKSPACE,               "GLINGETBRKSPACE"},
    {GLINSETBRKSPACE,               "GLINSETBRKSPACE"},
    {GLINGETBRKMARK,                "GLINGETBRKMARK"},
    {GLINSETBRKMARK,                "GLINSETBRKMARK"},
    {GLINGETIDDELAY,                "GLINGETIDDELAY"},
    {GLINSETIDDELAY,                "GLINSETIDDELAY"},
    {GLINGETRESPDELAY,              "GLINGETRESPDELAY"},
    {GLINSETRESPDELAY,              "GLINSETRESPDELAY"},
    {GLINGETINTERBYTE,              "GLINGETINTERBYTE"},
    {GLINSETINTERBYTE,              "GLINSETINTERBYTE"},
    {GLINGETWAKEUPDELAY,            "GLINGETWAKEUPDELAY"},
    {GLINSETWAKEUPDELAY,            "GLINSETWAKEUPDELAY"},
    {GLINGETWAKEUPTIMEOUT,          "GLINGETWAKEUPTIMEOUT"},
    {GLINSETWAKEUPTIMEOUT,          "GLINSETWAKEUPTIMEOUT"},
    {GLINGETWUTIMOUT3BR,            "GLINGETWUTIMOUT3BR"},
    {GLINSETWUTIMOUT3BR,            "GLINSETWUTIMOUT3BR"},
    {GLINSENDWAKEUP,                "GLINSENDWAKEUP"},
    {GLINGETMODE,                   "GLINGETMODE"},
    {GLINSETMODE,                   "GLINSETMODE"},
    /* 20171109 lin LDF */
    {GLINGETSLEW,                   "GLINGETSLEW: get slew rate"},
    {GLINSETSLEW,                   "GLINSETSLEW: set slew rate"},
    {GLINADDSCHED,                  "GLINADDSCHED: add a LIN schedule"},
    {GLINGETSCHED,                  "GLINGETSCHED: get a LIN schedule"},
    {GLINGETSCHEDSIZE,              "GLINGETSCHEDSIZE: get schedule size"},
    {GLINDELSCHED,                  "GLINDELSCHED: delete a LIN schedule"},
    {GLINACTSCHED,                  "GLINACTSCHED: activate a LIN schedule"},
    {GLINDEACTSCHED,                "GLINDEACTSCHED: deactivate a LIN schedule"},
    {GLINGETACTSCHED,               "GLINGETACTSCHED: get active LIN schedule"},
    {GLINGETNUMSCHEDS,              "GLINGETNUMSCHED: get number of LIN schedules"},
    {GLINGETSCHEDNAMES,             "GLINGETSCHEDNAMES: get LIN schedule names"},
    {GLINGETMASTEREVENTENABLE,      "GLINGETMASTEREVENTENABLE: get LIN master schedule event enable flag"},
    {GLINSETMASTEREVENTENABLE,      "GLINSETMASTEREVENTENABLE: set LIN master schedule event enable flag"},
    {GLINGETNSLAVETABLE,            "GLINGETNSLAVETABLE: set number of LIN slave table entries"},
    {GLINGETSLAVETABLEPIDS,         "GLINGETSLAVETABLEPIDS: get list of LIN slave table PIDs"},
    {GLINGETSLAVETABLE,             "GLINGETSLAVETABLE: get LIN slave table entry for this PID"},
    {GLINSETSLAVETABLE,             "GLINSETSLAVETABLE: set LIN slave table entry for this PID"},
    {GLINCLEARSLAVETABLE,           "GLINCLEARSLAVETABLE: clear LIN slave table entry for this PID"},
    {GLINCLEARALLSLAVETABLE,        "GLINCLEARALLSLAVETABLE: clear all LIN slave table entries"},
    {GLINGETONESHOT,                "GLINGETONESHOT: get LIN one-shot entry"},
    {GLINSETONESHOT,                "GLINSETONESHOT: set LIN one-shot entry"},
    {GLINCLEARONESHOT,              "GLINCLEARONESHOT: clear LIN one-shot entry"},
    {GLINSETFLAGS,                  "GLINSETFLAGS"},
    {GLINGETAUTOCHECKSUM,           "GLINGETAUTOCHECKSUM: get LIN auto checksum"},
    {GLINSETAUTOCHECKSUM,           "GLINSETAUTOCHECKSUM: set LIN auto checksum"},
    {GLINGETAUTOPARITY,             "GLINGETAUTOPARITY: get LIN auto parity"},
    {GLINSETAUTOPARITY,             "GLINSETAUTOPARITY: set LIN auto parity"},
    {GLINGETSLAVETABLEENABLE,       "GLINGETSLAVETABLEENABLE: get LIN slave table enable"},
    {GLINSETSLAVETABLEENABLE,       "GLINSETSLAVETABLEENABLE: set LIN slave table enable"},
    {GLINGETFLAGS,                  "GLINGETFLAGS"},
    {GLINGETWAKEUPMODE,             "GLINGETWAKEUPMODE: get LIN wakeup mode"},
    {GLINSETWAKEUPMODE,             "GLINSETWAKEUPMODE: set LIN wakeup mode"},
    {GDLYGETHIVALUE,                "GDLYGETHIVALUE: get the high water value"},
    {GDLYSETHIVALUE,                "GDLYSETHIVALUE: set the high water value"},
    {GDLYGETLOVALUE,                "GDLYGETLOVALUE: get the low water value"},
    {GDLYSETLOVALUE,                "GDLYSETLOVALUE: set the low water value"},
    {GDLYGETHITIME,                 "GDLYGETHITIME: get the high water time"},
    {GDLYSETHITIME,                 "GDLYSETHITIME: set the high water time"},
    {GDLYGETLOTIME,                 "GDLYGETLOTIME: get the low water time"},
    {GDLYSETLOTIME,                 "GDLYSETLOTIME: set the low water time"},
    {GDLYGETLOREPORT,               "GDLYGETLOREPORT:get the low water report flag"},
    {GDLYFLUSHSTREAM,               "GDLYFLUSHSTREAM: flush the delay buffer"},
    {GDLYINITSTREAM,                "GDLYINITSTREAM: set default hi & lo water marks"},
    {GDLYPARTIALFLUSHSTREAM,        "GDLYPARTIALFLUSHSTREAM: flush the delay buffer"},
    {GINPGETINP,                    "GINPGETINP: Read current digital inputs"},
    {GINPGETLATCH,                  "GINPGETLATCH: Read latched digital inputs"},
    {GINPCLRLATCH,                  "GINPCLRLATCH: Read and clear latched digital inputs"},
    {GOUTGET,                       "GOUTGET: Read digital outputs"},
    {GOUTSET,                       "GOUTSET: Write digital outputs"},
    {GOUTSETBIT,                    "GOUTSETBIT: Set digital output bits"},
    {GOUTCLEARBIT,                  "GOUTCLEARBIT"},
    {GPWRGETWHICH,                  "GPWRGETWHICH"},
    {GPWROFF,                       "GPWROFF"},
    {GPWROFFRESET,                  "GPWROFFRESET"},
    {GPWRRESET,                     "GPWRRESET"},
    {0,                         NULL},
};


static const value_string cmd_sort_type[] = {
    {0,         "Do not sort messages"},
    {1,         "Sort into blocks of up to 16 messages"},
    {0,         NULL}
};

static const value_string protocol_types[] = {
    {GDUMMY * 256 + GDGDMARKONE,              "Dummy device driver"},
    {GCAN * 256 + G82527,                     "CAN, 82527 subtype"},
    {GCAN * 256 + GSJA1000,                   "CAN, SJA1000 subtype"},
    {GCAN * 256 + G82527SW,                   "CAN, 82527 single wire subtype"},
    {GCAN * 256 + G82527ISO11992,             "CAN, 82527 ISO11992 subtype"},
    {GCAN * 256 + G82527_SINGLECHAN,          "CAN, Fiber Optic 82527 subtype"},
    {GCAN * 256 + G82527SW_SINGLECHAN,        "CAN, Fiber Optic 82527 single wire subtype"},
    {GCAN * 256 + G82527ISO11992_SINGLECHAN,  "CAN, Fiber Optic ISO11992 subtype"},
    {GCAN * 256 + GSJA1000FT,                 "CAN, SJA1000 Fault Tolerant subtype"},
    {GCAN * 256 + GSJA1000C,                  "CAN, SJA1000 onboard subtype"},
    {GCAN * 256 + GSJA1000FT_FO,              "CAN, SJA1000 Fiber Optic Fault Tolerant subtype"},
    {GCAN * 256 + GSJA1000_BEACON_CANFD,      "CAN, SJA1000 BEACON CAN-FD subtype"},
    {GCAN * 256 + GSJA1000_BEACON_SW,         "CAN, SJA1000 BEACON CAN single wire subtype"},
    {GCAN * 256 + GSJA1000_BEACON_FT,         "CAN, SJA1000 BEACON CAN Fault Tolerant subtype"},
    {GJ1850 * 256 + GHBCCPAIR,                "J1850, HBCC subtype"},
    {GJ1850 * 256 + GDLC,                     "J1850, GM DLC subtype"},
    {GJ1850 * 256 + GCHRYSLER,                "J1850, Chrysler subtype"},
    {GJ1850 * 256 + GDEHC12,                  "J1850, DE HC12 KWP/BDLC subtype"},
    {GKWP2000 * 256 + GDEHC12KWP,             "Keyword protocol 2000/ISO 9141"},
    {GHONDA * 256 + GDGHC08,                  "Honda UART, DG HC08 subtype"},
    {GFORDUBP * 256 + GDGUBP08,               "Ford UBP, DG HC08 subtype"},
    {GSCI * 256 + G16550SCI,                  "Chrysler SCI, UART subtype"},
    {GCCD * 256 + G16550CDP68HC68,            "Chrysler C2D, UART / CDP68HC68S1 subtype"},
    {GLIN * 256 + GDGLIN08,                   "LIN, DG HC08 subtype"},
    {GLIN * 256 + GDGLIN_BEACON,              "LIN, BEACON LIN updated subtype"},
    {0,                             NULL},
};

/* Note: using external tfs strings doesn't work in a plugin */
static const true_false_string tfs_wait_response = { "Wait", "Don't Wait" };
static const true_false_string true_false = { "True", "False" };
static const true_false_string register_unregister_action_flags = { "Register", "Unregister" };
static const true_false_string tfs_passed_blocked = { "Pass", "Block" };
static const true_false_string active_inactive = { "Active", "Inactive" };
static const true_false_string critical_normal = { "Critical", "Normal" };
static const true_false_string skip_not_skip = { "Skip", "Do not skip" };
static const true_false_string frames_01seconds = { "Frames", "0.01 seconds" };
static const true_false_string present_not_present = { "Present", "Not present" };
static const true_false_string yes_no = { "Yes", "No" };
static const true_false_string set_not_set = { "Set", "Not set" };

/*
 * returns 1 if the ID is one of the special servers
 * return 0 otherwise
 */
static int is_special_client(guint32 id)
{
    if((id == SD_SERVER) || (id == SD_CLIENT)) {
        return 1;
    }
    return 0;
}

static int
decode_data(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree  *tree;
    int         hdrsize, datasize, extrasize, msgsize, padding;
    nstime_t    timestamp;
    /*int       hdrbits;*/

    static int * const data_mode_flags[] = {
        &hf_gryphon_data_mode_transmitted,
        &hf_gryphon_data_mode_receive,
        &hf_gryphon_data_mode_local,
        &hf_gryphon_data_mode_remote,
        &hf_gryphon_data_mode_oneshot,
        &hf_gryphon_data_mode_combined,
        &hf_gryphon_data_mode_nomux,
        &hf_gryphon_data_mode_internal,
        NULL
    };

    hdrsize   = tvb_get_guint8(tvb, offset+0);
    /* hdrbits   = tvb_get_guint8(tvb, offset+1); */
    datasize  = tvb_get_ntohs(tvb, offset+2);
    extrasize = tvb_get_guint8(tvb, offset+4);
    padding   = 3 - (hdrsize + datasize + extrasize + 3) % 4;
    msgsize   = hdrsize + datasize + extrasize + padding + 16;

    tree = proto_tree_add_subtree(pt, tvb, offset, 16, ett_gryphon_data_header, NULL, "Message header");

    /* fixed major problem with header length, length is 1-byte not 2-bytes */
    proto_tree_add_item(tree, hf_gryphon_data_header_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_data_header_length_bits, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_data_data_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_data_extra_data_length, tvb, offset+4, 1, ENC_BIG_ENDIAN);

    /* 20171012 always display mode bits, not just conditionally */
    proto_tree_add_bitmask(tree, tvb, offset+5, hf_gryphon_data_mode, ett_gryphon_flags, data_mode_flags, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gryphon_data_priority, tvb, offset+6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_data_error_status, tvb, offset+7, 1, ENC_BIG_ENDIAN);

    timestamp.secs = tvb_get_ntohl(tvb, offset+8)/100000;
    timestamp.nsecs = (tvb_get_ntohl(tvb, offset+8)%100000)*1000;
    proto_tree_add_time(tree, hf_gryphon_data_time, tvb, offset+8, 4, &timestamp);

    proto_tree_add_item(tree, hf_gryphon_data_context, tvb, offset+12, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_reserved, tvb, offset+13, 3, ENC_NA);
    offset += 16;

    tree = proto_tree_add_subtree(pt, tvb, offset, msgsize-16-padding, ett_gryphon_data_body, NULL, "Message Body");
    if (hdrsize) {
        proto_tree_add_item(tree, hf_gryphon_data_header_data, tvb, offset, hdrsize, ENC_NA);
        offset += hdrsize;
    }
    if (datasize) {
        proto_tree_add_item(tree, hf_gryphon_data_data, tvb, offset, datasize, ENC_NA);
        offset += datasize;
    }
    if (extrasize) {
        proto_tree_add_item(tree, hf_gryphon_data_extra_data, tvb, offset, extrasize, ENC_NA);
        offset += extrasize;
    }
    if (padding) {
        proto_tree_add_item(tree, hf_gryphon_data_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    /*proto_tree_add_debug_text(pt, "decode_data() debug offset=%d msgsize=%d", offset, msgsize);*/
    return offset;
}

static int
decode_event(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen, msgend, padding, length;
    nstime_t        timestamp;

    msglen = tvb_reported_length_remaining(tvb, offset);
    padding = 3 - (msglen + 3) % 4;
    msgend = offset + msglen;

    proto_tree_add_item(pt, hf_gryphon_event_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_event_context, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+2, 2, ENC_NA);
    offset += 4;

    timestamp.secs = tvb_get_ntohl(tvb, offset)/100000;
    timestamp.nsecs = (tvb_get_ntohl(tvb, offset)%100000)*1000;
    proto_tree_add_time(pt, hf_gryphon_event_time, tvb, offset, 4, &timestamp);
    offset += 4;

    if (offset < msgend) {
        length = msgend - offset;
        proto_tree_add_item(pt, hf_gryphon_event_data, tvb, offset, length, ENC_NA);
        offset += length;
    }
    if (padding) {
        proto_tree_add_item(pt, hf_gryphon_event_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    return offset;
}

static int
decode_misc (tvbuff_t *tvb, int offset, packet_info* pinfo, proto_tree *pt)
{
    tvbuff_t    *next_tvb;

    /* proto_tree_add_debug_text(pt, "decode_misc() debug a offset=%d msglen=%d",offset, msglen); */
    while(tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
         * 20180221
         * This function is called because Gryphon Protocol MISC packets contain within
         * them Gryphon Protocol packets (including possibly MISC packets!). So, this
         * function decodes that packet and return the offset. Loop thru all such packets
         * in the MISC packet.
         */

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        offset += dissect_gryphon_message(next_tvb, pinfo, pt, TRUE);
    }
    return offset;
}

static int
decode_text (tvbuff_t *tvb, int offset, int msglen, proto_tree *pt)
{
    int       padding, length;

    padding = 3 - (msglen + 3) % 4;

    proto_tree_add_item_ret_length(pt, hf_gryphon_misc_text, tvb, offset, -1, ENC_NA|ENC_ASCII, &length);
    offset += length;
    if (padding) {
        proto_tree_add_item(pt, hf_gryphon_misc_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    return offset;
}

static int
cmd_init(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 mode = tvb_get_guint8(tvb, offset);

    if (mode == 0)
        proto_tree_add_uint_format_value(pt, hf_gryphon_cmd_mode, tvb, offset, 1, mode,  "Always initialize");
    else
        proto_tree_add_uint_format_value(pt, hf_gryphon_cmd_mode, tvb, offset, 1, mode,  "Initialize if not previously initialized");
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}
static int
eventnum(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 event = tvb_get_guint8(tvb, offset);

    if (event)
        proto_tree_add_item(pt, hf_gryphon_eventnum, tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_uint_format_value(pt, hf_gryphon_eventnum, tvb, offset, 1, 0, "All Events.");
    offset += 1;
    return offset;
}

static int
resp_time(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint64         val;
    nstime_t        timestamp;

    val = tvb_get_ntoh64(tvb, offset);
    timestamp.secs = (time_t)(val/100000);
    timestamp.nsecs = (int)((val%100000)*1000);

    proto_tree_add_time(pt, hf_gryphon_resp_time, tvb, offset, 8, &timestamp);
    offset += 8;

    return offset;
}

static int
cmd_setfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int    flag = tvb_get_ntohl(tvb, offset);
    int    length, padding;

    length =  tvb_get_guint8(tvb, offset+4) + tvb_get_guint8(tvb, offset+5)
        + tvb_get_ntohs(tvb, offset+6);

    proto_tree_add_uint_format_value(pt, hf_gryphon_setfilt, tvb, offset, 4,
        flag, "%s%s", ((flag) ? "Pass" : "Block"), ((length == 0) ? " all" : ""));
    proto_tree_add_uint(pt, hf_gryphon_setfilt_length, tvb, offset+4, 4, length);
    offset += 8;
    if (length) {
        proto_tree_add_item(pt, hf_gryphon_setfilt_discard_data, tvb, offset, length * 2, ENC_NA);
        offset += length * 2;
    }
    padding = 3 - (length * 2 + 3) % 4;
    if (padding) {
        proto_tree_add_item(pt, hf_gryphon_setfilt_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    return offset;
}

static int
cmd_ioctl_details(tvbuff_t *tvb, int offset, proto_tree *pt, guint32 ui_command, int msglen)
{
    char *string;
    int length;
    gint32 nbytes;
    gint32 block_nbytes;
    gint16 us_stream;
    gint16 us_value;
    proto_tree  *tree;
    unsigned int msg;
    guint8 number_ids;
    guint8 number_bytes;
    guint8 number_extra_bytes;
    guint8 flags;
    guint8 pid;
    guint8 datalen;
    guint8 extralen;
    int i;
    guint32 mtime;
    guint16 us_nsched;
    float value;
    static int * const ldf_schedule_flags[] = {
        &hf_gryphon_ldf_schedule_event,
        &hf_gryphon_ldf_schedule_sporadic,
        NULL
    };

    /* TODO Gryphon Protocol has LOTS more ioctls, for CANbus, etc. */
    /* 20171109 mc */
    switch(ui_command) {
    case GLINDEACTSCHED:
        {
            /* 20180104 done */
        }
        break;
    case GLINACTSCHED:
        {
            /* schedule name */
            proto_tree_add_item(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
        }
        break;
    case GLINGETNUMSCHEDS:
        {
        /* 20180227 */
        us_nsched = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_sched_numb_place, tvb, offset, 2, us_nsched, "%d", us_nsched);
        offset += 2;
        }
        break;
    case GLINGETSCHEDNAMES:
        {
        nbytes = tvb_reported_length_remaining(tvb, offset);
        while(nbytes > 0)
        {
            /* schedule name */
            proto_tree_add_item(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
            offset += 32;
            nbytes -= 32;
        }
        }
        break;
    case GLINGETSCHED:
        {
        /* 20180227 */
        nbytes = tvb_get_letohl(tvb, offset);
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_sched_size, tvb, offset, 4, nbytes, "%d", nbytes);
        offset += 4;
        /* schedule name */
        proto_tree_add_item(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset += 32;

        /* delay time */
        mtime = tvb_get_letohl(tvb, offset);
        value = (float)mtime / (float)10.0;
        proto_tree_add_float_format_value(pt, hf_gryphon_init_strat_delay, tvb, offset, 4, value, "%.1f milliseconds", value);
        offset += 4;

        number_ids = tvb_get_guint8(tvb, offset);

        /* header length, number of IDs to follow */
        proto_tree_add_item(pt, hf_gryphon_data_header_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        number_bytes = tvb_get_guint8(tvb, offset);
        number_bytes &= 0x0F; /* bit0 thru bit3 */

        /* data length, number data bytes to follow */
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_schedule_msg_dbytes, tvb, offset, 1, number_bytes, "%d", number_bytes);
        /* sporadic, event-driven flags */
        proto_tree_add_bitmask(pt, tvb, offset, hf_gryphon_ldf_schedule_flags, ett_gryphon_flags, ldf_schedule_flags, ENC_BIG_ENDIAN);
        offset += 1;

        /* id's */
        proto_tree_add_item(pt, hf_gryphon_data_header_data, tvb, offset, number_ids, ENC_NA);
        offset += number_ids;
        proto_tree_add_item(pt, hf_gryphon_data_data, tvb, offset, number_bytes, ENC_NA);
        offset += number_bytes;
        }
        break;
    case GLINGETSCHEDSIZE:
        {
        /* 20180227 */
        nbytes = tvb_get_letohl(tvb, offset);
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_sched_size_place, tvb, offset, 4, nbytes, "%d", nbytes);
        offset += 4;
        /* schedule name */
        proto_tree_add_item(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset += 32;
        }
        break;
    case GLINDELSCHED:
        {
        string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &length, ENC_ASCII);
        /*proto_tree_add_debug_text(pt, "cmd_ioctl_details() debug offset=%d length=%d string='%s'",offset,length,string); */
        if(string[0] == '\0') {
            proto_tree_add_string(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, "All schedules");
        } else {
            proto_tree_add_string(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, string);
        }
        offset += 32;
        }
        break;
    case GLINADDSCHED:
        {
        /* 20180227 */
        /* number of bytes to follow */
        nbytes = tvb_get_letohl(tvb, offset);
        /*proto_tree_add_item(pt, hf_gryphon_ioctl_nbytes, tvb, offset, 4, ENC_BIG_ENDIAN);*/
        proto_tree_add_uint_format_value(pt, hf_gryphon_ioctl_nbytes, tvb, offset, 4, nbytes, "%d", nbytes);
        offset += 4;
        nbytes -= 4;
        /* schedule name */
        proto_tree_add_item(pt, hf_gryphon_ldf_schedule_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset += 32;
        nbytes -= 32;

        /* messages */
        msg = 1;
        while(nbytes > 0) {

            /* calc the number of bytes in this block */
            number_ids = tvb_get_guint8(tvb, offset+4);
            number_bytes = tvb_get_guint8(tvb, offset+5);

            number_bytes &= 0x0F; /* bit0 thru bit3 */
            block_nbytes = 4 + 1 + 1 + number_ids + number_bytes;

            /* message number */
            tree = proto_tree_add_subtree_format(pt, tvb, offset, block_nbytes, ett_gryphon_lin_schedule_msg, NULL, "LIN message %u", msg);

            /* delay time */
            /*mtime = tvb_get_ntohl(tvb, offset);*/
            mtime = tvb_get_letohl(tvb, offset);
            value = (float)mtime / (float)10.0;
            proto_tree_add_float_format_value(tree, hf_gryphon_init_strat_delay, tvb, offset, 4, value, "%.1f milliseconds", value);
            offset += 4;

            /* header length, number of IDs to follow */
            proto_tree_add_item(tree, hf_gryphon_data_header_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            /* data length, number data bytes to follow */
            /*proto_tree_add_item(tree, hf_gryphon_data_data_length, tvb, offset, 1, ENC_BIG_ENDIAN);*/
            proto_tree_add_uint_format_value(tree, hf_gryphon_ldf_schedule_msg_dbytes, tvb, offset, 1, number_bytes, "%d", number_bytes);
            /* sporadic, event-driven flags */
            proto_tree_add_bitmask(tree, tvb, offset, hf_gryphon_ldf_schedule_flags, ett_gryphon_flags, ldf_schedule_flags, ENC_BIG_ENDIAN);
            offset += 1;

            /* id's */
            proto_tree_add_item(tree, hf_gryphon_data_header_data, tvb, offset, number_ids, ENC_NA);
            offset += number_ids;
            proto_tree_add_item(tree, hf_gryphon_data_data, tvb, offset, number_bytes, ENC_NA);
            offset += number_bytes;

            nbytes -= block_nbytes;
            msg++;
            /* proto_tree_add_debug_text(pt, "cmd_ioctl_details() debug offset=%d msglen=%d nbytes=%d",offset,msglen,nbytes);*/
        }
        }
        break;
    case GLINSETFLAGS:
        {
            /* 20171113 */
            proto_tree_add_item(pt, hf_gryphon_ldf_ioctl_setflags, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            number_ids = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_ldf_numb_ids, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            for(i = 0; i < number_ids; i++) {
                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, flags, "0x%x %s",i,flags==0 ? "Classic checksum" : (flags==0x80?"Enhanced checksum":(flags==0x40?"Event":"UNKNOWN")));
                offset += 1;
            }
        }
        break;
    case GLINSETBITRATE:
        {
            /* 20180227 */
            /* 20171113 */
            mtime = tvb_get_letohl(tvb, offset);
            value = (float)mtime / (float)1000.0;
            proto_tree_add_float_format_value(pt, hf_gryphon_ldf_bitrate, tvb, offset, 4, value, "%.3f Kbps", value);
            offset += 4;
        }
        break;
    case GLINGETNSLAVETABLE:
        {
            /* 20180104 */
            proto_tree_add_item(pt, hf_gryphon_ldf_numb_ids, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        break;
    case GLINGETSLAVETABLEPIDS:
        {
            /* 20180104 */
            number_ids = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_ldf_numb_ids, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            for(i = 0; i < number_ids; i++) {
                pid = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, pid, "0x%x ",pid);
                offset += 1;
            }
        }
        break;
    case GLINGETSLAVETABLE:
        {
            /* 20180104 */
            /*
             * byte 0: PID
             * byte 1: datalen
             * byte 2: extralen
             * byte 3: enabled=1 or disabled=0, 2=has one-shot
             * byte 4: good cs=0 or bad cs=1
             * byte 5-13: data[datalen]
             * byte n: checksum
             */
            pid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, pid, "0x%02x ",pid);
            offset += 1;
            datalen = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_lin_data_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            extralen = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_data_extra_data_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(pt, hf_gryphon_lin_slave_table_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(pt, hf_gryphon_lin_slave_table_cs, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if(datalen != 0) {
                proto_tree_add_item(pt, hf_gryphon_lin_slave_table_data, tvb, offset, datalen, ENC_NA);
                offset += datalen;
            }
            if(extralen != 0) {
                proto_tree_add_item(pt, hf_gryphon_lin_slave_table_datacs, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;
    case GLINSETSLAVETABLE:
        {
            /* 20180104 */
            /*
             * byte 0: PID
             * byte 1: datalen
             * byte 2: extralen
             * byte 3: enabled=1 or disabled=0
             * byte 4-12: data[datalen]
             * byte n: checksum
             */
            pid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, pid, "0x%02x ",pid);
            offset += 1;
            datalen = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_lin_data_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            extralen = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(pt, hf_gryphon_data_extra_data_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(pt, hf_gryphon_lin_slave_table_enable, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if(datalen != 0) {
                proto_tree_add_item(pt, hf_gryphon_lin_slave_table_data, tvb, offset, datalen, ENC_NA);
                offset += datalen;
            }
            if(extralen != 0) {
                proto_tree_add_item(pt, hf_gryphon_lin_slave_table_datacs, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;
    case GLINCLEARSLAVETABLE:
        {
            /* 20180104 done */
            pid = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, pid, "0x%02x ",pid);
            offset += 1;
        }
        break;
    case GLINCLEARALLSLAVETABLE:
        {
            /* 20180104 done */
        }
        break;
    case GLINGETMASTEREVENTENABLE:
    case GLINSETMASTEREVENTENABLE:
        {
            /* 20180227 */
            proto_tree_add_item(pt, hf_gryphon_lin_masterevent, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        break;
    case GLINGETONESHOT:
    case GLINSETONESHOT:
        {
            /* 20180104 */
            /* 20180228 */
            number_bytes = tvb_get_guint8(tvb, offset+1);
            number_extra_bytes = tvb_get_guint8(tvb, offset+2);
            /* id */
            proto_tree_add_item(pt, hf_gryphon_data_header_data, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(pt, hf_gryphon_lin_numdata, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(pt, hf_gryphon_lin_numextra, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if (number_bytes) {
                proto_tree_add_item(pt, hf_gryphon_data_data, tvb, offset, number_bytes, ENC_NA);
                offset += number_bytes;
            }
            if (number_extra_bytes) {
                proto_tree_add_item(pt, hf_gryphon_data_extra_data, tvb, offset, number_extra_bytes, ENC_NA);
                offset += number_extra_bytes;
            }
        }
        break;
    case GLINCLEARONESHOT:
        {
            /* 20180104 */
            /* 20180227 done */
        }
        break;
    case GDLYGETHIVALUE:
    case GDLYSETHIVALUE:
    case GDLYGETLOVALUE:
    case GDLYSETLOVALUE:
        {
            /* 20180227 */
            /* 20180104 */
            us_stream = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_dd_stream, tvb, offset, 2, us_stream, "%d (0x%04X)", us_stream, us_stream);
            offset += 2;
            us_value = tvb_get_letohs(tvb, offset);
            /* proto_tree_add_item(pt, hf_gryphon_dd_value, tvb, offset, 2, ENC_BIG_ENDIAN);*/
            proto_tree_add_uint_format_value(pt, hf_gryphon_dd_value, tvb, offset, 2, us_value, "%d (0x%04X)", us_value, us_value);
            offset += 2;
        }
        break;
    case GDLYGETHITIME:
    case GDLYSETHITIME:
    case GDLYGETLOTIME:
    case GDLYSETLOTIME:
        {
            /* 20180227 */
            /* 20180104 */
            us_stream = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_dd_stream, tvb, offset, 2, us_stream, "%d (0x%04X)", us_stream, us_stream);
            offset += 2;
            mtime = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint_format_value(pt, hf_gryphon_dd_time, tvb, offset, 2, mtime, "%d", mtime);
            offset += 2;
        }
        break;
/* TODO implement remaining delay driver ioctls */
#if 0
    case GDLYGETLOREPORT: /*get the low water report flag*/
        break;
    case GDLYFLUSHSTREAM: /*flush the delay buffer*/
        break;
    case GDLYINITSTREAM: /*set default hi & lo water marks*/
        break;
    case GDLYPARTIALFLUSHSTREAM: /*flush the delay buffer */
        break;
#endif
    default:
        proto_tree_add_item(pt, hf_gryphon_ioctl_data, tvb, offset, msglen, ENC_NA);
        offset += msglen;
        break;
    }
    return offset;
}

/*
 * cmd_ioctl() performs the initial decode of the IOCTL command, then
 * calls cmd_ioctl_details()
 */
static int
cmd_ioctl(tvbuff_t *tvb, int offset, proto_tree *pt, guint32 ui_command)
{
    int  msglen;
    /*guint32 ioctl;*/
    int    padding;

    msglen = tvb_reported_length_remaining(tvb, offset);
    /* 20171109 mc */
    /*ioctl = tvb_get_ntohl(tvb, offset);*/

    /* 20171012 debug */
    /*proto_tree_add_debug_text(pt, "cmd_ioctl() debug offset=%d msglen=%d",offset,msglen);*/
    proto_tree_add_item(pt, hf_gryphon_ioctl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    msglen -= 4;

    if (msglen > 0) {
        offset = cmd_ioctl_details(tvb, offset, pt, ui_command,  msglen);
    }

    padding = tvb_reported_length_remaining(tvb, offset);
    /*proto_tree_add_debug_text(pt, "cmd_ioctl() debug offset=%d msglen=%d padding=%d",offset,msglen,padding);*/
    if (padding > 0) {
        proto_tree_add_item(pt, hf_gryphon_setfilt_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    return offset;
}

/*
 * cmd_ioctl_resp()
 * displays the IOCTL data in the IOCTL response to the IOCTL request
 * Here is an issue with the IOCTLs. The IOCTL request contains the IOCTL number,
 * but the IOCTL response does not contain the number. IOCTL response
 * contains the context byte of the request, so application software can match
 * the IOCTL response to the request.
 */
static int
cmd_ioctl_resp(tvbuff_t *tvb, int offset, proto_tree *pt, guint32 ui_command)
{
    int  msglen = tvb_reported_length_remaining(tvb, offset);

    /* 20171012 debug */
    /*proto_tree_add_debug_text(pt, "cmd_ioctl_resp() debug offset=%d msglen=%d",offset,msglen);*/

    if (msglen > 0) {
        /*proto_tree_add_item(pt, hf_gryphon_ioctl_data, tvb, offset, msglen, ENC_NA);*/
        /*offset += msglen;*/
        offset = cmd_ioctl_details(tvb, offset, pt, ui_command,  msglen);
    }
    return offset;
}

static int
filter_block(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint32 op, length, padding;

    /* 20171017 fixed display of filter block padding */

    /* start 2bytes */
    proto_tree_add_item(pt, hf_gryphon_filter_block_filter_start, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* length 2bytes */
    proto_tree_add_item_ret_uint(pt, hf_gryphon_filter_block_filter_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    offset += 2;

    /* type 1byte */
    proto_tree_add_item(pt, hf_gryphon_filter_block_filter_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* operator 1byte */
    proto_tree_add_item_ret_uint(pt, hf_gryphon_filter_block_filter_operator, tvb, offset, 1, ENC_BIG_ENDIAN, &op);
    offset += 1;

    /* rsvd 2bytes */
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    if (op == BIT_FIELD_CHECK) {
        proto_tree_add_item(pt, hf_gryphon_filter_block_pattern, tvb, offset, length, ENC_NA);
        proto_tree_add_item(pt, hf_gryphon_filter_block_mask, tvb, offset + length, length, ENC_NA);

        offset += length * 2;
        padding = (length * 2) % 4;
        if (padding) {
            proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
    }
    else {
        switch (length) {
        case 1:
            proto_tree_add_item(pt, hf_gryphon_filter_block_filter_value1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 2:
            proto_tree_add_item(pt, hf_gryphon_filter_block_filter_value2, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case 4:
            proto_tree_add_item(pt, hf_gryphon_filter_block_filter_value4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        default:
            proto_tree_add_item(pt, hf_gryphon_filter_block_filter_value_bytes, tvb, offset, length, ENC_NA);
            offset += length;
        }

        padding = 3 - ((length + 3) % 4);
        if (padding) {
            proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
    }
    return offset;
}

static int
cmd_addfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree  *tree;
    int         blocks, i, length;
    int padding;

    tree = proto_tree_add_subtree(pt, tvb, offset, 1, ett_gryphon_flags, NULL, "Flags");
    proto_tree_add_item(tree, hf_gryphon_addfilt_pass, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_addfilt_active, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    blocks = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_addfilt_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 6, ENC_NA);
    offset += 7;

    for (i = 1; i <= blocks; i++) {
        length = tvb_get_ntohs(tvb, offset+2) + 8;
        /*length += 3 - (length + 3) % 4; */
        padding = 3 - (length + 3) % 4;
        tree = proto_tree_add_subtree_format(pt, tvb, offset, length + padding, ett_gryphon_cmd_filter_block, NULL, "Filter block %d", i);
        offset = filter_block(tvb, offset, tree);
    }
    return offset;
}

static int
resp_addfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_addfilt_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
cmd_modfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 filter_handle = tvb_get_guint8(tvb, offset);

    if (filter_handle)
        proto_tree_add_item(pt, hf_gryphon_modfilt, tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_uint_format_value(pt, hf_gryphon_modfilt, tvb, offset, 1,
                0, "Filter handles: all");

    proto_tree_add_item(pt, hf_gryphon_modfilt_action, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+2, 2, ENC_NA);
    offset += 4;
    return offset;
}

static int
resp_filthan(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int     handles = tvb_get_guint8(tvb, offset);
    int     i, padding, handle;

    proto_tree_add_item(pt, hf_gryphon_filthan, tvb, offset, 1, ENC_BIG_ENDIAN);
    for (i = 1; i <= handles; i++){
        handle = tvb_get_guint8(tvb, offset+i);
        proto_tree_add_uint_format_value(pt, hf_gryphon_filthan_id, tvb, offset+i, 1,
        handle, "Handle %d: %u", i, handle);
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
        proto_tree_add_item(pt, hf_gryphon_filthan_padding, tvb, offset+1+handles, padding, ENC_NA);
    offset += 1+handles+padding;
    return offset;
}

static int
dfiltmode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_dfiltmode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
filtmode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_filtmode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
resp_events(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;
    unsigned int    i;
    proto_tree      *tree;

    msglen = tvb_reported_length_remaining(tvb, offset);
    i = 1;
    while (msglen != 0) {
        tree = proto_tree_add_subtree_format(pt, tvb, offset, 20, ett_gryphon_cmd_events_data, NULL, "Event %d:", i);
        proto_tree_add_item(tree, hf_gryphon_event_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gryphon_event_name, tvb, offset+1, 19, ENC_NA|ENC_ASCII);
        offset += 20;
        msglen -= 20;
        i++;
    }
    return offset;
}

static int
cmd_register(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_register_username, tvb, offset, 16, ENC_NA|ENC_ASCII);
    offset += 16;
    proto_tree_add_item(pt, hf_gryphon_register_password, tvb, offset, 32, ENC_NA|ENC_ASCII);
    offset += 32;
    return offset;
}

static int
resp_register(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_register_client_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_register_privileges, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+2, 2, ENC_NA);
    offset += 4;
    return offset;
}


static int
resp_getspeeds(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int indx,
        size = tvb_get_guint8(tvb, offset+8),
        number = tvb_get_guint8(tvb, offset+9);

    proto_tree_add_item(pt, hf_gryphon_getspeeds_set_ioctl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_getspeeds_get_ioctl, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_getspeeds_size, tvb, offset+8, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_getspeeds_preset, tvb, offset+9, 1, ENC_BIG_ENDIAN);
    offset += 10;

    for (indx = 1; indx <= number; indx++) {
        proto_tree_add_bytes_format(pt, hf_gryphon_getspeeds_data, tvb, offset, size,
                tvb_get_ptr(tvb, offset, size), "Data for preset %d", indx);
        offset += size;
    }
    return offset;
}

static int
cmd_sort(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_cmd_sort, tvb, offset, 1, ENC_BIG_ENDIAN);
    return (offset+1);
}

static int
cmd_optimize(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_cmd_optimize, tvb, offset, 1, ENC_BIG_ENDIAN);
    return (offset+1);
}

static int
resp_config(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree   *ft, *tree;
    int          devices;
    int          i;
    unsigned int j, x;

    proto_tree_add_item(pt, hf_gryphon_config_device_name, tvb, offset, 20, ENC_NA|ENC_ASCII);
    offset += 20;

    proto_tree_add_item(pt, hf_gryphon_config_device_version, tvb, offset, 8, ENC_NA|ENC_ASCII);
    offset += 8;

    proto_tree_add_item(pt, hf_gryphon_config_device_serial_number, tvb, offset, 20, ENC_NA|ENC_ASCII);
    offset += 20;

    devices = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(pt, hf_gryphon_config_num_channels, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_config_name_version_ext, tvb, offset+1, 11, ENC_NA|ENC_ASCII);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+12, 4, ENC_NA);
    offset += 16;

    for (i = 1; i <= devices; i++) {
        ft = proto_tree_add_subtree_format(pt, tvb, offset, 80, ett_gryphon_cmd_config_device, NULL, "Channel %d:", i);

        proto_tree_add_item(ft, hf_gryphon_config_driver_name, tvb, offset, 20, ENC_NA|ENC_ASCII);
        offset += 20;

        proto_tree_add_item(ft, hf_gryphon_config_driver_version, tvb, offset, 8, ENC_NA|ENC_ASCII);
        offset += 8;

        proto_tree_add_item(ft, hf_gryphon_config_device_security, tvb, offset, 16, ENC_NA|ENC_ASCII);
        offset += 16;

        x = tvb_get_ntohl (tvb, offset);
        if (x) {
            tree = proto_tree_add_subtree(ft, tvb, offset, 4, ett_gryphon_valid_headers, NULL, "Valid Header lengths");
            for (j = 0; ; j++) {
                if (x & 1) {
                    proto_tree_add_uint_format(tree, hf_gryphon_valid_header_length, tvb, offset, 4, j, "%d byte%s", j,
                    j == 1 ? "" : "s");
                }
                if ((x >>= 1) == 0)
                    break;
            }
        }
        offset += 4;

        proto_tree_add_item(ft, hf_gryphon_config_max_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ft, hf_gryphon_config_min_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ft, hf_gryphon_config_hardware_serial_number, tvb, offset, 20, ENC_NA|ENC_ASCII);
        offset += 20;

        proto_tree_add_item(ft, hf_gryphon_config_protocol_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ft, hf_gryphon_config_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(ft, hf_gryphon_config_card_slot_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;

        proto_tree_add_item(ft, hf_gryphon_config_max_extra_data, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ft, hf_gryphon_config_min_extra_data, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

    }
    return offset;
}

static int
cmd_sched(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;
    proto_item      *item, *item1;
    proto_tree      *tree, *tree1;
    int             save_offset;
    unsigned int    i, x, length;
    guint8 def_chan = tvb_get_guint8(tvb, offset-9);

    msglen = tvb_reported_length_remaining(tvb, offset);

    if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF)
        proto_tree_add_uint_format_value(pt, hf_gryphon_sched_num_iterations, tvb, offset, 4,
                0, "\"infinite\"");
    else
        proto_tree_add_item(pt, hf_gryphon_sched_num_iterations, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    msglen -= 4;


    item = proto_tree_add_item(pt, hf_gryphon_sched_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_item(tree, hf_gryphon_sched_flags_scheduler, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    msglen -= 4;

    i = 1;
    while (msglen > 0) {

        length = 16 + tvb_get_guint8(tvb, offset+16) + tvb_get_ntohs(tvb, offset+18) + tvb_get_guint8(tvb, offset+20) + 16;
        length += 3 - (length + 3) % 4;

        tree = proto_tree_add_subtree_format(pt, tvb, offset, length, ett_gryphon_cmd_sched_data, NULL, "Message %d", i);
        proto_tree_add_item(tree, hf_gryphon_sched_sleep, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        msglen -= 4;

        proto_tree_add_item(tree, hf_gryphon_sched_transmit_count, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        msglen -= 4;

        proto_tree_add_item(tree, hf_gryphon_sched_transmit_period, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        msglen -= 4;

        item1 = proto_tree_add_item(tree, hf_gryphon_sched_transmit_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
        tree1 = proto_item_add_subtree (item1, ett_gryphon_flags);
        proto_tree_add_item(tree1, hf_gryphon_sched_skip_transmit_period, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (i == 1) {
            proto_tree_add_item(tree1, hf_gryphon_sched_skip_sleep, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

        x = tvb_get_guint8(tvb, offset+2);
        /* 20171026 */
        if (x == 0) {
            x = def_chan;
            proto_tree_add_uint(tree, hf_gryphon_sched_channel0, tvb, offset+2, 1, x);
        } else {
            proto_tree_add_uint(tree, hf_gryphon_sched_channel, tvb, offset+2, 1, x);
        }

        proto_tree_add_item(tree, hf_gryphon_reserved, tvb, offset+3, 1, ENC_NA);
        offset += 4;
        msglen -= 4;

        tree1 = proto_tree_add_subtree(tree, tvb, offset, msglen, ett_gryphon_cmd_sched_cmd, NULL, "Message");
        save_offset = offset;
        offset = decode_data(tvb, offset, tree1);
        msglen -= offset - save_offset;
        i++;
    }
    return offset;
}

static int
cmd_sched_rep(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned int    x;
    const char      *type;

    x = tvb_get_ntohl(tvb, offset);
    if (x & 0x80000000)
        type = "Critical";
    else
        type = "Normal";
    proto_tree_add_uint_format_value(pt, hf_gryphon_sched_rep_id, tvb,
                offset, 4, x, "%s schedule ID: %u", type, x);
    offset += 4;

    proto_tree_add_item(pt, hf_gryphon_sched_rep_message_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    offset = decode_data(tvb, offset, pt);
    return offset;
}

static int
resp_blm_data(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int               x;

    nstime_t        timestamp;

    timestamp.secs = tvb_get_ntohl(tvb, offset)/100000;
    timestamp.nsecs = (tvb_get_ntohl(tvb, offset)%100000)*1000;
    proto_tree_add_time(pt, hf_gryphon_blm_data_time, tvb, offset, 4, &timestamp);
    offset += 4;

    x = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_blm_data_bus_load, tvb,
                offset, 2, x, "%d.%02d%%", x / 100, x % 100);
    offset += 2;
    x = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_blm_data_current_bus_load, tvb,
                offset, 2, x, "%d.%02d%%", x / 100, x % 100);
    offset += 2;
    x = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_blm_data_peak_bus_load, tvb,
                offset, 2, x, "%d.%02d%%", x / 100, x % 100);
    offset += 2;
    x = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_blm_data_historic_peak_bus_load, tvb,
                offset, 2, x, "%d.%02d%%", x / 100, x % 100);
    offset += 2;

    return offset;
}

static int
resp_blm_stat(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    offset = resp_blm_data(tvb, offset, pt);

    proto_tree_add_item(pt, hf_gryphon_blm_stat_receive_frame_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_blm_stat_transmit_frame_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_blm_stat_receive_dropped_frame_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_blm_stat_transmit_dropped_frame_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_blm_stat_receive_error_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_blm_stat_transmit_error_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

/*
 * command to get a list of LDFs
 */
static int
cmd_ldf_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{

    /* block index */
    proto_tree_add_item(pt, hf_gryphon_ldf_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static int
resp_ldf_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int blocks;
    int i;
    proto_tree  *localTree;

    /* block index */
    blocks = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* rsvd */
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* number remaining */
    proto_tree_add_item(pt, hf_gryphon_ldf_remaining, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* LDF blocks */
    for(i=0;i<blocks;i++) {
        localTree = proto_tree_add_subtree_format(pt, tvb, offset, 32+80, ett_gryphon_ldf_block, NULL, "LDF %d",i+1);
        proto_tree_add_item(localTree, hf_gryphon_ldf_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
        offset += 32;
        proto_tree_add_item(localTree, hf_gryphon_ldf_description, tvb, offset, 80, ENC_ASCII|ENC_NA);
        offset += 80;
    }

    return offset;
}

static int
cmd_ldf_delete(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    /* name */
    proto_tree_add_item(pt, hf_gryphon_ldf_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
    offset += 32;

    return offset;
}

static int
cmd_ldf_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint32 size;

    /* size 4 bytes */
    size = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_size, tvb, offset, 4, size, "%u", size);
    offset += 4;
    proto_tree_add_item(pt, hf_gryphon_ldf_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
    offset += 32;
    proto_tree_add_item(pt, hf_gryphon_ldf_description, tvb, offset, 80, ENC_ASCII|ENC_NA);
    offset += 80;
    return offset;
}

static int
resp_ldf_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_ldf_exists, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pt, hf_gryphon_ldf_desc_pad, tvb, offset, 2, ENC_NA);
    offset += 2;
    return offset;
}

static int
cmd_ldf_upload(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int msglen;
    /*int blockn;*/

    msglen = tvb_reported_length_remaining(tvb, offset);

    /* block number */
    /*blockn = tvb_get_ntohs(tvb, offset);*/
    /* 20171101 debug */
    /*proto_tree_add_debug_text(pt, "------------------debug offset=%d blockn=%d msglen=%d",offset,blockn,msglen);*/
    proto_tree_add_item(pt, hf_gryphon_ldf_blockn, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 20171101 file string */
    proto_tree_add_item(pt, hf_gryphon_ldf_file, tvb, offset, msglen - 2, ENC_NA|ENC_ASCII);
    offset += msglen - 2;
    return offset;
}

static int
cmd_ldf_parse(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_ldf_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
    offset += 32;
    return offset;
}

static int
resp_get_ldf_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint32 bitrate;
    float value;
    proto_tree_add_item(pt, hf_gryphon_ldf_info_pv, tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset += 16;
    proto_tree_add_item(pt, hf_gryphon_ldf_info_lv, tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset += 16;
    bitrate = tvb_get_ntohl(tvb, offset);
    value = (float)bitrate / (float)1000.0;
    proto_tree_add_float_format_value(pt, hf_gryphon_ldf_bitrate, tvb, offset, 4, value, "%.3f Kbps", value);
    offset += 4;
    return offset;
}

static int
cmd_cnvt_get_values(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 num_signals;
    int length;
    int i;
    num_signals = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for(i=0;i< num_signals; i++) {
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    }
    return offset;
}

static int
resp_cnvt_get_values(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 flag;
    guint8 num_signals;
    float fvalue;
    int i;
    int length;
    num_signals = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for(i=0;i< num_signals; i++) {
        /* flag */
        flag = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(pt, hf_gryphon_cnvt_flags_getvalues, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if(flag & 0x01) {
            /* float */
            fvalue = tvb_get_ntohieee_float (tvb, offset);
            proto_tree_add_float_format_value(pt, hf_gryphon_cnvt_valuef, tvb, offset, 4, fvalue, "%.1f", fvalue);
            offset += 4;
        }
        if(flag & 0x02) {
            /* int */
            proto_tree_add_item(pt, hf_gryphon_cnvt_valuei, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if(flag & 0x04) {
            /* string */
            proto_tree_add_item_ret_length(pt, hf_gryphon_cnvt_values, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
            offset += length;
        }

    }
    return offset;
}

static int
cmd_cnvt_get_units(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 num_signals;
    int length;
    int i;
    num_signals = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for(i=0;i< num_signals; i++) {
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    }
    return offset;
}

static int
resp_cnvt_get_units(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 num_signals;
    int i;
    int length;
    num_signals = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for(i=0;i< num_signals; i++) {
        /* string */
        proto_tree_add_item_ret_length(pt, hf_gryphon_cnvt_units, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    }
    return offset;
}

static int
cmd_cnvt_set_values(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8 num_signals;
    int length;
    int i;
    float fvalue;
    num_signals = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for(i=0;i< num_signals; i++) {
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;

        fvalue = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_float_format_value(pt, hf_gryphon_cnvt_valuef, tvb, offset, 4, fvalue, "%.2f", fvalue);
        offset += 4;
    }
    return offset;
}

static int
cmd_cnvt_destroy_session(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int msglen;
    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_ui, tvb, offset, msglen, ENC_NA);
    offset += msglen;
    return offset;
}

static int
resp_ldf_get_node_names(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    guint16 us_num;
    /* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_node_names, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* master node name */
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_master_node_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    us_num -= 1;
    while(us_num > 0) {
        /* slave node names */
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_slave_node_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        us_num -= 1;
    }
    return offset;
}

static int
cmd_ldf_get_frames(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_get_frame, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
resp_ldf_get_frames(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    guint16 us_num;
    guint8 pid;
    /* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_frames, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while(us_num > 0) {
        /* id */
        pid = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, pid, "0x%x ",pid);
        offset += 1;
        /* frame name */
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_get_frame, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        us_num -= 1;
    }
    return offset;
}

static int
cmd_ldf_get_frame_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    char *string;
    int length;
    guint8 id;
    string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &length, ENC_ASCII);
    if(length > 1) {
        proto_tree_add_string(pt, hf_gryphon_ldf_get_frame, tvb, offset, length, string);
        offset += length;
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, 0, "(Id not used)");
        offset += 1;
    } else {
        id = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format_value(pt, hf_gryphon_ldf_ioctl_setflags_flags, tvb, offset, 1, id, "0x%x ",id);
        offset += 1;
    }
    return offset;
}

static int
resp_ldf_get_frame_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    guint8 count, i;
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_get_frame_pub, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_get_frame_num_signals, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for (i = 0; i < count; i++) {
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    }
    return offset;
}

static int
cmd_ldf_get_signal_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
resp_ldf_get_signal_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
/* offset */
    proto_tree_add_item(pt, hf_gryphon_ldf_signal_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

/* length */
    proto_tree_add_item(pt, hf_gryphon_ldf_signal_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

/* signal encoding name */
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
cmd_ldf_get_signal_detail(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
resp_ldf_do_encoding_block(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    char *string;
    int length;
    /* encoding */
    string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &length, ENC_ASCII);
    proto_tree_add_string(pt, hf_gryphon_ldf_signal_encoding_type, tvb, offset, 12, string);
    offset += 12;
    if(string[0] == 'l') {
        /* logical */
        proto_tree_add_item(pt, hf_gryphon_ldf_encoding_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_logical, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    } else if(string[0] == 'p') {
        /* physical */
        proto_tree_add_item(pt, hf_gryphon_ldf_encoding_min, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(pt, hf_gryphon_ldf_encoding_max, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_logical, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_logical, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_logical, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
    } else if(string[0] == 'b') {
        proto_tree_add_item(pt, hf_gryphon_ldf_encoding_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* bcd */
    } else if(string[0] == 'a') {
        proto_tree_add_item(pt, hf_gryphon_ldf_encoding_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* ascii */
    } else {
        /* error */
    }
    return(offset);
}

static int
resp_ldf_get_signal_detail(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint16 us_num;
/* offset */
    proto_tree_add_item(pt, hf_gryphon_ldf_signal_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

/* length */
    proto_tree_add_item(pt, hf_gryphon_ldf_signal_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

/* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_encodings, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while(us_num > 0) {
        offset = resp_ldf_do_encoding_block(tvb, offset, pt);
        us_num -= 1;
    }

    return offset;
}

static int
cmd_ldf_get_encoding_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_encoding_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
resp_ldf_get_encoding_info(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint16 us_num;
    /* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_encodings, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while(us_num > 0) {
        /* encoding data */
        offset = resp_ldf_do_encoding_block(tvb, offset, pt);
        us_num -= 1;
    }
    return offset;
}

static int
cmd_ldf_save_session(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int msglen;
    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_restore_session, tvb, offset, msglen, ENC_NA);
    offset += msglen;
    return offset;
}

static int
cmd_ldf_emulate_nodes(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int nnodes;
    int node_numb=1;
    int i;
    unsigned int xchannel;
    char *string;
    int length;
    proto_tree  *tree2;

    nnodes = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_nodenumber, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    for(i=0;i<nnodes;i++) {
        /* first, find the end of the string, then use that string len to build a subtree */

        string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset+1, &length, ENC_ASCII);

        tree2 = proto_tree_add_subtree_format(pt, tvb, offset, 1+length, ett_gryphon_lin_emulate_node, NULL, "Node %u", node_numb);

        xchannel = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree2, hf_gryphon_sched_channel, tvb, offset, 1, xchannel);
        offset += 1;

        proto_tree_add_string(tree2, hf_gryphon_lin_nodename, tvb, offset, length, string);
        offset += length;

        node_numb++;
    }
    return offset;
}

static int
resp_ldf_get_schedules(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    guint16 us_num;
    /* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_schedules, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while(us_num > 0) {
        /* slave node names */
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_schedule_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        us_num -= 1;
    }
    return offset;
}

static int
cmd_ldf_start_schedule(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_schedule_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
cmd_ldf_get_node_signals(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_node_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
    offset += length;
    return offset;
}

static int
resp_ldf_get_node_signals(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int length;
    guint16 us_num;
    /* number */
    us_num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_num_signal_names, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while(us_num > 0) {
        /* signal names */
        proto_tree_add_item_ret_length(pt, hf_gryphon_ldf_signal_name, tvb, offset, -1, ENC_NA | ENC_ASCII, &length);
        offset += length;
        us_num -= 1;
    }
    return offset;
}

static int
cmd_restore_session(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int msglen;
    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_ldf_restore_session, tvb, offset, msglen, ENC_NA);
    offset += msglen;
    return offset;
}

static int
resp_restore_session(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_ldf_name, tvb, offset, 32, ENC_ASCII|ENC_NA);
    offset += 32;
    return offset;
}

static int
cmd_addresp(tvbuff_t *tvb, int offset, packet_info* pinfo, proto_tree *pt)
{
    proto_item  *item;
    proto_tree  *tree;
    guint       blocks, responses, i, msglen, length;
    int padding;
    int         action, actionType, actionValue;
    tvbuff_t    *next_tvb;

    actionType = 0;
    /* flags */
    item = proto_tree_add_item(pt, hf_gryphon_addresp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    /* 20171017 fixed display of filter flags */
    /* flags: active */
    proto_tree_add_item(tree, hf_gryphon_addresp_flags_active, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    /* number of filter blocks */
    proto_tree_add_item_ret_uint(pt, hf_gryphon_addresp_blocks, tvb, offset, 1, ENC_BIG_ENDIAN, &blocks);
    offset += 1;

    /* number of responses */
    proto_tree_add_item_ret_uint(pt, hf_gryphon_addresp_responses, tvb, offset, 1, ENC_BIG_ENDIAN, &responses);
    offset += 1;

    /* old handle */
    proto_tree_add_item(pt, hf_gryphon_addresp_old_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* action */
    action = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(pt, hf_gryphon_addresp_action, tvb, offset, 1, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    actionValue = tvb_get_ntohs(tvb, offset+2);
    if (actionValue) {
        if (action & FR_PERIOD_MSGS) {
            actionType = 1;
        } else {
            actionType = 0;
        }

        proto_tree_add_item(tree, hf_gryphon_addresp_action_period, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(tree, hf_gryphon_addresp_action_deact_on_event, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gryphon_addresp_action_deact_after_period, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* reserved */
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (actionValue) {
        if (actionType == 1) {
            proto_tree_add_uint_format_value(pt, hf_gryphon_addresp_action_period_type, tvb,
                    offset, 2, actionValue, "Period: %d messages", actionValue);
        } else {
            proto_tree_add_uint_format_value(pt, hf_gryphon_addresp_action_period_type, tvb,
                    offset, 2, actionValue, "Period: %d.%02d seconds", actionValue/100, actionValue%100);
        }
    } else {
        /* 20171017 */
        /* value 2-bytes */
        proto_tree_add_uint_format_value(pt, hf_gryphon_addresp_action_period_type, tvb, offset, 2, actionValue, "(not used)");
    }
    offset += 2;

    for (i = 1; i <= blocks; i++) {
        length = tvb_get_ntohs(tvb, offset+2) + 8;
        padding = 3 - (length + 3) % 4;
        tree = proto_tree_add_subtree_format(pt, tvb, offset, length + padding, ett_gryphon_cmd_filter_block, NULL, "Filter block %d", i);
        /* 20171017 fixed display of filter block padding */
        offset = filter_block(tvb, offset, tree);
    }
    for (i = 1; i <= responses; i++) {
        msglen = tvb_get_ntohs(tvb, offset+4) + 8;
        padding = 3 - (msglen + 3) % 4;
        tree = proto_tree_add_subtree_format(pt, tvb, offset, msglen + padding, ett_gryphon_cmd_response_block, NULL, "Response block %d", i);
        next_tvb = tvb_new_subset_length(tvb, offset, msglen + padding);
        dissect_gryphon_message(next_tvb, pinfo, tree, TRUE);
        offset += msglen + padding;
    }
    return offset;
}

static int
resp_addresp(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_addresp_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
cmd_modresp(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8   dest = tvb_get_guint8(tvb, offset-5),
             resp_handle = tvb_get_guint8(tvb, offset);

    if (resp_handle)
        proto_tree_add_item(pt, hf_gryphon_modresp_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    else if (dest)
        proto_tree_add_uint_format_value(pt, hf_gryphon_modresp_handle, tvb,
                    offset, 1, dest, "Response handles: all on channel %c", dest);
    else
        proto_tree_add_uint_format_value(pt, hf_gryphon_modresp_handle, tvb, offset, 1,
                0, "Response handles: all");

    proto_tree_add_item(pt, hf_gryphon_modresp_action, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+2, 2, ENC_NA);
    offset += 4;
    return offset;
}

static int
resp_resphan(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int         handles = tvb_get_guint8(tvb, offset);
    int         i, padding, handle;

    proto_tree_add_item(pt, hf_gryphon_num_resphan, tvb, offset, 1, ENC_BIG_ENDIAN);
    for (i = 1; i <= handles; i++){
        handle = tvb_get_guint8(tvb, offset+i);
        proto_tree_add_uint_format(pt, hf_gryphon_handle, tvb, offset+i, 1, handle, "Handle %d: %u", i,
            handle);
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
        proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset+1+handles, padding, ENC_NA);
    offset += 1+handles+padding;
    return offset;
}

static int
resp_sched(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_transmit_sched_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

static int
cmd_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_desc_program_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_gryphon_desc_program_name, tvb, offset, 32, ENC_NA|ENC_ASCII);
    offset += 32;

    proto_tree_add_item(pt, hf_gryphon_desc_program_description, tvb, offset, 80, ENC_NA|ENC_ASCII);
    offset += 80;

    return offset;
}

static int
resp_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item  *item;
    proto_tree  *tree;

    item = proto_tree_add_item(pt, hf_gryphon_desc_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_item(tree, hf_gryphon_desc_flags_program, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_desc_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+2, 2, ENC_NA);
    offset += 4;
    return offset;
}

static int
cmd_upload(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;
    unsigned int    length;

    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_upload_block_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_upload_handle, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    offset += 3;
    msglen -= 3;

    length = msglen;
    proto_tree_add_item(pt, hf_gryphon_upload_data, tvb, offset, length, ENC_NA);
    offset += length;

    length = 3 - (length + 3) % 4;
    if (length) {
        proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset, length, ENC_NA);
        offset += length;
    }
    return offset;
}

static int
cmd_delete(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_delete, tvb, offset, 32, ENC_NA|ENC_ASCII);
    offset += 32;
    return offset;
}

static int
cmd_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_list_block_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
resp_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree  *tree;
    guint32     i, count;

    proto_tree_add_item_ret_uint(pt, hf_gryphon_list_num_programs, tvb, offset, 1, ENC_BIG_ENDIAN, &count);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 1, ENC_NA);
    offset += 2;

    proto_tree_add_item(pt, hf_gryphon_list_num_remain_programs, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i = 1; i <= count; i++) {
        tree = proto_tree_add_subtree_format(pt, tvb, offset, 112, ett_gryphon_pgm_list, NULL, "Program %u", i);
        proto_tree_add_item(tree, hf_gryphon_list_name, tvb, offset, 32, ENC_NA|ENC_ASCII);
        offset += 32;

        proto_tree_add_item(tree, hf_gryphon_list_description, tvb, offset, 80, ENC_NA|ENC_ASCII);
        offset += 80;
    }
    return offset;
}

static int
cmd_start(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    char      *string;
    gint      length;
    int       msglen;
    int       hdr_stuff = offset;

    msglen = tvb_reported_length_remaining(tvb, offset);
    offset = cmd_delete(tvb, offset, pt);       /* decode the name */
    if (offset < msglen + hdr_stuff) {
        string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &length, ENC_ASCII);
        if (length > 1) {
            proto_tree_add_string(pt, hf_gryphon_start_arguments, tvb, offset,
                length, string);
            offset += length;

            length = 3 - (length + 3) % 4;
            if (length) {
                proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset, length, ENC_NA);
                offset += length;
            }
        }
    }
    return offset;
}

static int
resp_start(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;

    msglen = tvb_reported_length_remaining(tvb, offset);
    if (msglen > 0) {
        proto_tree_add_item(pt, hf_gryphon_start_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
        offset += 4;
    }
    return offset;
}

static int
resp_status(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item  *item;
    proto_tree  *tree;
    unsigned int   i, copies, length, channel;

    copies = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(pt, hf_gryphon_status_num_running_copies, tvb, offset, 1, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (item, ett_gryphon_pgm_status);
    offset += 1;
    if (copies) {
        for (i = 1; i <= copies; i++) {
            channel = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_gryphon_program_channel_number, tvb, offset, 1, channel,
                    "Program %u channel (client) number %u", i, channel);
            offset += 1;
        }
    }
    length = 3 - (copies + 1 + 3) % 4;
    if (length) {
        proto_tree_add_item(pt, hf_gryphon_padding, tvb, offset, length, ENC_NA);
        offset += length;
    }
    return offset;
}

static int
cmd_options(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;
    proto_tree      *tree;
    unsigned int    i, size, padding, option, option_length, option_value;
    const char      *string, *string1;

    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_options_handle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    msglen -= 4;

    for (i = 1; msglen > 0; i++) {
        option_length = tvb_get_guint8(tvb, offset+1);
        size = option_length + 2;
        padding = 3 - ((size + 3) %4);
        tree = proto_tree_add_subtree_format(pt, tvb, offset, size + padding, ett_gryphon_pgm_options, NULL, "Option number %u", i);
        option = tvb_get_guint8(tvb, offset);
        switch (option_length) {
        case 1:
            option_value = tvb_get_guint8(tvb, offset+2);
            break;
        case 2:
            option_value = tvb_get_ntohs(tvb, offset+2);
            break;
        case 4:
            option_value = tvb_get_ntohl(tvb, offset+2);
            break;
        default:
            option_value = 0;
        }
        string = "unknown option";
        string1 = "unknown option data";
        switch (option) {
        case PGM_CONV:
            string = "Type of data in the file";
            switch (option_value) {
            case PGM_BIN:
                string1 = "Binary - Don't modify";
                break;
            case PGM_ASCII:
                string1 = "ASCII - Remove CR's";
                break;
            }
            break;
        case PGM_TYPE:
            string = "Type of file";
            switch (option_value) {
            case PGM_PGM:
                string1 = "Executable";
                break;
            case PGM_DATA:
                string1 = "Data";
                break;
            }
            break;
        }
        proto_tree_add_uint_format_value(tree, hf_gryphon_option, tvb, offset, 1, option, "%s", string);
        proto_tree_add_bytes_format_value(tree, hf_gryphon_option_data, tvb, offset+2, option_length, NULL, "%s", string1);
        if (padding)
            proto_tree_add_item(tree, hf_gryphon_padding, tvb, offset+option_length+2, padding, ENC_NA);
        offset += size + padding;
        msglen -= size + padding;
    }
    return offset;
}

static int
cmd_files(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int          msglen;
    guint8 file;

    msglen = tvb_reported_length_remaining(tvb, offset);
    file = tvb_get_guint8(tvb, offset);
    if (file == 0)
        proto_tree_add_uint_format(pt, hf_gryphon_cmd_file, tvb, offset, 1, file, "First group of names");
    else
        proto_tree_add_uint_format(pt, hf_gryphon_cmd_file, tvb, offset, 1, file, "Subsequent group of names");

    proto_tree_add_item(pt, hf_gryphon_files, tvb, offset+1, msglen-1, ENC_NA|ENC_ASCII);
    offset += msglen;
    return offset;
}

static int
resp_files(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int            msglen;

    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_more_filenames, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pt, hf_gryphon_filenames, tvb, offset+1, msglen-1, ENC_ASCII|ENC_NA);
    offset += msglen;
    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_register_non_legacy(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int         remain;
    unsigned int ui_block;
    guint32 ui_ids;
    int         id_usdtreq;
    int         id_usdtresp;
    int         id_uudtresp;
    guint8      u8_options;
    guint8      u8USDTReqExtAddr_bit;
    guint8      u8USDTRespExtAddr_bit;
    guint8      u8UUDTRespExtAddr_bit;
    guint8      u8USDTReqExtAddr;
    guint8      u8USDTRespExtAddr;
    guint8      u8UUDTRespExtAddr;
    guint8      u8USDTReqHeaderSize;
    guint8      u8USDTRespHeaderSize;
    guint8      u8UUDTRespHeaderSize;
    guint8      flags;
    proto_tree  *tree1;
    proto_tree  *tree2;
    proto_tree  *tree3;
    proto_tree  *tree4;
    proto_tree  *tree5;
    static int * const transmit_options_flags[] = {
        &hf_gryphon_usdt_transmit_options_flags_echo,
        &hf_gryphon_usdt_transmit_options_action,
        &hf_gryphon_usdt_transmit_options_done_event,
        &hf_gryphon_usdt_transmit_options_echo_short,
        &hf_gryphon_usdt_transmit_options_rx_nth_fc,
        NULL
    };
    static int * const receive_options_flags[] = {
        &hf_gryphon_usdt_receive_options_action,
        &hf_gryphon_usdt_receive_options_firstframe_event,
        &hf_gryphon_usdt_receive_options_lastframe_event,
        &hf_gryphon_usdt_receive_options_tx_nth_fc,
        NULL
    };
    static int * const length_options_flags[] = {
        &hf_gryphon_usdt_length_control_j1939,
        NULL
    };
    remain = tvb_reported_length_remaining(tvb, offset);

    /* 20171012 */
    /* Action flags */
    flags = tvb_get_guint8(tvb, offset);
    tree1 = proto_tree_add_subtree_format(pt, tvb, offset, 1, ett_gryphon_usdt_action_flags, NULL, "Action flags 0x%02x", flags);
    proto_tree_add_item(tree1, hf_gryphon_usdt_action_flags_non_legacy, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    remain -= 1;

    /* tx options */
    flags = tvb_get_guint8(tvb, offset);
    tree2 = proto_tree_add_subtree_format(pt, tvb, offset, 1, ett_gryphon_usdt_tx_options_flags, NULL, "Transmit options 0x%02x", flags);
    proto_tree_add_bitmask(tree2, tvb, offset, hf_gryphon_usdt_transmit_options_flags, ett_gryphon_flags, transmit_options_flags, ENC_BIG_ENDIAN);
    offset += 1;
    remain -= 1;

    /* rx options */
    flags = tvb_get_guint8(tvb, offset);
    tree3 = proto_tree_add_subtree_format(pt, tvb, offset, 1, ett_gryphon_usdt_rx_options_flags, NULL, "Receive options 0x%02x", flags);
    proto_tree_add_bitmask(tree3, tvb, offset, hf_gryphon_usdt_receive_options_flags, ett_gryphon_flags, receive_options_flags, ENC_BIG_ENDIAN);
    offset += 1;
    remain -= 1;

    /* reserved */
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;
    remain -= 1;

    /* blocks */
    ui_block = 1;
    while (remain > 0) {
        tree4 = proto_tree_add_subtree_format(pt, tvb, offset, 20, ett_gryphon_usdt_data_block, NULL, "Block %u", ui_block);

        /* TODO implement J1939-style length address src and dst byte swap */

        /* mask the upper bits of the long */
        /* number of IDs in the block */
        ui_ids = tvb_get_ntohl (tvb, offset);
        u8_options = ((ui_ids >> 24) & 0xE0);
        ui_ids &= 0x1FFFFFFF; /* mask the upper control bits */
        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_nids, tvb, offset, 4, ui_ids, "%u", ui_ids);

        if(ui_ids == 0) {
            proto_item_set_len(tree4, 20);
        } else {


            /* display control bits */
            tree5 = proto_tree_add_subtree_format(tree4, tvb, offset, 1, ett_gryphon_usdt_len_options_flags, NULL, "Options 0x%02x", u8_options);
            proto_tree_add_bitmask(tree5, tvb, offset, hf_gryphon_usdt_length_options_flags, ett_gryphon_flags, length_options_flags, ENC_BIG_ENDIAN);
            offset += 4;
            remain -= 4;

            u8UUDTRespExtAddr = tvb_get_guint8(tvb, offset+10);
            u8USDTRespExtAddr = tvb_get_guint8(tvb, offset+13);
            u8USDTReqExtAddr = tvb_get_guint8(tvb, offset+16);
            if(ui_ids == 1) {
                /* single ID */

                /* add extended address display of the IDs */
                /* mask the upper bits of the IDs */
                /* usdt req */
                id_usdtreq = tvb_get_ntohl (tvb, offset);
                u8USDTReqExtAddr_bit = ((id_usdtreq >> 24) & 0x20);
                u8USDTReqHeaderSize = ((id_usdtreq >> 24) & 0x80);
                id_usdtreq &= 0x1FFFFFFF;
                /* usdt req */
                if(u8USDTReqExtAddr_bit == 0) {
                    if(u8USDTReqHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%02x (11-bit)", id_usdtreq);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%04x (29-bit)", id_usdtreq);
                    }
                } else {
                    u8USDTReqExtAddr = tvb_get_guint8(tvb, offset+16);
                    if(u8USDTReqHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%02x (11-bit extended address %01x)", id_usdtreq, u8USDTReqExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%04x (29-bit extended address %01x)", id_usdtreq, u8USDTReqExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;

                /* usdt resp */
                id_usdtresp = tvb_get_ntohl (tvb, offset);
                u8USDTRespExtAddr_bit = ((id_usdtresp >> 24) & 0x20);
                u8USDTRespHeaderSize = ((id_usdtresp >> 24) & 0x80);
                id_usdtresp &= 0x1FFFFFFF;
                /* usdt resp */
                if(u8USDTRespExtAddr_bit == 0) {
                    if(u8USDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%02x (11-bit)", id_usdtresp);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%04x (29-bit)", id_usdtresp);
                    }
                } else {
                    u8USDTRespExtAddr = tvb_get_guint8(tvb, offset+13);
                    if(u8USDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%02x (11-bit extended address %01x)", id_usdtresp, u8USDTRespExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%04x (29-bit extended address %01x)", id_usdtresp, u8USDTRespExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;


                /* uudt resp */
                id_uudtresp = tvb_get_ntohl (tvb, offset);
                u8UUDTRespExtAddr_bit = ((id_uudtresp >> 24) & 0x20);
                u8UUDTRespHeaderSize = ((id_uudtresp >> 24) & 0x80);
                id_uudtresp &= 0x1FFFFFFF;
                /* uudt resp */
                if(u8UUDTRespExtAddr_bit == 0) {
                    if(u8UUDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%02x (11-bit)", id_uudtresp);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%04x (29-bit)", id_uudtresp);
                    }
                } else {
                    u8UUDTRespExtAddr = tvb_get_guint8(tvb, offset+10);
                    if(u8UUDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%02x (11-bit extended address %01x)", id_uudtresp, u8UUDTRespExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%04x (29-bit extended address %01x)", id_uudtresp, u8UUDTRespExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;


            } else {
                /* multiple IDs */

                /* add extended address display of the IDs */
                /* mask the upper bits of the IDs */

                /* usdt req */
                id_usdtreq = tvb_get_ntohl (tvb, offset);
                u8USDTReqExtAddr_bit = ((id_usdtreq >> 24) & 0x20);
                u8USDTReqHeaderSize = ((id_usdtreq >> 24) & 0x80);
                id_usdtreq &= 0x1FFFFFFF;
                /* usdt req */
                if(u8USDTReqExtAddr_bit == 0) {
                    if(u8USDTReqHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%02x through 0x%02x (11-bit)", id_usdtreq, id_usdtreq + ui_ids-1);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%04x through 0x%04x (29-bit)", id_usdtreq, id_usdtreq + ui_ids-1);
                    }
                } else {
                    u8USDTReqExtAddr = tvb_get_guint8(tvb, offset+16);
                    if(u8USDTReqHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%02x through 0x%02x (11-bit extended address %0x)", id_usdtreq, id_usdtreq + ui_ids-1, u8USDTReqExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request, tvb, offset, 4, id_usdtreq, "0x%04x through 0x%04x (29-bit extended address %0x)", id_usdtreq, id_usdtreq + ui_ids-1, u8USDTReqExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;

                /* usdt resp */
                id_usdtresp = tvb_get_ntohl (tvb, offset);
                u8USDTRespExtAddr_bit = ((id_usdtresp >> 24) & 0x20);
                u8USDTRespHeaderSize = ((id_usdtresp >> 24) & 0x80);
                id_usdtresp &= 0x1FFFFFFF;
                /* usdt resp */
                if(u8USDTRespExtAddr_bit == 0) {
                    if(u8USDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%02x through 0x%02x (11-bit)", id_usdtresp, id_usdtresp + ui_ids-1);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%04x through 0x%04x (29-bit)", id_usdtresp, id_usdtresp + ui_ids-1);
                    }
                } else {
                    u8USDTRespExtAddr = tvb_get_guint8(tvb, offset+13);
                    if(u8USDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%02x through 0x%02x (11-bit extended address %01x)", id_usdtresp, id_usdtresp + ui_ids-1, u8USDTRespExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response, tvb, offset, 4, id_usdtresp, "0x%04x through 0x%04x (29-bit extended address %01x)", id_usdtresp, id_usdtresp + ui_ids-1, u8USDTRespExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;

                /* uudt resp */
                id_uudtresp = tvb_get_ntohl (tvb, offset);
                u8UUDTRespExtAddr_bit = ((id_uudtresp >> 24) & 0x20);
                u8UUDTRespHeaderSize = ((id_uudtresp >> 24) & 0x80);
                id_uudtresp &= 0x1FFFFFFF;
                /* uudt resp */
                if(u8UUDTRespExtAddr_bit == 0) {
                    if(u8UUDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%02x through 0x%02x (11-bit)", id_uudtresp, id_uudtresp + ui_ids-1);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%04x through 0x%04x (29-bit)", id_uudtresp, id_uudtresp + ui_ids-1);
                    }
                } else {
                    u8UUDTRespExtAddr = tvb_get_guint8(tvb, offset+10);
                    if(u8UUDTRespHeaderSize == 0) {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%02x through 0x%02x (11-bit extended address %01x)", id_uudtresp, id_uudtresp + ui_ids-1, u8UUDTRespExtAddr);
                    } else {
                        proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response, tvb, offset, 4, id_uudtresp, "0x%04x through 0x%04x (29-bit extended address %01x)", id_uudtresp, id_uudtresp + ui_ids-1, u8UUDTRespExtAddr);
                    }
                }
                offset += 4;
                remain -= 4;
            }

            if(u8USDTReqExtAddr_bit == 0) {
                /* proto_tree_add_item(tree4, hf_gryphon_reserved, tvb, offset, 1, ENC_NA); */
                proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request_ext, tvb, offset, 1, 0, "(no extended address)");
            } else {
                proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_request_ext, tvb, offset, 1, u8USDTReqExtAddr, "0x%01x", u8USDTReqExtAddr);
            }
            offset += 1;
            remain -= 1;

            if(u8USDTRespExtAddr_bit == 0) {
                /* proto_tree_add_item(tree4, hf_gryphon_reserved, tvb, offset, 1, ENC_NA); */
                proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response_ext, tvb, offset, 1, 0, "(no extended address)");
            } else {
                proto_tree_add_uint_format_value(tree4, hf_gryphon_usdt_response_ext, tvb, offset, 1, u8USDTRespExtAddr, "0x%01x", u8USDTRespExtAddr);
            }
            offset += 1;
            remain -= 1;

            if(u8UUDTRespExtAddr_bit == 0) {
                /* proto_tree_add_item(tree4, hf_gryphon_reserved, tvb, offset, 1, ENC_NA); */
                proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response_ext, tvb, offset, 1, 0, "(no extended address)");
            } else {
                proto_tree_add_uint_format_value(tree4, hf_gryphon_uudt_response_ext, tvb, offset, 1, u8UUDTRespExtAddr, "0x%01x", u8UUDTRespExtAddr);
            }
            offset += 1;
            remain -= 1;

            proto_tree_add_item(tree4, hf_gryphon_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            remain -= 1;
        }


        ui_block += 1;
    }

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_stmin_fc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_usdt_stmin_fc, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_bsmax_fc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_usdt_bsmax_fc, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_stmin_override(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_usdt_stmin_override, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_get_stmin_override(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_usdt_stmin_override, tvb, offset, 1, ENC_NA);
    offset += 1;
    /* fixed this for get */
    proto_tree_add_item(pt, hf_gryphon_usdt_stmin_override_active, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_stmin_override_activate(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_usdt_stmin_override_activate, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

/* 20171012 gryphon command for USDT */
static int
cmd_usdt_set_stmin_mul(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    float value;
    /* TODO fix this float value? */
    value = tvb_get_ntohieee_float (tvb, offset);
    proto_tree_add_float_format_value(pt, hf_gryphon_usdt_set_stmin_mul, tvb, offset, 4,
                    value, "%.1f", value);
    offset += 4;

    return offset;
}

/*
 * legacy command for usdt register
 */
static int
cmd_usdt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int         ids, id, remain, size, i, bytes;
    guint8      flags;
    proto_tree  *localTree;
    proto_item  *localItem;

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(pt, hf_gryphon_usdt_flags_register, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (flags & 1) {
        static int * const action_flags[] = {
            &hf_gryphon_usdt_action_flags_register,
            &hf_gryphon_usdt_action_flags_action,
            NULL
        };

        static int * const transmit_option_flags[] = {
            &hf_gryphon_usdt_transmit_options_flags_echo,
            &hf_gryphon_usdt_transmit_options_action,
            &hf_gryphon_usdt_transmit_options_send_done,
            NULL
        };

        static int * const receive_option_flags[] = {
            &hf_gryphon_usdt_receive_options_action,
            &hf_gryphon_usdt_receive_options_firstframe,
            &hf_gryphon_usdt_receive_options_lastframe,
            NULL
        };

        proto_tree_add_bitmask(pt, tvb, offset, hf_gryphon_usdt_action_flags, ett_gryphon_flags, action_flags, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(pt, tvb, offset+1, hf_gryphon_usdt_transmit_options_flags, ett_gryphon_flags, transmit_option_flags, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(pt, tvb, offset+2, hf_gryphon_usdt_receive_options_flags, ett_gryphon_flags, receive_option_flags, ENC_BIG_ENDIAN);

        if ((ids = tvb_get_guint8(tvb, offset+3))) {
            localItem = proto_tree_add_item(pt, hf_gryphon_usdt_ext_address, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            offset += 4;

            localTree = proto_item_add_subtree (localItem, ett_gryphon_usdt_data);
            while (ids) {
                proto_tree_add_item(localTree, hf_gryphon_usdt_ext_address_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ids--;
            }
        } else {
            proto_tree_add_uint_format_value(pt, hf_gryphon_usdt_ext_address, tvb, offset+3, 1,
                    0, "Using extended addressing for the single, internally defined, ID");
            offset += 4;
        }
        for (i = 0; i < 2; i++) {
            bytes = tvb_reported_length_remaining (tvb, offset);
            if (bytes <= 0)
                break;
            localTree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_gryphon_usdt_data, NULL, "%s block of USDT/UUDT IDs", i==0?"First":"Second");

            size = tvb_get_ntohl (tvb, offset);
            localItem = proto_tree_add_item(localTree, hf_gryphon_usdt_block_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            localTree = proto_item_add_subtree (localItem, ett_gryphon_usdt_data_block);
            if (size == 0) {
                proto_item_set_len(localItem, 16);
            } else {
                offset += 4;
                id = tvb_get_ntohl (tvb, offset);
                proto_tree_add_uint_format_value(localTree, hf_gryphon_usdt_request, tvb, offset, 4, id, "%04X through %04X", id, id+size-1);
                offset += 4;

                id = tvb_get_ntohl (tvb, offset);
                proto_tree_add_uint_format_value(localTree, hf_gryphon_usdt_response, tvb, offset, 4, id, "%04X through %04X", id, id+size-1);
                offset += 4;

                id = tvb_get_ntohl (tvb, offset);
                proto_tree_add_uint_format_value(localTree, hf_gryphon_uudt_response, tvb, offset, 4, id, "%04X through %04X", id, id+size-1);
                offset += 4;
            }
        }
    } else {
        proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
        offset += 4;
    }

    if ((remain = tvb_reported_length_remaining(tvb, offset))) {
        proto_tree_add_item(pt, hf_gryphon_ignored, tvb, offset, remain, ENC_NA);
        offset += remain;
    }

    return offset;
}

static int
cmd_bits_in (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int          msglen, value;

    msglen = tvb_reported_length_remaining(tvb, offset);
    value = tvb_get_guint8(tvb, offset);
    if (value) {
        static int * const digital_values[] = {
            &hf_gryphon_bits_in_input1,
            &hf_gryphon_bits_in_input2,
            &hf_gryphon_bits_in_input3,
            &hf_gryphon_bits_in_pushbutton,
            NULL
        };
        proto_tree_add_bitmask(pt, tvb, 1, hf_gryphon_bit_in_digital_data, ett_gryphon_digital_data, digital_values, ENC_NA);
    } else {
        proto_tree_add_uint_format(pt, hf_gryphon_bit_in_digital_data, tvb, offset, 1, value, "No digital values are set");
    }

    offset++;
    msglen--;
    return offset;
}

static int
cmd_bits_out (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int          msglen, value;

    msglen = tvb_reported_length_remaining(tvb, offset);
    value = tvb_get_guint8(tvb, offset);
    if (value) {
        static int * const digital_values[] = {
            &hf_gryphon_bits_out_output1,
            &hf_gryphon_bits_out_output2,
            NULL
        };
        proto_tree_add_bitmask(pt, tvb, 1, hf_gryphon_bit_out_digital_data, ett_gryphon_digital_data, digital_values, ENC_NA);
    } else {
        proto_tree_add_uint_format(pt, hf_gryphon_bit_out_digital_data, tvb, offset, 1, value, "No digital values are set");
    }

    offset++;
    msglen--;
    return offset;
}

static int
cmd_init_strat (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint32 reset_limit;
    int     msglen, indx;
    float   value;

    msglen = tvb_reported_length_remaining(tvb, offset);
    reset_limit = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(pt, hf_gryphon_init_strat_reset_limit, tvb, offset, 4,
        reset_limit, "Reset Limit = %u messages", reset_limit);
    offset += 4;
    msglen -= 4;
    for (indx = 1; msglen; indx++, offset++, msglen--) {
        value = tvb_get_guint8(tvb, offset);
        if (value)
            proto_tree_add_float_format_value(pt, hf_gryphon_init_strat_delay, tvb, offset, 1,
                    value/4, "Delay %d = %.2f seconds", indx, value/4);
        else
            proto_tree_add_float_format_value(pt, hf_gryphon_init_strat_delay, tvb, offset, 1,
                    0, "Delay %d = infinite", indx);
    }

    return offset;
}

static int
speed(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_item(pt, hf_gryphon_speed_baud_rate_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset+1, 3, ENC_NA);
    offset += 4;
    return offset;
}

static int
blm_mode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item   *item;
    proto_tree   *tree;
    guint32      mode, milliseconds;

    item = proto_tree_add_item_ret_uint(pt, hf_gryphon_blm_mode, tvb, offset, 4, ENC_BIG_ENDIAN, &mode);
    tree = proto_item_add_subtree(item, ett_gryphon_blm_mode);
    offset += 4;
    switch (mode) {
    case 1:
        milliseconds = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format_value(tree, hf_gryphon_blm_mode_avg_period, tvb, offset, 4,
            milliseconds, "%d.%03d seconds", milliseconds/1000, milliseconds%1000);
        break;
    case 2:
        proto_tree_add_item(tree, hf_gryphon_blm_mode_avg_frames, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset, 4, ENC_NA);
        break;
    }

    offset += 4;
    return offset;
}

static gryphon_conversation*
get_conversation_data(packet_info* pinfo)
{
    conversation_t       *conversation;
    gryphon_conversation *conv_data;

    /* Find a conversation, create a new if no one exists */
    conversation = find_or_create_conversation(pinfo);
    conv_data = (gryphon_conversation*)conversation_get_proto_data(conversation, proto_gryphon);

    if (conv_data == NULL) {
        conv_data = wmem_new(wmem_file_scope(), gryphon_conversation);
        conv_data->request_frame_data = wmem_list_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_gryphon, (void *)conv_data);
    }

    return conv_data;
}

static int
decode_command(tvbuff_t *tvb, packet_info* pinfo, int msglen, int offset, int dst, proto_tree *pt)
{
    guint32         cmd;
    guint32         context, ioctl_command;
    proto_tree      *ft;
    proto_item      *hi;
    gryphon_pkt_info_t *pkt_info;

    hi = proto_tree_add_item_ret_uint(pt, hf_gryphon_cmd, tvb, offset, 1, ENC_BIG_ENDIAN, &cmd);
    proto_item_set_hidden(hi);

    if (cmd > 0x3F)
        cmd += dst * 256;

    if (!pinfo->fd->visited) {
        /* Find a conversation, create a new if no one exists */
        gryphon_conversation *conv_data = get_conversation_data(pinfo);

        pkt_info = wmem_new0(wmem_file_scope(), gryphon_pkt_info_t);

        /* load information into the request frame */
        pkt_info->cmd = cmd;
        pkt_info->req_frame_num = pinfo->num;
        pkt_info->req_time = pinfo->abs_ts;

        wmem_list_prepend(conv_data->request_frame_data, pkt_info);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_gryphon, (guint32)tvb_raw_offset(tvb), pkt_info);
    } else {
        pkt_info = (gryphon_pkt_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_gryphon, (guint32)tvb_raw_offset(tvb));
    }

    proto_tree_add_uint(pt, hf_gryphon_command, tvb, offset, 1, cmd);
    proto_tree_add_item_ret_uint(pt, hf_gryphon_cmd_context, tvb, offset + 1, 1, ENC_NA, &context);
    if (!pinfo->fd->visited) {
        pkt_info->cmd_context = context;
    }
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset + 2, 2, ENC_NA);
    if (pkt_info->rsp_frame_num > 0) {
        proto_item* it = proto_tree_add_uint(pt, hf_gryphon_response_in,
            tvb, 0, 0, pkt_info->rsp_frame_num);
        proto_item_set_generated(it);
    }
    offset += 4;
    msglen -= 4;

    if (msglen > 0)
    {
        ft = proto_tree_add_subtree_format(pt, tvb, offset, msglen, ett_gryphon_command_data, NULL,
            "Data: (%d byte%s)", msglen, plurality(msglen, "", "s"));

        switch (cmd)
        {
        case CMD_INIT:
            offset = cmd_init(tvb, offset, ft);
            break;
        case CMD_EVENT_ENABLE:
        case CMD_EVENT_DISABLE:
            offset = eventnum(tvb, offset, ft);
            break;
        case CMD_SET_TIME:
            offset = resp_time(tvb, offset, ft);
            break;
        case CMD_CARD_SET_SPEED:
            offset = speed(tvb, offset, ft);
            break;
        case CMD_CARD_SET_FILTER:
            offset = cmd_setfilt(tvb, offset, ft);
            break;
        case CMD_CARD_GET_FILTER:
            offset = resp_addfilt(tvb, offset, ft);
            break;
        case CMD_CARD_TX:
            offset = decode_data(tvb, offset, ft);
            break;
        case CMD_CARD_ADD_FILTER:
            offset = cmd_addfilt(tvb, offset, ft);
            break;
        case CMD_CARD_MODIFY_FILTER:
            offset = cmd_modfilt(tvb, offset, ft);
            break;
        case CMD_CARD_SET_DEFAULT_FILTER:
            offset = dfiltmode(tvb, offset, ft);
            break;
        case CMD_CARD_SET_FILTER_MODE:
            offset = filtmode(tvb, offset, ft);
            break;
        case CMD_SERVER_REG:
            offset = cmd_register(tvb, offset, ft);
            break;
        case CMD_SERVER_SET_SORT:
            offset = cmd_sort(tvb, offset, ft);
            break;
        case CMD_SERVER_SET_OPT:
            offset = cmd_optimize(tvb, offset, ft);
            break;
        case CMD_BLM_SET_MODE:
            offset = blm_mode(tvb, offset, ft);
            break;
        case CMD_LDF_LIST:
            offset = cmd_ldf_list(tvb, offset, ft);
            break;
        case CMD_LDF_DELETE:
            offset = cmd_ldf_delete(tvb, offset, ft);
            break;
        case CMD_LDF_DESC:
            offset = cmd_ldf_desc(tvb, offset, ft);
            break;
        case CMD_LDF_UPLOAD:
            offset = cmd_ldf_upload(tvb, offset, ft);
            break;
        case CMD_LDF_PARSE:
            offset = cmd_ldf_parse(tvb, offset, ft);
            break;
        case CMD_GET_NODE_SIGNALS:
            offset = cmd_ldf_get_node_signals(tvb, offset, ft);
            break;
        case CMD_GET_FRAMES:
            offset = cmd_ldf_get_frames(tvb, offset, ft);
            break;
        case CMD_GET_FRAME_INFO:
            offset = cmd_ldf_get_frame_info(tvb, offset, ft);
            break;
        case CMD_GET_SIGNAL_INFO:
            offset = cmd_ldf_get_signal_info(tvb, offset, ft);
            break;
        case CMD_GET_SIGNAL_DETAIL:
            offset = cmd_ldf_get_signal_detail(tvb, offset, ft);
            break;
        case CMD_GET_ENCODING_INFO:
            offset = cmd_ldf_get_encoding_info(tvb, offset, ft);
            break;
        case CMD_SAVE_SESSION:
            offset = cmd_ldf_save_session(tvb, offset, ft);
            break;
        case CMD_EMULATE_NODES:
            offset = cmd_ldf_emulate_nodes(tvb, offset, ft);
            break;
        case CMD_START_SCHEDULE:
            offset = cmd_ldf_start_schedule(tvb, offset, ft);
            break;
        case CMD_RESTORE_SESSION:
            offset = cmd_restore_session(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_VALUES:
            offset = cmd_cnvt_get_values(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_UNITS:
            offset = cmd_cnvt_get_units(tvb, offset, ft);
            break;
        case CMD_CNVT_SET_VALUES:
            offset = cmd_cnvt_set_values(tvb, offset, ft);
            break;
        case CMD_CNVT_SAVE_SESSION:
            offset = cmd_ldf_save_session(tvb, offset, ft);
            break;
        case CMD_CNVT_RESTORE_SESSION:
            offset = cmd_restore_session(tvb, offset, ft);
            break;
        case CMD_CNVT_DESTROY_SESSION:
            offset = cmd_cnvt_destroy_session(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_NODE_SIGNALS:
            offset = cmd_ldf_get_node_signals(tvb, offset, ft);
            break;
        case CMD_MSGRESP_ADD:
            offset = cmd_addresp(tvb, offset, pinfo, ft);
            break;
        case CMD_MSGRESP_GET:
            offset = resp_addresp(tvb, offset, ft);
            break;
        case CMD_MSGRESP_MODIFY:
            offset = cmd_modresp(tvb, offset, ft);
            break;
        case CMD_PGM_DESC:
            offset = cmd_desc(tvb, offset, ft);
            break;
        case CMD_PGM_UPLOAD:
            offset = cmd_upload(tvb, offset, ft);
            break;
        case CMD_PGM_DELETE:
            offset = cmd_delete(tvb, offset, ft);
            break;
        case CMD_PGM_LIST:
            offset = cmd_list(tvb, offset, ft);
            break;
        case CMD_PGM_START:
            offset = cmd_start(tvb, offset, ft);
            break;
        case CMD_PGM_STOP:
            offset = resp_start(tvb, offset, ft);
            break;
        case CMD_PGM_STATUS:
            offset = cmd_delete(tvb, offset, ft);
            break;
        case CMD_PGM_OPTIONS:
            offset = cmd_options(tvb, offset, ft);
            break;
        case CMD_PGM_FILES:
            offset = cmd_files(tvb, offset, ft);
            break;
        case CMD_SCHED_TX:
            offset = cmd_sched(tvb, offset, ft);
            break;
        case CMD_SCHED_KILL_TX:
            offset = resp_sched(tvb, offset, ft);
            break;
        case CMD_SCHED_MSG_REPLACE:
            offset = cmd_sched_rep(tvb, offset, ft);
            break;
        case CMD_USDT_REGISTER:
            offset = cmd_usdt(tvb, offset, ft);
            break;
        case CMD_USDT_SET_FUNCTIONAL:
            offset = cmd_usdt(tvb, offset, ft);
            break;
        case CMD_USDT_SET_STMIN_MULT:
            offset = cmd_usdt_set_stmin_mul(tvb, offset, ft);
            break;
        case CMD_USDT_REGISTER_NON_LEGACY:
            offset = cmd_usdt_register_non_legacy(tvb, offset, ft);
            break;
        case CMD_USDT_SET_STMIN_FC:
            offset = cmd_usdt_stmin_fc(tvb, offset, ft);
            break;
        case CMD_USDT_SET_BSMAX_FC:
            offset = cmd_usdt_bsmax_fc(tvb, offset, ft);
            break;
        case CMD_USDT_SET_STMIN_OVERRIDE:
            offset = cmd_usdt_stmin_override(tvb, offset, ft);
            break;
        case CMD_USDT_ACTIVATE_STMIN_OVERRIDE:
            offset = cmd_usdt_stmin_override_activate(tvb, offset, ft);
            break;
        case CMD_IOPWR_CLRLATCH:
            offset = cmd_bits_in(tvb, offset, ft);
            break;
        case CMD_IOPWR_SETOUT:
        case CMD_IOPWR_SETBIT:
        case CMD_IOPWR_CLRBIT:
            offset = cmd_bits_out(tvb, offset, ft);
            break;
        case CMD_UTIL_SET_INIT_STRATEGY:
            offset = cmd_init_strat(tvb, offset, ft);
            break;
        case CMD_CARD_IOCTL:
            ioctl_command = tvb_get_ntohl(tvb, offset);
            /* save the IOCTL in the context array for use during the command response */
            if (!pinfo->fd->visited) {
                pkt_info->ioctl_command = ioctl_command;
            }
            offset = cmd_ioctl(tvb, offset, ft, ioctl_command);
            break;
        default:
            proto_tree_add_item(ft, hf_gryphon_data, tvb, offset, msglen, ENC_NA);
            offset += msglen;
            break;
        }
    }

    return offset;
}

static int
decode_response(tvbuff_t *tvb, packet_info* pinfo, int offset, int src, proto_tree *pt)
{
    int             msglen;
    guint32         cmd;
    proto_tree      *ft;
    gryphon_pkt_info_t *pkt_info, *pkt_info_list;

    msglen = tvb_reported_length_remaining(tvb, offset);
    cmd = tvb_get_guint8(tvb, offset);

    if (cmd > 0x3F)
        cmd += src * 256;

    if (!pinfo->fd->visited) {
        /* Find a conversation, create a new if no one exists */
        gryphon_conversation *conv_data = get_conversation_data(pinfo);

        pkt_info = wmem_new0(wmem_file_scope(), gryphon_pkt_info_t);

        wmem_list_frame_t *frame = wmem_list_head(conv_data->request_frame_data);
        /* Step backward through all logged instances of request frames, looking for a request frame number that
        occurred immediately prior to current frame number that has a matching command */
        while (frame) {
            pkt_info_list = (gryphon_pkt_info_t*)wmem_list_frame_data(frame);
            if ((pinfo->num > pkt_info_list->req_frame_num) && (pkt_info_list->rsp_frame_num == 0) && (pkt_info_list->cmd == cmd)) {
                pkt_info->req_frame_num = pkt_info_list->req_frame_num;
                pkt_info->cmd_context = pkt_info_list->cmd_context;
                pkt_info->ioctl_command = pkt_info_list->ioctl_command;
                pkt_info->req_time = pkt_info_list->req_time;
                pkt_info_list->rsp_frame_num = pinfo->num;
                break;
            }

            frame = wmem_list_frame_next(frame);
        }

        p_add_proto_data(wmem_file_scope(), pinfo, proto_gryphon, (guint32)tvb_raw_offset(tvb), pkt_info);
    }
    else {
        pkt_info = (gryphon_pkt_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_gryphon, (guint32)tvb_raw_offset(tvb));
    }

    /* this is the old original way of displaying */
    proto_tree_add_uint(pt, hf_gryphon_command, tvb, offset, 1, cmd);
    if (pkt_info->ioctl_command != 0) {
        proto_tree_add_uint(pt, hf_gryphon_cmd_ioctl_context, tvb, offset + 1, 1, pkt_info->ioctl_command);
    } else {
        proto_tree_add_item(pt, hf_gryphon_cmd_context, tvb, offset + 1, 1, ENC_NA);
    }
    proto_tree_add_item(pt, hf_gryphon_reserved, tvb, offset + 2, 2, ENC_NA);
    offset += 4;
    msglen -= 4;

    proto_tree_add_item(pt, hf_gryphon_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    msglen -= 4;

    if (pkt_info->req_frame_num) {
        proto_item *it;
        nstime_t ns;

        it = proto_tree_add_uint(pt, hf_gryphon_response_to, tvb, 0, 0, pkt_info->req_frame_num);
        proto_item_set_generated(it);

        nstime_delta(&ns, &pinfo->fd->abs_ts, &pkt_info->req_time);
        it = proto_tree_add_time(pt, hf_gryphon_response_time, tvb, 0, 0, &ns);
        proto_item_set_generated(it);
    }

    if (msglen > 0) {
        ft = proto_tree_add_subtree_format(pt, tvb, offset, msglen, ett_gryphon_response_data, NULL,
            "Data: (%d byte%s)", msglen, plurality(msglen, "", "s"));

        switch (cmd)
        {
        case CMD_GET_CONFIG:
            offset = resp_config(tvb, offset, ft);
            break;
        case CMD_GET_TIME:
            offset = resp_time(tvb, offset, ft);
            break;
        case CMD_CARD_GET_SPEED:
            offset = speed(tvb, offset, ft);
            break;
        case CMD_CARD_GET_FILTER:
            offset = cmd_addfilt(tvb, offset, ft);
            break;
        case CMD_CARD_ADD_FILTER:
            offset = resp_addfilt(tvb, offset, ft);
            break;
        case CMD_CARD_GET_FILTER_HANDLES:
            offset = resp_filthan(tvb, offset, ft);
            break;
        case CMD_CARD_GET_DEFAULT_FILTER:
            offset = dfiltmode(tvb, offset, ft);
            break;
        case CMD_CARD_GET_FILTER_MODE:
            offset = filtmode(tvb, offset, ft);
            break;
        case CMD_CARD_GET_EVNAMES:
            offset = resp_events(tvb, offset, ft);
            break;
        case CMD_CARD_GET_SPEEDS:
            offset = resp_getspeeds(tvb, offset, ft);
            break;
        case CMD_SERVER_REG:
            offset = resp_register(tvb, offset, ft);
            break;
        case CMD_BLM_GET_MODE:
            offset = blm_mode(tvb, offset, ft);
            break;
        case CMD_BLM_GET_DATA:
            offset = resp_blm_data(tvb, offset, ft);
            break;
        case CMD_BLM_GET_STATS:
            offset = resp_blm_stat(tvb, offset, ft);
            break;
        case CMD_LDF_LIST:
            offset = resp_ldf_list(tvb, offset, ft);
            break;
        case CMD_LDF_DESC:
            offset = resp_ldf_desc(tvb, offset, ft);
            break;
        case CMD_GET_LDF_INFO:
            offset = resp_get_ldf_info(tvb, offset, ft);
            break;
        case CMD_GET_NODE_NAMES:
            offset = resp_ldf_get_node_names(tvb, offset, ft);
            break;
        case CMD_GET_NODE_SIGNALS:
            offset = resp_ldf_get_node_signals(tvb, offset, ft);
            break;
        case CMD_GET_FRAMES:
            offset = resp_ldf_get_frames(tvb, offset, ft);
            break;
        case CMD_GET_FRAME_INFO:
            offset = resp_ldf_get_frame_info(tvb, offset, ft);
            break;
        case CMD_GET_SIGNAL_INFO:
            offset = resp_ldf_get_signal_info(tvb, offset, ft);
            break;
        case CMD_GET_SIGNAL_DETAIL:
            offset = resp_ldf_get_signal_detail(tvb, offset, ft);
            break;
        case CMD_GET_ENCODING_INFO:
            offset = resp_ldf_get_encoding_info(tvb, offset, ft);
            break;
        case CMD_GET_SCHEDULES:
            offset = resp_ldf_get_schedules(tvb, offset, ft);
            break;
        case CMD_RESTORE_SESSION:
            offset = resp_restore_session(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_VALUES:
            offset = resp_cnvt_get_values(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_UNITS:
            offset = resp_cnvt_get_units(tvb, offset, ft);
            break;
        case CMD_CNVT_RESTORE_SESSION:
            offset = resp_restore_session(tvb, offset, ft);
            break;
        case CMD_CNVT_GET_NODE_SIGNALS:
            offset = resp_ldf_get_node_signals(tvb, offset, ft);
            break;
        case CMD_MSGRESP_ADD:
            offset = resp_addresp(tvb, offset, ft);
            break;
        case CMD_MSGRESP_GET:
            offset = cmd_addresp(tvb, offset, pinfo, ft);
            break;
        case CMD_MSGRESP_GET_HANDLES:
            offset = resp_resphan(tvb, offset, ft);
            break;
        case CMD_PGM_DESC:
            offset = resp_desc(tvb, offset, ft);
            break;
        case CMD_PGM_LIST:
            offset = resp_list(tvb, offset, ft);
            break;
        case CMD_PGM_START:
        case CMD_PGM_START2:
            offset = resp_start(tvb, offset, ft);
            break;
        case CMD_PGM_STATUS:
        case CMD_PGM_OPTIONS:
            offset = resp_status(tvb, offset, ft);
            break;
        case CMD_PGM_FILES:
            offset = resp_files(tvb, offset, ft);
            break;
        case CMD_SCHED_TX:
            offset = resp_sched(tvb, offset, ft);
            break;
        case CMD_USDT_GET_STMIN_FC:
            offset = cmd_usdt_stmin_fc(tvb, offset, ft);
            break;
        case CMD_USDT_GET_BSMAX_FC:
            offset = cmd_usdt_bsmax_fc(tvb, offset, ft);
            break;
        case CMD_USDT_GET_STMIN_OVERRIDE:
            offset = cmd_usdt_get_stmin_override(tvb, offset, ft);
            break;
        case CMD_IOPWR_GETINP:
        case CMD_IOPWR_GETLATCH:
        case CMD_IOPWR_CLRLATCH:
        case CMD_IOPWR_GETPOWER:
            offset = cmd_bits_in(tvb, offset, ft);
            break;
        case CMD_IOPWR_GETOUT:
            offset = cmd_bits_out(tvb, offset, ft);
            break;
        case CMD_UTIL_GET_INIT_STRATEGY:
            offset = cmd_init_strat(tvb, offset, ft);
            break;
        case CMD_CARD_IOCTL:
            offset = cmd_ioctl_resp(tvb, offset, ft, pkt_info->ioctl_command);
            break;
        default:
            proto_tree_add_item(ft, hf_gryphon_data, tvb, offset, msglen, ENC_NA);
            offset += msglen;
        }
    }

    return offset;
}

/*
* 20180221
* This function exists because Gryphon Protocol MISC packets contain within them Gryphon Protocol packets.
* So, this function will decode a packet and return the offset.
*/
static int
dissect_gryphon_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_msgresp_add)
{
    proto_tree      *gryphon_tree;
    proto_item      *ti, *type_item;
    proto_tree      *header_tree, *body_tree;
    int             msgend, msglen, msgpad;
    int             offset = 0;
    guint32         src, dest, i, frmtyp, flags;

    if (!is_msgresp_add) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gryphon");
        col_clear(pinfo->cinfo, COL_INFO);

        ti = proto_tree_add_item(tree, proto_gryphon, tvb, 0, -1, ENC_NA);
        gryphon_tree = proto_item_add_subtree(ti, ett_gryphon);
    }
    else {
        gryphon_tree = tree;
    }

    header_tree = proto_tree_add_subtree(gryphon_tree, tvb, offset, MSG_HDR_SZ, ett_gryphon_header, NULL, "Header");

    /* src */
    proto_tree_add_item_ret_uint(header_tree, hf_gryphon_src, tvb, offset, 1, ENC_BIG_ENDIAN, &src);
    /* 20180306 20171012 */
    /* srcchan */
    if (is_special_client(src)) {
        proto_tree_add_item(header_tree, hf_gryphon_srcchanclient, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    }
    else {
        proto_tree_add_item(header_tree, hf_gryphon_srcchan, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    }

    /* dest */
    proto_tree_add_item_ret_uint(header_tree, hf_gryphon_dest, tvb, offset + 2, 1, ENC_BIG_ENDIAN, &dest);
    /* 20180306 20171012 */
    /* destchan */
    if (is_special_client(dest)) {
        proto_tree_add_item(header_tree, hf_gryphon_destchanclient, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    }
    else {
        proto_tree_add_item(header_tree, hf_gryphon_destchan, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item_ret_uint(header_tree, hf_gryphon_data_length, tvb, offset + 4, 2, ENC_BIG_ENDIAN, &msglen);
    flags = tvb_get_guint8(tvb, offset + 6);
    frmtyp = flags & ~RESPONSE_FLAGS;
    type_item = proto_tree_add_uint(header_tree, hf_gryphon_type, tvb, offset + 6, 1, frmtyp);
    /*
    * Indicate what kind of message this is.
    */
    if (!is_msgresp_add)
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(frmtyp, frame_type, "- Invalid -"));

    if (is_msgresp_add) {
        static int * const wait_flags[] = {
            &hf_gryphon_wait_resp,
            &hf_gryphon_wait_prev_resp,
            NULL
        };

        proto_tree_add_bitmask(header_tree, tvb, offset + 6, hf_gryphon_wait_flags, ett_gryphon_flags, wait_flags, ENC_NA);
    }
    proto_tree_add_item(header_tree, hf_gryphon_reserved, tvb, offset + 7, 1, ENC_NA);
    offset += MSG_HDR_SZ;

    msgpad = 3 - (msglen + 3) % 4;
    msgend = offset + msglen + msgpad;

    body_tree = proto_tree_add_subtree(gryphon_tree, tvb, offset, msglen, ett_gryphon_body, NULL, "Body");

    switch (frmtyp) {
    case GY_FT_CMD:
        offset = decode_command(tvb, pinfo, msglen, offset, dest, body_tree);
        break;
    case GY_FT_RESP:
        offset = decode_response(tvb, pinfo, offset, src, body_tree);
        break;
    case GY_FT_DATA:
        offset = decode_data(tvb, offset, body_tree);
        break;
    case GY_FT_EVENT:
        offset = decode_event(tvb, offset, body_tree);
        break;
    case GY_FT_MISC:
        offset = decode_misc(tvb, offset, pinfo, body_tree);
        break;
    case GY_FT_TEXT:
        offset = decode_text(tvb, offset, msglen, body_tree);
        break;
    case GY_FT_SIG:
        break;
    default:
        expert_add_info(pinfo, type_item, &ei_gryphon_type);
        proto_tree_add_item(body_tree, hf_gryphon_data, tvb, offset, msglen, ENC_NA);
        break;
    }

    /*debug*/
    /*i = msgend - offset;*/
    /*proto_tree_add_debug_text(gryphon_tree, "debug offset=%d msgend=%d i=%d",offset,msgend,i);*/

    if (offset < msgend) {
        i = msgend - offset;
        /*
        * worked when msglen=4, offset=8, msgend=12, get i=4
        * did not work when msglen=5, offset=8, msgend=16, i is 8
        */
        proto_tree_add_item(gryphon_tree, hf_gryphon_padding, tvb, offset, i, ENC_NA);
        offset += i;
    }
    return offset;
}

static guint
get_gryphon_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint16 plen;
    int padded_len;

    /*
    * Get the length of the Gryphon packet, and then get the length as
    * padded to a 4-byte boundary.
    */
    plen = tvb_get_ntohs(tvb, offset + 4);
    padded_len = plen + 3 - (plen + 3) % 4;

    /*
    * That length doesn't include the fixed-length part of the header;
    * add that in.
    */
    return padded_len + GRYPHON_FRAME_HEADER_LEN;
}

static int
dissect_gryphon_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_gryphon_message(tvb, pinfo, tree, FALSE);
    return tvb_reported_length(tvb);
}

static int
dissect_gryphon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, gryphon_desegment, GRYPHON_FRAME_HEADER_LEN,
        get_gryphon_pdu_len, dissect_gryphon_pdu, data);
    return tvb_reported_length(tvb);
}

void
proto_register_gryphon(void)
{
    static hf_register_info hf[] = {
        { &hf_gryphon_src,
          { "Source",           "gryphon.src", FT_UINT8, BASE_HEX, VALS(src_dest), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_srcchan,
          { "Source channel",   "gryphon.srcchan", FT_UINT8,
                BASE_DEC | BASE_SPECIAL_VALS, VALS(channel_or_broadcast), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_srcchanclient,
          { "Source client id",   "gryphon.srcchanclient", FT_UINT8,
                BASE_DEC | BASE_SPECIAL_VALS, VALS(channel_or_broadcast), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_dest,
          { "Destination",      "gryphon.dest", FT_UINT8, BASE_HEX, VALS(src_dest), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_destchan,
          { "Destination channel", "gryphon.destchan", FT_UINT8,
                BASE_DEC | BASE_SPECIAL_VALS, VALS(channel_or_broadcast), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_destchanclient,
          { "Destination client id", "gryphon.destchanclient", FT_UINT8,
                BASE_DEC | BASE_SPECIAL_VALS, VALS(channel_or_broadcast), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_type,
          { "Frame type",       "gryphon.type", FT_UINT8, BASE_DEC, VALS(frame_type), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd,
          { "Command",          "gryphon.cmd", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_context,
          { "Context",      "gryphon.cmd.context", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_ioctl_context,
          { "IOCTL Response",  "gryphon.cmd.context", FT_UINT8, BASE_DEC, VALS(ioctls), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data,
          { "Data",          "gryphon.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_padding,
          { "Padding",          "gryphon.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ignored,
          { "Ignored",          "gryphon.ignored", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_length,
          { "Data length (bytes)",   "gryphon.data_length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_reserved,
          { "Reserved",          "gryphon.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_wait_flags,
          { "Flags",          "gryphon.wait_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_wait_resp,
          { "Wait for response", "gryphon.wait_resp", FT_BOOLEAN, 8, TFS(&tfs_wait_response), DONT_WAIT_FOR_RESP,
                NULL, HFILL }},
        { &hf_gryphon_wait_prev_resp,
          { "Wait for previous response", "gryphon.wait_prev_resp", FT_BOOLEAN, 8, TFS(&tfs_wait_response), WAIT_FOR_PREV_RESP,
                NULL, HFILL }},
        { &hf_gryphon_status,
          { "Status",          "gryphon.status", FT_UINT32, BASE_HEX, VALS(responses_vs), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_response_in,
          { "Response In",     "gryphon.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
                "The response to this Gryphon request is in this frame", HFILL }},
        { &hf_gryphon_response_to,
          { "Request In",      "gryphon.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
                "This is a response to the PANA request in this frame", HFILL }},
        { &hf_gryphon_response_time,
          { "Response Time",   "gryphon.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "The time between the request and the response", HFILL }},
        { &hf_gryphon_data_header_length,
          { "Header length (bytes)",   "gryphon.data.header_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_header_length_bits,
          { "Header length (bits)",   "gryphon.data.header_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_data_length,
          { "Data length (bytes)",   "gryphon.data.data_length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_extra_data_length,
          { "Extra data length (bytes)",   "gryphon.data.extra_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_mode,
          { "Mode",          "gryphon.data.mode", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_transmitted,
          { "Transmitted message", "gryphon.data.mode.transmitted", FT_BOOLEAN, 8, TFS(&true_false), 0x80,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_receive,
          { "Received message", "gryphon.data.mode.receive", FT_BOOLEAN, 8, TFS(&true_false), 0x40,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_local,
          { "Local message", "gryphon.data.mode.local", FT_BOOLEAN, 8, TFS(&true_false), 0x20,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_remote,
          { "Remote message (LIN)", "gryphon.data.mode.remote", FT_BOOLEAN, 8, TFS(&true_false), 0x10,
                NULL, HFILL }},
        /* 20171012 added additional mode bits */
        { &hf_gryphon_data_mode_oneshot,
          { "One-shot slave table message (LIN)", "gryphon.data.mode.oneshot", FT_BOOLEAN, 8, TFS(&true_false), 0x08,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_combined,
          { "Channel number is in context", "gryphon.data.mode.combined", FT_BOOLEAN, 8, TFS(&true_false), 0x04,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_nomux,
          { "Do not multiplex message", "gryphon.data.mode.nomux", FT_BOOLEAN, 8, TFS(&true_false), 0x02,
                NULL, HFILL }},
        { &hf_gryphon_data_mode_internal,
          { "Internal message", "gryphon.data.mode.internal", FT_BOOLEAN, 8, TFS(&true_false), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_data_priority,
          { "Priority",         "gryphon.data.priority", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_error_status,
          { "Error status",     "gryphon.data.error_status", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_time,
          { "Timestamp",        "gryphon.data.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_context,
          { "Context",      "gryphon.data.context", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_header_data,
          { "Header",          "gryphon.data.header_data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_data,
          { "Data",          "gryphon.data.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_extra_data,
          { "Extra data",          "gryphon.data.extra_data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_data_padding,
          { "Padding",          "gryphon.data.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_id,
          { "Event ID",      "gryphon.event.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_name,
          { "Event name",          "gryphon.event.name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_context,
          { "Event context",      "gryphon.event.context", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_time,
          { "Timestamp",        "gryphon.event.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_data,
          { "Data",          "gryphon.event.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_event_padding,
          { "Padding",       "gryphon.event.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_misc_text,
          { "Text",          "gryphon.misc.text", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_misc_padding,
          { "Padding",       "gryphon.misc.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_eventnum,
          { "Event numbers", "gryphon.eventnum", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_resp_time,
          { "Date/Time",     "gryphon.resp_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_setfilt,
          { "Pass/Block flag", "gryphon.setfilt.flag", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_setfilt_length,
          { "Length of Pattern & Mask", "gryphon.setfilt.length", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_setfilt_discard_data,
          { "Discarded data", "gryphon.setfilt.discard_data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_setfilt_padding,
          { "Padding",        "gryphon.setfilt.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ioctl,
          { "IOCTL", "gryphon.ioctl", FT_UINT32, BASE_HEX, VALS(ioctls), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ioctl_nbytes,
          { "Number of bytes to follow (bytes)", "gryphon.ioctl_nbytes", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ioctl_data,
          { "Data",        "gryphon.ioctl.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addfilt_pass,
          { "Conforming messages", "gryphon.addfilt.pass", FT_BOOLEAN, 8, TFS(&tfs_passed_blocked), FILTER_PASS_FLAG,
                NULL, HFILL }},
        { &hf_gryphon_addfilt_active,
          { "Filter", "gryphon.addfilt.active", FT_BOOLEAN, 8, TFS(&active_inactive), FILTER_ACTIVE_FLAG,
                NULL, HFILL }},
        { &hf_gryphon_addfilt_blocks,
          { "Number of filter blocks", "gryphon.addfilt.blocks", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addfilt_handle,
          { "Filter handle", "gryphon.addfilt.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_modfilt,
          { "Filter handle", "gryphon.modfilt", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_modfilt_action,
          { "Action", "gryphon.modfilt.action", FT_UINT8, BASE_DEC, VALS(filtacts), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filthan,
          { "Number of filter handles", "gryphon.filthan", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filthan_id,
          { "Filter handle ID", "gryphon.filthan.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filthan_padding,
          { "Padding",        "gryphon.filthan.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_dfiltmode,
          { "Filter mode", "gryphon.dfiltmode", FT_UINT8, BASE_DEC, VALS(dmodes), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filtmode,
          { "Filter mode", "gryphon.filtmode", FT_UINT8, BASE_DEC, VALS(modes), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_register_username,
          { "Username",          "gryphon.register.username", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_register_password,
          { "Password",          "gryphon.register.password", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_register_client_id,
          { "Client ID", "gryphon.register.client_id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_register_privileges,
          { "Privileges", "gryphon.register.privileges", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_getspeeds_set_ioctl,
          { "Set Speed IOCTL", "gryphon.getspeeds.set_ioctl", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_getspeeds_get_ioctl,
          { "Get Speed IOCTL", "gryphon.getspeeds.get_ioctl", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_getspeeds_size,
          { "Speed data size (bytes)", "gryphon.getspeeds.size", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_getspeeds_preset,
          { "Preset speed numbers", "gryphon.getspeeds.preset", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_getspeeds_data,
          { "Data for preset",      "gryphon.getspeeds.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_sort,
          { "Set sorting", "gryphon.cmd_sort", FT_UINT8, BASE_DEC, VALS(cmd_sort_type), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_optimize,
          { "Set optimization", "gryphon.cmd_optimize", FT_UINT8, BASE_DEC, VALS(cmd_optimize_type), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_device_name,
          { "Device name",          "gryphon.config.device_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_device_version,
          { "Device version",          "gryphon.config.device_version", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_device_serial_number,
          { "Device serial number",    "gryphon.config.device_serial_number", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_num_channels,
          { "Number of channels", "gryphon.config.num_channels", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_name_version_ext,
          { "Name & version extension",    "gryphon.config.name_version_ext", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_driver_name,
          { "Driver name",          "gryphon.config.driver_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_driver_version,
          { "Driver version",          "gryphon.config.driver_version", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_device_security,
          { "Device security string",    "gryphon.config.device_security", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_max_data_length,
          { "Maximum data length (bytes)", "gryphon.config.max_data_length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_min_data_length,
          { "Minimum data length (bytes)", "gryphon.config.min_data_length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_hardware_serial_number,
          { "Hardware serial number",    "gryphon.config.hardware_serial_number", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_protocol_type,
          { "Protocol type & subtype", "gryphon.config.protocol_type", FT_UINT16, BASE_HEX, VALS(protocol_types), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_channel_id,
          { "Channel ID", "gryphon.config.channel_id", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_card_slot_number,
          { "Card slot number", "gryphon.config.card_slot_number", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_max_extra_data,
          { "Maximum extra data (bytes)", "gryphon.config.max_extra_data", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_config_min_extra_data,
          { "Minimum extra data (bytes)", "gryphon.config.min_extra_data", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_num_iterations,
          { "Number of iterations", "gryphon.sched.num_iterations", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_flags,
          { "Flags", "gryphon.sched.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_flags_scheduler,
          { "Scheduler", "gryphon.sched.flags.scheduler", FT_BOOLEAN, 32, TFS(&critical_normal), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_sched_sleep,
          { "Sleep (milliseconds)", "gryphon.sched.sleep", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_transmit_count,
          { "Transmit count", "gryphon.sched.transmit_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_transmit_period,
          { "Transmit period (milliseconds)", "gryphon.sched.transmit_period", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_transmit_flags,
          { "Flags", "gryphon.sched.transmit_flags", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_skip_transmit_period,
          { "Last transmit period", "gryphon.sched.skip_transmit_period", FT_BOOLEAN, 16, TFS(&skip_not_skip), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_sched_skip_sleep,
          { "Last transmit period", "gryphon.sched.skip_transmit_period", FT_BOOLEAN, 16, TFS(&skip_not_skip), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_sched_channel,
          { "Channel", "gryphon.sched.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_channel0,
          { "Channel (specified by the destination channel)", "gryphon.sched.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_rep_id,
          { "Schedule ID", "gryphon.sched.rep_id", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_sched_rep_message_index,
          { "Message index", "gryphon.sched.rep_message_index", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_data_time,
          { "Timestamp",        "gryphon.blm_data.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_data_bus_load,
          { "Bus load average (%)", "gryphon.blm_data.bus_load", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_data_current_bus_load,
          { "Current bus load (%)", "gryphon.blm_data.current_bus_load", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_data_peak_bus_load,
          { "Peak bus load (%)", "gryphon.blm_data.peak_bus_load", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_data_historic_peak_bus_load,
          { "Historic peak bus load (%)", "gryphon.blm_data.historic_peak_bus_load", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_receive_frame_count,
          { "Receive frame count", "gryphon.blm_stat.receive_frame_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_transmit_frame_count,
          { "Transmit frame count", "gryphon.blm_stat.transmit_frame_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_receive_dropped_frame_count,
          { "Receive dropped frame count", "gryphon.blm_stat.receive_dropped_frame_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_transmit_dropped_frame_count,
          { "Transmit dropped frame count", "gryphon.blm_stat.transmit_dropped_frame_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_receive_error_count,
          { "Receive error count", "gryphon.blm_stat.receive_error_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_stat_transmit_error_count,
          { "Transmit error count", "gryphon.blm_stat.transmit_error_count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addresp_flags,
          { "Flags", "gryphon.addresp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        /* 20171017 fixed display of filter flags */
        { &hf_gryphon_addresp_flags_active,
          { "Filter active flag", "gryphon.addresp.flags.active", FT_BOOLEAN, 8, TFS(&active_inactive), FILTER_ACTIVE_FLAG,
                NULL, HFILL }},
        { &hf_gryphon_addresp_blocks,
          { "Number of filter blocks", "gryphon.addresp.blocks", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_number,
          { "Number of LDF names", "gryphon.ldf.number", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_nodenumber,
          { "Number of nodes", "gryphon.ldf.nodenumber", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_list,
          { "LDF block index", "gryphon.ldf.list", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_remaining,
          { "Remaining LDF names", "gryphon.ldf.remaining", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_name,
          { "File Name",    "gryphon.ldf.name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_info_pv,
          { "Protocol version",    "gryphon.ldf.pv", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_info_lv,
          { "Language version",    "gryphon.ldf.lv", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_ui,
          { "Unique identifier",        "gryphon.ldf.ui", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_nodename,
          { "Node Name",    "gryphon.lin.nodename", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_data_length,
          { "Data length (bytes)",   "gryphon.lin.data_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_slave_table_enable,
          { "Slave table entry",   "gryphon.lin.slave_table_enable", FT_UINT8, BASE_DEC, VALS(lin_slave_table_enable), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_slave_table_cs,
          { "Slave table checksum",   "gryphon.lin.slave_table_cs", FT_UINT8, BASE_DEC, VALS(lin_slave_table_cs), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_slave_table_data,
          { "Data",          "gryphon.lin.slave_table_data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_slave_table_datacs,
          { "Checksum",          "gryphon.lin.slave_table_datacs", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_masterevent,
          { "Starting frame id", "gryphon.lin.masterevent", FT_UINT8, BASE_DEC, VALS(lin_ioctl_masterevent), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_numdata,
          { "Number of data bytes", "gryphon.lin.numdata", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_lin_numextra,
          { "Number of extra bytes", "gryphon.lin.numextra", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_description,
          { "Description",    "gryphon.ldf.description", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_size,
          { "Size of LDF to be uploaded", "gryphon.ldf.size", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_exists,
          { "LDF name existence check",       "gryphon.ldf.exists", FT_UINT8, BASE_DEC, VALS(ldf_exists), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_blockn,
          { "Block number",   "gryphon.ldf.blockn", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_file,
          { "Upload text block",    "gryphon.ldf.file", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_desc_pad,
          { "Padding (TODO: need to fix response data length)",          "gryphon.ldf.desc_pad", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_restore_session,
          { "Session id",        "gryphon.ldf.restore_session", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_schedule_name,
          { "Schedule name",          "gryphon.ldf.schedule_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_schedule_msg_dbytes,
          { "Data length (bytes)", "gryphon.ldf.schedule_msg_dbytes", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_schedule_flags,
          { "Flags",          "gryphon.ldf.schedule_flags", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_schedule_event,
          { "Event driven", "gryphon.ldf.schedule_event_ev", FT_BOOLEAN, 8, TFS(&true_false), 0x80,
                NULL, HFILL }},
        { &hf_gryphon_ldf_schedule_sporadic,
          { "Sporadic", "gryphon.ldf.schedule_event_sp", FT_BOOLEAN, 8, TFS(&true_false), 0x40,
                NULL, HFILL }},
        { &hf_gryphon_ldf_ioctl_setflags,
          { "Starting frame id", "gryphon.ldf.ioctl_setflags", FT_UINT8, BASE_DEC, VALS(lin_ldf_ioctl_setflags), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_ioctl_setflags_flags,
          { "Id", "gryphon.ldf.ioctl_setflags_flags", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_numb_ids,
          { "Number of ids", "gryphon.ldf.numb_ids", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_bitrate,
          { "Bitrate", "gryphon.ldf.bitrate", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_sched_size_place,
          { "Placeholder for schedule size (bytes)", "gryphon.ldf.schedsize", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_sched_numb_place,
          { "Placeholder for number of schedules", "gryphon.ldf.numbsched", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_sched_size,
          { "Schedule size (bytes)", "gryphon.ldf.schedsize", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_num_node_names,
          { "Number of node names", "gryphon.ldf.num_node_names", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_num_frames,
          { "Number of frames", "gryphon.ldf.num_frames", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_get_frame,
          { "Frame",    "gryphon.ldf.get_frame", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_get_frame_num,
          { "Number of data bytes in slave response", "gryphon.ldf.get_frame_num", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_get_frame_pub,
          { "Publisher",    "gryphon.ldf.get_frame_pub", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_get_frame_num_signals,
          { "Number of signals", "gryphon.ldf.get_frame_num_signals", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_num_signal_names,
          { "Number of signal names", "gryphon.ldf.num_signal_names", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_num_schedules,
          { "Number of schedules", "gryphon.ldf.num_schedules", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_num_encodings,
          { "Number of encodings", "gryphon.ldf.num_encodings", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_encoding_value,
          { "Encoding value", "gryphon.ldf.encoding_value", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_encoding_min,
          { "Encoding min value", "gryphon.ldf.encoding_min", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_encoding_max,
          { "Encoding max value", "gryphon.ldf.encoding_max", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_master_node_name,
          { "Master node name",    "gryphon.ldf.master", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_slave_node_name,
          { "Slave node name",    "gryphon.ldf.slave", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_node_name,
          { "Node name",    "gryphon.ldf.node_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_name,
          { "Signal name",    "gryphon.ldf.signal_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_encoding_name,
          { "Signal encoding name",    "gryphon.ldf.signal_encoding_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_encoding_type,
          { "Signal encoding type",    "gryphon.ldf.signal_encoding_type", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_encoding_logical,
          { "Signal encoding string",    "gryphon.ldf.signal_encoding_logical", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_offset,
          { "Offset (bits)", "gryphon.ldf.signal_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_ldf_signal_length,
          { "Length (bits)", "gryphon.ldf.signal_length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* cnvt */
        { &hf_gryphon_cnvt_valuef,
          { "Float value", "gryphon.cnvt.valuef", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cnvt_valuei,
          { "Int value", "gryphon.cnvt.valuei", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cnvt_values,
          { "String value",    "gryphon.cnvt.values", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cnvt_units,
          { "String units",    "gryphon.cnvt.units", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cnvt_flags_getvalues,
          { "Flags", "gryphon.cnvt.flags.getvalues", FT_UINT8, BASE_DEC, VALS(lin_cnvt_getflags), 0x0,
                NULL, HFILL }},
        /* delay driver */
        { &hf_gryphon_dd_stream,
          { "Stream number", "gryphon.dd.stream", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_dd_value,
          { "Value (bytes)",   "gryphon.dd.value", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_dd_time,
          { "Time (msec)",   "gryphon.dd.time", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addresp_responses,
          { "Number of response blocks", "gryphon.addresp.responses", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addresp_old_handle,
          { "Old handle", "gryphon.addresp.old_handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addresp_action,
          { "Action", "gryphon.addresp.action", FT_UINT8, BASE_DEC, VALS(action_vals), 0x07,
                NULL, HFILL }},
        { &hf_gryphon_addresp_action_period,
          { "Period", "gryphon.addresp.action_period", FT_BOOLEAN, 8, TFS(&frames_01seconds), FR_PERIOD_MSGS,
                NULL, HFILL }},
        { &hf_gryphon_addresp_action_deact_on_event,
          { "Deact on event", "gryphon.addresp.action.deact_on_event", FT_UINT8, BASE_DEC, VALS(deact_on_event_vals), FR_DELETE|FR_DEACT_ON_EVENT,
                NULL, HFILL }},
        { &hf_gryphon_addresp_action_deact_after_period,
          { "Deact on Period", "gryphon.addresp.action.deact_after_period", FT_UINT8, BASE_DEC, VALS(deact_after_per_vals), FR_DELETE|FR_DEACT_AFTER_PER,
                NULL, HFILL }},
        { &hf_gryphon_addresp_action_period_type,
          { "Period", "gryphon.addresp.action_period_type", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_addresp_handle,
          { "Response handle", "gryphon.addresp.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_modresp_handle,
          { "Response handle", "gryphon.modresp.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_modresp_action,
          { "Action response", "gryphon.modresp.action", FT_UINT8, BASE_DEC, VALS(filtacts), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_num_resphan,
          { "Number of response handles", "gryphon.num_resphan", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_handle,
          { "Handle", "gryphon.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_transmit_sched_id,
          { "Transmit schedule ID", "gryphon.transmit_sched_id", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_desc_program_size,
          { "Program size", "gryphon.desc.program_size", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_desc_program_name,
          { "Program name",    "gryphon.desc.program_name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_desc_program_description,
          { "Program description",    "gryphon.desc.program_description", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_desc_flags,
          { "Flags", "gryphon.desc.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_desc_flags_program,
          { "Period", "gryphon.desc.flags.program", FT_BOOLEAN, 8, TFS(&present_not_present), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_desc_handle,
          { "Handle", "gryphon.desc.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_upload_block_number,
          { "Block number", "gryphon.upload.block_number", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_upload_handle,
          { "Handle", "gryphon.upload.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_upload_data,
          { "Data",          "gryphon.upload.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_delete,
          { "Program name",    "gryphon.delete", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_list_block_number,
          { "Block number", "gryphon.list.block_number", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_list_num_programs,
          { "Number of programs in this response", "gryphon.list.num_programs", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_list_num_remain_programs,
          { "Number of remaining programs", "gryphon.list.num_remain_programs", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_list_name,
          { "Name",    "gryphon.list.name", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_list_description,
          { "Description",    "gryphon.list.description", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_start_arguments,
          { "Arguments",    "gryphon.start.arguments", FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_start_channel,
          { "Channel (Client) number", "gryphon.start.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_status_num_running_copies,
          { "Number of running copies", "gryphon.status.num_running_copies", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_options_handle,
          { "Handle", "gryphon.options.handle", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_files,
          { "Directory",    "gryphon.files", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_flags_register,
          { "USDT", "gryphon.usdt.flags_register", FT_UINT8, BASE_DEC, VALS(register_unregister), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_usdt_action_flags,
          { "Action Flags", "gryphon.usdt.action_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        /* 20171012 added non legacy USDT */
        { &hf_gryphon_usdt_action_flags_non_legacy,
          { "Action Flags", "gryphon.usdt.action_flags.non_legacy", FT_BOOLEAN, 8, TFS(&register_unregister_action_flags), 0x01,
                NULL, HFILL }},

        { &hf_gryphon_usdt_action_flags_register,
          { "Register", "gryphon.usdt.action_flags.register", FT_UINT8, BASE_DEC, VALS(register_unregister), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_usdt_action_flags_action,
          { "Action", "gryphon.usdt.action_flags.action", FT_UINT8, BASE_DEC, VALS(usdt_action_vals), 0x06,
                NULL, HFILL }},
        { &hf_gryphon_usdt_transmit_options_flags,
          { "Transmit options", "gryphon.usdt.transmit_options_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        /* 20171012 USDT tx options */
        /* bit 0*/
        { &hf_gryphon_usdt_transmit_options_flags_echo,
          { "Echo long", "gryphon.usdt.transmit_options_flags.echo_long", FT_UINT8, BASE_DEC, VALS(xmit_opt_echo_long), 0x01, NULL, HFILL }},
        /* bits 1 & 2 */
        { &hf_gryphon_usdt_transmit_options_action,
          { "Transmit Action", "gryphon.usdt.transmit_options_flags.action", FT_UINT8, BASE_DEC, VALS(xmit_opt_vals), 0x06,
                NULL, HFILL }},
        /* bit 3 */
        { &hf_gryphon_usdt_transmit_options_done_event,
          { "Done event", "gryphon.usdt.transmit_options_flags.done_event", FT_UINT8, BASE_DEC, VALS(xmit_opt_done), 0x08, NULL, HFILL }},
        /* bit 4 */
        { &hf_gryphon_usdt_transmit_options_echo_short,
          { "Echo short", "gryphon.usdt.transmit_options_flags.echo_log", FT_UINT8, BASE_DEC, VALS(xmit_opt_echo_short), 0x10, NULL, HFILL }},
        /* bit 5 */
        { &hf_gryphon_usdt_transmit_options_rx_nth_fc,
          { "Nth flowcontrol event", "gryphon.usdt.transmit_options_flags.nth_fc_event", FT_UINT8, BASE_DEC, VALS(xmit_opt_nth_fc_event), 0x20, NULL, HFILL }},

        /* bit 5 */
        { &hf_gryphon_usdt_transmit_options_send_done,
          { "Send a USDT_DONE event when the last frame of a multi-frame USDT message is transmitted",
                "gryphon.usdt.transmit_options_flags.send_done", FT_BOOLEAN, 8, TFS(&yes_no), 0x08, NULL, HFILL }},

        /* 20171012 USDT rx options */
        { &hf_gryphon_usdt_receive_options_flags,
          { "Receive options", "gryphon.usdt.receive_options_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        /* bits 0 & 1 */
        { &hf_gryphon_usdt_receive_options_action, /* legacy */
          { "Receive Action", "gryphon.usdt.receive_options_flags.action", FT_UINT8, BASE_DEC, VALS(recv_opt_vals), 0x03, NULL, HFILL }},
        /* bit 2 */
        { &hf_gryphon_usdt_receive_options_firstframe_event,
          { "First frame event", "gryphon.usdt.receive_options_flags.firstframe_event", FT_UINT8, BASE_DEC, VALS(recv_opt_firstframe_event), 0x04, NULL, HFILL }},
        /* bit 3 */
        { &hf_gryphon_usdt_receive_options_lastframe_event,
          { "Last frame event", "gryphon.usdt.receive_options_flags.lastframe_event", FT_UINT8, BASE_DEC, VALS(recv_opt_lastframe_event), 0x08, NULL, HFILL }},
        /* bit 5 */
        { &hf_gryphon_usdt_receive_options_tx_nth_fc,
          { "Nth flowcontrol event", "gryphon.usdt.receive_options_flags.nth_fc_event", FT_UINT8, BASE_DEC, VALS(recv_opt_nth_fc_event), 0x20, NULL, HFILL }},

        /* J1939 options */
        { &hf_gryphon_usdt_length_options_flags,
          { "Length options", "gryphon.usdt.length_options_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        /* bit 6 */
        { &hf_gryphon_usdt_length_control_j1939,
          { "Length control bit", "gryphon.usdt.length_options_flags.j1939", FT_UINT8, BASE_DEC, VALS(recv_opt_j1939), 0x40, NULL, HFILL }},

        /* 20171013 */
        { &hf_gryphon_usdt_stmin_fc,
          { "STMIN flow control time (milliseconds)", "gryphon.usdt.set_stmin_fc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_gryphon_usdt_set_stmin_mul,
          { "STMIN multiplier", "gryphon.usdt.set_stmin_mul", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_bsmax_fc,
          { "Block size max for flow control", "gryphon.usdt.set_bsmax_fc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_gryphon_usdt_stmin_override,
          { "STMIN override time (milliseconds)", "gryphon.usdt.set_stmin_override", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_gryphon_usdt_stmin_override_active,
          { "STMIN override active", "gryphon.usdt.stmin_active", FT_BOOLEAN, 8, TFS(&active_inactive), FILTER_ACTIVE_FLAG,
                NULL, HFILL }},
        { &hf_gryphon_usdt_stmin_override_activate,
          { "STMIN override activate", "gryphon.usdt.stmin_active", FT_BOOLEAN, 8, TFS(&active_inactive), FILTER_ACTIVE_FLAG,
                NULL, HFILL }},

        { &hf_gryphon_usdt_receive_options_firstframe,
          { "Send a USDT_FIRSTFRAME event when the first frame of a multi-frame USDT message is received",
            "gryphon.usdt.receive_options_flags.firstframe",  FT_BOOLEAN, 8, TFS(&yes_no), 0x04, NULL, HFILL }},
        { &hf_gryphon_usdt_receive_options_lastframe,
          { "Send a USDT_LASTFRAME event when the first frame of a multi-frame USDT message is received",
             "gryphon.usdt.receive_options_flags.lastframe", FT_BOOLEAN, 8, TFS(&yes_no), 0x08, NULL, HFILL }},
        { &hf_gryphon_usdt_ext_address,
          { "Using extended addressing for", "gryphon.usdt.ext_address", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_ext_address_id,
          { "ID", "gryphon.usdt.ext_address.id", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_block_size,
          { "Number of IDs in the block", "gryphon.usdt.block_size", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_bits_in_input1,
          { "Input 1", "gryphon.bits_in.input1", FT_BOOLEAN, 8, TFS(&set_not_set), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_bits_in_input2,
          { "Input 2", "gryphon.bits_in.input2", FT_BOOLEAN, 8, TFS(&set_not_set), 0x02,
                NULL, HFILL }},
        { &hf_gryphon_bits_in_input3,
          { "Input 3", "gryphon.bits_in.input3", FT_BOOLEAN, 8, TFS(&set_not_set), 0x04,
                NULL, HFILL }},
        { &hf_gryphon_bits_in_pushbutton,
          { "Pushbutton", "gryphon.bits_in.pushbutton", FT_BOOLEAN, 8, TFS(&set_not_set), 0x08,
                NULL, HFILL }},
        { &hf_gryphon_bits_out_output1,
          { "Input 1", "gryphon.bits_out.output1", FT_BOOLEAN, 8, TFS(&set_not_set), 0x01,
                NULL, HFILL }},
        { &hf_gryphon_bits_out_output2,
          { "Input 2", "gryphon.bits_out.output2", FT_BOOLEAN, 8, TFS(&set_not_set), 0x02,
                NULL, HFILL }},
        { &hf_gryphon_init_strat_reset_limit,
          { "Reset Limit", "gryphon.init_strat.reset_limit", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_init_strat_delay,
          { "Delay", "gryphon.init_strat.strat_delay", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_speed_baud_rate_index,
          { "Baud rate index", "gryphon.speed.baud_rate_index", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_start,
          { "Filter field starts at byte", "gryphon.filter_block.filter_start", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_length,
          { "Filter field length", "gryphon.filter_block.filter_length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_type,
          { "Filtering on", "gryphon.filter_block.filter_type", FT_UINT8, BASE_DEC, VALS(filter_data_types), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_operator,
          { "Type of comparison", "gryphon.filter_block.filter_operator", FT_UINT8, BASE_DEC, VALS(operators), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_value1,
          { "Value", "gryphon.filter_block.filter_value", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_value2,
          { "Value", "gryphon.filter_block.filter_value", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_value4,
          { "Value", "gryphon.filter_block.filter_value", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_filter_value_bytes,
          { "Value",    "gryphon.filter_block.filter_value_bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_mode,
          { "Mode", "gryphon.blm_mode", FT_UINT32, BASE_DEC, VALS(blm_mode_vals), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_mode_avg_period,
          { "Averaging period", "gryphon.blm_mode.avg_period", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_blm_mode_avg_frames,
          { "Averaging period (frames)", "gryphon.blm_mode.avg_frames", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_command,
          { "Command", "gryphon.command", FT_UINT32, BASE_HEX|BASE_EXT_STRING, &cmd_vals_ext, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_mode,
          { "Mode", "gryphon.command.mode", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_option,
          { "Option", "gryphon.option", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_option_data,
          { "Option data", "gryphon.option_data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_cmd_file,
          { "File", "gryphon.command.file", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_bit_in_digital_data,
          { "Digital values set", "gryphon.bit_in_digital_data", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_bit_out_digital_data,
          { "Digital values set", "gryphon.bit_out_digital_data", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_pattern,
          { "Pattern", "gryphon.filter_block.pattern", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filter_block_mask,
          { "Mask", "gryphon.filter_block.mask", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        /* 20171012 USDT */
        { &hf_gryphon_usdt_nids,
          { "Number of IDs in block", "gryphon.nids", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gryphon_usdt_request,
          { "USDT request IDs", "gryphon.usdt_request", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_request_ext,
          { "USDT request extended address", "gryphon.usdt_request_ext", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_response,
          { "USDT response IDs", "gryphon.usdt_response", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_usdt_response_ext,
          { "USDT response extended address", "gryphon.usdt_response_ext", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_uudt_response,
          { "UUDT response IDs", "gryphon.uudt_response", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_uudt_response_ext,
          { "UUDT response extended address", "gryphon.usdt_response_ext", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_more_filenames,
          { "More filenames to return", "gryphon.more_filenames", FT_BOOLEAN, 8, TFS(&yes_no), 0x0,
                NULL, HFILL }},
        { &hf_gryphon_filenames,
          { "File and directory names", "gryphon.filenames", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_program_channel_number,
          { "Program channel number", "gryphon.program_channel_number", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_gryphon_valid_header_length,
          { "Valid Header length", "gryphon.valid_header_length", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_gryphon,
        &ett_gryphon_header,
        &ett_gryphon_body,
        &ett_gryphon_command_data,
        &ett_gryphon_response_data,
        &ett_gryphon_data_header,
        &ett_gryphon_flags,
        &ett_gryphon_data_body,
        &ett_gryphon_cmd_filter_block,
        &ett_gryphon_cmd_events_data,
        &ett_gryphon_cmd_config_device,
        &ett_gryphon_cmd_sched_data,
        &ett_gryphon_cmd_sched_cmd,
        &ett_gryphon_cmd_response_block,
        &ett_gryphon_pgm_list,
        &ett_gryphon_pgm_status,
        &ett_gryphon_pgm_options,
        &ett_gryphon_valid_headers,
        &ett_gryphon_usdt_data,
        &ett_gryphon_usdt_action_flags,
        &ett_gryphon_usdt_tx_options_flags,
        &ett_gryphon_usdt_rx_options_flags,
        &ett_gryphon_usdt_len_options_flags,
        &ett_gryphon_usdt_data_block,
        &ett_gryphon_lin_emulate_node,
        &ett_gryphon_ldf_block,
        &ett_gryphon_ldf_schedule_name,
        &ett_gryphon_lin_schedule_msg,
        &ett_gryphon_cnvt_getflags,
        &ett_gryphon_digital_data,
        &ett_gryphon_blm_mode
    };

    static ei_register_info ei[] = {
        { &ei_gryphon_type,{ "gryphon.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid frame type", EXPFILL } },
    };

    module_t *gryphon_module;
    expert_module_t* expert_gryphon;

    proto_gryphon = proto_register_protocol("DG Gryphon Protocol", "Gryphon", "gryphon");
    proto_register_field_array(proto_gryphon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gryphon = expert_register_protocol(proto_gryphon);
    expert_register_field_array(expert_gryphon, ei, array_length(ei));

    gryphon_module = prefs_register_protocol(proto_gryphon, NULL);
    prefs_register_bool_preference(gryphon_module, "desegment",
        "Desegment all Gryphon messages spanning multiple TCP segments",
        "Whether the Gryphon dissector should desegment all messages spanning multiple TCP segments",
        &gryphon_desegment);

}

void
proto_reg_handoff_gryphon(void)
{
    dissector_handle_t gryphon_handle;

    gryphon_handle = create_dissector_handle(dissect_gryphon, proto_gryphon);
    dissector_add_uint_with_preference("tcp.port", GRYPHON_TCP_PORT, gryphon_handle);
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
