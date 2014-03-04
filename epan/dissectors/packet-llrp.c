/* packet-llrp.c
 * Routines for Low Level Reader Protocol dissection
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 * Copyright 2012, Martin Kupec <martin.kupec@kupson.cz>
 *
 * http://www.gs1.org/gsmp/kc/epcglobal/llrp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>

void proto_register_llrp(void);
void proto_reg_handoff_llrp(void);

#define LLRP_PORT 5084

/* Initialize the protocol and registered fields */
static int proto_llrp                             = -1;
static int hf_llrp_version                        = -1;
static int hf_llrp_type                           = -1;
static int hf_llrp_length                         = -1;
static int hf_llrp_id                             = -1;
static int hf_llrp_cur_ver                        = -1;
static int hf_llrp_sup_ver                        = -1;
static int hf_llrp_req_cap                        = -1;
static int hf_llrp_req_conf                       = -1;
static int hf_llrp_rospec                         = -1;
static int hf_llrp_antenna_id                     = -1;
static int hf_llrp_gpi_port                       = -1;
static int hf_llrp_gpo_port                       = -1;
static int hf_llrp_rest_fact                      = -1;
static int hf_llrp_accessspec                     = -1;
static int hf_llrp_vendor                         = -1;
static int hf_llrp_impinj_msg_type                = -1;
static int hf_llrp_tlv_type                       = -1;
static int hf_llrp_tv_type                        = -1;
static int hf_llrp_tlv_len                        = -1;
static int hf_llrp_param                          = -1;
static int hf_llrp_num_gpi                        = -1;
static int hf_llrp_num_gpo                        = -1;
static int hf_llrp_microseconds                   = -1;
static int hf_llrp_max_supported_antenna          = -1;
static int hf_llrp_can_set_antenna_prop           = -1;
static int hf_llrp_has_utc_clock                  = -1;
static int hf_llrp_device_manufacturer            = -1;
static int hf_llrp_model                          = -1;
static int hf_llrp_firmware_version               = -1;
static int hf_llrp_max_receive_sense              = -1;
static int hf_llrp_index                          = -1;
static int hf_llrp_receive_sense                  = -1;
static int hf_llrp_receive_sense_index_min        = -1;
static int hf_llrp_receive_sense_index_max        = -1;
static int hf_llrp_num_protocols                  = -1;
static int hf_llrp_protocol_id                    = -1;
static int hf_llrp_can_do_survey                  = -1;
static int hf_llrp_can_report_buffer_warning      = -1;
static int hf_llrp_support_client_opspec          = -1;
static int hf_llrp_can_stateaware                 = -1;
static int hf_llrp_support_holding                = -1;
static int hf_llrp_max_priority_supported         = -1;
static int hf_llrp_client_opspec_timeout          = -1;
static int hf_llrp_max_num_rospec                 = -1;
static int hf_llrp_max_num_spec_per_rospec        = -1;
static int hf_llrp_max_num_inventory_per_aispec   = -1;
static int hf_llrp_max_num_accessspec             = -1;
static int hf_llrp_max_num_opspec_per_accressspec = -1;
static int hf_llrp_country_code                   = -1;
static int hf_llrp_comm_standard                  = -1;
static int hf_llrp_transmit_power                 = -1;
static int hf_llrp_hopping                        = -1;
static int hf_llrp_hop_table_id                   = -1;
static int hf_llrp_rfu                            = -1;
static int hf_llrp_num_hops                       = -1;
static int hf_llrp_frequency                      = -1;
static int hf_llrp_num_freqs                      = -1;
static int hf_llrp_min_freq                       = -1;
static int hf_llrp_max_freq                       = -1;
static int hf_llrp_rospec_id                      = -1;
static int hf_llrp_priority                       = -1;
static int hf_llrp_cur_state                      = -1;
static int hf_llrp_rospec_start_trig_type         = -1;
static int hf_llrp_offset                         = -1;
static int hf_llrp_period                         = -1;
static int hf_llrp_gpi_event                      = -1;
static int hf_llrp_timeout                        = -1;
static int hf_llrp_rospec_stop_trig_type          = -1;
static int hf_llrp_duration_trig                  = -1;
static int hf_llrp_antenna_count                  = -1;
static int hf_llrp_antenna                        = -1;
static int hf_llrp_aispec_stop_trig_type          = -1;
static int hf_llrp_trig_type                      = -1;
static int hf_llrp_number_of_tags                 = -1;
static int hf_llrp_number_of_attempts             = -1;
static int hf_llrp_t                              = -1;
static int hf_llrp_inventory_spec_id              = -1;
static int hf_llrp_start_freq                     = -1;
static int hf_llrp_stop_freq                      = -1;
static int hf_llrp_stop_trig_type                 = -1;
static int hf_llrp_n_4                            = -1;
static int hf_llrp_duration                       = -1;
static int hf_llrp_accessspec_id                  = -1;
static int hf_llrp_access_cur_state               = -1;
static int hf_llrp_access_stop_trig_type          = -1;
static int hf_llrp_operation_count                = -1;
static int hf_llrp_opspec_id                      = -1;
static int hf_llrp_conf_value                     = -1;
static int hf_llrp_id_type                        = -1;
static int hf_llrp_reader_id                      = -1;
static int hf_llrp_gpo_data                       = -1;
static int hf_llrp_keepalive_trig_type            = -1;
static int hf_llrp_time_iterval                   = -1;
static int hf_llrp_antenna_connected              = -1;
static int hf_llrp_antenna_gain                   = -1;
static int hf_llrp_receiver_sense                 = -1;
static int hf_llrp_channel_idx                    = -1;
static int hf_llrp_gpi_config                     = -1;
static int hf_llrp_gpi_state                      = -1;
static int hf_llrp_hold_events_and_reports        = -1;
static int hf_llrp_ro_report_trig                 = -1;
static int hf_llrp_n_2                            = -1;
static int hf_llrp_enable_rospec_id               = -1;
static int hf_llrp_enable_spec_idx                = -1;
static int hf_llrp_enable_inv_spec_id             = -1;
static int hf_llrp_enable_antenna_id              = -1;
static int hf_llrp_enable_channel_idx             = -1;
static int hf_llrp_enable_peak_rssi               = -1;
static int hf_llrp_enable_first_seen              = -1;
static int hf_llrp_enable_last_seen               = -1;
static int hf_llrp_enable_seen_count              = -1;
static int hf_llrp_enable_accessspec_id           = -1;
static int hf_llrp_access_report_trig             = -1;
static int hf_llrp_length_bits                    = -1;
static int hf_llrp_epc                            = -1;
static int hf_llrp_spec_idx                       = -1;
static int hf_llrp_peak_rssi                      = -1;
static int hf_llrp_tag_count                      = -1;
static int hf_llrp_bandwidth                      = -1;
static int hf_llrp_average_rssi                   = -1;
static int hf_llrp_notif_state                    = -1;
static int hf_llrp_event_type                     = -1;
static int hf_llrp_next_chan_idx                  = -1;
static int hf_llrp_roevent_type                   = -1;
static int hf_llrp_prem_rospec_id                 = -1;
static int hf_llrp_buffer_full_percentage         = -1;
static int hf_llrp_message                        = -1;
static int hf_llrp_rfevent_type                   = -1;
static int hf_llrp_aievent_type                   = -1;
static int hf_llrp_antenna_event_type             = -1;
static int hf_llrp_conn_status                    = -1;
static int hf_llrp_loop_count                     = -1;
static int hf_llrp_status_code                    = -1;
static int hf_llrp_error_desc                     = -1;
static int hf_llrp_field_num                      = -1;
static int hf_llrp_error_code                     = -1;
static int hf_llrp_parameter_type                 = -1;
static int hf_llrp_can_support_block_erase        = -1;
static int hf_llrp_can_support_block_write        = -1;
static int hf_llrp_can_support_block_permalock    = -1;
static int hf_llrp_can_support_tag_recomm         = -1;
static int hf_llrp_can_support_UMI_method2        = -1;
static int hf_llrp_can_support_XPC                = -1;
static int hf_llrp_max_num_filter_per_query       = -1;
static int hf_llrp_mode_ident                     = -1;
static int hf_llrp_DR                             = -1;
static int hf_llrp_hag_conformance                = -1;
static int hf_llrp_mod                            = -1;
static int hf_llrp_flm                            = -1;
static int hf_llrp_m                              = -1;
static int hf_llrp_bdr                            = -1;
static int hf_llrp_pie                            = -1;
static int hf_llrp_min_tari                       = -1;
static int hf_llrp_max_tari                       = -1;
static int hf_llrp_step_tari                      = -1;
static int hf_llrp_inventory_state_aware          = -1;
static int hf_llrp_trunc                          = -1;
static int hf_llrp_mb                             = -1;
static int hf_llrp_pointer                        = -1;
static int hf_llrp_tag_mask                       = -1;
static int hf_llrp_aware_filter_target            = -1;
static int hf_llrp_aware_filter_action            = -1;
static int hf_llrp_unaware_filter_action          = -1;
static int hf_llrp_mode_idx                       = -1;
static int hf_llrp_tari                           = -1;
static int hf_llrp_session                        = -1;
static int hf_llrp_tag_population                 = -1;
static int hf_llrp_tag_transit_time               = -1;
static int hf_llrp_sing_i                         = -1;
static int hf_llrp_sing_s                         = -1;
static int hf_llrp_sing_a                         = -1;
static int hf_llrp_match                          = -1;
static int hf_llrp_tag_data                       = -1;
static int hf_llrp_access_pass                    = -1;
static int hf_llrp_word_pointer                   = -1;
static int hf_llrp_word_count                     = -1;
static int hf_llrp_write_data                     = -1;
static int hf_llrp_kill_pass                      = -1;
static int hf_llrp_kill_3                         = -1;
static int hf_llrp_kill_2                         = -1;
static int hf_llrp_kill_l                         = -1;
static int hf_llrp_privilege                      = -1;
static int hf_llrp_data_field                     = -1;
static int hf_llrp_block_pointer                  = -1;
static int hf_llrp_block_mask                     = -1;
static int hf_llrp_length_words                   = -1;
static int hf_llrp_block_range                    = -1;
static int hf_llrp_enable_crc                     = -1;
static int hf_llrp_enable_pc                      = -1;
static int hf_llrp_enable_xpc                     = -1;
static int hf_llrp_pc_bits                        = -1;
static int hf_llrp_xpc_w1                         = -1;
static int hf_llrp_xpc_w2                         = -1;
static int hf_llrp_crc                            = -1;
static int hf_llrp_num_coll                       = -1;
static int hf_llrp_num_empty                      = -1;
static int hf_llrp_access_result                  = -1;
static int hf_llrp_read_data                      = -1;
static int hf_llrp_num_words_written              = -1;
static int hf_llrp_permlock_status                = -1;
static int hf_llrp_vendor_id                      = -1;
static int hf_llrp_impinj_param_type              = -1;
static int hf_llrp_save_config                    = -1;
static int hf_llrp_impinj_req_data                = -1;
static int hf_llrp_impinj_reg_region              = -1;
static int hf_llrp_impinj_search_mode             = -1;
static int hf_llrp_impinj_en_tag_dir              = -1;
static int hf_llrp_impinj_antenna_conf            = -1;
static int hf_llrp_decision_time                  = -1;
static int hf_llrp_impinj_tag_dir                 = -1;
static int hf_llrp_confidence                     = -1;
static int hf_llrp_impinj_fix_freq_mode           = -1;
static int hf_llrp_num_channels                   = -1;
static int hf_llrp_channel                        = -1;
static int hf_llrp_impinj_reduce_power_mode       = -1;
static int hf_llrp_impinj_low_duty_mode           = -1;
static int hf_llrp_empty_field_timeout            = -1;
static int hf_llrp_field_ping_interval            = -1;
static int hf_llrp_model_name                     = -1;
static int hf_llrp_serial_number                  = -1;
static int hf_llrp_soft_ver                       = -1;
static int hf_llrp_firm_ver                       = -1;
static int hf_llrp_fpga_ver                       = -1;
static int hf_llrp_pcba_ver                       = -1;
static int hf_llrp_height_thresh                  = -1;
static int hf_llrp_zero_motion_thresh             = -1;
static int hf_llrp_board_manufacturer             = -1;
static int hf_llrp_fw_ver_hex                     = -1;
static int hf_llrp_hw_ver_hex                     = -1;
static int hf_llrp_gpi_debounce                   = -1;
static int hf_llrp_temperature                    = -1;
static int hf_llrp_impinj_link_monitor_mode       = -1;
static int hf_llrp_link_down_thresh               = -1;
static int hf_llrp_impinj_report_buff_mode        = -1;
static int hf_llrp_permalock_result               = -1;
static int hf_llrp_block_permalock_result         = -1;
static int hf_llrp_impinj_data_profile            = -1;
static int hf_llrp_impinj_access_range            = -1;
static int hf_llrp_impinj_persistence             = -1;
static int hf_llrp_set_qt_config_result           = -1;
static int hf_llrp_get_qt_config_result           = -1;
static int hf_llrp_impinj_serialized_tid_mode     = -1;
static int hf_llrp_impinj_rf_phase_mode           = -1;
static int hf_llrp_impinj_peak_rssi_mode          = -1;
static int hf_llrp_impinj_gps_coordinates_mode    = -1;
static int hf_llrp_impinj_tid                     = -1;
static int hf_llrp_phase_angle                    = -1;
static int hf_llrp_rssi                           = -1;
static int hf_llrp_latitude                       = -1;
static int hf_llrp_longitude                      = -1;
static int hf_llrp_gga_sentence                   = -1;
static int hf_llrp_rmc_sentence                   = -1;
static int hf_llrp_impinj_optim_read_mode         = -1;
static int hf_llrp_impinj_rf_doppler_mode         = -1;
static int hf_llrp_retry_count                    = -1;
static int hf_llrp_impinj_access_spec_ordering    = -1;
static int hf_llrp_impinj_gpo_mode                = -1;
static int hf_llrp_gpo_pulse_dur                  = -1;

/* Initialize the subtree pointers */
static gint ett_llrp = -1;
static gint ett_llrp_param = -1;

static expert_field ei_llrp_req_conf = EI_INIT;
static expert_field ei_llrp_invalid_length = EI_INIT;

/* Message Types */
#define LLRP_TYPE_GET_READER_CAPABILITIES           1
#define LLRP_TYPE_GET_READER_CONFIG                 2
#define LLRP_TYPE_SET_READER_CONFIG                 3
#define LLRP_TYPE_CLOSE_CONNECTION_RESPONSE         4
#define LLRP_TYPE_GET_READER_CAPABILITIES_RESPONSE 11
#define LLRP_TYPE_GET_READER_CONFIG_RESPONSE       12
#define LLRP_TYPE_SET_READER_CONFIG_RESPONSE       13
#define LLRP_TYPE_CLOSE_CONNECTION                 14
#define LLRP_TYPE_ADD_ROSPEC                       20
#define LLRP_TYPE_DELETE_ROSPEC                    21
#define LLRP_TYPE_START_ROSPEC                     22
#define LLRP_TYPE_STOP_ROSPEC                      23
#define LLRP_TYPE_ENABLE_ROSPEC                    24
#define LLRP_TYPE_DISABLE_ROSPEC                   25
#define LLRP_TYPE_GET_ROSPECS                      26
#define LLRP_TYPE_ADD_ROSPEC_RESPONSE              30
#define LLRP_TYPE_DELETE_ROSPEC_RESPONSE           31
#define LLRP_TYPE_START_ROSPEC_RESPONSE            32
#define LLRP_TYPE_STOP_ROSPEC_RESPONSE             33
#define LLRP_TYPE_ENABLE_ROSPEC_RESPONSE           34
#define LLRP_TYPE_DISABLE_ROSPEC_RESPONSE          35
#define LLRP_TYPE_GET_ROSPECS_RESPONSE             36
#define LLRP_TYPE_ADD_ACCESSSPEC                   40
#define LLRP_TYPE_DELETE_ACCESSSPEC                41
#define LLRP_TYPE_ENABLE_ACCESSSPEC                42
#define LLRP_TYPE_DISABLE_ACCESSSPEC               43
#define LLRP_TYPE_GET_ACCESSSPECS                  44
#define LLRP_TYPE_CLIENT_REQUEST_OP                45
#define LLRP_TYPE_GET_SUPPORTED_VERSION            46
#define LLRP_TYPE_SET_PROTOCOL_VERSION             47
#define LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE          50
#define LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE       51
#define LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE       52
#define LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE      53
#define LLRP_TYPE_GET_ACCESSSPECS_RESPONSE         54
#define LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE      55
#define LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE   56
#define LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE    57
#define LLRP_TYPE_GET_REPORT                       60
#define LLRP_TYPE_RO_ACCESS_REPORT                 61
#define LLRP_TYPE_KEEPALIVE                        62
#define LLRP_TYPE_READER_EVENT_NOTIFICATION        63
#define LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS        64
#define LLRP_TYPE_KEEPALIVE_ACK                    72
#define LLRP_TYPE_ERROR_MESSAGE                   100
#define LLRP_TYPE_CUSTOM_MESSAGE                 1023

static const value_string message_types[] = {
    { LLRP_TYPE_GET_READER_CAPABILITIES,         "Get Reader Capabilities"         },
    { LLRP_TYPE_GET_READER_CONFIG,               "Get Reader Config"               },
    { LLRP_TYPE_SET_READER_CONFIG,               "Set Reader Config"               },
    { LLRP_TYPE_CLOSE_CONNECTION_RESPONSE,       "Close Connection Response"       },
    { LLRP_TYPE_GET_READER_CAPABILITIES_RESPONSE,"Get Reader Capabilities Response"},
    { LLRP_TYPE_GET_READER_CONFIG_RESPONSE,      "Get Reader Config Response"      },
    { LLRP_TYPE_SET_READER_CONFIG_RESPONSE,      "Set Reader Config Response"      },
    { LLRP_TYPE_CLOSE_CONNECTION,                "Close Connection"                },
    { LLRP_TYPE_ADD_ROSPEC,                      "Add ROSpec"                      },
    { LLRP_TYPE_DELETE_ROSPEC,                   "Delete ROSpec"                   },
    { LLRP_TYPE_START_ROSPEC,                    "Start ROSpec"                    },
    { LLRP_TYPE_STOP_ROSPEC,                     "Stop ROSpec"                     },
    { LLRP_TYPE_ENABLE_ROSPEC,                   "Enable ROSpec"                   },
    { LLRP_TYPE_DISABLE_ROSPEC,                  "Disable ROSpec"                  },
    { LLRP_TYPE_GET_ROSPECS,                     "Get ROSpecs"                     },
    { LLRP_TYPE_ADD_ROSPEC_RESPONSE,             "Add ROSpec Response"             },
    { LLRP_TYPE_DELETE_ROSPEC_RESPONSE,          "Delete ROSpec Response"          },
    { LLRP_TYPE_START_ROSPEC_RESPONSE,           "Start ROSpec Response"           },
    { LLRP_TYPE_STOP_ROSPEC_RESPONSE,            "Stop ROSpec Response"            },
    { LLRP_TYPE_ENABLE_ROSPEC_RESPONSE,          "Enable ROSpec Response"          },
    { LLRP_TYPE_DISABLE_ROSPEC_RESPONSE,         "Disable ROSpec Response"         },
    { LLRP_TYPE_GET_ROSPECS_RESPONSE,            "Get ROSpecs Response"            },
    { LLRP_TYPE_ADD_ACCESSSPEC,                  "Add AccessSpec"                  },
    { LLRP_TYPE_DELETE_ACCESSSPEC,               "Delete AccessSpec"               },
    { LLRP_TYPE_ENABLE_ACCESSSPEC,               "Enable AccessSpec"               },
    { LLRP_TYPE_DISABLE_ACCESSSPEC,              "Disable AccessSpec"              },
    { LLRP_TYPE_GET_ACCESSSPECS,                 "Get AccessSpecs"                 },
    { LLRP_TYPE_CLIENT_REQUEST_OP,               "Client Request OP"               },
    { LLRP_TYPE_GET_SUPPORTED_VERSION,           "Get Supported Version"           },
    { LLRP_TYPE_SET_PROTOCOL_VERSION,            "Set Protocol Version"            },
    { LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE,         "Add AccessSpec Response"         },
    { LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE,      "Delete AccessSpec Response"      },
    { LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE,      "Enable AccessSpec Response"      },
    { LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE,     "Disable AccessSpec Response"     },
    { LLRP_TYPE_GET_ACCESSSPECS_RESPONSE,        "Get AccessSpecs Response"        },
    { LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE,     "Client Resquest OP Response"     },
    { LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE,  "Get Supported Version Response"  },
    { LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE,   "Set Protocol Version Response"   },
    { LLRP_TYPE_GET_REPORT,                      "Get Report"                      },
    { LLRP_TYPE_RO_ACCESS_REPORT,                "RO Access Report"                },
    { LLRP_TYPE_KEEPALIVE,                       "Keepalive"                       },
    { LLRP_TYPE_READER_EVENT_NOTIFICATION,       "Reader Event Notification"       },
    { LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS,       "Enable Events And Reports"       },
    { LLRP_TYPE_KEEPALIVE_ACK,                   "Keepalive Ack"                   },
    { LLRP_TYPE_ERROR_MESSAGE,                   "Error Message"                   },
    { LLRP_TYPE_CUSTOM_MESSAGE,                  "Custom Message"                  },
    { 0,                                          NULL                             }
};
static value_string_ext message_types_ext = VALUE_STRING_EXT_INIT(message_types);

/* Versions */
#define LLRP_VERS_1_0_1 0x01
#define LLRP_VERS_1_1   0x02

static const value_string llrp_versions[] = {
    { LLRP_VERS_1_0_1, "1.0.1" },
    { LLRP_VERS_1_1,   "1.1"   },
    { 0,                NULL   }
};

/* Capabilities */
#define LLRP_CAP_ALL            0
#define LLRP_CAP_GENERAL_DEVICE 1
#define LLRP_CAP_LLRP           2
#define LLRP_CAP_REGULATORY     3
#define LLRP_CAP_AIR_PROTOCOL   4

static const value_string capabilities_request[] = {
    { LLRP_CAP_ALL,            "All"                            },
    { LLRP_CAP_GENERAL_DEVICE, "General Device Capabilities"    },
    { LLRP_CAP_LLRP,           "LLRP Capabilities"              },
    { LLRP_CAP_REGULATORY,     "Regulatory Capabilities"        },
    { LLRP_CAP_AIR_PROTOCOL,   "Air Protocol LLRP Capabilities" },
    { 0,                        NULL                            }
};

/* Configurations */
#define LLRP_CONF_ALL                             0
#define LLRP_CONF_IDENTIFICATION                  1
#define LLRP_CONF_ANTENNA_PROPERTIES              2
#define LLRP_CONF_ANTENNA_CONFIGURATION           3
#define LLRP_CONF_RO_REPORT_SPEC                  4
#define LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC  5
#define LLRP_CONF_ACCESS_REPORT_SPEC              6
#define LLRP_CONF_LLRP_CONFIGURATION_STATE        7
#define LLRP_CONF_KEEPALIVE_SPEC                  8
#define LLRP_CONF_GPI_PORT_CURRENT_STATE          9
#define LLRP_CONF_GPO_WRITE_DATA                 10
#define LLRP_CONF_EVENTS_AND_REPORTS             11

static const value_string config_request[] = {
    { LLRP_CONF_ALL,                            "All"                            },
    { LLRP_CONF_IDENTIFICATION,                 "Identification"                 },
    { LLRP_CONF_ANTENNA_PROPERTIES,             "Antenna Properties"             },
    { LLRP_CONF_ANTENNA_CONFIGURATION,          "Antenna Configuration"          },
    { LLRP_CONF_RO_REPORT_SPEC,                 "RO Report Spec"                 },
    { LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC, "Reader Event Notification Spec" },
    { LLRP_CONF_ACCESS_REPORT_SPEC,             "Access Report Spec"             },
    { LLRP_CONF_LLRP_CONFIGURATION_STATE,       "LLRP Configuration State"       },
    { LLRP_CONF_KEEPALIVE_SPEC,                 "Keepalive Spec"                 },
    { LLRP_CONF_GPI_PORT_CURRENT_STATE,         "GPI Port Current State"         },
    { LLRP_CONF_GPO_WRITE_DATA,                 "GPO Write Data"                 },
    { LLRP_CONF_EVENTS_AND_REPORTS,             "Events and Reports"             },
    { 0,                                         NULL                            }
};
static value_string_ext config_request_ext = VALUE_STRING_EXT_INIT(config_request);

/* TLV Parameter Types */
#define LLRP_TLV_UTC_TIMESTAMP           128
#define LLRP_TLV_UPTIME                  129
#define LLRP_TLV_GENERAL_DEVICE_CAP      137
#define LLRP_TLV_RECEIVE_SENSE_ENTRY     139
#define LLRP_TLV_ANTENNA_AIR_PROTO       140
#define LLRP_TLV_GPIO_CAPABILITIES       141
#define LLRP_TLV_LLRP_CAPABILITIES       142
#define LLRP_TLV_REGU_CAPABILITIES       143
#define LLRP_TLV_UHF_CAPABILITIES        144
#define LLRP_TLV_XMIT_POWER_LEVEL_ENTRY  145
#define LLRP_TLV_FREQ_INFORMATION        146
#define LLRP_TLV_FREQ_HOP_TABLE          147
#define LLRP_TLV_FIXED_FREQ_TABLE        148
#define LLRP_TLV_ANTENNA_RCV_SENSE_RANGE 149
#define LLRP_TLV_RO_SPEC                 177
#define LLRP_TLV_RO_BOUND_SPEC           178
#define LLRP_TLV_RO_SPEC_START_TRIGGER   179
#define LLRP_TLV_PER_TRIGGER_VAL         180
#define LLRP_TLV_GPI_TRIGGER_VAL         181
#define LLRP_TLV_RO_SPEC_STOP_TRIGGER    182
#define LLRP_TLV_AI_SPEC                 183
#define LLRP_TLV_AI_SPEC_STOP            184
#define LLRP_TLV_TAG_OBSERV_TRIGGER      185
#define LLRP_TLV_INVENTORY_PARAM_SPEC    186
#define LLRP_TLV_RF_SURVEY_SPEC          187
#define LLRP_TLV_RF_SURVEY_SPEC_STOP_TR  188
#define LLRP_TLV_ACCESS_SPEC             207
#define LLRP_TLV_ACCESS_SPEC_STOP_TRIG   208
#define LLRP_TLV_ACCESS_COMMAND          209
#define LLRP_TLV_CLIENT_REQ_OP_SPEC      210
#define LLRP_TLV_CLIENT_REQ_RESPONSE     211
#define LLRP_TLV_LLRP_CONF_STATE_VAL     217
#define LLRP_TLV_IDENT                   218
#define LLRP_TLV_GPO_WRITE_DATA          219
#define LLRP_TLV_KEEPALIVE_SPEC          220
#define LLRP_TLV_ANTENNA_PROPS           221
#define LLRP_TLV_ANTENNA_CONF            222
#define LLRP_TLV_RF_RECEIVER             223
#define LLRP_TLV_RF_TRANSMITTER          224
#define LLRP_TLV_GPI_PORT_CURRENT_STATE  225
#define LLRP_TLV_EVENTS_AND_REPORTS      226
#define LLRP_TLV_RO_REPORT_SPEC          237
#define LLRP_TLV_TAG_REPORT_CONTENT_SEL  238
#define LLRP_TLV_ACCESS_REPORT_SPEC      239
#define LLRP_TLV_TAG_REPORT_DATA         240
#define LLRP_TLV_EPC_DATA                241
#define LLRP_TLV_RF_SURVEY_REPORT_DATA   242
#define LLRP_TLV_FREQ_RSSI_LEVEL_ENTRY   243
#define LLRP_TLV_READER_EVENT_NOTI_SPEC  244
#define LLRP_TLV_EVENT_NOTIF_STATE       245
#define LLRP_TLV_READER_EVENT_NOTI_DATA  246
#define LLRP_TLV_HOPPING_EVENT           247
#define LLRP_TLV_GPI_EVENT               248
#define LLRP_TLV_RO_SPEC_EVENT           249
#define LLRP_TLV_REPORT_BUF_LEVEL_WARN   250
#define LLRP_TLV_REPORT_BUF_OVERFLOW_ERR 251
#define LLRP_TLV_READER_EXCEPTION_EVENT  252
#define LLRP_TLV_RF_SURVEY_EVENT         253
#define LLRP_TLV_AI_SPEC_EVENT           254
#define LLRP_TLV_ANTENNA_EVENT           255
#define LLRP_TLV_CONN_ATTEMPT_EVENT      256
#define LLRP_TLV_CONN_CLOSE_EVENT        257
#define LLRP_TLV_LLRP_STATUS             287
#define LLRP_TLV_FIELD_ERROR             288
#define LLRP_TLV_PARAM_ERROR             289
#define LLRP_TLV_C1G2_LLRP_CAP           327
#define LLRP_TLV_C1G2_UHF_RF_MD_TBL      328
#define LLRP_TLV_C1G2_UHF_RF_MD_TBL_ENT  329
#define LLRP_TLV_C1G2_INVENTORY_COMMAND  330
#define LLRP_TLV_C1G2_FILTER             331
#define LLRP_TLV_C1G2_TAG_INV_MASK       332
#define LLRP_TLV_C1G2_TAG_INV_AWARE_FLTR 333
#define LLRP_TLV_C1G2_TAG_INV_UNAWR_FLTR 334
#define LLRP_TLV_C1G2_RF_CONTROL         335
#define LLRP_TLV_C1G2_SINGULATION_CTRL   336
#define LLRP_TLV_C1G2_TAG_INV_AWARE_SING 337
#define LLRP_TLV_C1G2_TAG_SPEC           338
#define LLRP_TLV_C1G2_TARGET_TAG         339
#define LLRP_TLV_C1G2_READ               341
#define LLRP_TLV_C1G2_WRITE              342
#define LLRP_TLV_C1G2_KILL               343
#define LLRP_TLV_C1G2_LOCK               344
#define LLRP_TLV_C1G2_LOCK_PAYLOAD       345
#define LLRP_TLV_C1G2_BLK_ERASE          346
#define LLRP_TLV_C1G2_BLK_WRITE          347
#define LLRP_TLV_C1G2_EPC_MEMORY_SLCTOR  348
#define LLRP_TLV_C1G2_READ_OP_SPEC_RES   349
#define LLRP_TLV_C1G2_WRT_OP_SPEC_RES    350
#define LLRP_TLV_C1G2_KILL_OP_SPEC_RES   351
#define LLRP_TLV_C1G2_LOCK_OP_SPEC_RES   352
#define LLRP_TLV_C1G2_BLK_ERS_OP_SPC_RES 353
#define LLRP_TLV_C1G2_BLK_WRT_OP_SPC_RES 354
#define LLRP_TLV_LOOP_SPEC               355
#define LLRP_TLV_SPEC_LOOP_EVENT         356
#define LLRP_TLV_C1G2_RECOMMISSION       357
#define LLRP_TLV_C1G2_BLK_PERMALOCK      358
#define LLRP_TLV_C1G2_GET_BLK_PERMALOCK  359
#define LLRP_TLV_C1G2_RECOM_OP_SPEC_RES  360
#define LLRP_TLV_C1G2_BLK_PRL_OP_SPC_RES 361
#define LLRP_TLV_C1G2_BLK_PRL_STAT_RES   362
#define LLRP_TLV_MAX_RECEIVE_SENSE       363
#define LLRP_TLV_RF_SURVEY_FREQ_CAP      365
#define LLRP_TLV_CUSTOM_PARAMETER       1023

static const value_string tlv_type[] = {
    { LLRP_TLV_UTC_TIMESTAMP,           "UTC Timestamp"                                  },
    { LLRP_TLV_UPTIME,                  "Uptime"                                         },
    { LLRP_TLV_GENERAL_DEVICE_CAP,      "General Device Capabilities"                    },
    { LLRP_TLV_RECEIVE_SENSE_ENTRY,     "Receive Sensitivity Entry"                      },
    { LLRP_TLV_ANTENNA_AIR_PROTO,       "Antenna Air Protocol"                           },
    { LLRP_TLV_GPIO_CAPABILITIES,       "GPIO Capabilities"                              },
    { LLRP_TLV_LLRP_CAPABILITIES,       "LLRP Capabilities"                              },
    { LLRP_TLV_REGU_CAPABILITIES,       "REGU Capabilities"                              },
    { LLRP_TLV_UHF_CAPABILITIES,        "UHF Capabilities"                               },
    { LLRP_TLV_XMIT_POWER_LEVEL_ENTRY,  "Transmit Power Level Entry"                     },
    { LLRP_TLV_FREQ_INFORMATION,        "Frequency Information"                          },
    { LLRP_TLV_FREQ_HOP_TABLE,          "Frequenct Hop Table"                            },
    { LLRP_TLV_FIXED_FREQ_TABLE,        "Fixed Frequency Table"                          },
    { LLRP_TLV_ANTENNA_RCV_SENSE_RANGE, "Antenna RCV Sensitivity Range"                  },
    { LLRP_TLV_RO_SPEC,                 "RO Spec"                                        },
    { LLRP_TLV_RO_BOUND_SPEC,           "RO Bound Spec"                                  },
    { LLRP_TLV_RO_SPEC_START_TRIGGER,   "RO Spec Start Trigger"                          },
    { LLRP_TLV_PER_TRIGGER_VAL,         "PER Trigger Value"                              },
    { LLRP_TLV_GPI_TRIGGER_VAL,         "GPI Trigger Value"                              },
    { LLRP_TLV_RO_SPEC_STOP_TRIGGER,    "RO Spec Stop Trigger"                           },
    { LLRP_TLV_AI_SPEC,                 "AI Spec"                                        },
    { LLRP_TLV_AI_SPEC_STOP,            "AI Spec Stop"                                   },
    { LLRP_TLV_TAG_OBSERV_TRIGGER,      "Tag Observation Trigger"                        },
    { LLRP_TLV_INVENTORY_PARAM_SPEC,    "Inventory Parameter Spec ID"                    },
    { LLRP_TLV_RF_SURVEY_SPEC,          "RF Survey Spec"                                 },
    { LLRP_TLV_RF_SURVEY_SPEC_STOP_TR,  "RF Survey Spec Stop Trigger"                    },
    { LLRP_TLV_ACCESS_SPEC,             "Access Spec"                                    },
    { LLRP_TLV_ACCESS_SPEC_STOP_TRIG,   "Access Spec Stop Trigger"                       },
    { LLRP_TLV_ACCESS_COMMAND,          "Access Command"                                 },
    { LLRP_TLV_CLIENT_REQ_OP_SPEC,      "Client Request Op Spec"                         },
    { LLRP_TLV_CLIENT_REQ_RESPONSE,     "Client Request Response"                        },
    { LLRP_TLV_LLRP_CONF_STATE_VAL,     "LLRP Configuration State Value"                 },
    { LLRP_TLV_IDENT,                   "Identification"                                 },
    { LLRP_TLV_GPO_WRITE_DATA,          "GPO Write Data"                                 },
    { LLRP_TLV_KEEPALIVE_SPEC,          "Keepalive Spec"                                 },
    { LLRP_TLV_ANTENNA_PROPS,           "Antenna Properties"                             },
    { LLRP_TLV_ANTENNA_CONF,            "Antenna Configuration"                          },
    { LLRP_TLV_RF_RECEIVER,             "RF Receiver"                                    },
    { LLRP_TLV_RF_TRANSMITTER,          "RF Transmitter"                                 },
    { LLRP_TLV_GPI_PORT_CURRENT_STATE,  "GPI Port Current State"                         },
    { LLRP_TLV_EVENTS_AND_REPORTS,      "Events And Reports"                             },
    { LLRP_TLV_RO_REPORT_SPEC,          "RO Report Spec"                                 },
    { LLRP_TLV_TAG_REPORT_CONTENT_SEL,  "Tag Report Content Selector"                    },
    { LLRP_TLV_ACCESS_REPORT_SPEC,      "Access Report Spec"                             },
    { LLRP_TLV_TAG_REPORT_DATA,         "Tag Report Data"                                },
    { LLRP_TLV_EPC_DATA,                "EPC Data"                                       },
    { LLRP_TLV_RF_SURVEY_REPORT_DATA,   "RF Survey Report Data"                          },
    { LLRP_TLV_FREQ_RSSI_LEVEL_ENTRY,   "Frequency RSSI Level Entry"                     },
    { LLRP_TLV_READER_EVENT_NOTI_SPEC,  "Reader Event Notification Spec"                 },
    { LLRP_TLV_EVENT_NOTIF_STATE,       "Event Notification State"                       },
    { LLRP_TLV_READER_EVENT_NOTI_DATA,  "Reader Event Notification Data"                 },
    { LLRP_TLV_HOPPING_EVENT,           "Hopping Event"                                  },
    { LLRP_TLV_GPI_EVENT,               "GPI Event"                                      },
    { LLRP_TLV_RO_SPEC_EVENT,           "RO Spec Event"                                  },
    { LLRP_TLV_REPORT_BUF_LEVEL_WARN,   "Report Buffer Level Warning Event"              },
    { LLRP_TLV_REPORT_BUF_OVERFLOW_ERR, "Report Buffer Overflow Error Event"             },
    { LLRP_TLV_READER_EXCEPTION_EVENT,  "Reader Exception Event"                         },
    { LLRP_TLV_RF_SURVEY_EVENT,         "RF Survey Event"                                },
    { LLRP_TLV_AI_SPEC_EVENT,           "AI Spec Event"                                  },
    { LLRP_TLV_ANTENNA_EVENT,           "ANTENNA Event"                                  },
    { LLRP_TLV_CONN_ATTEMPT_EVENT,      "CONN Attempt Event"                             },
    { LLRP_TLV_CONN_CLOSE_EVENT,        "CONN Close Event"                               },
    { LLRP_TLV_LLRP_STATUS,             "LLRP Status"                                    },
    { LLRP_TLV_FIELD_ERROR,             "Field Error"                                    },
    { LLRP_TLV_PARAM_ERROR,             "Param Error"                                    },
    { LLRP_TLV_C1G2_LLRP_CAP,           "C1G2 LLRP Capabilities"                         },
    { LLRP_TLV_C1G2_UHF_RF_MD_TBL,      "C1G2 UHF RF Mode Table"                         },
    { LLRP_TLV_C1G2_UHF_RF_MD_TBL_ENT,  "C1G2 UHF RF Mode Table Entry"                   },
    { LLRP_TLV_C1G2_INVENTORY_COMMAND,  "C1G2 Inventory Command"                         },
    { LLRP_TLV_C1G2_FILTER,             "C1G2 Filter"                                    },
    { LLRP_TLV_C1G2_TAG_INV_MASK,       "C1G2 Tag Inventory Mask"                        },
    { LLRP_TLV_C1G2_TAG_INV_AWARE_FLTR, "C1G2 Tag Inventory State-Aware Filtre Action"   },
    { LLRP_TLV_C1G2_TAG_INV_UNAWR_FLTR, "C1G2 Tag Inventory State-Unaware Filter Action" },
    { LLRP_TLV_C1G2_RF_CONTROL,         "C1G2 RF Control"                                },
    { LLRP_TLV_C1G2_SINGULATION_CTRL,   "C1G2 Singulation Control"                       },
    { LLRP_TLV_C1G2_TAG_INV_AWARE_SING, "C1G2 Tag Inventory State-Aware Singulation"     },
    { LLRP_TLV_C1G2_TAG_SPEC,           "C1G2 Tag Spec"                                  },
    { LLRP_TLV_C1G2_TARGET_TAG,         "C1G2 Target Tag"                                },
    { LLRP_TLV_C1G2_READ,               "C1G2 Read"                                      },
    { LLRP_TLV_C1G2_WRITE,              "C1G2 Write"                                     },
    { LLRP_TLV_C1G2_KILL,               "C1G2 Kill"                                      },
    { LLRP_TLV_C1G2_LOCK,               "C1G2 Lock"                                      },
    { LLRP_TLV_C1G2_LOCK_PAYLOAD,       "C1G2 Lock Payload"                              },
    { LLRP_TLV_C1G2_BLK_ERASE,          "C1G2 Block Erase"                               },
    { LLRP_TLV_C1G2_BLK_WRITE,          "C1G2 Block Write"                               },
    { LLRP_TLV_C1G2_EPC_MEMORY_SLCTOR,  "C1G2 EPC Memory Selector"                       },
    { LLRP_TLV_C1G2_READ_OP_SPEC_RES,   "C1G2 Read Op Spec Result"                       },
    { LLRP_TLV_C1G2_WRT_OP_SPEC_RES,    "C1G2 Write Op Spec Result"                      },
    { LLRP_TLV_C1G2_KILL_OP_SPEC_RES,   "C1G2 Kill Op Spec Result"                       },
    { LLRP_TLV_C1G2_LOCK_OP_SPEC_RES,   "C1G2 Lock Op Spec Result"                       },
    { LLRP_TLV_C1G2_BLK_ERS_OP_SPC_RES, "C1G2 Block Erase Op Spec Result"                },
    { LLRP_TLV_C1G2_BLK_WRT_OP_SPC_RES, "C1G2 Block Write Op Spec Result"                },
    { LLRP_TLV_LOOP_SPEC,               "Loop Spec"                                      },
    { LLRP_TLV_SPEC_LOOP_EVENT,         "Spec loop event"                                },
    { LLRP_TLV_C1G2_RECOMMISSION,       "C1G2 Recommission"                              },
    { LLRP_TLV_C1G2_BLK_PERMALOCK,      "C1G2 Block Permalock"                           },
    { LLRP_TLV_C1G2_GET_BLK_PERMALOCK,  "C1G2 Get Block Permalock Status"                },
    { LLRP_TLV_C1G2_RECOM_OP_SPEC_RES,  "C1G2 Recommission Op Spec Result"               },
    { LLRP_TLV_C1G2_BLK_PRL_OP_SPC_RES, "C1G2 Block Permalock Op Spec Result"            },
    { LLRP_TLV_C1G2_BLK_PRL_STAT_RES,   "C1G2 Block Permalock Status Op Spec Result"     },
    { LLRP_TLV_MAX_RECEIVE_SENSE,       "Maximum Receive Sensitivity"                    },
    { LLRP_TLV_RF_SURVEY_FREQ_CAP,      "RF Survey Frequency Capabilities"               },
    { LLRP_TLV_CUSTOM_PARAMETER,        "Custom parameter"                               },
    { 0,                                 NULL                                            }
};
static value_string_ext tlv_type_ext = VALUE_STRING_EXT_INIT(tlv_type);

/* TV Parameter Types */
#define LLRP_TV_ANTENNA_ID               1
#define LLRP_TV_FIRST_SEEN_TIME_UTC      2
#define LLRP_TV_FIRST_SEEN_TIME_UPTIME   3
#define LLRP_TV_LAST_SEEN_TIME_UTC       4
#define LLRP_TV_LAST_SEEN_TIME_UPTIME    5
#define LLRP_TV_PEAK_RSSI                6
#define LLRP_TV_CHANNEL_INDEX            7
#define LLRP_TV_TAG_SEEN_COUNT           8
#define LLRP_TV_RO_SPEC_ID               9
#define LLRP_TV_INVENTORY_PARAM_SPEC_ID 10
#define LLRP_TV_C1G2_CRC                11
#define LLRP_TV_C1G2_PC                 12
#define LLRP_TV_EPC96                   13
#define LLRP_TV_SPEC_INDEX              14
#define LLRP_TV_CLIENT_REQ_OP_SPEC_RES  15
#define LLRP_TV_ACCESS_SPEC_ID          16
#define LLRP_TV_OP_SPEC_ID              17
#define LLRP_TV_C1G2_SINGULATION_DET    18
#define LLRP_TV_C1G2_XPC_W1             19
#define LLRP_TV_C1G2_XPC_W2             20

/* Since TV's don't have a length field,
 * use these values instead */
#define LLRP_TV_LEN_ANTENNA_ID               2
#define LLRP_TV_LEN_FIRST_SEEN_TIME_UTC      8
#define LLRP_TV_LEN_FIRST_SEEN_TIME_UPTIME   8
#define LLRP_TV_LEN_LAST_SEEN_TIME_UTC       8
#define LLRP_TV_LEN_LAST_SEEN_TIME_UPTIME    8
#define LLRP_TV_LEN_PEAK_RSSI                1
#define LLRP_TV_LEN_CHANNEL_INDEX            2
#define LLRP_TV_LEN_TAG_SEEN_COUNT           2
#define LLRP_TV_LEN_RO_SPEC_ID               4
#define LLRP_TV_LEN_INVENTORY_PARAM_SPEC_ID  2
#define LLRP_TV_LEN_C1G2_CRC                 2
#define LLRP_TV_LEN_C1G2_PC                  2
#define LLRP_TV_LEN_EPC96                   12
#define LLRP_TV_LEN_SPEC_INDEX               2
#define LLRP_TV_LEN_CLIENT_REQ_OP_SPEC_RES   2
#define LLRP_TV_LEN_ACCESS_SPEC_ID           4
#define LLRP_TV_LEN_OP_SPEC_ID               2
#define LLRP_TV_LEN_C1G2_SINGULATION_DET     4
#define LLRP_TV_LEN_C1G2_XPC_W1              2
#define LLRP_TV_LEN_C1G2_XPC_W2              2

static const value_string tv_type[] = {
    { LLRP_TV_ANTENNA_ID,              "Antenna ID"                    },
    { LLRP_TV_FIRST_SEEN_TIME_UTC,     "First Seen Timestamp UTC"      },
    { LLRP_TV_FIRST_SEEN_TIME_UPTIME,  "First Seen Timestamp Uptime"   },
    { LLRP_TV_LAST_SEEN_TIME_UTC,      "Last Seen Timestamp UTC"       },
    { LLRP_TV_LAST_SEEN_TIME_UPTIME,   "Last Seen Timestamp Uptime"    },
    { LLRP_TV_PEAK_RSSI,               "Peak RSSI"                     },
    { LLRP_TV_CHANNEL_INDEX,           "Channel Index"                 },
    { LLRP_TV_TAG_SEEN_COUNT,          "Tag Seen Count"                },
    { LLRP_TV_RO_SPEC_ID,              "RO Spec ID"                    },
    { LLRP_TV_INVENTORY_PARAM_SPEC_ID, "Inventory Parameter Spec ID"   },
    { LLRP_TV_C1G2_CRC,                "C1G2 CRC"                      },
    { LLRP_TV_C1G2_PC,                 "C1G2 PC"                       },
    { LLRP_TV_EPC96,                   "EPC-96"                        },
    { LLRP_TV_SPEC_INDEX,              "Spec Index"                    },
    { LLRP_TV_CLIENT_REQ_OP_SPEC_RES,  "Client Request Op Spec Result" },
    { LLRP_TV_ACCESS_SPEC_ID,          "Access Spec ID"                },
    { LLRP_TV_OP_SPEC_ID,              "Op Spec ID"                    },
    { LLRP_TV_C1G2_SINGULATION_DET,    "C1G2 Singulation Details"      },
    { LLRP_TV_C1G2_XPC_W1,             "C1G2 XPC W1"                   },
    { LLRP_TV_C1G2_XPC_W2,             "C1G2 XPC W2"                   },
    { 0,                                NULL                           }
};
static value_string_ext tv_type_ext = VALUE_STRING_EXT_INIT(tv_type);

/* Protocol IDs */
#define LLRP_PROT_ID_UNSPECIFIED    0
#define LLRP_PROT_ID_EPC_C1G2       1

static const range_string protocol_id[] = {
    { LLRP_PROT_ID_UNSPECIFIED, LLRP_PROT_ID_UNSPECIFIED, "Unspecified protocol"          },
    { LLRP_PROT_ID_EPC_C1G2, LLRP_PROT_ID_EPC_C1G2,       "EPCGlobal Class 1 Gen 2"       },
    { LLRP_PROT_ID_EPC_C1G2 + 1, 255,                     "Reserved for furure use"       },
    { 0, 0,                                                NULL                           }
};

/* Communication standards */
#define LLRP_COMM_STANDARD_UNSPECIFIED              0
#define LLRP_COMM_STANDARD_US_FCC_PART_15           1
#define LLRP_COMM_STANDARD_ETSI_302_208             2
#define LLRP_COMM_STANDARD_ETSI_300_220             3
#define LLRP_COMM_STANDARD_AUSTRALIA_LIPD_1W        4
#define LLRP_COMM_STANDARD_AUSTRALIA_LIPD_4W        5
#define LLRP_COMM_STANDARD_JAPAN_ARIB_STD_T89       6
#define LLRP_COMM_STANDARD_HONG_KONG_OFTA_1049      7
#define LLRP_COMM_STANDARD_TAIWAN_DGT_LP0002        8
#define LLRP_COMM_STANDARD_KOREA_MIC_ARTICLE_5_2    9

static const value_string comm_standard[] = {
    { LLRP_COMM_STANDARD_UNSPECIFIED,           "Unspecified"           },
    { LLRP_COMM_STANDARD_US_FCC_PART_15,        "US FCC Part 15"        },
    { LLRP_COMM_STANDARD_ETSI_302_208,          "ETSI 302 208"          },
    { LLRP_COMM_STANDARD_ETSI_300_220,          "ETSI 300 220"          },
    { LLRP_COMM_STANDARD_AUSTRALIA_LIPD_1W,     "Australia LIPD 1W"     },
    { LLRP_COMM_STANDARD_AUSTRALIA_LIPD_4W,     "Australia LIPD 4W"     },
    { LLRP_COMM_STANDARD_JAPAN_ARIB_STD_T89,    "Japan_ARIB STD T89"    },
    { LLRP_COMM_STANDARD_HONG_KONG_OFTA_1049,   "Hong_Kong OFTA 1049"   },
    { LLRP_COMM_STANDARD_TAIWAN_DGT_LP0002,     "Taiwan DGT LP0002"     },
    { LLRP_COMM_STANDARD_KOREA_MIC_ARTICLE_5_2, "Korea MIC Article 5 2" },
    { 0,                                        NULL                    }
};
static value_string_ext comm_standard_ext = VALUE_STRING_EXT_INIT(comm_standard);

/* ID type */
#define LLRP_ID_TYPE_MAC    0
#define LLRP_ID_TYPE_EPC    1

static const value_string id_type[] = {
    { LLRP_ID_TYPE_MAC,           "MAC"        },
    { LLRP_ID_TYPE_EPC,           "EPC"        },
    { 0,                          NULL         }
};

/* KeepAlive type */
#define LLRP_KEEPALIVE_TYPE_NULL        0
#define LLRP_KEEPALIVE_TYPE_PERIODIC    1

static const value_string keepalive_type[] = {
    { LLRP_KEEPALIVE_TYPE_NULL,           "Null"            },
    { LLRP_KEEPALIVE_TYPE_PERIODIC,       "Periodic"        },
    { 0,                                  NULL              }
};

/* Notification Event type */
#define LLRP_NOTIFICATION_EVENT_TYPE_UPON_HOPPING_TO_NEXT_CHANNEL     0
#define LLRP_NOTIFICATION_EVENT_TYPE_GPI_EVENT                        1
#define LLRP_NOTIFICATION_EVENT_TYPE_ROSPEC_EVENT                     2
#define LLRP_NOTIFICATION_EVENT_TYPE_REPORT_BUFFER_FILL_WARNING       3
#define LLRP_NOTIFICATION_EVENT_TYPE_READER_EXCEPTION_EVENT           4
#define LLRP_NOTIFICATION_EVENT_TYPE_RFSURVEY_EVENT                   5
#define LLRP_NOTIFICATION_EVENT_TYPE_AISPEC_EVENT                     6
#define LLRP_NOTIFICATION_EVENT_TYPE_AISPEC_EVENT_WITH_DETAILS        7
#define LLRP_NOTIFICATION_EVENT_TYPE_ANTENNA_EVENT                    8
#define LLRP_NOTIFICATION_EVENT_TYPE_SPEC_LOOP_EVENT                  9

static const value_string event_type[] = {
    { LLRP_NOTIFICATION_EVENT_TYPE_UPON_HOPPING_TO_NEXT_CHANNEL,    "Upon hopping to next channel"  },
    { LLRP_NOTIFICATION_EVENT_TYPE_GPI_EVENT,                       "GPI event"                     },
    { LLRP_NOTIFICATION_EVENT_TYPE_ROSPEC_EVENT,                    "ROSpec event"                  },
    { LLRP_NOTIFICATION_EVENT_TYPE_REPORT_BUFFER_FILL_WARNING,      "Report buffer fill warning"    },
    { LLRP_NOTIFICATION_EVENT_TYPE_READER_EXCEPTION_EVENT,          "Reader exception event"        },
    { LLRP_NOTIFICATION_EVENT_TYPE_RFSURVEY_EVENT,                  "RFSurvey event"                },
    { LLRP_NOTIFICATION_EVENT_TYPE_AISPEC_EVENT,                    "AISpec event"                  },
    { LLRP_NOTIFICATION_EVENT_TYPE_AISPEC_EVENT_WITH_DETAILS,       "AISpec event with details"     },
    { LLRP_NOTIFICATION_EVENT_TYPE_ANTENNA_EVENT,                   "Antenna event"                 },
    { LLRP_NOTIFICATION_EVENT_TYPE_SPEC_LOOP_EVENT,                 "SpecLoop event"                },
    { 0,                                                            NULL                            }
};
static value_string_ext event_type_ext = VALUE_STRING_EXT_INIT(event_type);

/* ROSpec event type */
#define LLRP_ROSPEC_EVENT_TYPE_START_OF_ROSPEC          0
#define LLRP_ROSPEC_EVENT_TYPE_END_OF_ROSPEC            1
#define LLRP_ROSPEC_EVENT_TYPE_PREEMPTION_OF_ROSPEC     2

static const value_string roevent_type[] = {
    { LLRP_ROSPEC_EVENT_TYPE_START_OF_ROSPEC,         "Start of ROSpec"      },
    { LLRP_ROSPEC_EVENT_TYPE_END_OF_ROSPEC,           "End of ROSpec"        },
    { LLRP_ROSPEC_EVENT_TYPE_PREEMPTION_OF_ROSPEC,    "Preemption of ROSpec" },
    { 0,                                              NULL                   }
};

/* ROSpec event type */
#define LLRP_RF_SURVEY_EVENT_TYPE_START_OF_SURVEY     0
#define LLRP_RF_SURVEY_EVENT_TYPE_END_OF_SURVEY       1

static const value_string rfevent_type[] = {
    { LLRP_RF_SURVEY_EVENT_TYPE_START_OF_SURVEY,      "Start of survey"      },
    { LLRP_RF_SURVEY_EVENT_TYPE_END_OF_SURVEY,        "End of survey"        },
    { 0,                                              NULL                   }
};

/* AISpec event type */
#define LLRP_AISPEC_EVENT_TYPE_END_OF_AISPEC    0

static const value_string aievent_type[] = {
    { LLRP_AISPEC_EVENT_TYPE_END_OF_AISPEC,          "End of AISpec"        },
    { 0,                                              NULL                  }
};

/* Antenna event type */
#define LLRP_ANTENNA_EVENT_DISCONNECTED      0
#define LLRP_ANTENNA_EVENT_CONNECTED         1

static const value_string antenna_event_type[] = {
    { LLRP_ANTENNA_EVENT_DISCONNECTED,               "Antenna disconnected"  },
    { LLRP_ANTENNA_EVENT_CONNECTED,                  "Antenna connected"     },
    { 0,                                              NULL                   }
};

/* Connection status */
#define LLRP_CONNECTION_SUCCESS                                     0
#define LLRP_CONNECTION_FAILED_READER_INITIATE_ALREADY_EXISTS       1
#define LLRP_CONNECTION_FAILED_CLIENT_INITIATE_ALREADY_EXISTS       2
#define LLRP_CONNECTION_FAILED_OTHER_REASON_THAN_ALREADY_EXISTS     3
#define LLRP_CONNECTION_ANOTHER_CONNECTION_ATTEMPTED                4

static const value_string connection_status[] = {
    { LLRP_CONNECTION_SUCCESS,                                    "Success"                                              },
    { LLRP_CONNECTION_FAILED_READER_INITIATE_ALREADY_EXISTS,      "Failed a reader initiated connection already exists"  },
    { LLRP_CONNECTION_FAILED_CLIENT_INITIATE_ALREADY_EXISTS,      "Failed a client initiated connection already exists"  },
    { LLRP_CONNECTION_FAILED_OTHER_REASON_THAN_ALREADY_EXISTS,    "Failed reason other than a connection already exists" },
    { LLRP_CONNECTION_ANOTHER_CONNECTION_ATTEMPTED,               "Another connection attempted"                         },
    { 0,                                                          NULL                                                   }
};

/* Status code */
#define LLRP_STATUS_CODE_M_SUCCESS                0
#define LLRP_STATUS_CODE_M_PARAMETERERROR       100
#define LLRP_STATUS_CODE_M_FIELDERROR           101
#define LLRP_STATUS_CODE_M_UNEXPECTEDPARAMETER  102
#define LLRP_STATUS_CODE_M_MISSINGPARAMETER     103
#define LLRP_STATUS_CODE_M_DUPLICATEPARAMETER   104
#define LLRP_STATUS_CODE_M_OVERFLOWPARAMETER    105
#define LLRP_STATUS_CODE_M_OVERFLOWFIELD        106
#define LLRP_STATUS_CODE_M_UNKNOWNPARAMETER     107
#define LLRP_STATUS_CODE_M_UNKNOWNFIELD         108
#define LLRP_STATUS_CODE_M_UNSUPPORTEDMESSAGE   109
#define LLRP_STATUS_CODE_M_UNSUPPORTEDVERSION   110
#define LLRP_STATUS_CODE_M_UNSUPPORTEDPARAMETER 111
#define LLRP_STATUS_CODE_P_PARAMETERERROR       200
#define LLRP_STATUS_CODE_P_FIELDERROR           201
#define LLRP_STATUS_CODE_P_UNEXPECTEDPARAMETER  202
#define LLRP_STATUS_CODE_P_MISSINGPARAMETER     203
#define LLRP_STATUS_CODE_P_DUPLICATEPARAMETER   204
#define LLRP_STATUS_CODE_P_OVERFLOWPARAMETER    205
#define LLRP_STATUS_CODE_P_OVERFLOWFIELD        206
#define LLRP_STATUS_CODE_P_UNKNOWNPARAMETER     207
#define LLRP_STATUS_CODE_P_UNKNOWNFIELD         208
#define LLRP_STATUS_CODE_P_UNSUPPORTEDPARAMETER 209
#define LLRP_STATUS_CODE_A_INVALID              300
#define LLRP_STATUS_CODE_A_OUTOFRANGE           301
#define LLRP_STATUS_CODE_R_DEVICEERROR          401

static const value_string status_code[] = {
    { LLRP_STATUS_CODE_M_SUCCESS,             "M_Success"               },
    { LLRP_STATUS_CODE_M_PARAMETERERROR,      "M_ParameterError"        },
    { LLRP_STATUS_CODE_M_FIELDERROR,          "M_FieldError"            },
    { LLRP_STATUS_CODE_M_UNEXPECTEDPARAMETER, "M_UnexpectedParameter"   },
    { LLRP_STATUS_CODE_M_MISSINGPARAMETER,    "M_MissingParameter"      },
    { LLRP_STATUS_CODE_M_DUPLICATEPARAMETER,  "M_DuplicateParameter"    },
    { LLRP_STATUS_CODE_M_OVERFLOWPARAMETER,   "M_OverflowParameter"     },
    { LLRP_STATUS_CODE_M_OVERFLOWFIELD,       "M_OverflowField"         },
    { LLRP_STATUS_CODE_M_UNKNOWNPARAMETER,    "M_UnknownParameter"      },
    { LLRP_STATUS_CODE_M_UNKNOWNFIELD,        "M_UnknownField"          },
    { LLRP_STATUS_CODE_M_UNSUPPORTEDMESSAGE,  "M_UnsupportedMessage"    },
    { LLRP_STATUS_CODE_M_UNSUPPORTEDVERSION,  "M_UnsupportedVersion"    },
    { LLRP_STATUS_CODE_M_UNSUPPORTEDPARAMETER,"M_UnsupportedParameter"  },
    { LLRP_STATUS_CODE_P_PARAMETERERROR,      "P_ParameterError"        },
    { LLRP_STATUS_CODE_P_FIELDERROR,          "P_FieldError"            },
    { LLRP_STATUS_CODE_P_UNEXPECTEDPARAMETER, "P_UnexpectedParameter"   },
    { LLRP_STATUS_CODE_P_MISSINGPARAMETER,    "P_MissingParameter"      },
    { LLRP_STATUS_CODE_P_DUPLICATEPARAMETER,  "P_DuplicateParameter"    },
    { LLRP_STATUS_CODE_P_OVERFLOWPARAMETER,   "P_OverflowParameter"     },
    { LLRP_STATUS_CODE_P_OVERFLOWFIELD,       "P_OverflowField"         },
    { LLRP_STATUS_CODE_P_UNKNOWNPARAMETER,    "P_UnknownParameter"      },
    { LLRP_STATUS_CODE_P_UNKNOWNFIELD,        "P_UnknownField"          },
    { LLRP_STATUS_CODE_P_UNSUPPORTEDPARAMETER,"P_UnsupportedParameter"  },
    { LLRP_STATUS_CODE_A_INVALID,             "A_Invalid"               },
    { LLRP_STATUS_CODE_A_OUTOFRANGE,          "A_OutOfRange"            },
    { LLRP_STATUS_CODE_R_DEVICEERROR,         "R_DeviceError"           },
    { 0,                                      NULL                      }
};
static value_string_ext status_code_ext = VALUE_STRING_EXT_INIT(status_code);

/* C1G2 tag inventory state aware singulation action */
const true_false_string tfs_state_a_b = { "State B", "State A" };
const true_false_string tfs_sl =        { "~SL",     "SL"      };
const true_false_string tfs_all_no =    { "All",     "No"      };

/* Vendors */
#define LLRP_VENDOR_IMPINJ 25882

static const value_string llrp_vendors[] = {
    { LLRP_VENDOR_IMPINJ,  "Impinj" },
    { 0,                   NULL     }
};

/* Vendor subtypes */

/* Impinj custom message types */
#define LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS            21
#define LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS_RESPONSE   22
#define LLRP_IMPINJ_TYPE_SAVE_SETTINGS                23
#define LLRP_IMPINJ_TYPE_SAVE_SETTINGS_RESPONSE       24

static const value_string impinj_msg_subtype[] = {
    { LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS,          "Enable extensions"          },
    { LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS_RESPONSE, "Enable extensions response" },
    { LLRP_IMPINJ_TYPE_SAVE_SETTINGS,              "Save settings"              },
    { LLRP_IMPINJ_TYPE_SAVE_SETTINGS_RESPONSE,     "Save setting response"      },
    { 0,                                           NULL                         }
};
static value_string_ext impinj_msg_subtype_ext = VALUE_STRING_EXT_INIT(impinj_msg_subtype);

/* Impinj custom parameter types */
#define LLRP_IMPINJ_PARAM_REQUESTED_DATA                           21
#define LLRP_IMPINJ_PARAM_SUBREGULATORY_REGION                     22
#define LLRP_IMPINJ_PARAM_INVENTORY_SEARCH_MODE                    23
#define LLRP_IMPINJ_PARAM_TAG_DIRECTION_REPORTING                  24
#define LLRP_IMPINJ_PARAM_TAG_DIRECTION                            25
#define LLRP_IMPINJ_PARAM_FIXED_FREQUENCY_LIST                     26
#define LLRP_IMPINJ_PARAM_REDUCED_POWER_FREQUENCY_LIST             27
#define LLRP_IMPINJ_PARAM_LOW_DUTY_CYCLE                           28
#define LLRP_IMPINJ_PARAM_DETAILED_VERSION                         29
#define LLRP_IMPINJ_PARAM_FREQUENCY_CAPABILITIES                   30
#define LLRP_IMPINJ_PARAM_TAG_INFORMATION                          31
#define LLRP_IMPINJ_PARAM_FORKLIFT_CONFIGURATION                   32
#define LLRP_IMPINJ_PARAM_FORKLIFT_HEIGHT_THRESHOLD                33
#define LLRP_IMPINJ_PARAM_FORKLIFT_ZEROMOTION_TIME_THRESHOLD       34
#define LLRP_IMPINJ_PARAM_FORKLIFT_COMPANION_BOARD_INFO            35
#define LLRP_IMPINJ_PARAM_GPI_DEBOUNCE_CONFIGURATION               36
#define LLRP_IMPINJ_PARAM_READER_TEMPERATURE                       37
#define LLRP_IMPINJ_PARAM_LINK_MONITOR_CONFIGURATION               38
#define LLRP_IMPINJ_PARAM_REPORT_BUFFER_CONFIGURATION              39
#define LLRP_IMPINJ_PARAM_ACCESS_SPEC_CONFIGURATION                40
#define LLRP_IMPINJ_PARAM_BLOCK_WRITE_WORD_COUNT                   41
#define LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK                          42
#define LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK_OPSPEC_RESULT            43
#define LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS               44
#define LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS_OPSPEC_RESULT 45
#define LLRP_IMPINJ_PARAM_SET_QT_CONFIG                            46
#define LLRP_IMPINJ_PARAM_SET_QT_CONFIG_OPSPEC_RESULT              47
#define LLRP_IMPINJ_PARAM_GET_QT_CONFIG                            48
#define LLRP_IMPINJ_PARAM_GET_QT_CONFIG_OPSPEC_RESULT              49
#define LLRP_IMPINJ_PARAM_TAG_REPORT_CONTENT_SELECTOR              50
#define LLRP_IMPINJ_PARAM_ENABLE_SERIALIZED_TID                    51
#define LLRP_IMPINJ_PARAM_ENABLE_RF_PHASE_ANGLE                    52
#define LLRP_IMPINJ_PARAM_ENABLE_PEAK_RSSI                         53
#define LLRP_IMPINJ_PARAM_ENABLE_GPS_COORDINATES                   54
#define LLRP_IMPINJ_PARAM_SERIALIZED_TID                           55
#define LLRP_IMPINJ_PARAM_RF_PHASE_ANGLE                           56
#define LLRP_IMPINJ_PARAM_PEAK_RSSI                                57
#define LLRP_IMPINJ_PARAM_GPS_COORDINATES                          58
#define LLRP_IMPINJ_PARAM_LOOP_SPEC                                59
#define LLRP_IMPINJ_PARAM_GPS_NMEA_SENTENCES                       60
#define LLRP_IMPINJ_PARAM_GGA_SENTENCE                             61
#define LLRP_IMPINJ_PARAM_RMC_SENTENCE                             62
#define LLRP_IMPINJ_PARAM_OPSPEC_RETRY_COUNT                       63
#define LLRP_IMPINJ_PARAM_ADVANCE_GPO_CONFIG                       64
#define LLRP_IMPINJ_PARAM_ENABLE_OPTIM_READ                        65
#define LLRP_IMPINJ_PARAM_ACCESS_SPEC_ORDERING                     66
#define LLRP_IMPINJ_PARAM_ENABLE_RF_DOPPLER_FREQ                   67

static const value_string impinj_param_type[] = {
    { LLRP_IMPINJ_PARAM_REQUESTED_DATA,                          "Requested Data"                           },
    { LLRP_IMPINJ_PARAM_SUBREGULATORY_REGION,                    "Sub regulatory region"                    },
    { LLRP_IMPINJ_PARAM_INVENTORY_SEARCH_MODE,                   "Inventory search mode"                    },
    { LLRP_IMPINJ_PARAM_TAG_DIRECTION_REPORTING,                 "Tag direction reporting"                  },
    { LLRP_IMPINJ_PARAM_TAG_DIRECTION,                           "Tag direction"                            },
    { LLRP_IMPINJ_PARAM_FIXED_FREQUENCY_LIST,                    "Fixed frequency list"                     },
    { LLRP_IMPINJ_PARAM_REDUCED_POWER_FREQUENCY_LIST,            "Reduced power frequency list"             },
    { LLRP_IMPINJ_PARAM_LOW_DUTY_CYCLE,                          "Low duty cycle"                           },
    { LLRP_IMPINJ_PARAM_DETAILED_VERSION,                        "Detailed version"                         },
    { LLRP_IMPINJ_PARAM_FREQUENCY_CAPABILITIES,                  "Frequency capabilities"                   },
    { LLRP_IMPINJ_PARAM_TAG_INFORMATION,                         "Tag information"                          },
    { LLRP_IMPINJ_PARAM_FORKLIFT_CONFIGURATION,                  "Forklift configuration"                   },
    { LLRP_IMPINJ_PARAM_FORKLIFT_HEIGHT_THRESHOLD,               "Forklift height threshold"                },
    { LLRP_IMPINJ_PARAM_FORKLIFT_ZEROMOTION_TIME_THRESHOLD,      "Forklift zero motion time threshold"      },
    { LLRP_IMPINJ_PARAM_FORKLIFT_COMPANION_BOARD_INFO,           "Forklift companion board info"            },
    { LLRP_IMPINJ_PARAM_GPI_DEBOUNCE_CONFIGURATION,              "Gpi debounce configuration"               },
    { LLRP_IMPINJ_PARAM_READER_TEMPERATURE,                      "Reader temperature"                       },
    { LLRP_IMPINJ_PARAM_LINK_MONITOR_CONFIGURATION,              "Link monitor configuration"               },
    { LLRP_IMPINJ_PARAM_REPORT_BUFFER_CONFIGURATION,             "Report buffer configuration"              },
    { LLRP_IMPINJ_PARAM_ACCESS_SPEC_CONFIGURATION,               "Access spec configuration"                },
    { LLRP_IMPINJ_PARAM_BLOCK_WRITE_WORD_COUNT,                  "Block write word count"                   },
    { LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK,                         "Block permalock"                          },
    { LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK_OPSPEC_RESULT,           "Block permalock OpSpec result"            },
    { LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS,              "Get block permalock status"               },
    { LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS_OPSPEC_RESULT,"Get block permalock status OpSpec result" },
    { LLRP_IMPINJ_PARAM_SET_QT_CONFIG,                           "Set QT config"                            },
    { LLRP_IMPINJ_PARAM_SET_QT_CONFIG_OPSPEC_RESULT,             "Set QT config OpSpec result"              },
    { LLRP_IMPINJ_PARAM_GET_QT_CONFIG,                           "Get QT config"                            },
    { LLRP_IMPINJ_PARAM_GET_QT_CONFIG_OPSPEC_RESULT,             "Get QT config OpSpec result"              },
    { LLRP_IMPINJ_PARAM_TAG_REPORT_CONTENT_SELECTOR,             "Tag report content selector"              },
    { LLRP_IMPINJ_PARAM_ENABLE_SERIALIZED_TID,                   "Enable serialized TID"                    },
    { LLRP_IMPINJ_PARAM_ENABLE_RF_PHASE_ANGLE,                   "Enable RF phase angle"                    },
    { LLRP_IMPINJ_PARAM_ENABLE_PEAK_RSSI,                        "Enable peak RSSI"                         },
    { LLRP_IMPINJ_PARAM_ENABLE_GPS_COORDINATES,                  "Enable GPS coordinates"                   },
    { LLRP_IMPINJ_PARAM_SERIALIZED_TID,                          "Serialized TID"                           },
    { LLRP_IMPINJ_PARAM_RF_PHASE_ANGLE,                          "RF phase angle"                           },
    { LLRP_IMPINJ_PARAM_PEAK_RSSI,                               "Peak RSSI"                                },
    { LLRP_IMPINJ_PARAM_GPS_COORDINATES,                         "GPS coordinates"                          },
    { LLRP_IMPINJ_PARAM_LOOP_SPEC,                               "LoopSpec"                                 },
    { LLRP_IMPINJ_PARAM_GPS_NMEA_SENTENCES,                      "GPS NMEA sentences"                       },
    { LLRP_IMPINJ_PARAM_GGA_SENTENCE,                            "GGA sentence"                             },
    { LLRP_IMPINJ_PARAM_RMC_SENTENCE,                            "RMC sentence"                             },
    { LLRP_IMPINJ_PARAM_OPSPEC_RETRY_COUNT,                      "OpSpec retry count"                       },
    { LLRP_IMPINJ_PARAM_ADVANCE_GPO_CONFIG,                      "Advanced GPO configuration"               },
    { LLRP_IMPINJ_PARAM_ENABLE_OPTIM_READ,                       "Enable optimized read"                    },
    { LLRP_IMPINJ_PARAM_ACCESS_SPEC_ORDERING,                    "AccessSpec ordering"                      },
    { LLRP_IMPINJ_PARAM_ENABLE_RF_DOPPLER_FREQ,                  "Enable RF doppler frequency"              },
    { 0,                                                         NULL                                       }
};
static value_string_ext impinj_param_type_ext = VALUE_STRING_EXT_INIT(impinj_param_type);

/* Impinj requested data */
#define LLRP_IMPINJ_REQ_DATA_ALL_CAPABILITIES                1000
#define LLRP_IMPINJ_REQ_DATA_DETAILED_VERSION                1001
#define LLRP_IMPINJ_REQ_DATA_FREQUENCY_CAPABILITIES          1002
#define LLRP_IMPINJ_REQ_DATA_CONFIGURATION                   2000
#define LLRP_IMPINJ_REQ_DATA_SUB_REGULATORY_REGION           2001
#define LLRP_IMPINJ_REQ_DATA_FORKLIFT_CONFIGURATION          2002
#define LLRP_IMPINJ_REQ_DATA_GPI_DEBOUNCE_CONFIGURATION      2003
#define LLRP_IMPINJ_REQ_DATA_READER_TEMPERATURE              2004
#define LLRP_IMPINJ_REQ_DATA_LINK_MONITOR_CONFIGURATION      2005
#define LLRP_IMPINJ_REQ_DATA_REPORT_BUFFER_CONFIGURATION     2006
#define LLRP_IMPINJ_REQ_DATA_ACCESS_SPEC_CONFIGURATION       2007
#define LLRP_IMPINJ_REQ_DATA_GPS_NMEA_SENTENCES              2008


static const value_string impinj_req_data[] = {
    { LLRP_IMPINJ_REQ_DATA_ALL_CAPABILITIES,            "All capabilities"            },
    { LLRP_IMPINJ_REQ_DATA_DETAILED_VERSION,            "Detailed version"            },
    { LLRP_IMPINJ_REQ_DATA_FREQUENCY_CAPABILITIES,      "Frequency capabilities"      },
    { LLRP_IMPINJ_REQ_DATA_CONFIGURATION,               "Configuration"               },
    { LLRP_IMPINJ_REQ_DATA_SUB_REGULATORY_REGION,       "Sub regulatory region"       },
    { LLRP_IMPINJ_REQ_DATA_FORKLIFT_CONFIGURATION,      "Forklift configuration"      },
    { LLRP_IMPINJ_REQ_DATA_GPI_DEBOUNCE_CONFIGURATION,  "GPI debounce configuration"  },
    { LLRP_IMPINJ_REQ_DATA_READER_TEMPERATURE,          "Reader temperature"          },
    { LLRP_IMPINJ_REQ_DATA_LINK_MONITOR_CONFIGURATION,  "Link monitor configuration"  },
    { LLRP_IMPINJ_REQ_DATA_REPORT_BUFFER_CONFIGURATION, "Report buffer configuration" },
    { LLRP_IMPINJ_REQ_DATA_ACCESS_SPEC_CONFIGURATION,   "Access spec configuration"   },
    { LLRP_IMPINJ_REQ_DATA_GPS_NMEA_SENTENCES,          "GPS NMEA sentences"          },
    { 0,                                                NULL                          }
};
static value_string_ext impinj_req_data_ext = VALUE_STRING_EXT_INIT(impinj_req_data);

/* Impinj regulatory region */
#define LLRP_IMPINJ_REG_REGION_FCC_PART_15_247                   0
#define LLRP_IMPINJ_REG_REGION_ETSI_EN_300_220                   1
#define LLRP_IMPINJ_REG_REGION_ETSI_EN_302_208_WITH_LBT          2
#define LLRP_IMPINJ_REG_REGION_HONG_KONG_920_925_MHZ             3
#define LLRP_IMPINJ_REG_REGION_TAIWAN_922_928_MHZ                4
#define LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ                 5
#define LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ_LOW_POWER       6
#define LLRP_IMPINJ_REG_REGION_ETSI_EN_302_208_V1_2_1            7
#define LLRP_IMPINJ_REG_REGION_KOREA_910_914_MHZ                 8
#define LLRP_IMPINJ_REG_REGION_MALAYSIA_919_923_MHZ              9
#define LLRP_IMPINJ_REG_REGION_CHINA_920_925_MHZ                10
#define LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ_WITHOUT_LBT    11
#define LLRP_IMPINJ_REG_REGION_SOUTH_AFRICA_915_919_MHZ         12
#define LLRP_IMPINJ_REG_REGION_BRAZIL_902_907_AND_915_928_MHZ   13
#define LLRP_IMPINJ_REG_REGION_THAILAND_920_925_MHZ             14
#define LLRP_IMPINJ_REG_REGION_SINGAPORE_920_925_MHZ            15
#define LLRP_IMPINJ_REG_REGION_AUSTRALIA_920_926_MHZ            16
#define LLRP_IMPINJ_REG_REGION_INDIA_865_867_MHZ                17
#define LLRP_IMPINJ_REG_REGION_URUGUAY_916_928_MHZ              18
#define LLRP_IMPINJ_REG_REGION_VIETNAM_920_925_MHZ              19
#define LLRP_IMPINJ_REG_REGION_ISRAEL_915_917_MHZ               20

static const value_string impinj_reg_region[] = {
    { LLRP_IMPINJ_REG_REGION_FCC_PART_15_247,                "Fcc part 15 247"                },
    { LLRP_IMPINJ_REG_REGION_ETSI_EN_300_220,                "ETSI EN 300 220"                },
    { LLRP_IMPINJ_REG_REGION_ETSI_EN_302_208_WITH_LBT,       "ETSI EN 302 208 with LBT"       },
    { LLRP_IMPINJ_REG_REGION_HONG_KONG_920_925_MHZ,          "Hong kong 920-925 MHz"          },
    { LLRP_IMPINJ_REG_REGION_TAIWAN_922_928_MHZ,             "Taiwan 922-928 MHz"             },
    { LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ,              "Japan 952-954 MHz"              },
    { LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ_LOW_POWER,    "Japan 952-954 MHz low power"    },
    { LLRP_IMPINJ_REG_REGION_ETSI_EN_302_208_V1_2_1,         "ETSI EN 302 208 v1.2.1"         },
    { LLRP_IMPINJ_REG_REGION_KOREA_910_914_MHZ,              "Korea 910-914 MHz"              },
    { LLRP_IMPINJ_REG_REGION_MALAYSIA_919_923_MHZ,           "Malaysia 919-923 MHz"           },
    { LLRP_IMPINJ_REG_REGION_CHINA_920_925_MHZ,              "China 920-925 MHz"              },
    { LLRP_IMPINJ_REG_REGION_JAPAN_952_954_MHZ_WITHOUT_LBT,  "Japan 952-954 MHz without LBT"  },
    { LLRP_IMPINJ_REG_REGION_SOUTH_AFRICA_915_919_MHZ,       "South africa 915-919 MHz"       },
    { LLRP_IMPINJ_REG_REGION_BRAZIL_902_907_AND_915_928_MHZ, "Brazil 902-907 and 915-928 MHz" },
    { LLRP_IMPINJ_REG_REGION_THAILAND_920_925_MHZ,           "Thailand 920-925 MHz"           },
    { LLRP_IMPINJ_REG_REGION_SINGAPORE_920_925_MHZ,          "Singapore 920-925 MHz"          },
    { LLRP_IMPINJ_REG_REGION_AUSTRALIA_920_926_MHZ,          "Australia 920-926 MHz"          },
    { LLRP_IMPINJ_REG_REGION_INDIA_865_867_MHZ,              "India 865-867 MHz"              },
    { LLRP_IMPINJ_REG_REGION_URUGUAY_916_928_MHZ,            "Uruguay 916-928 MHz"            },
    { LLRP_IMPINJ_REG_REGION_VIETNAM_920_925_MHZ,            "Vietnam 920-925 MHz"            },
    { LLRP_IMPINJ_REG_REGION_ISRAEL_915_917_MHZ,             "Israel 915-917 MHz"             },
    { 0,                                                     NULL                             }
};
static value_string_ext impinj_reg_region_ext = VALUE_STRING_EXT_INIT(impinj_reg_region);

/* Impinj inventory search type */
#define LLRP_IMPINJ_SEARCH_TYPE_READER_SELECTED         0
#define LLRP_IMPINJ_SEARCH_TYPE_SINGLE_TARGET           1
#define LLRP_IMPINJ_SEARCH_TYPE_DUAL_TARGET             2
#define LLRP_IMPINJ_SEARCH_TYPE_SINGLE_TARGET_WITH_SUPP 3

static const value_string impinj_search_mode[] = {
    { LLRP_IMPINJ_SEARCH_TYPE_READER_SELECTED,           "Reader selected"                },
    { LLRP_IMPINJ_SEARCH_TYPE_SINGLE_TARGET,             "Single target"                  },
    { LLRP_IMPINJ_SEARCH_TYPE_DUAL_TARGET,               "Dual target"                    },
    { LLRP_IMPINJ_SEARCH_TYPE_SINGLE_TARGET_WITH_SUPP,   "Single target with suppression" },
    { 0,                                                 NULL                             }
};

/* Impinj antenna configuration */
#define LLRP_IMPINJ_ANT_CONF_DUAL   1
#define LLRP_IMPINJ_ANT_CONF_QUAD   2

static const value_string impinj_ant_conf[] = {
    { LLRP_IMPINJ_ANT_CONF_DUAL, "Dual antenna" },
    { LLRP_IMPINJ_ANT_CONF_QUAD, "Quad antenna" },
    { 0,                        NULL            }
};

/* Impinj tag direction */
#define LLRP_IMPINJ_TAG_DIR_INDETERMINED  0
#define LLRP_IMPINJ_TAG_DIR_FROM_2_TO_1   1
#define LLRP_IMPINJ_TAG_DIR_FROM_1_TO_2   2

static const value_string impinj_tag_dir[] = {
    { LLRP_IMPINJ_TAG_DIR_INDETERMINED, "Indeterminate"       },
    { LLRP_IMPINJ_TAG_DIR_FROM_2_TO_1,  "From side2 to side1" },
    { LLRP_IMPINJ_TAG_DIR_FROM_1_TO_2,  "From side1 to side2" },
    { 0,                                NULL                  }
};

/* Impinj fixed frequency mode */
#define LLRP_IMPINJ_FIX_FREQ_MODE_DISABLED      0
#define LLRP_IMPINJ_FIX_FREQ_MODE_AUTO_SELECT   1
#define LLRP_IMPINJ_FIX_FREQ_MODE_CHANNEL_LIST  2

static const value_string impinj_fix_freq_mode[] = {
    { LLRP_IMPINJ_FIX_FREQ_MODE_DISABLED,      "Disabled"     },
    { LLRP_IMPINJ_FIX_FREQ_MODE_AUTO_SELECT,   "Auto select"  },
    { LLRP_IMPINJ_FIX_FREQ_MODE_CHANNEL_LIST,  "Channel list" },
    { 0,                                       NULL           }
};

/* Impinj enabled/disabled */
#define LLRP_IMPINJ_BOOLEAN_DISABLED      0
#define LLRP_IMPINJ_BOOLEAN_ENABLED       1

static const value_string impinj_boolean[] = {
    { LLRP_IMPINJ_BOOLEAN_DISABLED, "Disabled" },
    { LLRP_IMPINJ_BOOLEAN_ENABLED,  "Enabled"  },
    { 0,                            NULL       }
};

/* Impinj report buffer mode */
#define LLRP_IMPINJ_REPORT_BUFF_MODE_NORMAL      0
#define LLRP_IMPINJ_REPORT_BUFF_MODE_LOW_LATENCY 1

static const value_string impinj_report_buff_mode[] = {
    { LLRP_IMPINJ_REPORT_BUFF_MODE_NORMAL,       "Normal"      },
    { LLRP_IMPINJ_REPORT_BUFF_MODE_LOW_LATENCY,  "Low latency" },
    { 0,                                         NULL          }
};

/* Impinj permalock operation result */
#define LLRP_IMPINJ_PERMALOCK_SUCCESS                      0
#define LLRP_IMPINJ_PERMALOCK_INSUFFICIENT_POWER           1
#define LLRP_IMPINJ_PERMALOCK_NONSPECIFIC_TAG_ERROR        2
#define LLRP_IMPINJ_PERMALOCK_NO_RESPONSE_FROM_TAG         3
#define LLRP_IMPINJ_PERMALOCK_NONSPECIFIC_READER_ERROR     4
#define LLRP_IMPINJ_PERMALOCK_INCORRECT_PASSWORD_ERROR     5
#define LLRP_IMPINJ_PERMALOCK_TAG_MEMORY_OVERRUN_ERROR     6

static const value_string impinj_permalock_result[] = {
    { LLRP_IMPINJ_PERMALOCK_SUCCESS,                  "Success"                  },
    { LLRP_IMPINJ_PERMALOCK_INSUFFICIENT_POWER,       "Insufficient power"       },
    { LLRP_IMPINJ_PERMALOCK_NONSPECIFIC_TAG_ERROR,    "Nonspecific tag error"    },
    { LLRP_IMPINJ_PERMALOCK_NO_RESPONSE_FROM_TAG,     "No response from tag"     },
    { LLRP_IMPINJ_PERMALOCK_NONSPECIFIC_READER_ERROR, "Nonspecific reader error" },
    { LLRP_IMPINJ_PERMALOCK_INCORRECT_PASSWORD_ERROR, "Incorrect password error" },
    { LLRP_IMPINJ_PERMALOCK_TAG_MEMORY_OVERRUN_ERROR, "Tag memory overrun error" },
    { 0,                                              NULL                       }
};
static value_string_ext impinj_permalock_result_ext = VALUE_STRING_EXT_INIT(impinj_permalock_result);

/* Impinj get block permalock operation result */
#define LLRP_IMPINJ_BLOCK_PERMALOCK_SUCCESS                      0
#define LLRP_IMPINJ_BLOCK_PERMALOCK_NONSPECIFIC_TAG_ERROR        1
#define LLRP_IMPINJ_BLOCK_PERMALOCK_NO_RESPONSE_FROM_TAG         2
#define LLRP_IMPINJ_BLOCK_PERMALOCK_NONSPECIFIC_READER_ERROR     3
#define LLRP_IMPINJ_BLOCK_PERMALOCK_INCORRECT_PASSWORD_ERROR     4
#define LLRP_IMPINJ_BLOCK_PERMALOCK_TAG_MEMORY_OVERRUN_ERROR     5

static const value_string impinj_block_permalock_result[] = {
    { LLRP_IMPINJ_BLOCK_PERMALOCK_SUCCESS,                  "Success"                  },
    { LLRP_IMPINJ_BLOCK_PERMALOCK_NONSPECIFIC_TAG_ERROR,    "Nonspecific tag error"    },
    { LLRP_IMPINJ_BLOCK_PERMALOCK_NO_RESPONSE_FROM_TAG,     "No response from tag"     },
    { LLRP_IMPINJ_BLOCK_PERMALOCK_NONSPECIFIC_READER_ERROR, "Nonspecific reader error" },
    { LLRP_IMPINJ_BLOCK_PERMALOCK_INCORRECT_PASSWORD_ERROR, "Incorrect password error" },
    { LLRP_IMPINJ_BLOCK_PERMALOCK_TAG_MEMORY_OVERRUN_ERROR, "Tag memory overrun error" },
    { 0,                                                    NULL                       }
};
static value_string_ext impinj_block_permalock_result_ext = VALUE_STRING_EXT_INIT(impinj_block_permalock_result);

/* Impinj data profile parameter */
#define LLRP_IMPINJ_DATA_PROFILE_UNKNOWN        0
#define LLRP_IMPINJ_DATA_PROFILE_PRIVATE        1
#define LLRP_IMPINJ_DATA_PROFILE_PUBLIC         2

static const value_string impinj_data_profile[] = {
    { LLRP_IMPINJ_DATA_PROFILE_UNKNOWN,  "Unknown" },
    { LLRP_IMPINJ_DATA_PROFILE_PRIVATE,  "Private" },
    { LLRP_IMPINJ_DATA_PROFILE_PUBLIC,   "Public"  },
    { 0,                                 NULL      }
};

/* Impinj access range parameter */
#define LLRP_IMPINJ_ACCESS_RANGE_UNKNOWN        0
#define LLRP_IMPINJ_ACCESS_RANGE_NORMAL_RANGE   1
#define LLRP_IMPINJ_ACCESS_RANGE_SHORT_RANGE    2

static const value_string impinj_access_range[] = {
    { LLRP_IMPINJ_ACCESS_RANGE_UNKNOWN,       "Unknown"      },
    { LLRP_IMPINJ_ACCESS_RANGE_NORMAL_RANGE,  "Normal range" },
    { LLRP_IMPINJ_ACCESS_RANGE_SHORT_RANGE,   "Short range"  },
    { 0,                                      NULL           }
};

/* Impinj persistence parameter */
#define LLRP_IMPINJ_PERSISTENCE_UNKNOWN     0
#define LLRP_IMPINJ_PERSISTENCE_TEMPORARY   1
#define LLRP_IMPINJ_PERSISTENCE_PERMANENT   2

static const value_string impinj_persistence[] = {
    { LLRP_IMPINJ_PERSISTENCE_UNKNOWN,     "Unknown"    },
    { LLRP_IMPINJ_PERSISTENCE_TEMPORARY,   "Temporary"  },
    { LLRP_IMPINJ_PERSISTENCE_PERMANENT,   "Permament"  },
    { 0,                                   NULL         }
};

/* Impinj set QT config result */
#define LLRP_IMPINJ_SET_QT_CONFIG_SUCCESS                      0
#define LLRP_IMPINJ_SET_QT_CONFIG_INSUFFICIENT_POWER           1
#define LLRP_IMPINJ_SET_QT_CONFIG_NONSPECIFIC_TAG_ERROR        2
#define LLRP_IMPINJ_SET_QT_CONFIG_NO_RESPONSE_FROM_TAG         3
#define LLRP_IMPINJ_SET_QT_CONFIG_NONSPECIFIC_READER_ERROR     4
#define LLRP_IMPINJ_SET_QT_CONFIG_INCORRECT_PASSWORD_ERROR     5

static const value_string impinj_set_qt_config_result[] = {
    { LLRP_IMPINJ_SET_QT_CONFIG_SUCCESS,                  "Success"                  },
    { LLRP_IMPINJ_SET_QT_CONFIG_INSUFFICIENT_POWER,       "Insufficient power"       },
    { LLRP_IMPINJ_SET_QT_CONFIG_NONSPECIFIC_TAG_ERROR,    "Nonspecific tag error"    },
    { LLRP_IMPINJ_SET_QT_CONFIG_NO_RESPONSE_FROM_TAG,     "No response from tag"     },
    { LLRP_IMPINJ_SET_QT_CONFIG_NONSPECIFIC_READER_ERROR, "Nonspecific reader error" },
    { LLRP_IMPINJ_SET_QT_CONFIG_INCORRECT_PASSWORD_ERROR, "Incorrect password error" },
    { 0,                                                  NULL                       }
};
static value_string_ext impinj_set_qt_config_result_ext = VALUE_STRING_EXT_INIT(impinj_set_qt_config_result);

/* Impinj get QT config result */
#define LLRP_IMPINJ_GET_QT_CONFIG_SUCCESS                      0
#define LLRP_IMPINJ_GET_QT_CONFIG_NONSPECIFIC_TAG_ERROR        1
#define LLRP_IMPINJ_GET_QT_CONFIG_NO_RESPONSE_FROM_TAG         2
#define LLRP_IMPINJ_GET_QT_CONFIG_NONSPECIFIC_READER_ERROR     3
#define LLRP_IMPINJ_GET_QT_CONFIG_INCORRECT_PASSWORD_ERROR     4

static const value_string impinj_get_qt_config_result[] = {
    { LLRP_IMPINJ_GET_QT_CONFIG_SUCCESS,                  "Success"                  },
    { LLRP_IMPINJ_GET_QT_CONFIG_NONSPECIFIC_TAG_ERROR,    "Nonspecific tag error"    },
    { LLRP_IMPINJ_GET_QT_CONFIG_NO_RESPONSE_FROM_TAG,     "No response from tag"     },
    { LLRP_IMPINJ_GET_QT_CONFIG_NONSPECIFIC_READER_ERROR, "Nonspecific reader error" },
    { LLRP_IMPINJ_GET_QT_CONFIG_INCORRECT_PASSWORD_ERROR, "Incorrect password error" },
    { 0,                                                  NULL                       }
};
static value_string_ext impinj_get_qt_config_result_ext = VALUE_STRING_EXT_INIT(impinj_get_qt_config_result);

/* Impinj access spec ordering */
#define LLRP_IMPINJ_ACCESS_SPEC_ORDERING_FIFO        0
#define LLRP_IMPINJ_ACCESS_SPEC_ORDERING_ASCENDING   1

static const value_string impinj_access_spec_ordering[] = {
    { LLRP_IMPINJ_ACCESS_SPEC_ORDERING_FIFO,       "FIFO"      },
    { LLRP_IMPINJ_ACCESS_SPEC_ORDERING_ASCENDING,  "Ascending" },
    { 0,                                           NULL        }
};

/* Impinj GPO mode */
#define LLRP_IMPINJ_GPO_MODE_NORMAL                         0
#define LLRP_IMPINJ_GPO_MODE_PULSED                         1
#define LLRP_IMPINJ_GPO_MODE_READER_OPERATIONAL_STATUS      2
#define LLRP_IMPINJ_GPO_MODE_LLRP_CONNECTION_STATUS         3
#define LLRP_IMPINJ_GPO_MODE_READER_INVENTORY_STATUS        4
#define LLRP_IMPINJ_GPO_MODE_NETWORK_CONNECTION_STATUS      5
#define LLRP_IMPINJ_GPO_MODE_READER_INVENTORY_TAGS_STATUS   6

static const value_string impinj_gpo_mode[] = {
    { LLRP_IMPINJ_GPO_MODE_NORMAL,                        "Normal"                       },
    { LLRP_IMPINJ_GPO_MODE_PULSED,                        "Pulsed"                       },
    { LLRP_IMPINJ_GPO_MODE_READER_OPERATIONAL_STATUS,     "Reader operational status"    },
    { LLRP_IMPINJ_GPO_MODE_LLRP_CONNECTION_STATUS,        "LLRP connection status"       },
    { LLRP_IMPINJ_GPO_MODE_READER_INVENTORY_STATUS,       "Reader inventory status"      },
    { LLRP_IMPINJ_GPO_MODE_NETWORK_CONNECTION_STATUS,     "Network connection status"    },
    { LLRP_IMPINJ_GPO_MODE_READER_INVENTORY_TAGS_STATUS,  "Reader inventory tags status" },
    { 0,                                                  NULL                           }
};
static value_string_ext impinj_gpo_mode_ext = VALUE_STRING_EXT_INIT(impinj_gpo_mode);

/* Misc */
#define LLRP_ROSPEC_ALL      0
#define LLRP_ANTENNA_ALL     0
#define LLRP_GPI_PORT_ALL    0
#define LLRP_GPO_PORT_ALL    0
#define LLRP_ACCESSSPEC_ALL  0
#define LLRP_TLV_LEN_MIN     4
#define LLRP_HEADER_LENGTH  10
#define LLRP_NO_LIMIT        0

static guint
dissect_llrp_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset, const guint end);

static guint dissect_llrp_utf8_parameter(tvbuff_t * const tvb, packet_info *pinfo,
        proto_tree * const tree, const guint hfindex, const guint offset)
{
    gint len;

    len = tvb_get_ntohs(tvb, offset);
    if(tvb_reported_length_remaining(tvb, offset) < len) {
        expert_add_info_format(pinfo, tree, &ei_llrp_invalid_length,
            "invalid length of string: claimed %u, available %u.",
            len, tvb_reported_length_remaining(tvb, offset));
        return offset + 2;
    }
    proto_tree_add_item(tree, hfindex, tvb,
            offset, 2, ENC_BIG_ENDIAN | ENC_UTF_8);

    return offset + len + 2;
}

static guint dissect_llrp_bit_field(tvbuff_t * const tvb,
        proto_tree * const tree, const guint hfindex, const guint offset)
{
    guint len;

    len = tvb_get_ntohs(tvb, offset);
    len = (len + 7) / 8;
    proto_tree_add_item(tree, hf_llrp_length_bits, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hfindex, tvb,
            offset + 2, len, ENC_NA);
    return offset + len + 2;
}

static guint dissect_llrp_word_array(tvbuff_t * const tvb,
        proto_tree * const tree, const guint hfindex, const guint offset)
{
    guint len;

    len = tvb_get_ntohs(tvb, offset);
    len *= 2;
    proto_tree_add_item(tree, hf_llrp_length_words, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hfindex, tvb,
            offset + 2, len, ENC_NA);
    return offset + len + 2;
}

static guint dissect_llrp_item_array(tvbuff_t * const tvb, packet_info *pinfo,
        proto_tree * const tree, const guint hfindex_number,
        const guint hfindex_item, const guint item_size, guint offset)
{
    guint num;

    num = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hfindex_number, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if(tvb_reported_length_remaining(tvb, offset) < ((gint)(num*item_size))) {
        expert_add_info_format(pinfo, tree, &ei_llrp_invalid_length,
                "Array longer than message");
        return offset + tvb_reported_length_remaining(tvb, offset);
    }
    while(num--) {
        proto_tree_add_item(tree, hfindex_item, tvb,
                offset, item_size, item_size == 1 ? ENC_NA : ENC_BIG_ENDIAN);
        offset += item_size;
    }
    return offset;
}

#define PARAM_TREE_ADD_STAY(hfindex, length, flag) \
            proto_tree_add_item(param_tree, hf_llrp_##hfindex, tvb, \
                    suboffset, length, flag)

#define PARAM_TREE_ADD(hfindex, length, flag) \
            PARAM_TREE_ADD_STAY(hfindex, length, flag); \
            suboffset += length

#define PARAM_TREE_ADD_SPEC_STAY(type, hfindex, length, number, string) \
            proto_tree_add_##type(param_tree, hf_llrp_##hfindex, tvb, \
                    suboffset, length, number, string, number)

#define PARAM_TREE_ADD_SPEC(type, hfindex, length, number, string) \
            PARAM_TREE_ADD_SPEC_STAY(type, hfindex, length, number, string); \
            suboffset += length

static guint
dissect_llrp_impinj_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *param_tree,
        guint suboffset, const guint param_end)
{
    guint32 subtype;

    subtype = tvb_get_ntohl(tvb, suboffset);
    proto_item_append_text(param_tree, " (Impinj - %s)",
            val_to_str_ext(subtype, &impinj_param_type_ext, "Unknown Type: %d"));
    proto_tree_add_item(param_tree, hf_llrp_impinj_param_type, tvb, suboffset, 4, ENC_BIG_ENDIAN);
    suboffset += 4;

    switch(subtype) {
    case LLRP_IMPINJ_PARAM_TAG_INFORMATION:
    case LLRP_IMPINJ_PARAM_FORKLIFT_CONFIGURATION:
    case LLRP_IMPINJ_PARAM_ACCESS_SPEC_CONFIGURATION:
    case LLRP_IMPINJ_PARAM_TAG_REPORT_CONTENT_SELECTOR:
    case LLRP_IMPINJ_PARAM_GPS_NMEA_SENTENCES:
        /* Just parameters */
        break;
    case LLRP_IMPINJ_PARAM_REQUESTED_DATA:
        PARAM_TREE_ADD(impinj_req_data, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_SUBREGULATORY_REGION:
        PARAM_TREE_ADD(impinj_reg_region, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_INVENTORY_SEARCH_MODE:
        PARAM_TREE_ADD(impinj_search_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_TAG_DIRECTION_REPORTING:
        PARAM_TREE_ADD(impinj_en_tag_dir, 2, ENC_NA);
        PARAM_TREE_ADD(impinj_antenna_conf, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(rfu, 4, ENC_NA);
        break;
    case LLRP_IMPINJ_PARAM_TAG_DIRECTION:
        PARAM_TREE_ADD(decision_time, 8, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(impinj_tag_dir, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(confidence, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_FIXED_FREQUENCY_LIST:
        PARAM_TREE_ADD(impinj_fix_freq_mode, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(rfu, 2, ENC_NA);
        suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                hf_llrp_num_channels, hf_llrp_channel, 2, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_REDUCED_POWER_FREQUENCY_LIST:
        PARAM_TREE_ADD(impinj_reduce_power_mode, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(rfu, 2, ENC_NA);
        suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                hf_llrp_num_channels, hf_llrp_channel, 2, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_LOW_DUTY_CYCLE:
        PARAM_TREE_ADD(impinj_low_duty_mode, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(empty_field_timeout, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(field_ping_interval, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_DETAILED_VERSION:
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_model_name, suboffset);
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_serial_number, suboffset);
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_soft_ver, suboffset);
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_firm_ver, suboffset);
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_fpga_ver, suboffset);
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_pcba_ver, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_FREQUENCY_CAPABILITIES:
        suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                hf_llrp_num_freqs, hf_llrp_frequency, 4, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_FORKLIFT_HEIGHT_THRESHOLD:
        PARAM_TREE_ADD(height_thresh, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_FORKLIFT_ZEROMOTION_TIME_THRESHOLD:
        PARAM_TREE_ADD(zero_motion_thresh, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_FORKLIFT_COMPANION_BOARD_INFO:
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_board_manufacturer, suboffset);
        PARAM_TREE_ADD(fw_ver_hex, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(hw_ver_hex, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GPI_DEBOUNCE_CONFIGURATION:
        PARAM_TREE_ADD(gpi_port, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(gpi_debounce, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_READER_TEMPERATURE:
        PARAM_TREE_ADD(temperature, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_LINK_MONITOR_CONFIGURATION:
        PARAM_TREE_ADD(impinj_link_monitor_mode, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(link_down_thresh, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_REPORT_BUFFER_CONFIGURATION:
        PARAM_TREE_ADD(impinj_report_buff_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_BLOCK_WRITE_WORD_COUNT:
        PARAM_TREE_ADD(word_count, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK:
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(mb, 1, ENC_NA);
        PARAM_TREE_ADD(block_pointer, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(block_mask, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_BLOCK_PERMALOCK_OPSPEC_RESULT:
        PARAM_TREE_ADD(permalock_result, 1, ENC_NA);
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS:
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(mb, 1, ENC_NA);
        PARAM_TREE_ADD(block_pointer, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(block_range, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GET_BLOCK_PERMALOCK_STATUS_OPSPEC_RESULT:
        PARAM_TREE_ADD(block_permalock_result, 1, ENC_NA);
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_SET_QT_CONFIG:
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(impinj_data_profile, 1, ENC_NA);
        PARAM_TREE_ADD(impinj_access_range, 1, ENC_NA);
        PARAM_TREE_ADD(impinj_persistence, 1, ENC_NA);
        PARAM_TREE_ADD(rfu, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_SET_QT_CONFIG_OPSPEC_RESULT:
        PARAM_TREE_ADD(set_qt_config_result, 1, ENC_NA);
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GET_QT_CONFIG:
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GET_QT_CONFIG_OPSPEC_RESULT:
        PARAM_TREE_ADD(get_qt_config_result, 1, ENC_NA);
        PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(impinj_data_profile, 1, ENC_NA);
        PARAM_TREE_ADD(impinj_access_range, 1, ENC_NA);
        PARAM_TREE_ADD(rfu, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_SERIALIZED_TID:
        PARAM_TREE_ADD(impinj_serialized_tid_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_RF_PHASE_ANGLE:
        PARAM_TREE_ADD(impinj_rf_phase_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_PEAK_RSSI:
        PARAM_TREE_ADD(impinj_peak_rssi_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_GPS_COORDINATES:
        PARAM_TREE_ADD(impinj_gps_coordinates_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_SERIALIZED_TID:
        PARAM_TREE_ADD(impinj_tid, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_RF_PHASE_ANGLE:
        PARAM_TREE_ADD(phase_angle, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_PEAK_RSSI:
        PARAM_TREE_ADD(rssi, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GPS_COORDINATES:
        PARAM_TREE_ADD(latitude, 4, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(longitude, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_LOOP_SPEC:
        PARAM_TREE_ADD(loop_count, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_GGA_SENTENCE:
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_gga_sentence, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_RMC_SENTENCE:
        suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_rmc_sentence, suboffset);
        break;
    case LLRP_IMPINJ_PARAM_OPSPEC_RETRY_COUNT:
        PARAM_TREE_ADD(retry_count, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ADVANCE_GPO_CONFIG:
        PARAM_TREE_ADD(gpo_port, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(impinj_gpo_mode, 2, ENC_BIG_ENDIAN);
        PARAM_TREE_ADD(gpo_pulse_dur, 4, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_OPTIM_READ:
        PARAM_TREE_ADD(impinj_optim_read_mode, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ACCESS_SPEC_ORDERING:
        PARAM_TREE_ADD(impinj_access_spec_ordering, 2, ENC_BIG_ENDIAN);
        break;
    case LLRP_IMPINJ_PARAM_ENABLE_RF_DOPPLER_FREQ:
        PARAM_TREE_ADD(impinj_rf_doppler_mode, 2, ENC_BIG_ENDIAN);
        break;
    default:
        return suboffset;
        break;
    }
    /* Each custom parameters ends with optional custom parameter, disscect it */
    return dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
}

static guint
dissect_llrp_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset, const guint end)
{
    guint8      has_length;
    guint16     len, type;
    guint       real_len, param_end;
    guint       suboffset;
    guint       num;
    proto_item *ti;
    proto_tree *param_tree;

    while (((gint)(end - offset)) > 0)
    {
        has_length = !(tvb_get_guint8(tvb, offset) & 0x80);

        if (has_length)
        {
            type = tvb_get_ntohs(tvb, offset);
            len = tvb_get_ntohs(tvb, offset + 2);

            if (len < LLRP_TLV_LEN_MIN)
                real_len = LLRP_TLV_LEN_MIN;
            else if (len > tvb_reported_length_remaining(tvb, offset))
                real_len = tvb_reported_length_remaining(tvb, offset);
            else
                real_len = len;

            param_end = offset + real_len;

            ti = proto_tree_add_none_format(tree, hf_llrp_param, tvb,
                    offset, real_len, "TLV Parameter: %s",
                    val_to_str_ext(type, &tlv_type_ext, "Unknown Type: %d"));
            param_tree = proto_item_add_subtree(ti, ett_llrp_param);

            proto_tree_add_item(param_tree, hf_llrp_tlv_type, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            ti = proto_tree_add_item(param_tree, hf_llrp_tlv_len, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            if (len != real_len)
                expert_add_info_format(pinfo, ti, &ei_llrp_invalid_length,
                        "Invalid length field: claimed %u, should be %u.",
                        len, real_len);
            offset += 2;

            suboffset = offset;
            switch(type) {
            case LLRP_TLV_RO_BOUND_SPEC:
            case LLRP_TLV_UHF_CAPABILITIES:
            case LLRP_TLV_ACCESS_COMMAND:
            case LLRP_TLV_TAG_REPORT_DATA:
            case LLRP_TLV_RF_SURVEY_REPORT_DATA:
            case LLRP_TLV_READER_EVENT_NOTI_SPEC:
            case LLRP_TLV_READER_EVENT_NOTI_DATA:
            case LLRP_TLV_C1G2_UHF_RF_MD_TBL:
            case LLRP_TLV_C1G2_TAG_SPEC:
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_UTC_TIMESTAMP:
            case LLRP_TLV_UPTIME:
                PARAM_TREE_ADD(microseconds, 8, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_GENERAL_DEVICE_CAP:
                PARAM_TREE_ADD_STAY(max_supported_antenna, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(can_set_antenna_prop, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(has_utc_clock, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(device_manufacturer, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(model, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_firmware_version, suboffset);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_MAX_RECEIVE_SENSE:
                PARAM_TREE_ADD(max_receive_sense, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_RECEIVE_SENSE_ENTRY:
                PARAM_TREE_ADD(index, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(receive_sense, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_ANTENNA_RCV_SENSE_RANGE:
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(receive_sense_index_min, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(receive_sense_index_max, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_ANTENNA_AIR_PROTO:
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                        hf_llrp_num_protocols, hf_llrp_protocol_id, 1, suboffset);
                break;
            case LLRP_TLV_GPIO_CAPABILITIES:
                PARAM_TREE_ADD(num_gpi, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(num_gpo, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_LLRP_CAPABILITIES:
                PARAM_TREE_ADD_STAY(can_do_survey, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_report_buffer_warning, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(support_client_opspec, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_stateaware, 1, ENC_NA);
                PARAM_TREE_ADD(support_holding, 1, ENC_NA);
                PARAM_TREE_ADD(max_priority_supported, 1, ENC_NA);
                PARAM_TREE_ADD(client_opspec_timeout, 2, ENC_BIG_ENDIAN);
                num = tvb_get_ntohl(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_rospec, 4, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_rospec, 4, ENC_BIG_ENDIAN);
                suboffset += 4;
                num = tvb_get_ntohl(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_spec_per_rospec, 4, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_spec_per_rospec, 4, ENC_BIG_ENDIAN);
                suboffset += 4;
                num = tvb_get_ntohl(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_inventory_per_aispec, 4, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_inventory_per_aispec, 4, ENC_BIG_ENDIAN);
                suboffset += 4;
                num = tvb_get_ntohl(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_accessspec, 4, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_accessspec, 4, ENC_BIG_ENDIAN);
                suboffset += 4;
                num = tvb_get_ntohl(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_opspec_per_accressspec, 4, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_opspec_per_accressspec, 4, ENC_BIG_ENDIAN);
                suboffset += 4;
                break;
            case LLRP_TLV_REGU_CAPABILITIES:
                PARAM_TREE_ADD(country_code, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(comm_standard, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_XMIT_POWER_LEVEL_ENTRY:
                PARAM_TREE_ADD(index, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(transmit_power, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_FREQ_INFORMATION:
                PARAM_TREE_ADD(hopping, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_FREQ_HOP_TABLE:
                PARAM_TREE_ADD(hop_table_id, 1, ENC_NA);
                PARAM_TREE_ADD(rfu, 1, ENC_NA);
                suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                        hf_llrp_num_hops, hf_llrp_frequency, 4, suboffset);
                break;
            case LLRP_TLV_FIXED_FREQ_TABLE:
                suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                        hf_llrp_num_freqs, hf_llrp_frequency, 4, suboffset);
                break;
            case LLRP_TLV_RF_SURVEY_FREQ_CAP:
                PARAM_TREE_ADD(min_freq, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(max_freq, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_RO_SPEC:
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(priority, 1, ENC_NA);
                PARAM_TREE_ADD(cur_state, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_RO_SPEC_START_TRIGGER:
                PARAM_TREE_ADD(rospec_start_trig_type, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_PER_TRIGGER_VAL:
                PARAM_TREE_ADD(offset, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(period, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_GPI_TRIGGER_VAL:
                PARAM_TREE_ADD(gpi_port, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(gpi_event, 1, ENC_NA);
                PARAM_TREE_ADD(timeout, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_RO_SPEC_STOP_TRIGGER:
                PARAM_TREE_ADD(rospec_stop_trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(duration_trig, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_AI_SPEC:
                suboffset = dissect_llrp_item_array(tvb, pinfo, param_tree,
                        hf_llrp_antenna_count, hf_llrp_antenna, 2, suboffset);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_AI_SPEC_STOP:
                PARAM_TREE_ADD(aispec_stop_trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(duration_trig, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_TAG_OBSERV_TRIGGER:
                PARAM_TREE_ADD(trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(rfu, 1, ENC_NA);
                PARAM_TREE_ADD(number_of_tags, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(number_of_attempts, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(t, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(timeout, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_INVENTORY_PARAM_SPEC:
                PARAM_TREE_ADD(inventory_spec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(protocol_id, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_RF_SURVEY_SPEC:
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(start_freq, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(stop_freq, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_RF_SURVEY_SPEC_STOP_TR:
                PARAM_TREE_ADD(stop_trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(duration, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(n_4, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_LOOP_SPEC:
                PARAM_TREE_ADD(loop_count, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_ACCESS_SPEC:
                PARAM_TREE_ADD(accessspec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(protocol_id, 1, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_cur_state, 1, ENC_NA);
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_ACCESS_SPEC_STOP_TRIG:
                PARAM_TREE_ADD(access_stop_trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(operation_count, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_CLIENT_REQ_OP_SPEC:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_CLIENT_REQ_RESPONSE:
                PARAM_TREE_ADD(accessspec_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_LLRP_CONF_STATE_VAL:
                PARAM_TREE_ADD(conf_value, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_IDENT:
                PARAM_TREE_ADD(id_type, 1, ENC_NA);
                num = tvb_get_ntohs(tvb, suboffset);
                PARAM_TREE_ADD(reader_id, 2, ENC_BIG_ENDIAN);
                suboffset += num;
                break;
            case LLRP_TLV_GPO_WRITE_DATA:
                PARAM_TREE_ADD(gpo_port, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(gpo_data, 1, ENC_NA);
                break;
            case LLRP_TLV_KEEPALIVE_SPEC:
                PARAM_TREE_ADD(keepalive_trig_type, 1, ENC_NA);
                PARAM_TREE_ADD(time_iterval, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_ANTENNA_PROPS:
                PARAM_TREE_ADD(antenna_connected, 1, ENC_NA);
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(antenna_gain, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_ANTENNA_CONF:
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_RF_RECEIVER:
                PARAM_TREE_ADD(receiver_sense, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_RF_TRANSMITTER:
                PARAM_TREE_ADD(hop_table_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(channel_idx, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(transmit_power, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_GPI_PORT_CURRENT_STATE:
                PARAM_TREE_ADD(gpi_port, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(gpi_config, 1, ENC_NA);
                PARAM_TREE_ADD(gpi_state, 1, ENC_NA);
                break;
            case LLRP_TLV_EVENTS_AND_REPORTS:
                PARAM_TREE_ADD(hold_events_and_reports, 1, ENC_NA);
                break;
            case LLRP_TLV_RO_REPORT_SPEC:
                PARAM_TREE_ADD(ro_report_trig, 1, ENC_NA);
                PARAM_TREE_ADD(n_2, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_TAG_REPORT_CONTENT_SEL:
                PARAM_TREE_ADD_STAY(enable_rospec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_spec_idx, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_inv_spec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_antenna_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_channel_idx, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_peak_rssi, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_first_seen, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_last_seen, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(enable_seen_count, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(enable_accessspec_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_ACCESS_REPORT_SPEC:
                PARAM_TREE_ADD(access_report_trig, 1, ENC_NA);
                break;
            case LLRP_TLV_EPC_DATA:
                suboffset = dissect_llrp_bit_field(tvb, param_tree, hf_llrp_epc, suboffset);
                break;
            case LLRP_TLV_FREQ_RSSI_LEVEL_ENTRY:
                PARAM_TREE_ADD(frequency, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(bandwidth, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(average_rssi, 1, ENC_NA);
                PARAM_TREE_ADD(peak_rssi, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_EVENT_NOTIF_STATE:
                PARAM_TREE_ADD(event_type, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(notif_state, 1, ENC_NA);
                break;
            case LLRP_TLV_HOPPING_EVENT:
                PARAM_TREE_ADD(hop_table_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(next_chan_idx, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_GPI_EVENT:
                PARAM_TREE_ADD(gpi_port, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(gpi_event, 1, ENC_NA);
                break;
            case LLRP_TLV_RO_SPEC_EVENT:
                PARAM_TREE_ADD(roevent_type, 1, ENC_NA);
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(prem_rospec_id, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_REPORT_BUF_LEVEL_WARN:
                PARAM_TREE_ADD(buffer_full_percentage, 1, ENC_NA);
                break;
            case LLRP_TLV_REPORT_BUF_OVERFLOW_ERR:
                break;
            case LLRP_TLV_READER_EXCEPTION_EVENT:
                suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_message, suboffset);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_RF_SURVEY_EVENT:
                PARAM_TREE_ADD(rfevent_type, 1, ENC_NA);
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(spec_idx, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_AI_SPEC_EVENT:
                PARAM_TREE_ADD(aievent_type, 1, ENC_NA);
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(spec_idx, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_ANTENNA_EVENT:
                PARAM_TREE_ADD(antenna_event_type, 1, ENC_NA);
                PARAM_TREE_ADD(antenna_id, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_CONN_ATTEMPT_EVENT:
                PARAM_TREE_ADD(conn_status, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_CONN_CLOSE_EVENT:
                break;
            case LLRP_TLV_SPEC_LOOP_EVENT:
                PARAM_TREE_ADD(rospec_id, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(loop_count, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_LLRP_STATUS:
                PARAM_TREE_ADD(status_code, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_utf8_parameter(tvb, pinfo, param_tree, hf_llrp_error_desc, suboffset);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_FIELD_ERROR:
                PARAM_TREE_ADD(field_num, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(error_code, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_PARAM_ERROR:
                PARAM_TREE_ADD(parameter_type, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(error_code, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_C1G2_LLRP_CAP:
                PARAM_TREE_ADD_STAY(can_support_block_erase, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_support_block_write, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_support_block_permalock, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_support_tag_recomm, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(can_support_UMI_method2, 1, ENC_NA);
                PARAM_TREE_ADD(can_support_XPC, 1, ENC_NA);
                num = tvb_get_ntohs(tvb, suboffset);
                if(num == LLRP_NO_LIMIT)
                    PARAM_TREE_ADD_SPEC_STAY(uint_format_value, max_num_filter_per_query, 2, num, "No limit (%u)");
                else
                    PARAM_TREE_ADD_STAY(max_num_filter_per_query, 2, ENC_BIG_ENDIAN);
                suboffset += 2;
                break;
            case LLRP_TLV_C1G2_UHF_RF_MD_TBL_ENT:
                PARAM_TREE_ADD(mode_ident, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(DR, 1, ENC_NA);
                PARAM_TREE_ADD(hag_conformance, 1, ENC_NA);
                PARAM_TREE_ADD(mod, 1, ENC_NA);
                PARAM_TREE_ADD(flm, 1, ENC_NA);
                PARAM_TREE_ADD(m, 1, ENC_NA);
                PARAM_TREE_ADD(bdr, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(pie, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(min_tari, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(max_tari, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(step_tari, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_INVENTORY_COMMAND:
                PARAM_TREE_ADD(inventory_state_aware, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_C1G2_FILTER:
                PARAM_TREE_ADD(trunc, 1, ENC_NA);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_C1G2_TAG_INV_MASK:
                PARAM_TREE_ADD(mb, 1, ENC_NA);
                PARAM_TREE_ADD(pointer, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_bit_field(tvb, param_tree, hf_llrp_tag_mask, suboffset);
                break;
            case LLRP_TLV_C1G2_TAG_INV_AWARE_FLTR:
                PARAM_TREE_ADD(aware_filter_target, 1, ENC_NA);
                PARAM_TREE_ADD(aware_filter_action, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_TAG_INV_UNAWR_FLTR:
                PARAM_TREE_ADD(unaware_filter_action, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_RF_CONTROL:
                PARAM_TREE_ADD(mode_idx, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(tari, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_SINGULATION_CTRL:
                PARAM_TREE_ADD(session, 1, ENC_NA);
                PARAM_TREE_ADD(tag_population, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(tag_transit_time, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_C1G2_TAG_INV_AWARE_SING:
                PARAM_TREE_ADD_STAY(sing_i, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(sing_s, 1, ENC_NA);
                PARAM_TREE_ADD(sing_a, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_TARGET_TAG:
                PARAM_TREE_ADD_STAY(mb, 1, ENC_NA);
                PARAM_TREE_ADD(match, 1, ENC_NA);
                PARAM_TREE_ADD(pointer, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_bit_field(tvb, param_tree, hf_llrp_tag_mask, suboffset);
                suboffset = dissect_llrp_bit_field(tvb, param_tree, hf_llrp_tag_data, suboffset);
                break;
            case LLRP_TLV_C1G2_READ:
            case LLRP_TLV_C1G2_BLK_ERASE:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(mb, 1, ENC_NA);
                PARAM_TREE_ADD(word_pointer, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(word_count, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_WRITE:
            case LLRP_TLV_C1G2_BLK_WRITE:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(mb, 1, ENC_NA);
                PARAM_TREE_ADD(word_pointer, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_word_array(tvb, param_tree, hf_llrp_write_data, suboffset);
                break;
            case LLRP_TLV_C1G2_KILL:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(kill_pass, 4, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_RECOMMISSION:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(kill_pass, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD_STAY(kill_3, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(kill_2, 1, ENC_NA);
                PARAM_TREE_ADD(kill_l, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_LOCK:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_parameters(tvb, pinfo, param_tree, suboffset, param_end);
                break;
            case LLRP_TLV_C1G2_LOCK_PAYLOAD:
                PARAM_TREE_ADD(privilege, 1, ENC_NA);
                PARAM_TREE_ADD(data_field, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_BLK_PERMALOCK:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(mb, 1, ENC_NA);
                PARAM_TREE_ADD(block_pointer, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_word_array(tvb, param_tree, hf_llrp_block_mask, suboffset);
                break;
            case LLRP_TLV_C1G2_GET_BLK_PERMALOCK:
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(access_pass, 4, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(mb, 1, ENC_NA);
                PARAM_TREE_ADD(block_pointer, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(block_range, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_EPC_MEMORY_SLCTOR:
                PARAM_TREE_ADD_STAY(enable_crc, 1, ENC_NA);
                PARAM_TREE_ADD_STAY(enable_pc, 1, ENC_NA);
                PARAM_TREE_ADD(enable_xpc, 1, ENC_NA);
                break;
            case LLRP_TLV_C1G2_READ_OP_SPEC_RES:
                PARAM_TREE_ADD(access_result, 1, ENC_NA);
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_word_array(tvb, param_tree, hf_llrp_read_data, suboffset);
                break;
            case LLRP_TLV_C1G2_WRT_OP_SPEC_RES:
            case LLRP_TLV_C1G2_BLK_WRT_OP_SPC_RES:
                PARAM_TREE_ADD(access_result, 1, ENC_NA);
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                PARAM_TREE_ADD(num_words_written, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_KILL_OP_SPEC_RES:
            case LLRP_TLV_C1G2_RECOM_OP_SPEC_RES:
            case LLRP_TLV_C1G2_LOCK_OP_SPEC_RES:
            case LLRP_TLV_C1G2_BLK_ERS_OP_SPC_RES:
            case LLRP_TLV_C1G2_BLK_PRL_OP_SPC_RES:
                PARAM_TREE_ADD(access_result, 1, ENC_NA);
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                break;
            case LLRP_TLV_C1G2_BLK_PRL_STAT_RES:
                PARAM_TREE_ADD(access_result, 1, ENC_NA);
                PARAM_TREE_ADD(opspec_id, 2, ENC_BIG_ENDIAN);
                suboffset = dissect_llrp_word_array(tvb, param_tree, hf_llrp_permlock_status, suboffset);
                break;
            case LLRP_TLV_CUSTOM_PARAMETER:
                num = tvb_get_ntohl(tvb, suboffset);
                PARAM_TREE_ADD(vendor_id, 4, ENC_BIG_ENDIAN);
                switch(num) {
                case LLRP_VENDOR_IMPINJ:
                    suboffset = dissect_llrp_impinj_parameter(tvb, pinfo, param_tree, suboffset, param_end);
                    break;
                }
                break;
            }
            /* Have we decoded exactly the number of bytes declared in the parameter? */
            if(suboffset != param_end) {
                /* Report problem */
                expert_add_info_format(pinfo, param_tree, &ei_llrp_invalid_length,
                        "Incorrect length of parameter: %u bytes decoded, but %u bytes claimed.",
                        suboffset - offset + 4, real_len);
            }
            /* The len field includes the 4-byte parameter header that we've
             * already accounted for in offset */
            offset += real_len - 4;
        }
        else
        {
            type = tvb_get_guint8(tvb, offset) & 0x7F;

            switch (type)
            {
                case LLRP_TV_ANTENNA_ID:
                    real_len = LLRP_TV_LEN_ANTENNA_ID; break;
                case LLRP_TV_FIRST_SEEN_TIME_UTC:
                    real_len = LLRP_TV_LEN_FIRST_SEEN_TIME_UTC; break;
                case LLRP_TV_FIRST_SEEN_TIME_UPTIME:
                    real_len = LLRP_TV_LEN_FIRST_SEEN_TIME_UPTIME; break;
                case LLRP_TV_LAST_SEEN_TIME_UTC:
                    real_len = LLRP_TV_LEN_LAST_SEEN_TIME_UTC; break;
                case LLRP_TV_LAST_SEEN_TIME_UPTIME:
                    real_len = LLRP_TV_LEN_LAST_SEEN_TIME_UPTIME; break;
                case LLRP_TV_PEAK_RSSI:
                    real_len = LLRP_TV_LEN_PEAK_RSSI; break;
                case LLRP_TV_CHANNEL_INDEX:
                    real_len = LLRP_TV_LEN_CHANNEL_INDEX; break;
                case LLRP_TV_TAG_SEEN_COUNT:
                    real_len = LLRP_TV_LEN_TAG_SEEN_COUNT; break;
                case LLRP_TV_RO_SPEC_ID:
                    real_len = LLRP_TV_LEN_RO_SPEC_ID; break;
                case LLRP_TV_INVENTORY_PARAM_SPEC_ID:
                    real_len = LLRP_TV_LEN_INVENTORY_PARAM_SPEC_ID; break;
                case LLRP_TV_C1G2_CRC:
                    real_len = LLRP_TV_LEN_C1G2_CRC; break;
                case LLRP_TV_C1G2_PC:
                    real_len = LLRP_TV_LEN_C1G2_PC; break;
                case LLRP_TV_EPC96:
                    real_len = LLRP_TV_LEN_EPC96; break;
                case LLRP_TV_SPEC_INDEX:
                    real_len = LLRP_TV_LEN_SPEC_INDEX; break;
                case LLRP_TV_CLIENT_REQ_OP_SPEC_RES:
                    real_len = LLRP_TV_LEN_CLIENT_REQ_OP_SPEC_RES; break;
                case LLRP_TV_ACCESS_SPEC_ID:
                    real_len = LLRP_TV_LEN_ACCESS_SPEC_ID; break;
                case LLRP_TV_OP_SPEC_ID:
                    real_len = LLRP_TV_LEN_OP_SPEC_ID; break;
                case LLRP_TV_C1G2_SINGULATION_DET:
                    real_len = LLRP_TV_LEN_C1G2_SINGULATION_DET; break;
                case LLRP_TV_C1G2_XPC_W1:
                    real_len = LLRP_TV_LEN_C1G2_XPC_W1; break;
                case LLRP_TV_C1G2_XPC_W2:
                    real_len = LLRP_TV_LEN_C1G2_XPC_W2; break;
                default:
                    /* ???
                     * No need to mark it, since the hf_llrp_tv_type field
                     * will already show up as 'unknown'. */
                    real_len = 0;
                    break;
            };

            ti = proto_tree_add_none_format(tree, hf_llrp_param, tvb,
                    offset, real_len + 1, "TV Parameter : %s",
                    val_to_str_ext(type, &tv_type_ext, "Unknown Type: %d"));
            param_tree = proto_item_add_subtree(ti, ett_llrp_param);

            proto_tree_add_item(param_tree, hf_llrp_tv_type, tvb,
                    offset, 1, ENC_NA);
            offset++;

            suboffset = offset;
            switch (type)
            {
                case LLRP_TV_ANTENNA_ID:
                    PARAM_TREE_ADD_STAY(antenna_id, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_FIRST_SEEN_TIME_UTC:
                case LLRP_TV_FIRST_SEEN_TIME_UPTIME:
                case LLRP_TV_LAST_SEEN_TIME_UTC:
                case LLRP_TV_LAST_SEEN_TIME_UPTIME:
                    PARAM_TREE_ADD_STAY(microseconds, 8, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_PEAK_RSSI:
                    PARAM_TREE_ADD_STAY(peak_rssi, 1, ENC_NA);
                    break;
                case LLRP_TV_CHANNEL_INDEX:
                    PARAM_TREE_ADD_STAY(channel_idx, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_TAG_SEEN_COUNT:
                    PARAM_TREE_ADD_STAY(tag_count, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_RO_SPEC_ID:
                    PARAM_TREE_ADD_STAY(rospec_id, 4, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_INVENTORY_PARAM_SPEC_ID:
                    PARAM_TREE_ADD_STAY(inventory_spec_id, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_C1G2_CRC:
                    PARAM_TREE_ADD_STAY(crc, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_C1G2_PC:
                    PARAM_TREE_ADD_STAY(pc_bits, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_EPC96:
                    PARAM_TREE_ADD_STAY(epc, 96/8, ENC_NA);
                    break;
                case LLRP_TV_SPEC_INDEX:
                    PARAM_TREE_ADD_STAY(spec_idx, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_CLIENT_REQ_OP_SPEC_RES:
                    PARAM_TREE_ADD_STAY(opspec_id, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_ACCESS_SPEC_ID:
                    PARAM_TREE_ADD_STAY(accessspec_id, 4, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_OP_SPEC_ID:
                    PARAM_TREE_ADD_STAY(opspec_id, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_C1G2_SINGULATION_DET:
                    PARAM_TREE_ADD_STAY(num_coll, 2, ENC_BIG_ENDIAN);
                    PARAM_TREE_ADD_STAY(num_empty, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_C1G2_XPC_W1:
                    PARAM_TREE_ADD_STAY(xpc_w1, 2, ENC_BIG_ENDIAN);
                    break;
                case LLRP_TV_C1G2_XPC_W2:
                    PARAM_TREE_ADD_STAY(xpc_w2, 2, ENC_BIG_ENDIAN);
                    break;
            };
            /* Unlike for TLV's, real_len for TV's doesn't include the standard
             * header length, so just add it straight to the offset. */
            offset += real_len;
        }
    }
    return offset;
}

#undef PARAM_TREE_ADD_STAY
#undef PARAM_TREE_ADD
#undef PARAM_TREE_ADD_SPEC_STAY
#undef PARAM_TREE_ADD_SPEC

static guint
dissect_llrp_impinj_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint8 subtype;

    subtype = tvb_get_guint8(tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (Impinj - %s)",
            val_to_str_ext(subtype, &impinj_msg_subtype_ext, "Unknown Type: %d"));
    proto_tree_add_item(tree, hf_llrp_impinj_msg_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch(subtype) {
    case LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS:
        proto_tree_add_item(tree, hf_llrp_rfu, tvb, offset, 4, ENC_NA);
        offset += 4;
        break;
    case LLRP_IMPINJ_TYPE_ENABLE_EXTENSIONS_RESPONSE:
        /* Just parameters */
        break;
    case LLRP_IMPINJ_TYPE_SAVE_SETTINGS:
        proto_tree_add_item(tree, hf_llrp_save_config, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    case LLRP_IMPINJ_TYPE_SAVE_SETTINGS_RESPONSE:
        /* Just parameters */
        break;
    }
    /* Just return offset, parameters will be dissected by our callee */
    return offset;
}

static void
dissect_llrp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint16 type, guint offset)
{
    gboolean    ends_with_parameters;
    guint8      requested_data;
    guint16     antenna_id, gpi_port, gpo_port;
    guint32     spec_id, vendor;
    proto_item *request_item, *antenna_item, *gpi_item, *gpo_item;
    guint (*dissect_custom_message)(tvbuff_t *tvb,
            packet_info *pinfo, proto_tree *tree, guint offset) = NULL;

    ends_with_parameters = FALSE;
    switch (type)
    {
        /* Simple cases just have normal TLV or TV parameters */
        case LLRP_TYPE_CLOSE_CONNECTION_RESPONSE:
        case LLRP_TYPE_GET_READER_CAPABILITIES_RESPONSE:
        case LLRP_TYPE_ADD_ROSPEC:
        case LLRP_TYPE_ADD_ROSPEC_RESPONSE:
        case LLRP_TYPE_DELETE_ROSPEC_RESPONSE:
        case LLRP_TYPE_START_ROSPEC_RESPONSE:
        case LLRP_TYPE_STOP_ROSPEC_RESPONSE:
        case LLRP_TYPE_ENABLE_ROSPEC_RESPONSE:
        case LLRP_TYPE_DISABLE_ROSPEC_RESPONSE:
        case LLRP_TYPE_GET_ROSPECS_RESPONSE:
        case LLRP_TYPE_ADD_ACCESSSPEC:
        case LLRP_TYPE_ADD_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_DELETE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_ENABLE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_DISABLE_ACCESSSPEC_RESPONSE:
        case LLRP_TYPE_GET_ACCESSSPECS:
        case LLRP_TYPE_CLIENT_REQUEST_OP:
        case LLRP_TYPE_CLIENT_RESQUEST_OP_RESPONSE:
        case LLRP_TYPE_RO_ACCESS_REPORT:
        case LLRP_TYPE_READER_EVENT_NOTIFICATION:
        case LLRP_TYPE_ERROR_MESSAGE:
        case LLRP_TYPE_GET_READER_CONFIG_RESPONSE:
        case LLRP_TYPE_SET_READER_CONFIG_RESPONSE:
        case LLRP_TYPE_SET_PROTOCOL_VERSION_RESPONSE:
        case LLRP_TYPE_GET_ACCESSSPECS_RESPONSE:
        case LLRP_TYPE_GET_REPORT:
        case LLRP_TYPE_ENABLE_EVENTS_AND_REPORTS:
            ends_with_parameters = TRUE;
            break;
        /* Some just have an ROSpec ID */
        case LLRP_TYPE_START_ROSPEC:
        case LLRP_TYPE_STOP_ROSPEC:
        case LLRP_TYPE_ENABLE_ROSPEC:
        case LLRP_TYPE_DISABLE_ROSPEC:
        case LLRP_TYPE_DELETE_ROSPEC:
            spec_id = tvb_get_ntohl(tvb, offset);
            if (spec_id == LLRP_ROSPEC_ALL)
                proto_tree_add_uint_format(tree, hf_llrp_rospec, tvb,
                        offset, 4, spec_id, "All ROSpecs (%u)", spec_id);
            else
                proto_tree_add_item(tree, hf_llrp_rospec, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        /* Some just have an AccessSpec ID */
        case LLRP_TYPE_ENABLE_ACCESSSPEC:
        case LLRP_TYPE_DELETE_ACCESSSPEC:
        case LLRP_TYPE_DISABLE_ACCESSSPEC:
            spec_id = tvb_get_ntohl(tvb, offset);
            if (spec_id == LLRP_ACCESSSPEC_ALL)
                proto_tree_add_uint_format(tree, hf_llrp_accessspec, tvb,
                        offset, 4, spec_id, "All Access Specs (%u)", spec_id);
            else
                proto_tree_add_item(tree, hf_llrp_accessspec, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case LLRP_TYPE_GET_READER_CAPABILITIES:
            proto_tree_add_item(tree, hf_llrp_req_cap, tvb, offset, 1, ENC_NA);
            offset++;
            ends_with_parameters = TRUE;
            break;
        /* GET_READER_CONFIG is more complicated */
        case LLRP_TYPE_GET_READER_CONFIG:
            antenna_id = tvb_get_ntohs(tvb, offset);
            if (antenna_id == LLRP_ANTENNA_ALL)
                antenna_item = proto_tree_add_uint_format(tree, hf_llrp_antenna_id, tvb,
                        offset, 2, antenna_id, "All Antennas (%u)", antenna_id);
            else
                antenna_item = proto_tree_add_item(tree, hf_llrp_antenna_id, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            requested_data = tvb_get_guint8(tvb, offset);
            request_item = proto_tree_add_item(tree, hf_llrp_req_conf, tvb,
                    offset, 1, ENC_NA);
            offset++;

            gpi_port = tvb_get_ntohs(tvb, offset);
            if (gpi_port == LLRP_GPI_PORT_ALL)
                gpi_item = proto_tree_add_uint_format(tree, hf_llrp_gpi_port, tvb,
                        offset, 2, gpi_port, "All GPI Ports (%u)", gpi_port);
            else
                gpi_item = proto_tree_add_item(tree, hf_llrp_gpi_port, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            gpo_port = tvb_get_ntohs(tvb, offset);
            if (gpo_port == LLRP_GPO_PORT_ALL)
                gpo_item = proto_tree_add_uint_format(tree, hf_llrp_gpo_port, tvb,
                        offset, 2, gpo_port, "All GPO Ports (%u)", gpo_port);
            else
                gpo_item = proto_tree_add_item(tree, hf_llrp_gpo_port, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            switch (requested_data)
            {
                case LLRP_CONF_ALL:
                    break;
                case LLRP_CONF_ANTENNA_PROPERTIES:
                case LLRP_CONF_ANTENNA_CONFIGURATION:
                    /* Ignore both GPI and GPO ports */
                    proto_item_append_text(gpi_item, " (Ignored)");
                    proto_item_append_text(gpo_item, " (Ignored)");
                    break;
                case LLRP_CONF_IDENTIFICATION:
                case LLRP_CONF_RO_REPORT_SPEC:
                case LLRP_CONF_READER_EVENT_NOTIFICATION_SPEC:
                case LLRP_CONF_ACCESS_REPORT_SPEC:
                case LLRP_CONF_LLRP_CONFIGURATION_STATE:
                case LLRP_CONF_KEEPALIVE_SPEC:
                case LLRP_CONF_EVENTS_AND_REPORTS:
                    /* Ignore antenna ID */
                    proto_item_append_text(antenna_item, " (Ignored)");
                    /* Ignore both GPI and GPO ports */
                    proto_item_append_text(gpi_item, " (Ignored)");
                    proto_item_append_text(gpo_item, " (Ignored)");
                    break;
                case LLRP_CONF_GPI_PORT_CURRENT_STATE:
                    /* Ignore antenna ID */
                    proto_item_append_text(antenna_item, " (Ignored)");
                    /* Ignore GPO port */
                    proto_item_append_text(gpo_item, " (Ignored)");
                    break;
                case LLRP_CONF_GPO_WRITE_DATA:
                    /* Ignore antenna ID */
                    proto_item_append_text(antenna_item, " (Ignored)");
                    /* Ignore GPI port */
                    proto_item_append_text(gpi_item, " (Ignored)");
                    break;
                default:
                    /* Ignore antenna ID */
                    proto_item_append_text(antenna_item, " (Ignored)");
                    /* Tell the user that we are confused */
                    expert_add_info_format(pinfo, request_item, &ei_llrp_req_conf,
                            "Unrecognized configuration request: %u",
                            requested_data);
                    /* Ignore both GPI and GPO ports */
                    proto_item_append_text(gpi_item, " (Ignored)");
                    proto_item_append_text(gpo_item, " (Ignored)");
                    break;
            };
            ends_with_parameters = TRUE;
            break;
        /* END GET_READER_CONFIG */
        /* Misc */
        case LLRP_TYPE_SET_READER_CONFIG:
            proto_tree_add_item(tree, hf_llrp_rest_fact, tvb, offset, 1, ENC_NA);
            offset++;
            ends_with_parameters = TRUE;
            break;
        case LLRP_TYPE_SET_PROTOCOL_VERSION:
            proto_tree_add_item(tree, hf_llrp_version, tvb, offset, 1, ENC_NA);
            break;
        case LLRP_TYPE_GET_SUPPORTED_VERSION_RESPONSE:
            proto_tree_add_item(tree, hf_llrp_cur_ver, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_llrp_sup_ver, tvb, offset, 1, ENC_NA);
            offset++;
            ends_with_parameters = TRUE;
            break;
        case LLRP_TYPE_CUSTOM_MESSAGE:
            vendor = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(tree, hf_llrp_vendor, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            /* Do vendor specific dissection */
            switch(vendor) {
            case LLRP_VENDOR_IMPINJ:
                dissect_custom_message = dissect_llrp_impinj_message;
                ends_with_parameters = TRUE;
                break;
            }
            if (dissect_custom_message)
                offset = dissect_custom_message(tvb, pinfo, tree, offset);
            break;
        /* Some have no extra data expected */
        case LLRP_TYPE_KEEPALIVE:
        case LLRP_TYPE_KEEPALIVE_ACK:
        case LLRP_TYPE_CLOSE_CONNECTION:
        case LLRP_TYPE_GET_ROSPECS:
        case LLRP_TYPE_GET_SUPPORTED_VERSION:
            break;
        default:
            /* We shouldn't be called if we don't already recognize the value */
            DISSECTOR_ASSERT_NOT_REACHED();
    };
    if(ends_with_parameters) {
        offset = dissect_llrp_parameters(tvb, pinfo, tree, offset, tvb_reported_length(tvb));
    }
    if(tvb_reported_length_remaining(tvb, offset) != 0) {
        /* Report problem */
        expert_add_info_format(pinfo, tree, &ei_llrp_invalid_length,
                "Incorrect length of message: %u bytes decoded, but %u bytes available.",
                offset, tvb_reported_length(tvb));
    }
}

/* Code to actually dissect the packets */
static int
dissect_llrp_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *llrp_tree;
    guint16     type;
    guint32     len;
    guint       offset = 0;

    /* Check that there's enough data */
    DISSECTOR_ASSERT(tvb_reported_length(tvb) >= LLRP_HEADER_LENGTH);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLRP");

    col_set_str(pinfo->cinfo, COL_INFO, "LLRP Message");

    type = tvb_get_ntohs(tvb, offset) & 0x03FF;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_ext(type, &message_types_ext, "Unknown Type: %d"));

    ti = proto_tree_add_item(tree, proto_llrp, tvb, offset, -1, ENC_NA);
    llrp_tree = proto_item_add_subtree(ti, ett_llrp);

    proto_tree_add_item(llrp_tree, hf_llrp_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(llrp_tree, hf_llrp_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ti = proto_tree_add_item(llrp_tree, hf_llrp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    len = tvb_get_ntohl(tvb, offset);
    if (len != tvb_reported_length(tvb))
    {
        expert_add_info_format(pinfo, ti, &ei_llrp_invalid_length,
                               "Incorrect length field: claimed %u, but have %u.",
                               len, tvb_reported_length(tvb));
    }
    offset += 4;

    proto_tree_add_item(llrp_tree, hf_llrp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (try_val_to_str_ext(type, &message_types_ext))
        dissect_llrp_message(tvb, pinfo, llrp_tree, type, offset);

    return tvb_length(tvb);
}

/* Determine length of LLRP message */
static guint
get_llrp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    /* Peek into the header to determine the total message length */
    return (guint)tvb_get_ntohl(tvb, offset+2);
}

/* The main dissecting routine */
static int
dissect_llrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LLRP_HEADER_LENGTH,
        get_llrp_message_len, dissect_llrp_packet, data);
    return tvb_length(tvb);
}

void
proto_register_llrp(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details */
    static hf_register_info hf[] = {
        { &hf_llrp_version,
        { "Version", "llrp.version", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0x1C,
          NULL, HFILL }},

        { &hf_llrp_type,
        { "Type", "llrp.type", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &message_types_ext, 0x03FF,
          NULL, HFILL }},

        { &hf_llrp_length,
        { "Length", "llrp.length", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_id,
        { "ID", "llrp.id", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_cur_ver,
        { "Current Version", "llrp.cur_ver", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0,
          NULL, HFILL }},

        { &hf_llrp_sup_ver,
        { "Supported Version", "llrp.sup_ver", FT_UINT8, BASE_DEC, VALS(llrp_versions), 0,
          "The max supported protocol version.", HFILL }},

        { &hf_llrp_req_cap,
        { "Requested Capabilities", "llrp.req_cap", FT_UINT8, BASE_DEC, VALS(capabilities_request), 0,
          NULL, HFILL }},

        { &hf_llrp_req_conf,
        { "Requested Configuration", "llrp.req_conf", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &config_request_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_rospec,
        { "ROSpec ID", "llrp.rospec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_antenna_id,
        { "Antenna ID", "llrp.antenna_id", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpi_port,
        { "GPI Port Number", "llrp.gpi_port", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpo_port,
        { "GPO Port Number", "llrp.gpo_port", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rest_fact,
        { "Restore Factory Settings", "llrp.rest_fact", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_accessspec,
        { "Access Spec ID", "llrp.accessspec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_vendor,
        { "Vendor ID", "llrp.vendor", FT_UINT32, BASE_DEC, VALS(llrp_vendors), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_msg_type,
        { "Subtype", "llrp.impinj.type", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &impinj_msg_subtype_ext, 0,
          "Subtype specified by vendor", HFILL }},

        { &hf_llrp_tlv_type,
        { "Type", "llrp.tlv_type", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &tlv_type_ext, 0x03FF,
          "The type of TLV.", HFILL }},

        { &hf_llrp_tv_type,
        { "Type", "llrp.tv_type", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &tv_type_ext, 0x7F,
          "The type of TV.", HFILL }},

        { &hf_llrp_tlv_len,
        { "Length", "llrp.tlv_len", FT_UINT16, BASE_DEC, NULL, 0,
          "The length of this TLV.", HFILL }},

        { &hf_llrp_param,
        { "Parameter", "llrp.param", FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_gpi,
        { "Number of GPI ports", "llrp.param.num_gpi", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_gpo,
        { "Number of GPO ports", "llrp.param.num_gpo", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_microseconds,
        { "Microseconds", "llrp.param.microseconds", FT_UINT64, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_supported_antenna,
        { "Max number of antenna supported", "llrp.param.max_supported_antenna", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_can_set_antenna_prop,
        { "Can set antenna properties", "llrp.param.can_set_antenna_prop", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
          NULL, HFILL }},

        { &hf_llrp_has_utc_clock,
        { "Has UTC clock capabilities", "llrp.param.has_utc_clock", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
          NULL, HFILL }},

        { &hf_llrp_device_manufacturer,
        { "Device manufacturer name", "llrp.param.device_manufacturer", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_model,
        { "Model name", "llrp.param.model", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_firmware_version,
        { "Reader firmware version", "llrp.param.firmware_version", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_receive_sense,
        { "Maximum sensitivity value", "llrp.param.max_receive_sense", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_index,
        { "Index", "llrp.param.index", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_receive_sense,
        { "Receive sensitivity value", "llrp.param.receive_sense", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_receive_sense_index_min,
        { "Receive sensitivity index min", "llrp.param.receive_sense_index_min", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_receive_sense_index_max,
        { "Receive sensitivity index max", "llrp.param.receive_sense_index_max", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_protocols,
        { "Number of protocols", "llrp.param.num_protocols", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_protocol_id,
        { "Protocol ID", "llrp.param.protocol_id", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(protocol_id), 0,
          NULL, HFILL }},

        { &hf_llrp_can_do_survey,
        { "Can do RF survey", "llrp.param.can_do_survey", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_can_report_buffer_warning,
        { "Can report buffer fill warning", "llrp.param.can_report_buffer_warning", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
          NULL, HFILL }},

        { &hf_llrp_support_client_opspec,
        { "Support client request OpSpec", "llrp.param.support_client_opspec", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
          NULL, HFILL }},

        { &hf_llrp_can_stateaware,
        { "Can do tag inventory state aware singulation", "llrp.param.can_stateaware", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
          NULL, HFILL }},

        { &hf_llrp_support_holding,
        { "Support event and report holding", "llrp.param.support_holding", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
          NULL, HFILL }},

        { &hf_llrp_max_priority_supported,
        { "Max priority level supported", "llrp.param.max_priority_supported", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_client_opspec_timeout,
        { "Client request OpSpec timeout", "llrp.param.client_opspec_timeout", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_num_rospec,
        { "Maximum number of ROSpecs", "llrp.param.max_num_rospec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_num_spec_per_rospec,
        { "Maximum number of spec per ROSpec", "llrp.param.max_num_spec_per_rospec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_num_inventory_per_aispec,
        { "Maximum number of Inventory Spec per AISpec", "llrp.param.max_num_inventory_per_aispec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_num_accessspec,
        { "Maximum number of AccessSpec", "llrp.param.max_num_accessspec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_num_opspec_per_accressspec,
        { "Maximum number of OpSpec per AccessSpec", "llrp.param.max_num_opspec_per_accressspec", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        /* TODO add translation */
        { &hf_llrp_country_code,
        { "Contry code", "llrp.param.country_code", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_comm_standard,
        { "Communication standard", "llrp.param.comm_standard", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &comm_standard_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_transmit_power,
        { "Transmit power value", "llrp.param.transmit_power", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_hopping,
        { "Hopping", "llrp.param.hopping", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_hop_table_id,
        { "Hop table ID", "llrp.param.hop_table_id", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rfu,
        { "Reserved for future use", "llrp.param.rfu", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_hops,
        { "Number of hops", "llrp.param.num_hops", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_frequency,
        { "Frequency", "llrp.param.frequency", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_freqs,
        { "Number of frequencies", "llrp.param.num_freqs", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_min_freq,
        { "Minimum frequency", "llrp.param.min_freq", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_freq,
        { "Maximum frequency", "llrp.param.max_freq", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rospec_id,
        { "ROSpec ID", "llrp.param.rospec_id", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_priority,
        { "Priority", "llrp.param.priority", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_cur_state,
        { "Current state", "llrp.param.cur_state", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rospec_start_trig_type,
        { "ROSpec start trigger type", "llrp.param.rospec_start_trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_offset,
        { "Offset", "llrp.param.offset", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_period,
        { "Period", "llrp.param.period", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpi_event,
        { "GPI event", "llrp.param.gpi_event", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_timeout,
        { "Timeout", "llrp.param.timeout", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rospec_stop_trig_type,
        { "ROSpec stop trigger type", "llrp.param.rospec_stop_trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_duration_trig,
        { "Duration trigger value", "llrp.param.duration_trig", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_antenna_count,
        { "Antenna count", "llrp.param.antenna_count", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_antenna,
        { "Antenna ID", "llrp.param.antenna", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_aispec_stop_trig_type,
        { "AISpec stop trigger type", "llrp.param.aispec_stop_trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_trig_type,
        { "Trigger type", "llrp.param.trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_number_of_tags,
        { "Number of tags", "llrp.param.number_of_tags", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_number_of_attempts,
        { "Number of attempts", "llrp.param.number_of_attempts", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_t,
        { "T", "llrp.param.t", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_inventory_spec_id,
        { "Inventory parameter spec id", "llrp.param.inventory_spec_id", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_start_freq,
        { "Start frequency", "llrp.param.start_freq", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_stop_freq,
        { "Stop frequency", "llrp.param.stop_freq", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_stop_trig_type,
        { "Stop trigger type", "llrp.param.stop_trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_n_4,
        { "N", "llrp.param.n_4", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_duration,
        { "Duration", "llrp.param.duration", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_accessspec_id,
        { "AccessSpec ID", "llrp.param.accessspec_id", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_access_cur_state,
        { "Current state", "llrp.param.access_cur_state", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_access_stop_trig_type,
        { "AccessSpec Stop trigger", "llrp.param.access_stop_trig_type", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_operation_count,
        { "Operation count value", "llrp.param.operation_count", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_opspec_id,
        { "OpSpec ID", "llrp.param.opspec_id", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_conf_value,
        { "Configuration value", "llrp.param.conf_value", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_id_type,
        { "ID type", "llrp.param.id_type", FT_UINT8, BASE_DEC, VALS(id_type), 0,
          NULL, HFILL }},

        { &hf_llrp_reader_id,
        { "Reader ID", "llrp.param.reader_id", FT_UINT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpo_data,
        { "GPO data", "llrp.param.gpo_data", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_keepalive_trig_type,
        { "KeepAlive trigger type", "llrp.param.keepalive_trig_type", FT_UINT8, BASE_DEC, VALS(keepalive_type), 0,
          NULL, HFILL }},

        { &hf_llrp_time_iterval,
        { "Time interval", "llrp.param.time_iterval", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_antenna_connected,
        { "Antenna connected", "llrp.param.antenna_connected", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_antenna_gain,
        { "Antenna gain", "llrp.param.antenna_gain", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_receiver_sense,
        { "Receiver sensitivity", "llrp.param.receiver_sense", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_channel_idx,
        { "Channel index", "llrp.param.channel_idx", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpi_config,
        { "GPI config", "llrp.param.gpi_config", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_gpi_state,
        { "GPI state", "llrp.param.gpi_state", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_hold_events_and_reports,
        { "Hold events and reports upon reconnect", "llrp.param.hold_events_and_reports", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_ro_report_trig,
        { "RO report trigger", "llrp.param.ro_report_trig", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_n_2,
        { "N", "llrp.param.n_2", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_enable_rospec_id,
        { "Enable ROSpec ID", "llrp.param.enable_rospec_id", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
          NULL, HFILL }},

        { &hf_llrp_enable_spec_idx,
        { "Enable spec index", "llrp.param.enable_spec_idx", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
          NULL, HFILL }},

        { &hf_llrp_enable_inv_spec_id,
        { "Enable inventory spec ID", "llrp.param.enable_inv_spec_id", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
          NULL, HFILL }},

        { &hf_llrp_enable_antenna_id,
        { "Enable antenna ID", "llrp.param.enable_antenna_id", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
          NULL, HFILL }},

        { &hf_llrp_enable_channel_idx,
        { "Enable channel index", "llrp.param.enable_channel_idx", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
          NULL, HFILL }},

        { &hf_llrp_enable_peak_rssi,
        { "Enable peak RSSI", "llrp.param.enable_peak_rssi", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
          NULL, HFILL }},

        { &hf_llrp_enable_first_seen,
        { "Enable first seen timestamp", "llrp.param.enable_first_seen", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
          NULL, HFILL }},

        { &hf_llrp_enable_last_seen,
        { "Enable last seen timestamp", "llrp.param.enable_last_seen", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
          NULL, HFILL }},

        { &hf_llrp_enable_seen_count,
        { "Enable tag seen count", "llrp.param.enable_seen_count", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
          NULL, HFILL }},

        { &hf_llrp_enable_accessspec_id,
        { "Enable AccessSpec ID", "llrp.param.enable_accessspec_id", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
          NULL, HFILL }},

        { &hf_llrp_access_report_trig,
        { "Access report trigger", "llrp.param.access_report_trig", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_length_bits,
        { "Bit field length (bits)", "llrp.param.length_bits", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_epc,
        { "EPC", "llrp.param.epc", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_spec_idx,
        { "Spec index", "llrp.param.spec_idx", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_peak_rssi,
        { "Peak RSSI", "llrp.param.peak_rssi", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_tag_count,
        { "Tag count", "llrp.param.tag_count", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_bandwidth,
        { "Bandwidth", "llrp.param.bandwidth", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_average_rssi,
        { "Average RSSI", "llrp.param.average_rssi", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_notif_state,
        { "Notification state", "llrp.param.notif_state", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_event_type,
        { "Event type", "llrp.param.event_type", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &event_type_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_next_chan_idx,
        { "Next channel index", "llrp.param.next_chan_idx", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_roevent_type,
        { "Event type", "llrp.param.roevent_type", FT_UINT8, BASE_DEC, VALS(roevent_type), 0,
          NULL, HFILL }},

        { &hf_llrp_prem_rospec_id,
        { "Preempting ROSpec ID", "llrp.param.prem_rospec_id", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_buffer_full_percentage,
        { "Report Buffer percentage full", "llrp.param.buffer_full_percentage", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_message,
        { "Message", "llrp.param.message", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rfevent_type,
        { "Event type", "llrp.param.rfevent_type", FT_UINT8, BASE_DEC, VALS(rfevent_type), 0,
          NULL, HFILL }},

        { &hf_llrp_aievent_type,
        { "Event type", "llrp.param.aievent_type", FT_UINT8, BASE_DEC, VALS(aievent_type), 0,
          NULL, HFILL }},

        { &hf_llrp_antenna_event_type,
        { "Event type", "llrp.param.antenna_event_type", FT_UINT8, BASE_DEC, VALS(antenna_event_type), 0,
          NULL, HFILL }},

        { &hf_llrp_conn_status,
        { "Status", "llrp.param.conn_status", FT_UINT16, BASE_DEC, VALS(connection_status), 0,
          NULL, HFILL }},

        { &hf_llrp_loop_count,
        { "Loop count", "llrp.param.loop_count", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_status_code,
        { "Status code", "llrp.param.status_code", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &status_code_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_error_desc,
        { "Error Description", "llrp.param.error_desc", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_field_num,
        { "Field number", "llrp.param.field_num", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_error_code,
        { "Error code", "llrp.param.error_code", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &status_code_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_parameter_type,
        { "Parameter type", "llrp.param.parameter_type", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &tlv_type_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_can_support_block_erase,
        { "Can support block erase", "llrp.param.can_support_block_erase", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_can_support_block_write,
        { "Can support block write", "llrp.param.can_support_block_write", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
          NULL, HFILL }},

        { &hf_llrp_can_support_block_permalock,
        { "Can support block permalock", "llrp.param.can_support_block_permalock", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
          NULL, HFILL }},

        { &hf_llrp_can_support_tag_recomm,
        { "Can support tag recommisioning", "llrp.param.can_support_tag_recomm", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
          NULL, HFILL }},

        { &hf_llrp_can_support_UMI_method2,
        { "Can support UMI method 2", "llrp.param.can_support_UMI_method2", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
          NULL, HFILL }},

        { &hf_llrp_can_support_XPC,
        { "Can support XPC", "llrp.param.can_support_XPC", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
          NULL, HFILL }},

        { &hf_llrp_max_num_filter_per_query,
        { "Maximum number of select filters per query", "llrp.param.max_num_filter_per_query", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_mode_ident,
        { "Mode identifier", "llrp.param.mode_ident", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_DR,
        { "DR", "llrp.param.DR", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_hag_conformance,
        { "EPC HAG T&C Conformance", "llrp.param.hag_conformance", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
          NULL, HFILL }},

        { &hf_llrp_mod,
        { "M", "llrp.param.mod", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_flm,
        { "Forward link modulation", "llrp.param.flm", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_m,
        { "Spectral mask indicator", "llrp.param.m", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_bdr,
        { "BDR", "llrp.param.bdr", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_pie,
        { "PIE", "llrp.param.pie", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_min_tari,
        { "Minimum tari", "llrp.param.min_tari", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_max_tari,
        { "Maximum tari", "llrp.param.max_tari", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_step_tari,
        { "Tari step", "llrp.param.step_tari", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_inventory_state_aware,
        { "Tag inventory state aware", "llrp.param.inventory_state_aware", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_trunc,
        { "T", "llrp.param.trunc", FT_UINT8, BASE_DEC, NULL, 0xC0,
          NULL, HFILL }},

        { &hf_llrp_mb,
        { "MB", "llrp.param.mb", FT_UINT8, BASE_DEC, NULL, 0xC0,
          NULL, HFILL }},

        { &hf_llrp_pointer,
        { "Pointer", "llrp.param.pointer", FT_UINT16, BASE_DEC_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_tag_mask,
        { "Tag mask", "llrp.param.tag_mask", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_aware_filter_target,
        { "Target", "llrp.param.aware_filter_target", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_aware_filter_action,
        { "Action", "llrp.param.aware_filter_action", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_unaware_filter_action,
        { "Action", "llrp.param.unaware_filter_action", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_mode_idx,
        { "Mode index", "llrp.param.mode_idx", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_tari,
        { "Tari", "llrp.param.tari", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_session,
        { "Session", "llrp.param.session", FT_UINT8, BASE_DEC, NULL, 0xC0,
          NULL, HFILL }},

        { &hf_llrp_tag_population,
        { "Tag population", "llrp.param.tag_population", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_tag_transit_time,
        { "Tag tranzit time", "llrp.param.tag_transit_time", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_sing_i,
        { "I", "llrp.param.sing_i", FT_BOOLEAN, 8, TFS(&tfs_state_a_b), 0x80,
          NULL, HFILL }},

        { &hf_llrp_sing_s,
        { "S", "llrp.param.sing_s", FT_BOOLEAN, 8, TFS(&tfs_sl), 0x40,
          NULL, HFILL }},

        { &hf_llrp_sing_a,
        { "S_All", "llrp.param.sing_a", FT_BOOLEAN, 8, TFS(&tfs_all_no), 0x20,
          NULL, HFILL }},

        { &hf_llrp_match,
        { "Match", "llrp.param.match", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
          NULL, HFILL }},

        { &hf_llrp_tag_data,
        { "Tag data", "llrp.param.tag_data", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_access_pass,
        { "Access password", "llrp.param.access_pass", FT_UINT32, BASE_DEC_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_word_pointer,
        { "Word pointer", "llrp.param.word_pointer", FT_UINT16, BASE_DEC_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_word_count,
        { "Word count", "llrp.param.word_count", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_write_data,
        { "Write data", "llrp.param.write_data", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_kill_pass,
        { "Killpassword", "llrp.param.kill_pass", FT_UINT32, BASE_DEC_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_kill_3,
        { "3", "llrp.param.kill_3", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
          NULL, HFILL }},

        { &hf_llrp_kill_2,
        { "2", "llrp.param.kill_2", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
          NULL, HFILL }},

        { &hf_llrp_kill_l,
        { "L", "llrp.param.kill_l", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
          NULL, HFILL }},

        { &hf_llrp_privilege,
        { "Privilege", "llrp.param.privilege", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_data_field,
        { "Data field", "llrp.param.data_field", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_block_pointer,
        { "Block pointer", "llrp.param.block_pointer", FT_UINT16, BASE_DEC_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_block_mask,
        { "Block mask", "llrp.param.block_mask", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_length_words,
        { "Field Length (words)", "llrp.param.length_words", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_block_range,
        { "Block range", "llrp.param.block_range", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_enable_crc,
        { "Enable CRC", "llrp.param.enable_crc", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_enable_pc,
        { "Enable PC bits", "llrp.param.enable_pc", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
          NULL, HFILL }},

        { &hf_llrp_enable_xpc,
        { "Enable XPC bits", "llrp.param.enable_xpc", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
          NULL, HFILL }},

        { &hf_llrp_pc_bits,
        { "PC bits", "llrp.param.pc_bits", FT_UINT16, BASE_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_xpc_w1,
        { "XPC-W1", "llrp.param.xpc_w1", FT_UINT16, BASE_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_xpc_w2,
        { "XPC-W2", "llrp.param.xpc_w2", FT_UINT16, BASE_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_crc,
        { "CRC", "llrp.param.crc", FT_UINT16, BASE_HEX, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_coll,
        { "Number of collisions", "llrp.param.num_coll", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_empty,
        { "Number of empty slots", "llrp.param.num_empty", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_access_result,
        { "Result", "llrp.param.access_result", FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_read_data,
        { "Read data", "llrp.param.read_data", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_num_words_written,
        { "Number of words written", "llrp.param.num_words_written", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_permlock_status,
        { "Read data", "llrp.param.permlock_status", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_vendor_id,
        { "Vendor ID", "llrp.param.vendor_id", FT_UINT32, BASE_DEC, VALS(llrp_vendors), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_param_type,
        { "Impinj parameter subtype", "llrp.param.impinj_param_type", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &impinj_param_type_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_save_config,
        { "Save configuration", "llrp.param.save_config", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
          NULL, HFILL }},

        { &hf_llrp_impinj_req_data,
        { "Requested data", "llrp.param.impinj_req_data", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &impinj_req_data_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_reg_region,
        { "Regulatory region", "llrp.param.impinj_reg_region", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &impinj_reg_region_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_search_mode,
        { "Inventory search mode", "llrp.param.impinj_search_mode", FT_UINT16, BASE_DEC, VALS(impinj_search_mode), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_en_tag_dir,
        { "Enable tag direction", "llrp.param.impinj_en_tag_dir", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
          NULL, HFILL }},

        { &hf_llrp_impinj_antenna_conf,
        { "Antenna configuration", "llrp.param.impinj_antenna_conf", FT_UINT16, BASE_DEC, VALS(impinj_ant_conf), 0,
          NULL, HFILL }},

        { &hf_llrp_decision_time,
        { "Decision timestamp", "llrp.param.decision_time", FT_UINT64, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_tag_dir,
        { "Tag direction", "llrp.param.impinj_tag_dir", FT_UINT16, BASE_DEC, VALS(impinj_tag_dir), 0,
          NULL, HFILL }},

        { &hf_llrp_confidence,
        { "Confidence", "llrp.param.confidence", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_fix_freq_mode,
        { "Fixed frequency mode", "llrp.param.impinj_fix_freq_mode", FT_UINT16, BASE_DEC, VALS(impinj_fix_freq_mode), 0,
          NULL, HFILL }},

        { &hf_llrp_num_channels,
        { "Number of channels", "llrp.param.num_channels", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_channel,
        { "Channel", "llrp.param.channel", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_reduce_power_mode,
        { "Recuced power mode", "llrp.param.impinj_reduce_power_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_low_duty_mode,
        { "Low duty cycle mode", "llrp.param.impinj_low_duty_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_empty_field_timeout,
        { "Empty field timeout", "llrp.param.empty_field_timeout", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_field_ping_interval,
        { "Field ping interval", "llrp.param.field_ping_interval", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_model_name,
        { "Model name", "llrp.param.model_name", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_serial_number,
        { "Serial number", "llrp.param.serial_number", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_soft_ver,
        { "Softwave version", "llrp.param.soft_ver", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_firm_ver,
        { "Firmware version", "llrp.param.firm_ver", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_fpga_ver,
        { "FPGA version", "llrp.param.fpga_ver", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_pcba_ver,
        { "PCBA version", "llrp.param.pcba_ver", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_height_thresh,
        { "Height threshold", "llrp.param.height_thresh", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_zero_motion_thresh,
        { "Zero motion threshold", "llrp.param.zero_motion_thresh", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_board_manufacturer,
        { "Board manufacturer", "llrp.param.board_manufacturer", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_fw_ver_hex,
        { "Firmware version", "llrp.param.fw_ver_hex", FT_UINT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_hw_ver_hex,
        { "Hardware version", "llrp.param.hw_ver_hex", FT_UINT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gpi_debounce,
        { "GPI debounce timer Msec", "llrp.param.gpi_debounce", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_temperature,
        { "Temperature", "llrp.param.temperature", FT_INT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_link_monitor_mode,
        { "Link monitor mode", "llrp.param.impinj_link_monitor_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_link_down_thresh,
        { "Link down threshold", "llrp.param.link_down_thresh", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_report_buff_mode,
        { "Report buffer mode", "llrp.param.impinj_report_buff_mode", FT_UINT16, BASE_DEC, VALS(impinj_report_buff_mode), 0,
          NULL, HFILL }},

        { &hf_llrp_permalock_result,
        { "Result", "llrp.param.permalock_result", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &impinj_permalock_result_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_block_permalock_result,
        { "Result", "llrp.param.block_permalock_result", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &impinj_block_permalock_result_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_data_profile,
        { "Data profile", "llrp.param.impinj_data_profile", FT_UINT8, BASE_DEC, VALS(impinj_data_profile), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_access_range,
        { "Access range", "llrp.param.impinj_access_range", FT_UINT8, BASE_DEC, VALS(impinj_access_range), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_persistence,
        { "Persistence", "llrp.param.impinj_persistence", FT_UINT8, BASE_DEC, VALS(impinj_persistence), 0,
          NULL, HFILL }},

        { &hf_llrp_set_qt_config_result,
        { "Result", "llrp.param.set_qt_config_result", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &impinj_set_qt_config_result_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_get_qt_config_result,
        { "Result", "llrp.param.get_qt_config_result", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &impinj_get_qt_config_result_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_serialized_tid_mode,
        { "Serialized TID Mode", "llrp.param.impinj_serialized_tid_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_rf_phase_mode,
        { "RF phase angle mode", "llrp.param.impinj_rf_phase_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_peak_rssi_mode,
        { "Peak RSSI mode", "llrp.param.impinj_peak_rssi_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_gps_coordinates_mode,
        { "GPS coordinates mode", "llrp.param.impinj_gps_coordinates_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_tid,
        { "TID", "llrp.param.impinj_tid", FT_UINT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_phase_angle,
        { "Phase angle", "llrp.param.phase_angle", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rssi,
        { "RSSI", "llrp.param.rssi", FT_INT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_latitude,
        { "Latitude", "llrp.param.latitude", FT_INT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_longitude,
        { "Longitude", "llrp.param.longitude", FT_INT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_gga_sentence,
        { "GGA sentence", "llrp.param.gga_sentence", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_rmc_sentence,
        { "RMC sentence", "llrp.param.rmc_sentence", FT_UINT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_optim_read_mode,
        { "Optimized read mode", "llrp.param.impinj_optim_read_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_rf_doppler_mode,
        { "RF doppler frequency mode", "llrp.param.impinj_rf_doppler_mode", FT_UINT16, BASE_DEC, VALS(impinj_boolean), 0,
          NULL, HFILL }},

        { &hf_llrp_retry_count,
        { "Retry count", "llrp.param.retry_count", FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_access_spec_ordering,
        { "AccessSpec ordering", "llrp.param.impinj_access_spec_ordering", FT_UINT16, BASE_DEC, VALS(impinj_access_spec_ordering), 0,
          NULL, HFILL }},

        { &hf_llrp_impinj_gpo_mode,
        { "GPO mode", "llrp.param.impinj_gpo_mode", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &impinj_gpo_mode_ext, 0,
          NULL, HFILL }},

        { &hf_llrp_gpo_pulse_dur,
        { "GPO pulse duration", "llrp.param.gpo_pulse_dur", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_llrp,
        &ett_llrp_param
    };

    static ei_register_info ei[] = {
        { &ei_llrp_invalid_length, { "llrp.invalid_length_of_string_claimed", PI_MALFORMED, PI_ERROR, "invalid length of string: claimed %u, available %u.", EXPFILL }},
        { &ei_llrp_req_conf, { "llrp.req_conf.invalid", PI_PROTOCOL, PI_ERROR, "Unrecognized configuration request: %u", EXPFILL }},
    };

    expert_module_t* expert_llrp;

    /* Register the protocol name and description */
    proto_llrp = proto_register_protocol("Low Level Reader Protocol",
            "LLRP", "llrp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_llrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_llrp = expert_register_protocol(proto_llrp);
    expert_register_field_array(expert_llrp, ei, array_length(ei));
}

void
proto_reg_handoff_llrp(void)
{
    dissector_handle_t llrp_handle;

    llrp_handle = new_create_dissector_handle(dissect_llrp, proto_llrp);
    dissector_add_uint("tcp.port", LLRP_PORT, llrp_handle);
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
