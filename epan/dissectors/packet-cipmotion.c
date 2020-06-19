/* packet-cipmotion.c
 * Routines for CIP (Common Industrial Protocol) Motion dissection
 * CIP Motion Home: www.odva.org
 *
 * This dissector includes items from:
 *    CIP Volume 9: CIP Motion, Edition 1.5
 *
 * Copyright 2006-2007
 * Benjamin M. Stocks <bmstocks@ra.rockwell.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-cipmotion.h"

#include "packet-cip.h"
#include "packet-enip.h"

void proto_register_cipmotion(void);
/* The entry point to the actual dissection is: dissect_cipmotion */
void proto_reg_handoff_cipmotion(void);

/* Protocol handle for CIP Motion */
static int proto_cipmotion = -1;
static int proto_cipmotion3 = -1;

/* Header field identifiers, these are registered in the
 * proto_register_cipmotion function along with the bites/bytes
 * they represent */
static int hf_cip_format                    = -1;
static int hf_cip_revision                  = -1;
static int hf_cip_class1_seqnum             = -1;
static int hf_configuration_block_format_rev = -1;
static int hf_configuration_block_drive_power_struct_id = -1;
static int hf_cip_updateid                  = -1;
static int hf_cip_instance_cnt              = -1;
static int hf_cip_last_update               = -1;
static int hf_cip_node_status               = -1;
static int hf_cip_node_control              = -1;
static int hf_cip_node_control_remote       = -1;
static int hf_cip_node_control_sync         = -1;
static int hf_cip_node_data_valid           = -1;
static int hf_cip_node_fault_reset          = -1;
static int hf_cip_node_device_faulted       = -1;
static int hf_cip_time_data_set             = -1;
static int hf_cip_time_data_stamp           = -1;
static int hf_cip_time_data_offset          = -1;
static int hf_cip_time_data_diag            = -1;
static int hf_cip_time_data_time_diag       = -1;
static int hf_cip_cont_time_stamp           = -1;
static int hf_cip_cont_time_offset          = -1;
static int hf_cip_devc_time_stamp           = -1;
static int hf_cip_devc_time_offset          = -1;
static int hf_cip_lost_update               = -1;
static int hf_cip_late_update               = -1;
static int hf_cip_data_rx_time_stamp        = -1;
static int hf_cip_data_tx_time_stamp        = -1;
static int hf_cip_node_fltalarms            = -1;
static int hf_cip_motor_cntrl               = -1;
static int hf_cip_feedback                  = -1;
static int hf_cip_feedback_mode             = -1;
static int hf_cip_feedback_data_type        = -1;

static int hf_connection_configuration_bits = -1;
static int hf_connection_configuration_bits_power = -1;
static int hf_connection_configuration_bits_safety_bit_valid = -1;
static int hf_connection_configuration_bits_allow_network_safety = -1;

static int hf_cip_axis_control              = -1;
static int hf_cip_control_status            = -1;
static int hf_cip_control_status_complete   = -1;
static int hf_cip_control_status_bus_up     = -1;
static int hf_cip_control_status_bus_unload = -1;
static int hf_cip_control_status_power_loss = -1;
static int hf_cip_axis_response             = -1;
static int hf_cip_axis_resp_stat            = -1;
static int hf_cip_cmd_data_pos_cmd          = -1;
static int hf_cip_cmd_data_vel_cmd          = -1;
static int hf_cip_cmd_data_acc_cmd          = -1;
static int hf_cip_cmd_data_trq_cmd          = -1;
static int hf_cip_act_data_pos              = -1;
static int hf_cip_act_data_vel              = -1;
static int hf_cip_act_data_acc              = -1;
static int hf_cip_sts_flt                   = -1;
static int hf_cip_sts_alrm                  = -1;
static int hf_cip_sts_sts                   = -1;
static int hf_cip_sts_iosts                 = -1;
static int hf_cip_sts_axis_safety           = -1;
static int hf_cip_intrp                     = -1;
static int hf_cip_position_data_type        = -1;
static int hf_cip_axis_state                = -1;
static int hf_cip_evnt_ctrl_reg1_pos        = -1;
static int hf_cip_evnt_ctrl_reg1_neg        = -1;
static int hf_cip_evnt_ctrl_reg2_pos        = -1;
static int hf_cip_evnt_ctrl_reg2_neg        = -1;
static int hf_cip_evnt_ctrl_reg1_posrearm   = -1;
static int hf_cip_evnt_ctrl_reg1_negrearm   = -1;
static int hf_cip_evnt_ctrl_reg2_posrearm   = -1;
static int hf_cip_evnt_ctrl_reg2_negrearm   = -1;
static int hf_cip_evnt_ctrl_marker_pos      = -1;
static int hf_cip_evnt_ctrl_marker_neg      = -1;
static int hf_cip_evnt_ctrl_home_pos        = -1;
static int hf_cip_evnt_ctrl_home_neg        = -1;
static int hf_cip_evnt_ctrl_home_pp         = -1;
static int hf_cip_evnt_ctrl_home_pm         = -1;
static int hf_cip_evnt_ctrl_home_mp         = -1;
static int hf_cip_evnt_ctrl_home_mm         = -1;
static int hf_cip_evnt_ctrl_acks            = -1;
static int hf_cip_evnt_extend_format        = -1;
static int hf_cip_evnt_sts_reg1_pos         = -1;
static int hf_cip_evnt_sts_reg1_neg         = -1;
static int hf_cip_evnt_sts_reg2_pos         = -1;
static int hf_cip_evnt_sts_reg2_neg         = -1;
static int hf_cip_evnt_sts_reg1_posrearm    = -1;
static int hf_cip_evnt_sts_reg1_negrearm    = -1;
static int hf_cip_evnt_sts_reg2_posrearm    = -1;
static int hf_cip_evnt_sts_reg2_negrearm    = -1;
static int hf_cip_evnt_sts_marker_pos       = -1;
static int hf_cip_evnt_sts_marker_neg       = -1;
static int hf_cip_evnt_sts_home_pos         = -1;
static int hf_cip_evnt_sts_home_neg         = -1;
static int hf_cip_evnt_sts_home_pp          = -1;
static int hf_cip_evnt_sts_home_pm          = -1;
static int hf_cip_evnt_sts_home_mp          = -1;
static int hf_cip_evnt_sts_home_mm          = -1;
static int hf_cip_evnt_sts_nfs              = -1;
static int hf_cip_evnt_sts_stat             = -1;
static int hf_cip_evnt_type                 = -1;
static int hf_cip_svc_code                  = -1;
static int hf_cip_svc_sts                   = -1;
static int hf_cip_svc_set_axis_attr_sts     = -1;
static int hf_cip_svc_get_axis_attr_sts     = -1;
static int hf_cip_svc_transction            = -1;
static int hf_cip_svc_ext_status            = -1;
static int hf_cip_svc_data                  = -1;
static int hf_cip_ptp_grandmaster           = -1;
static int hf_cip_axis_alarm                = -1;
static int hf_cip_axis_fault                = -1;
static int hf_cip_axis_sts_local_ctrl       = -1;
static int hf_cip_axis_sts_alarm            = -1;
static int hf_cip_axis_sts_dc_bus           = -1;
static int hf_cip_axis_sts_pwr_struct       = -1;
static int hf_cip_axis_sts_flux_up          = -1;
static int hf_cip_axis_sts_tracking         = -1;
static int hf_cip_axis_sts_pos_lock         = -1;
static int hf_cip_axis_sts_vel_lock         = -1;
static int hf_cip_axis_sts_vel_standstill   = -1;
static int hf_cip_axis_sts_vel_threshold    = -1;
static int hf_cip_axis_sts_vel_limit        = -1;
static int hf_cip_axis_sts_acc_limit        = -1;
static int hf_cip_axis_sts_dec_limit        = -1;
static int hf_cip_axis_sts_torque_threshold = -1;
static int hf_cip_axis_sts_torque_limit     = -1;
static int hf_cip_axis_sts_cur_limit        = -1;
static int hf_cip_axis_sts_therm_limit      = -1;
static int hf_cip_axis_sts_feedback_integ   = -1;
static int hf_cip_axis_sts_shutdown         = -1;
static int hf_cip_axis_sts_in_process       = -1;
static int hf_cip_axis_sts_dc_bus_unload    = -1;
static int hf_cip_axis_sts_ac_pwr_loss      = -1;
static int hf_cip_axis_sts_pos_cntrl_mode   = -1;
static int hf_cip_axis_sts_vel_cntrl_mode   = -1;
static int hf_cip_axis_sts_trq_cntrl_mode   = -1;

static int hf_cip_axis_status2              = -1;
static int hf_cip_axis_sts2_motor           = -1;
static int hf_cip_axis_sts2_regenerate      = -1;
static int hf_cip_axis_sts2_ride_thru       = -1;
static int hf_cip_axis_sts2_ac_line_sync    = -1;
static int hf_cip_axis_sts2_bus_volt_lock   = -1;
static int hf_cip_axis_sts2_react_pwr_only  = -1;
static int hf_cip_axis_sts2_volt_ctrl_mode  = -1;
static int hf_cip_axis_sts2_pwr_loss        = -1;
static int hf_cip_axis_sts2_ac_volt_sag     = -1;
static int hf_cip_axis_sts2_ac_phase_loss   = -1;
static int hf_cip_axis_sts2_ac_freq_change  = -1;
static int hf_cip_axis_sts2_ac_sync_loss    = -1;
static int hf_cip_axis_sts2_single_phase    = -1;
static int hf_cip_axis_sts2_bus_volt_limit  = -1;
static int hf_cip_axis_sts2_bus_volt_rate_limit = -1;
static int hf_cip_axis_sts2_active_current_rate_limit = -1;
static int hf_cip_axis_sts2_reactive_current_rate_limit = -1;
static int hf_cip_axis_sts2_reactive_pwr_limit = -1;
static int hf_cip_axis_sts2_reactive_pwr_rate_limit = -1;
static int hf_cip_axis_sts2_active_current_limit = -1;
static int hf_cip_axis_sts2_reactive_current_limit = -1;
static int hf_cip_axis_sts2_motor_pwr_limit = -1;
static int hf_cip_axis_sts2_regen_pwr_limit = -1;
static int hf_cip_axis_sts2_convert_therm_limit = -1;

static int hf_cip_cyclic_wrt_data           = -1;
static int hf_cip_cyclic_rd_data            = -1;
static int hf_cip_cyclic_write_blk          = -1;
static int hf_cip_cyclic_read_blk           = -1;
static int hf_cip_cyclic_write_sts          = -1;
static int hf_cip_cyclic_read_sts           = -1;
static int hf_cip_attribute_data            = -1;
static int hf_cip_event_checking            = -1;
static int hf_cip_event_ack                 = -1;
static int hf_cip_event_status              = -1;
static int hf_cip_event_id                  = -1;
static int hf_cip_event_pos                 = -1;
static int hf_cip_event_ts                  = -1;
static int hf_cip_pos_cmd                   = -1;
static int hf_cip_pos_cmd_int               = -1;
static int hf_cip_vel_cmd                   = -1;
static int hf_cip_accel_cmd                 = -1;
static int hf_cip_trq_cmd                   = -1;
static int hf_cip_pos_trim                  = -1;
static int hf_cip_vel_trim                  = -1;
static int hf_cip_accel_trim                = -1;
static int hf_cip_trq_trim                  = -1;
static int hf_cip_act_pos                   = -1;
static int hf_cip_act_pos_64                = -1;
static int hf_cip_act_vel                   = -1;
static int hf_cip_act_accel                 = -1;
static int hf_cip_fault_type                = -1;
static int hf_cip_fault_sub_code            = -1;
static int hf_cip_fault_action              = -1;
static int hf_cip_fault_time_stamp          = -1;
static int hf_cip_alarm_type                = -1;
static int hf_cip_alarm_sub_code            = -1;
static int hf_cip_alarm_state               = -1;
static int hf_cip_alarm_time_stamp          = -1;
static int hf_cip_axis_status               = -1;
static int hf_cip_axis_status_mfg           = -1;
static int hf_cip_axis_io_status            = -1;
static int hf_cip_axis_io_status_mfg        = -1;
static int hf_cip_axis_safety_status        = -1;
static int hf_cip_axis_safety_status_mfg    = -1;
static int hf_cip_axis_safety_state         = -1;
static int hf_cip_cmd_data_set              = -1;
static int hf_cip_act_data_set              = -1;
static int hf_cip_sts_data_set              = -1;
static int hf_cip_group_sync                = -1;
static int hf_cip_command_control           = -1;

static int hf_get_axis_attr_list_attribute_cnt     = -1;
static int hf_get_axis_attr_list_attribute_id      = -1;
static int hf_get_axis_attr_list_dimension         = -1;
static int hf_get_axis_attr_list_element_size      = -1;
static int hf_get_axis_attr_list_start_index       = -1;
static int hf_get_axis_attr_list_data_elements     = -1;
static int hf_set_axis_attr_list_attribute_cnt     = -1;
static int hf_set_axis_attr_list_attribute_id      = -1;
static int hf_set_axis_attr_list_dimension         = -1;
static int hf_set_axis_attr_list_element_size      = -1;
static int hf_set_axis_attr_list_start_index       = -1;
static int hf_set_axis_attr_list_data_elements     = -1;
static int hf_set_cyclic_list_attribute_cnt        = -1;
static int hf_set_cyclic_list_attribute_id         = -1;
static int hf_set_cyclic_list_read_block_id        = -1;
static int hf_set_cyclic_list_attr_sts             = -1;
static int hf_var_devce_instance                   = -1;
static int hf_var_devce_instance_block_size        = -1;
static int hf_var_devce_cyclic_block_size          = -1;
static int hf_var_devce_cyclic_data_block_size     = -1;
static int hf_var_devce_cyclic_rw_block_size       = -1;
static int hf_var_devce_event_block_size           = -1;
static int hf_var_devce_service_block_size         = -1;
static int hf_cip_data                             = -1;

/* Subtree pointers for the dissection */
static gint ett_cipmotion           = -1;
static gint ett_cont_dev_header     = -1;
static gint ett_control_status      = -1;
static gint ett_node_control        = -1;
static gint ett_node_status         = -1;
static gint ett_time_data_set       = -1;
static gint ett_inst_data_header    = -1;
static gint ett_cyclic_data_block   = -1;
static gint ett_feedback_mode       = -1;
static gint ett_connection_configuration_bits = -1;
static gint ett_control_mode        = -1;
static gint ett_feedback_config     = -1;
static gint ett_command_data_set    = -1;
static gint ett_actual_data_set     = -1;
static gint ett_status_data_set     = -1;
static gint ett_interp_control      = -1;
static gint ett_cyclic_rd_wt        = -1;
static gint ett_event               = -1;
static gint ett_event_check_ctrl    = -1;
static gint ett_event_check_sts     = -1;
static gint ett_service             = -1;
static gint ett_get_axis_attribute  = -1;
static gint ett_set_axis_attribute  = -1;
static gint ett_get_axis_attr_list  = -1;
static gint ett_set_axis_attr_list  = -1;
static gint ett_set_cyclic_list     = -1;
static gint ett_group_sync          = -1;
static gint ett_axis_status_set     = -1;
static gint ett_command_control     = -1;
static gint ett_configuration_block = -1;

static expert_field ei_format_rev_conn_pt = EI_INIT;

static dissector_handle_t cipmotion_handle;
static dissector_handle_t cipmotion3_handle;

static gboolean display_full_attribute_data = FALSE;

/* These are the BITMASKS for the Time Data Set header field */
#define TIME_DATA_SET_TIME_STAMP                0x1
#define TIME_DATA_SET_TIME_OFFSET               0x2
#define TIME_DATA_SET_UPDATE_DIAGNOSTICS        0x4
#define TIME_DATA_SET_TIME_DIAGNOSTICS          0x8

/* These are the BITMASKS for the Command Data Set cyclic field */
#define COMMAND_DATA_SET_POSITION           0x01
#define COMMAND_DATA_SET_VELOCITY           0x02
#define COMMAND_DATA_SET_ACCELERATION       0x04
#define COMMAND_DATA_SET_TORQUE             0x08

/* These are the BITMASKS for the Actual Data Set cyclic field */
#define ACTUAL_DATA_SET_POSITION        0x01
#define ACTUAL_DATA_SET_VELOCITY        0x02
#define ACTUAL_DATA_SET_ACCELERATION    0x04

/* These are the BITMASKS for the Status Data Set cyclic field */
#define STATUS_DATA_SET_AXIS_FAULT              0x01
#define STATUS_DATA_SET_AXIS_ALARM              0x02
#define STATUS_DATA_SET_AXIS_STATUS             0x04
#define STATUS_DATA_SET_AXIS_IO_STATUS          0x08
#define STATUS_DATA_SET_AXIS_SAFETY             0x10

/* These are the BITMASKS for the Command Control cyclic field */
#define COMMAND_CONTROL_TARGET_UPDATE       0x03
#define COMMAND_CONTROL_POSITION_DATA_TYPE  0x0C

/* These are the VALUES of the connection format header field of the
 * CIP Motion protocol */
#define FORMAT_FIXED_CONTROL_TO_DEVICE      2
#define FORMAT_FIXED_DEVICE_TO_CONTROL      3
#define FORMAT_VAR_CONTROL_TO_DEVICE        6
#define FORMAT_VAR_DEVICE_TO_CONTROL        7

#define FEEDBACK_MODE_BITS             0x0F
#define FEEDBACK_DATA_TYPE_BITS        0x30

/* Translate function to string - connection format values */
static const value_string cip_con_format_vals[] = {
   { FORMAT_FIXED_CONTROL_TO_DEVICE,       "Fixed Controller-to-Device"        },
   { FORMAT_FIXED_DEVICE_TO_CONTROL,       "Fixed Device-to-Controller"        },
   { FORMAT_VAR_CONTROL_TO_DEVICE,         "Variable Controller-to-Device"     },
   { FORMAT_VAR_DEVICE_TO_CONTROL,         "Variable Device-to-Controller"     },
   { 0,                                    NULL                                }
};

/* Translate function to string - motor control mode values */
static const value_string cip_motor_control_vals[] = {
   { 0,    "No Control"            },
   { 1,    "Position Control"      },
   { 2,    "Velocity Control"      },
   { 3,    "Acceleration Control"  },
   { 4,    "Torque Control"        },
   { 0,    NULL                    }
};

/* Translate function to string - feedback mode values */
static const value_string cip_feedback_mode_vals[] = {
   { 0,    "No Feedback"       },
   { 1,    "Master Feedback"   },
   { 2,    "Motor Feedback"    },
   { 3,    "Load Feedback"     },
   { 4,    "Dual Feedback"     },
   { 0,    NULL                }
};

static const value_string cip_feedback_type_vals[] = {
   { 0,   "DINT"               },
   { 1,   "LINT"               },
   { 0,    NULL                }
};

/* Translate function to string - axis control values */
static const value_string cip_axis_control_vals[] =
{
   { 0,    "No Request"               },
   { 1,    "Enable Request"           },
   { 2,    "Disable Request"          },
   { 3,    "Shutdown Request"         },
   { 4,    "Shutdown Reset Request"   },
   { 5,    "Abort Request"            },
   { 6,    "Fault Reset Request"      },
   { 7,    "Stop Process"             },
   { 8,    "Change Actual Pos"        },
   { 9,    "Change Command Pos Ref"   },
   { 127,  "Cancel Request"           },
   { 0,    NULL                       }
};

/* Translate function to string - group sync Status */
static const value_string cip_sync_status_vals[] =
{
   { 0,       "Synchronized"      },
   { 1,       "Not Synchronized"  },
   { 2,       "Wrong Grandmaster" },
   { 3,       "Clock Skew Detected" },
   { 0,       NULL }
};

/* Translate function to string - command target update */
static const value_string cip_interpolation_vals[] = {
   { 0,  "Immediate"         },
   { 1,  "Extrapolate (+1)"  },
   { 2,  "Interpolate (+2)"  },
   { 0,  NULL                }
};

/* These are the VALUES for the Command Position Data Type */
#define POSITION_DATA_LREAL 0x00
#define POSITION_DATA_DINT  0x01

/* Translate function to string - position data type */
static const value_string cip_pos_data_type_vals[] = {
   { POSITION_DATA_LREAL, "LREAL (64-bit Float)"   },
   { POSITION_DATA_DINT,  "DINT (32-bit Integer)"  },
   { 0,                   NULL                     }
};

/* Translate function to string - axis response values */
static const value_string cip_axis_response_vals[] = {
   { 0,    "No Acknowledge"                 },
   { 1,    "Enable Acknowledge"            },
   { 2,    "Disable Acknowledge"           },
   { 3,    "Shutdown Acknowledge"          },
   { 4,    "Shutdown Reset Acknowledge"    },
   { 5,    "Abort Acknowledge"             },
   { 6,    "Fault Reset Acknowledge"       },
   { 7,    "Stop Process Acknowledge"      },
   { 8,    "Change Actual Position Reference Acknowledge" },
   { 9,    "Change Command Position Reference Acknowledge" },
   { 127,  "Cancel Acknowledge"            },
   { 0,    NULL                            }
};

/* Translate function to string - axis state values */
static const value_string cip_axis_state_vals[] = {
   { 0,    "Initializing"      },
   { 1,    "Pre-Charge"        },
   { 2,    "Stopped"           },
   { 3,    "Starting"          },
   { 4,    "Running"           },
   { 5,    "Testing"           },
   { 6,    "Stopping"          },
   { 7,    "Aborting"          },
   { 8,    "Major Faulted"     },
   { 9,    "Start Inhibited"   },
   { 10,   "Shutdown"          },
   { 0,    NULL                }
};

/* Translate function to string - event type values */
static const value_string cip_event_type_vals[] = {
   { 0,    "Registration 1 Positive Edge"  },
   { 1,    "Registration 1 Negative Edge"  },
   { 2,    "Registration 2 Positive Edge"  },
   { 3,    "Registration 2 Negative Edge"  },
   { 4,    "Marker Positive Edge"          },
   { 5,    "Marker Negative Edge"          },
   { 6,    "Home Switch Positive Edge"     },
   { 7,    "Home Switch Negative Edge"     },
   { 8,    "Home Switch Marker ++"         },
   { 9,    "Home Switch Marker +-"         },
   { 10,   "Home Switch Marker -+"         },
   { 11,   "Home Switch Marker --"         },
   { 0,    NULL                            }
};

#define SC_GET_AXIS_ATTRIBUTE_LIST  0x4B
#define SC_SET_AXIS_ATTRIBUTE_LIST  0x4C
#define SC_SET_CYCLIC_WRITE_LIST    0x4D
#define SC_SET_CYCLIC_READ_LIST     0x4E
#define SC_RUN_MOTOR_TEST           0x4F
#define SC_GET_MOTOR_TEST_DATA      0x50
#define SC_RUN_INERTIA_TEST         0x51
#define SC_GET_INERTIA_TEST_DATA    0x52
#define SC_RUN_HOOKUP_TEST          0x53
#define SC_GET_HOOKUP_TEST_DATA     0x54

/* Translate function to string - CIP Service codes */
static const value_string cip_sc_vals[] = {
   GENERIC_SC_LIST
   { SC_GET_AXIS_ATTRIBUTE_LIST,   "Get Axis Attribute List"   },
   { SC_SET_AXIS_ATTRIBUTE_LIST,   "Set Axis Attribute List"   },
   { SC_SET_CYCLIC_WRITE_LIST,     "Set Cyclic Write List"     },
   { SC_SET_CYCLIC_READ_LIST,      "Set Cyclic Read List"      },
   { SC_RUN_MOTOR_TEST,            "Run Motor Test"            },
   { SC_GET_MOTOR_TEST_DATA,       "Get Motor Test Data"       },
   { SC_RUN_INERTIA_TEST,          "Run Inertia Test"          },
   { SC_GET_INERTIA_TEST_DATA,     "Get Inertia Test Data"     },
   { SC_RUN_HOOKUP_TEST,           "Run Hookup Test"           },
   { SC_GET_HOOKUP_TEST_DATA,      "Get Hookup Test Data"      },
   { 0,                            NULL                        }
};

static int dissect_axis_status(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_axis_sts_local_ctrl,
      &hf_cip_axis_sts_alarm,
      &hf_cip_axis_sts_dc_bus,
      &hf_cip_axis_sts_pwr_struct,
      &hf_cip_axis_sts_flux_up,
      &hf_cip_axis_sts_tracking,
      &hf_cip_axis_sts_pos_lock,
      &hf_cip_axis_sts_vel_lock,
      &hf_cip_axis_sts_vel_standstill,
      &hf_cip_axis_sts_vel_threshold,
      &hf_cip_axis_sts_vel_limit,
      &hf_cip_axis_sts_acc_limit,
      &hf_cip_axis_sts_dec_limit,
      &hf_cip_axis_sts_torque_threshold,
      &hf_cip_axis_sts_torque_limit,
      &hf_cip_axis_sts_cur_limit,
      &hf_cip_axis_sts_therm_limit,
      &hf_cip_axis_sts_feedback_integ,
      &hf_cip_axis_sts_shutdown,
      &hf_cip_axis_sts_in_process,
      &hf_cip_axis_sts_dc_bus_unload,
      &hf_cip_axis_sts_ac_pwr_loss,
      &hf_cip_axis_sts_pos_cntrl_mode,
      &hf_cip_axis_sts_vel_cntrl_mode,
      &hf_cip_axis_sts_trq_cntrl_mode,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_axis_status, ett_axis_status_set, bits, ENC_LITTLE_ENDIAN);

   return 4;
}

static int dissect_axis_status2(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_axis_sts2_motor,
      &hf_cip_axis_sts2_regenerate,
      &hf_cip_axis_sts2_ride_thru,
      &hf_cip_axis_sts2_ac_line_sync,
      &hf_cip_axis_sts2_bus_volt_lock,
      &hf_cip_axis_sts2_react_pwr_only,
      &hf_cip_axis_sts2_volt_ctrl_mode,
      &hf_cip_axis_sts2_pwr_loss,
      &hf_cip_axis_sts2_ac_volt_sag,
      &hf_cip_axis_sts2_ac_phase_loss,
      &hf_cip_axis_sts2_ac_freq_change,
      &hf_cip_axis_sts2_ac_sync_loss,
      &hf_cip_axis_sts2_single_phase,
      &hf_cip_axis_sts2_bus_volt_limit,
      &hf_cip_axis_sts2_bus_volt_rate_limit,
      &hf_cip_axis_sts2_active_current_rate_limit,
      &hf_cip_axis_sts2_reactive_current_rate_limit,
      &hf_cip_axis_sts2_reactive_pwr_limit,
      &hf_cip_axis_sts2_reactive_pwr_rate_limit,
      &hf_cip_axis_sts2_active_current_limit,
      &hf_cip_axis_sts2_reactive_current_limit,
      &hf_cip_axis_sts2_motor_pwr_limit,
      &hf_cip_axis_sts2_regen_pwr_limit,
      &hf_cip_axis_sts2_convert_therm_limit,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_axis_status2, ett_axis_status_set, bits, ENC_LITTLE_ENDIAN);

   return 4;
}

static int dissect_event_checking_control(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_evnt_ctrl_reg1_pos,
      &hf_cip_evnt_ctrl_reg1_neg,
      &hf_cip_evnt_ctrl_reg2_pos,
      &hf_cip_evnt_ctrl_reg2_neg,
      &hf_cip_evnt_ctrl_reg1_posrearm,
      &hf_cip_evnt_ctrl_reg1_negrearm,
      &hf_cip_evnt_ctrl_reg2_posrearm,
      &hf_cip_evnt_ctrl_reg2_negrearm,
      &hf_cip_evnt_ctrl_marker_pos,
      &hf_cip_evnt_ctrl_marker_neg,
      &hf_cip_evnt_ctrl_home_pos,
      &hf_cip_evnt_ctrl_home_neg,
      &hf_cip_evnt_ctrl_home_pp,
      &hf_cip_evnt_ctrl_home_pm,
      &hf_cip_evnt_ctrl_home_mp,
      &hf_cip_evnt_ctrl_home_mm,
      &hf_cip_evnt_ctrl_acks,
      // The dissector will indicate if the protocol is requesting an extended event format but will not dissect it.
      &hf_cip_evnt_extend_format,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_event_checking, ett_event_check_ctrl, bits, ENC_LITTLE_ENDIAN);

   return 4;
}

static int dissect_event_checking_status(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_evnt_sts_reg1_pos,
      &hf_cip_evnt_sts_reg1_neg,
      &hf_cip_evnt_sts_reg2_pos,
      &hf_cip_evnt_sts_reg2_neg,
      &hf_cip_evnt_sts_reg1_posrearm,
      &hf_cip_evnt_sts_reg1_negrearm,
      &hf_cip_evnt_sts_reg2_posrearm,
      &hf_cip_evnt_sts_reg2_negrearm,
      &hf_cip_evnt_sts_marker_pos,
      &hf_cip_evnt_sts_marker_neg,
      &hf_cip_evnt_sts_home_pos,
      &hf_cip_evnt_sts_home_neg,
      &hf_cip_evnt_sts_home_pp,
      &hf_cip_evnt_sts_home_pm,
      &hf_cip_evnt_sts_home_mp,
      &hf_cip_evnt_sts_home_mm,
      &hf_cip_evnt_sts_nfs,
      // The dissector will indicate if the protocol is requesting an extended event format but will not dissect it.
      &hf_cip_evnt_extend_format,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_event_status, ett_event_check_sts, bits, ENC_LITTLE_ENDIAN);

   return 4;
}

static int dissect_actual_data_set_bits(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_act_data_pos,
      &hf_cip_act_data_vel,
      &hf_cip_act_data_acc,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_act_data_set, ett_actual_data_set, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_command_data_set_bits(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_cmd_data_pos_cmd,
      &hf_cip_cmd_data_vel_cmd,
      &hf_cip_cmd_data_acc_cmd,
      &hf_cip_cmd_data_trq_cmd,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_cmd_data_set, ett_command_data_set, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_command_control(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_intrp,
      &hf_cip_position_data_type,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_command_control, ett_command_control, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_status_data_set_bits(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_sts_flt,
      &hf_cip_sts_alrm,
      &hf_cip_sts_sts,
      &hf_cip_sts_iosts,
      &hf_cip_sts_axis_safety,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_sts_data_set, ett_status_data_set, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_node_control(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_node_control_remote,
      &hf_cip_node_control_sync,
      &hf_cip_node_data_valid,
      &hf_cip_node_fault_reset,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_node_control, ett_node_control, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_node_status(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_node_control_remote,
      &hf_cip_node_control_sync,
      &hf_cip_node_data_valid,
      &hf_cip_node_device_faulted,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_node_status, ett_node_status, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_time_data_set(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_time_data_stamp,
      &hf_cip_time_data_offset,
      &hf_cip_time_data_diag,
      &hf_cip_time_data_time_diag,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_time_data_set, ett_time_data_set, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_control_status(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_control_status_complete,
      &hf_cip_control_status_bus_up,
      &hf_cip_control_status_bus_unload,
      &hf_cip_control_status_power_loss,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_control_status, ett_control_status, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_feedback_mode(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_cip_feedback_mode,
      &hf_cip_feedback_data_type,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_feedback, ett_feedback_mode, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_connection_configuration_bits(packet_info* pinfo _U_, proto_tree* tree, proto_item* item _U_, tvbuff_t* tvb,
   int offset, int total_len _U_)
{
   static int* const bits[] = {
      &hf_connection_configuration_bits_power,
      &hf_connection_configuration_bits_safety_bit_valid,
      &hf_connection_configuration_bits_allow_network_safety,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_connection_configuration_bits, ett_connection_configuration_bits, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

attribute_info_t cip_motion_attribute_vals[] = {
   { CI_CLS_MOTION, CIP_ATTR_CLASS, 14, -1, "Node Control", cip_dissector_func, NULL, dissect_node_control },
   { CI_CLS_MOTION, CIP_ATTR_CLASS, 15, -1, "Node Status", cip_dissector_func, NULL, dissect_node_status },
   { CI_CLS_MOTION, CIP_ATTR_CLASS, 31, -1, "Time Data Set", cip_dissector_func, NULL, dissect_time_data_set },
   { CI_CLS_MOTION, CIP_ATTR_CLASS, 34, -1, "Drive Power Structure Class ID", cip_udint, &hf_configuration_block_drive_power_struct_id, NULL },
   { CI_CLS_MOTION, CIP_ATTR_CLASS, 36, -1, "Connection Configuration Bits", cip_dissector_func, NULL, dissect_connection_configuration_bits },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 40, -1, "Control Mode", cip_usint, &hf_cip_motor_cntrl, NULL },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 42, -1, "Feedback Mode", cip_dissector_func, NULL, dissect_feedback_mode },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 60, -1, "Event Checking Control", cip_dissector_func, NULL, dissect_event_checking_control },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 61, -1, "Event Checking Status", cip_dissector_func, NULL, dissect_event_checking_status },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 89, -1, "Control Status", cip_dissector_func, NULL, dissect_control_status },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 90, -1, "Actual Data Set", cip_dissector_func, NULL, dissect_actual_data_set_bits },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 91, -1, "Command Data Set", cip_dissector_func, NULL, dissect_command_data_set_bits },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 92, -1, "Command Control", cip_dissector_func, NULL, dissect_command_control },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 94, -1, "Status Data Set", cip_dissector_func, NULL, dissect_status_data_set_bits },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 431, -1, "Position Trim", cip_dint, &hf_cip_pos_trim, NULL },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 451, -1, "Velocity Trim", cip_real, &hf_cip_vel_trim, NULL },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 481, -1, "Acceleration Trim", cip_real, &hf_cip_accel_trim, NULL },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 491, -1, "Torque Trim", cip_real, &hf_cip_trq_trim, NULL },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 651, -1, "Axis Status", cip_dissector_func, NULL, dissect_axis_status },
   { CI_CLS_MOTION, CIP_ATTR_INSTANCE, 740, -1, "Axis Status 2", cip_dissector_func, NULL, dissect_axis_status2 },
};

/*
 * Function name: dissect_cmd_data_set
 *
 * Purpose: Dissect the command data set field of the cyclic data block header and if any
 * of the command value bits are set to retrieve and display those command values
 *
 * Returns: The number of bytes in the cyclic data used
 */
static guint32
dissect_cmd_data_set(guint32 cmd_data_set, proto_tree* tree, tvbuff_t* tvb, guint32 offset, gboolean lreal_pos)
{
   guint32 bytes_used = 0;

   /* The order of these if statements is VERY important, this is the order the values will
    * appear in the cyclic data */
   if ( (cmd_data_set & COMMAND_DATA_SET_POSITION) == COMMAND_DATA_SET_POSITION )
   {
      /* Based on the Command Position Data Type value embedded in the Command Control
      * header field the position is either 64-bit floating or 32-bit integer */
      if (lreal_pos)
      {
         /* Display the command data set position command value */
         proto_tree_add_item(tree, hf_cip_pos_cmd, tvb, offset + bytes_used, 8, ENC_LITTLE_ENDIAN );
         bytes_used += 8;
      }
      else
      {
         /* Display the command data set position command value */
         proto_tree_add_item(tree, hf_cip_pos_cmd_int, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
         bytes_used += 4;
      }
   }

   if ( (cmd_data_set & COMMAND_DATA_SET_VELOCITY) == COMMAND_DATA_SET_VELOCITY )
   {
      /* Display the command data set velocity command value */
      proto_tree_add_item(tree, hf_cip_vel_cmd, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
      bytes_used += 4;
   }

   if ( (cmd_data_set & COMMAND_DATA_SET_ACCELERATION) == COMMAND_DATA_SET_ACCELERATION )
   {
      /* Display the command data set acceleration command value */
      proto_tree_add_item(tree, hf_cip_accel_cmd, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
      bytes_used += 4;
   }

   if ( (cmd_data_set & COMMAND_DATA_SET_TORQUE) == COMMAND_DATA_SET_TORQUE )
   {
      /* Display the command data set torque command value */
      proto_tree_add_item(tree, hf_cip_trq_cmd, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
      bytes_used += 4;
   }

   return bytes_used;
}


/*
 * Function name: dissect_act_data_set
 *
 * Purpose: Dissect the actual data set field of the cyclic data block header and if any
 * of the actual value bits are set to retrieve and display those feedback values
 *
 * Returns: The number of bytes in the cyclic data used
 */
static guint32
dissect_act_data_set(guint32 act_data_set, proto_tree* tree, tvbuff_t* tvb, guint32 offset, guint8 feedback_mode)
{
   guint32 bytes_used = 0;

   /* The order of these if statements is VERY important, this is the order the values will
   * appear in the cyclic data */
   if ( (act_data_set & ACTUAL_DATA_SET_POSITION) == ACTUAL_DATA_SET_POSITION )
   {
      /* Display the actual data set position feedback value in either 32 or 64 bit */
      gboolean is_64_bit_position = (feedback_mode & FEEDBACK_DATA_TYPE_BITS) == 0x10;
      if (is_64_bit_position)
      {
         proto_tree_add_item(tree, hf_cip_act_pos_64, tvb, offset + bytes_used, 8, ENC_LITTLE_ENDIAN);
         bytes_used += 8;
      }
      else
      {
         proto_tree_add_item(tree, hf_cip_act_pos, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
         bytes_used += 4;
      }
   }

   if ( (act_data_set & ACTUAL_DATA_SET_VELOCITY) == ACTUAL_DATA_SET_VELOCITY )
   {
      /* Display the actual data set velocity feedback value */
      proto_tree_add_item(tree, hf_cip_act_vel, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
      bytes_used += 4;
   }

   if ( (act_data_set & ACTUAL_DATA_SET_ACCELERATION) == ACTUAL_DATA_SET_ACCELERATION )
   {
      /* Display the actual data set acceleration feedback value */
      proto_tree_add_item(tree, hf_cip_act_accel, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN );
      bytes_used += 4;
   }

   return bytes_used;
}

/*
 * Function name: dissect_status_data_set
 *
 * Purpose: Dissect the status data set field of the cyclic data block header and if any
 * of the status value bits are set to retrieve and display those status values
 *
 * Returns: The number of bytes in the cyclic data used
 */
static guint32
dissect_status_data_set(guint32 status_data_set, proto_tree* tree, tvbuff_t* tvb, guint32 offset)
{
   guint32 bytes_used = 0;

   /* The order of these if statements is VERY important, this is the order the values will
    * appear in the cyclic data */
   if ( (status_data_set & STATUS_DATA_SET_AXIS_FAULT) == STATUS_DATA_SET_AXIS_FAULT )
   {
      /* Display the various fault codes from the device */
      proto_tree_add_item(tree, hf_cip_fault_type, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_axis_fault, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_fault_sub_code, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_fault_action, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_fault_time_stamp, tvb, offset + bytes_used, 8, ENC_LITTLE_ENDIAN);
      bytes_used += 8;
   }

   if ( (status_data_set & STATUS_DATA_SET_AXIS_ALARM) == STATUS_DATA_SET_AXIS_ALARM )
   {
      /* Display the various alarm codes from the device */
      proto_tree_add_item(tree, hf_cip_alarm_type, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_axis_alarm, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_alarm_sub_code, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_alarm_state, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      proto_tree_add_item(tree, hf_cip_alarm_time_stamp, tvb, offset + bytes_used, 8, ENC_LITTLE_ENDIAN);
      bytes_used += 8;
   }

   if ( (status_data_set & STATUS_DATA_SET_AXIS_STATUS) == STATUS_DATA_SET_AXIS_STATUS )
   {
      /* Display the various axis state values from the device */
      bytes_used += dissect_axis_status(NULL, tree, NULL, tvb, offset + bytes_used, 4);

      proto_tree_add_item(tree, hf_cip_axis_status_mfg, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;
   }

   if ( (status_data_set & STATUS_DATA_SET_AXIS_IO_STATUS) == STATUS_DATA_SET_AXIS_IO_STATUS )
   {
      proto_tree_add_item(tree, hf_cip_axis_io_status, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;

      proto_tree_add_item(tree, hf_cip_axis_io_status_mfg, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;
   }

   if ( (status_data_set & STATUS_DATA_SET_AXIS_SAFETY) == STATUS_DATA_SET_AXIS_SAFETY )
   {
      proto_tree_add_item(tree, hf_cip_axis_safety_status, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;
      proto_tree_add_item(tree, hf_cip_axis_safety_status_mfg, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;
      proto_tree_add_item(tree, hf_cip_axis_safety_state, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 4;
   }

   return bytes_used;
}

/*
 * Function name: dissect_cntr_cyclic
 *
 * Purpose: Dissect the cyclic data block of a controller to device format message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_cntr_cyclic(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;
   guint32     temp_data;
   gboolean    lreal_pos;
   guint32     bytes_used = 0;

   /* Create the tree for the entire instance data header */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_cyclic_data_block, NULL, "Cyclic Data Block");

   /* Add the control mode header field to the tree */
   proto_tree_add_item(header_tree, hf_cip_motor_cntrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   dissect_feedback_mode(NULL, header_tree, NULL, tvb, offset + 1, 1);

   /* Add the axis control field to the tree */
   proto_tree_add_item(header_tree, hf_cip_axis_control, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   dissect_control_status(NULL, header_tree, NULL, tvb, offset + 3, 1);

   /* Read the command control header field from the packet into memory and determine if the dissector
   * should be using an LREAL or DINT for position */
   temp_data = tvb_get_guint8(tvb, offset + 7);
   lreal_pos = ( (temp_data & COMMAND_CONTROL_POSITION_DATA_TYPE) == POSITION_DATA_LREAL );

   /* Read the command data set header field from the packet into memory */
   temp_data = tvb_get_guint8(tvb, offset + 4);

   dissect_command_data_set_bits(NULL, header_tree, NULL, tvb, offset + 4, 1);

   /* Display the command data values from the cyclic data payload, the
   * cyclic data starts immediately after the interpolation control field in the controller to device
   * direction */
   bytes_used += dissect_cmd_data_set(temp_data, header_tree, tvb, offset + 8 + bytes_used, lreal_pos);

   dissect_actual_data_set_bits(NULL, header_tree, NULL, tvb, offset + 5, 1);
   dissect_status_data_set_bits(NULL, header_tree, NULL, tvb, offset + 6, 1);
   dissect_command_control(NULL, header_tree, NULL, tvb, offset + 7, 1);

   /* Return the offset to the next byte in the message */
   return offset + 8 + bytes_used;
}

/*
 * Function name: dissect_device_cyclic
 *
 * Purpose: Dissect the cyclic data block of a device to controller format message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_device_cyclic(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;
   guint32 temp_data;
   guint32 bytes_used = 0;

   /* Create the tree for the entire instance data header */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_cyclic_data_block, NULL, "Cyclic Data Block");

   /* Add the control mode header field to the tree */
   proto_tree_add_item(header_tree, hf_cip_motor_cntrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   dissect_feedback_mode(NULL, header_tree, NULL, tvb, offset + 1, 1);

   /* Add the axis response field to the tree */
   proto_tree_add_item(header_tree, hf_cip_axis_response, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   /* Add the axis response status to the tree */
   proto_tree_add_item(header_tree, hf_cip_axis_resp_stat, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);

   /* Read the actual data set header field from the packet into memory */
   temp_data = tvb_get_guint8(tvb, offset + 5);

   dissect_actual_data_set_bits(NULL, header_tree, NULL, tvb, offset + 5, 1);

   /* Display the actual data values from the cyclic data payload, the
   * cyclic data starts immediately after the interpolation control field in the controller to device
   * direction and the actual data starts immediately after the cyclic data */
   guint8 feedback_mode = tvb_get_guint8(tvb, offset + 1);
   bytes_used += dissect_act_data_set(temp_data, header_tree, tvb, offset + 8 + bytes_used, feedback_mode);

   /* Read the status data set header field from the packet into memory */
   temp_data = tvb_get_guint8(tvb, offset + 6);

   dissect_status_data_set_bits(NULL, header_tree, NULL, tvb, offset + 6, 1);

   /* Display the status data values from the cyclic data payload, the
   * cyclic data starts immediately after the axis state field in the device to controller
   * direction and the status data starts immediately after the cyclic data */
   bytes_used += dissect_status_data_set(temp_data, header_tree, tvb, offset + 8 + bytes_used);

   /* Display the axis state control field */
   proto_tree_add_item(header_tree, hf_cip_axis_state, tvb, offset + 7, 1, ENC_LITTLE_ENDIAN);

   /* Return the offset to the next byte in the message */
   return offset + 8 + bytes_used;
}

/*
 * Function name: dissect_cyclic_wt
 *
 * Purpose: Dissect the cyclic write data block in a controller to device message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_cyclic_wt(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;

   /* Create the tree for the entire cyclic write data block */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_cyclic_rd_wt, NULL, "Cyclic Write Data Block");

   /* Display the cyclic write block id value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_write_blk, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the cyclic read block id value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_read_blk, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   /* Display the remainder of the cyclic write data if there is any */
   if ( (size - 4) > 0 )
   {
      proto_tree_add_item(header_tree, hf_cip_cyclic_wrt_data, tvb, offset + 4, size - 4, ENC_NA);
   }

   return offset + size;
}

/*
 * Function name: dissect_cyclic_rd
 *
 * Purpose: Dissect the cyclic read data block in a device to controller message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_cyclic_rd(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;

   /* Create the tree for the entire cyclic write data block */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_cyclic_rd_wt, NULL, "Cyclic Read Data Block");

   /* Display the cyclic write block id value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_write_blk, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the cyclic write status value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_write_sts, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

   /* Display the cyclic read block id value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_read_blk, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   /* Display the cyclic read status value */
   proto_tree_add_item(header_tree, hf_cip_cyclic_read_sts, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);

   /* Display the remainder of the cyclic read data if there is any*/
   if ( (size - 4) > 0 )
   {
      proto_tree_add_item(header_tree, hf_cip_cyclic_rd_data, tvb, offset + 4, size - 4, ENC_NA);
   }

   return offset + size;
}

/*
 * Function name: dissect_cntr_event
 *
 * Purpose: Dissect the event data block in a controller to device message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_cntr_event(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;
   guint32 temp_data;
   guint32 acks, cur_ack;
   guint32 bytes_used = 0;

   /* Create the tree for the entire cyclic write data block */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_event, NULL, "Event Data Block");

   /* Read the event checking control header field from the packet into memory */
   temp_data = tvb_get_letohl(tvb, offset);

   dissect_event_checking_control(NULL, header_tree, NULL, tvb, offset, 4);

   /* The event checking control value is 4 bytes long */
   bytes_used = 4;

   /* The final 4 bits of the event checking control value are the number of acknowledgements in the message */
   acks = (temp_data >> 28) & 0x0F;

   /* Each acknowledgement contains and id and a status value */
   for (cur_ack = 0; cur_ack < acks; cur_ack++)
   {
     /* Display the current acknowledgement id */
     proto_tree_add_item(header_tree, hf_cip_event_ack, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
     bytes_used += 1;

     /* Display the current event status */
     proto_tree_add_item(header_tree, hf_cip_evnt_sts_stat, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
     bytes_used += 1;
   }

   return offset + size;
}

/*
 * Function name: dissect_devce_event
 *
 * Purpose: Dissect the event data block in a device to controller message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_devce_event(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;
   guint64     temp_data;
   guint64     nots, cur_not;
   guint32     bytes_used = 0;

   /* Create the tree for the entire cyclic write data block */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_event, NULL, "Event Data Block");

   /* Read the event checking control header field from the packet into memory */
   temp_data = tvb_get_letohl(tvb, offset);

   dissect_event_checking_status(NULL, header_tree, NULL, tvb, offset, 4);

   /* The event status control value is 4 bytes long */
   bytes_used = 4;

   /* The final 4 bits of the event status control value are the number of notifications in the message */
   nots = (temp_data >> 28) & 0x0F;

   /* Each notification contains and id, status value, event type, position and time stamp */
   for (cur_not = 0; cur_not < nots; cur_not++)
   {
      /* Display the current event id */
      proto_tree_add_item(header_tree, hf_cip_event_id, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      /* Display the current event status */
      proto_tree_add_item(header_tree, hf_cip_evnt_sts_stat, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 1;

      /* Display the current event type */
      proto_tree_add_item(header_tree, hf_cip_evnt_type, tvb, offset + bytes_used, 1, ENC_LITTLE_ENDIAN);
      bytes_used += 2;    /* Increment by 2 to jump the reserved byte */

      /* Display the event position value */
      proto_tree_add_item(header_tree, hf_cip_event_pos, tvb, offset + bytes_used, 4, ENC_LITTLE_ENDIAN);
      bytes_used += 4;

      /* Display the event time stamp value */
      proto_tree_add_item(header_tree, hf_cip_event_ts, tvb, offset + bytes_used, 8, ENC_LITTLE_ENDIAN);
      bytes_used += 8;
   }

   return size + offset;
}

/*
 * Function name: dissect_get_axis_attr_list_request
 *
 * Purpose: Dissect the get axis attribute list service request
 *
 * Returns: None
 */
static void
dissect_get_axis_attr_list_request(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_item *attr_item;
   proto_tree *header_tree, *attr_tree;
   guint32     local_offset;

   /* Create the tree for the get axis attribute list request */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_get_axis_attribute, NULL, "Get Axis Attribute List Request");

   /* Read the number of attributes that are contained within the request */
   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_get_axis_attr_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   /* Start the attribute loop at the beginning of the first attribute in the list */
   local_offset = offset + 4;

   /* For each attribute display the associated fields */
   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      /* At a minimum the local offset needs will need to be incremented by 4 bytes to reach the next attribute */
      guint8 increment_size = 4;

      /* Create the tree for this attribute within the request */
      guint32 attribute_id;
      attr_item = proto_tree_add_item_ret_uint(header_tree, hf_get_axis_attr_list_attribute_id, tvb, local_offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);
      attr_tree = proto_item_add_subtree(attr_item, ett_get_axis_attr_list);

      guint32 dimension;
      proto_tree_add_item_ret_uint(attr_tree, hf_get_axis_attr_list_dimension, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN, &dimension);
      proto_tree_add_item(attr_tree, hf_get_axis_attr_list_element_size, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);

      if (dimension == 1)
      {
         /* Display the start index and start index from the request */
         proto_tree_add_item(attr_tree, hf_get_axis_attr_list_start_index, tvb, local_offset + 4, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(attr_tree, hf_get_axis_attr_list_data_elements, tvb, local_offset + 6, 2, ENC_LITTLE_ENDIAN);

         /* Modify the amount to update the local offset by and the start of the data to include the index and elements field */
         increment_size += 4;
      }

      attribute_info_t* pattribute = cip_get_attribute(CI_CLS_MOTION, instance_id, attribute_id);
      if (pattribute != NULL)
      {
         proto_item_append_text(attr_item, " (%s)", pattribute->text);
      }

      /* Move the local offset to the next attribute */
      local_offset += increment_size;
   }
}

static int dissect_motion_attribute(packet_info *pinfo, tvbuff_t* tvb, int offset, guint32 attribute_id,
   guint32 instance_id, proto_item* attr_item, proto_tree* attr_tree, guint8 dimension, guint32 attribute_size)
{
   attribute_info_t* pattribute = cip_get_attribute(CI_CLS_MOTION, instance_id, attribute_id);
   int parsed_len = 0;

   if (pattribute != NULL)
   {
      proto_item_append_text(attr_item, " (%s)", pattribute->text);

      // TODO: Handle more dimensions. Unsure about the format when there is more than 1 item.
      if (dimension <= 1)
      {
         parsed_len = dissect_cip_attribute(pinfo, attr_tree, attr_item, tvb, pattribute, offset, attribute_size);
      }
   }

   return parsed_len;
}

/*
 * Function name: dissect_set_axis_attr_list_request
 *
 * Purpose: Dissect the set axis attribute list service request
 *
 * Returns: None
 */
static void
dissect_set_axis_attr_list_request(packet_info *pinfo, tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_item *attr_item;
   proto_tree *header_tree, *attr_tree;
   guint32     local_offset;

   /* Create the tree for the set axis attribute list request */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_set_axis_attribute, NULL, "Set Axis Attribute List Request");

   /* Read the number of attributes that are contained within the request */
   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_set_axis_attr_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   /* Start the attribute loop at the beginning of the first attribute in the list */
   local_offset = offset + 4;

   /* For each attribute display the associated fields */
   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      /* At a minimum the local offset needs to be incremented by 4 bytes to reach the next attribute */
      guint8 increment_size = 4;

      /* Pull the fields for this attribute from the payload, all fields are needed to make some calculations before
      *  properly displaying of the attribute is possible */
      guint8 attribute_start = 4;

      /* Create the tree for this attribute in the get axis attribute list request */
      guint32 attribute_id;
      attr_item = proto_tree_add_item_ret_uint(header_tree, hf_set_axis_attr_list_attribute_id, tvb, local_offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);
      attr_tree = proto_item_add_subtree(attr_item, ett_set_axis_attr_list);

      guint32 dimension;
      proto_tree_add_item_ret_uint(attr_tree, hf_set_axis_attr_list_dimension, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN, &dimension);

      guint32 attribute_size;
      proto_tree_add_item_ret_uint(attr_tree, hf_set_axis_attr_list_element_size, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN, &attribute_size);

      if (dimension == 1)
      {
         guint32 data_elements;

         /* Display the start index and start index from the request if the request is an array */
         proto_tree_add_item(attr_tree, hf_set_axis_attr_list_start_index, tvb, local_offset + 4, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item_ret_uint(attr_tree, hf_set_axis_attr_list_data_elements, tvb, local_offset + 6, 2, ENC_LITTLE_ENDIAN, &data_elements);

         /* Modify the size of the attribute data by the number of elements if the request is an array request */
         attribute_size *= data_elements;

         /* Modify the amount to update the local offset by and the start of the data to include the index and elements field */
         increment_size  += 4;
         attribute_start += 4;
      }

      int parsed_len = dissect_motion_attribute(pinfo, tvb, local_offset + attribute_start, attribute_id,
         instance_id, attr_item, attr_tree, dimension, attribute_size);

      // Display the raw attribute data if configured. Otherwise, just show the remaining unparsed data.
      if (display_full_attribute_data)
      {
         proto_tree_add_item(attr_tree, hf_cip_attribute_data, tvb, local_offset + attribute_start, attribute_size, ENC_NA);
      }
      else if ((attribute_size - parsed_len) > 0)
      {
         proto_tree_add_item(attr_tree, hf_cip_attribute_data, tvb, local_offset + attribute_start + parsed_len, attribute_size - parsed_len, ENC_NA);
      }

      /* Round the attribute size up so the next attribute lines up on a 32-bit boundary */
      if (attribute_size % 4 != 0)
      {
         attribute_size = attribute_size + (4 - (attribute_size % 4));
      }

      /* Move the local offset to the next attribute */
      local_offset += (attribute_size + increment_size);
   }
}

/*
 * Function name: dissect_group_sync_request
 *
 * Purpose: Dissect the group sync service request
 *
 * Returns: None
 */
static void
dissect_group_sync_request (tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size)
{
   proto_tree *header_tree;

   /* Create the tree for the group sync request */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_group_sync, NULL, "Group Sync Request");

   /* Read the grandmaster id from the payload */
   proto_tree_add_item(header_tree, hf_cip_ptp_grandmaster, tvb, offset, 8, ENC_LITTLE_ENDIAN);
}

static void dissect_set_cyclic_list_request(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id, const char* service_name)
{
   proto_tree* header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_set_cyclic_list, NULL, service_name);

   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_set_cyclic_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   // Skip Number of Attributes and Reserved field.
   offset += 4;

   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      guint32 attribute_id;
      proto_item* attr_item = proto_tree_add_item_ret_uint(header_tree, hf_set_cyclic_list_attribute_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);

      attribute_info_t* pattribute = cip_get_attribute(CI_CLS_MOTION, instance_id, attribute_id);
      if (pattribute != NULL)
      {
         proto_item_append_text(attr_item, " (%s)", pattribute->text);
      }

      offset += 2;
   }
}

static void dissect_set_cyclic_list_respone(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id, const char* service_name)
{
   proto_tree* header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_set_cyclic_list, NULL, service_name);

   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_set_cyclic_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   proto_tree_add_item(header_tree, hf_set_cyclic_list_read_block_id, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);

   // Skip Number of Attributes and Cyclic Read Block ID field.
   offset += 4;

   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      guint32 attribute_id;
      proto_item* attr_item = proto_tree_add_item_ret_uint(header_tree, hf_set_cyclic_list_attribute_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);

      attribute_info_t* pattribute = cip_get_attribute(CI_CLS_MOTION, instance_id, attribute_id);
      if (pattribute != NULL)
      {
         proto_item_append_text(attr_item, " (%s)", pattribute->text);
      }

      offset += 2;

      proto_tree_add_item(header_tree, hf_set_cyclic_list_attr_sts, tvb, offset, 1, ENC_LITTLE_ENDIAN);

      // Skip over Attribute Status and Reserved field.
      offset += 2;
   }
}

/*
 * Function name: dissect_cntr_service
 *
 * Purpose: Dissect the service data block in a controller to device message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_cntr_service(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_tree *header_tree;
   guint32      service;

   /* Create the tree for the entire service data block */
   proto_item *item;
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_service, &item, "Service Data Block");

   /* Display the transaction id value */
   proto_tree_add_item(header_tree, hf_cip_svc_transction, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the service code */
   proto_tree_add_item_ret_uint(header_tree, hf_cip_svc_code, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN, &service);

   /* If the service is a set axis, get axis attribute or group sync request dissect it as well */
   if (size > 4)
   {
       switch (service)
       {
       case SC_GET_AXIS_ATTRIBUTE_LIST:
           dissect_get_axis_attr_list_request(tvb, header_tree, offset + 4, size - 4, instance_id);
           break;
       case SC_SET_AXIS_ATTRIBUTE_LIST:
           dissect_set_axis_attr_list_request(pinfo, tvb, header_tree, offset + 4, size - 4, instance_id);
           break;
       case SC_GROUP_SYNC:
           dissect_group_sync_request(tvb, header_tree, offset + 4, size - 4);
           break;
       case SC_SET_CYCLIC_WRITE_LIST:
           dissect_set_cyclic_list_request(tvb, header_tree, offset + 4, size - 4, instance_id, "Set Cyclic Write List Request");
           break;
       case SC_SET_CYCLIC_READ_LIST:
           dissect_set_cyclic_list_request(tvb, header_tree, offset + 4, size - 4, instance_id, "Set Cyclic Read List Request");
           break;
       case SC_SET_ATT_LIST:
       {
           cip_simple_request_info_t motion_path;
           motion_path.iClass = CI_CLS_MOTION;
           motion_path.iInstance = instance_id;

           tvbuff_t* tvb_set_attr = tvb_new_subset_length(tvb, offset + 4, size - 4);
           int parsed_len = dissect_cip_set_attribute_list_req(tvb_set_attr, pinfo, header_tree, item, 0, &motion_path);

           // Display any remaining unparsed data.
           int remain_len = tvb_reported_length_remaining(tvb, offset + 4 + parsed_len);
           if (remain_len > 0)
           {
              proto_tree_add_item(header_tree, hf_cip_attribute_data, tvb, offset + 4 + parsed_len, size - 4 - parsed_len, ENC_NA);
           }

           break;
       }
       default:
           /* Display the remainder of the service channel data */
           proto_tree_add_item(header_tree, hf_cip_svc_data, tvb, offset + 4, size - 4, ENC_NA);
       }
   }

   return offset + size;
}

/*
 * Function name: dissect_set_axis_attr_list_response
 *
 * Purpose: Dissect the set axis attribute list service response
 *
 * Returns: None
 */
static void
dissect_set_axis_attr_list_response(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_item *attr_item;
   proto_tree *header_tree, *attr_tree;
   guint32     local_offset;

   /* Create the tree for the set axis attribute list response */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_get_axis_attribute, NULL, "Set Axis Attribute List Response");

   /* Read the number of attributes that are contained within the response */
   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_set_axis_attr_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   /* Start the attribute loop at the beginning of the first attribute in the list */
   local_offset = offset + 4;

   /* For each attribute display the associated fields */
   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      /* Create the tree for the current attribute in the set axis attribute list response */
      guint32 attribute_id;
      attr_item = proto_tree_add_item_ret_uint(header_tree, hf_set_axis_attr_list_attribute_id, tvb, local_offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);
      attr_tree = proto_item_add_subtree(attr_item, ett_get_axis_attr_list);

      /* Add the response status to the tree */
      proto_tree_add_item(attr_tree, hf_cip_svc_set_axis_attr_sts, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN);

      attribute_info_t* pattribute = cip_get_attribute(CI_CLS_MOTION, instance_id, attribute_id);
      if (pattribute != NULL)
      {
         proto_item_append_text(attr_item, " (%s)", pattribute->text);
      }

      /* Move the local offset to the next attribute */
      local_offset += 4;
   }
}

/*
 * Function name: dissect_get_axis_attr_list_response
 *
 * Purpose: Dissect the get axis attribute list service response
 *
 * Returns: None
 */
static void
dissect_get_axis_attr_list_response(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_item *attr_item;
   proto_tree *header_tree, *attr_tree;
   guint32     local_offset;

   /* Create the tree for the get axis attribute list response */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_get_axis_attribute, NULL, "Get Axis Attribute List Response");

   /* Read the number of attributes that are contained within the request */
   guint32 attribute_cnt;
   proto_tree_add_item_ret_uint(header_tree, hf_get_axis_attr_list_attribute_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN, &attribute_cnt);

   /* Start the attribute loop at the beginning of the first attribute in the list */
   local_offset = offset + 4;

   /* For each attribute display the associated fields */
   for (guint32 attribute = 0; attribute < attribute_cnt; attribute++)
   {
      /* At a minimum the local offset needs to be incremented by 4 bytes to reach the next attribute */
      guint8 increment_size = 4;

      /* Pull the fields for this attribute from the payload, all fields are needed to make some calculations before
      * properly displaying of the attribute is possible */
      guint8 dimension = tvb_get_guint8(tvb, local_offset + 2);
      guint32 attribute_size = tvb_get_guint8(tvb, local_offset + 3);
      guint8 attribute_start = 4;

      if (dimension == 1)
      {
         guint16 data_elements = tvb_get_letohs(tvb, local_offset + 6);

         /* Modify the size of the attribute data by the number of elements if the request is an array request */
         attribute_size *= data_elements;

         /* Modify the amount to update the local offset by and the start of the data to include the index and elements field */
         increment_size  += 4;
         attribute_start += 4;
      }

      /* Display the fields associated with the get axis attribute list response */
      guint32 attribute_id;
      attr_item = proto_tree_add_item_ret_uint(header_tree, hf_get_axis_attr_list_attribute_id, tvb, local_offset, 2, ENC_LITTLE_ENDIAN, &attribute_id);
      attr_tree = proto_item_add_subtree(attr_item, ett_get_axis_attr_list);

      if (dimension == 0xFF)
      {
         /* Display the element size as an error code if the dimension field indicates an error */
         proto_tree_add_item(attr_tree, hf_cip_svc_get_axis_attr_sts, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);

         /* No attribute data so no attribute size */
         attribute_size = 0;
      }
      else
      {
         proto_tree_add_item(attr_tree, hf_get_axis_attr_list_dimension, tvb, local_offset + 2, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(attr_tree, hf_get_axis_attr_list_element_size, tvb, local_offset + 3, 1, ENC_LITTLE_ENDIAN);

         if (dimension == 1)
         {
            /* Display the start index and start index from the request */
            proto_tree_add_item(attr_tree, hf_get_axis_attr_list_start_index, tvb, local_offset + 4, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(attr_tree, hf_get_axis_attr_list_data_elements, tvb, local_offset + 6, 2, ENC_LITTLE_ENDIAN);
         }

         int parsed_len = dissect_motion_attribute(pinfo, tvb, local_offset + attribute_start, attribute_id,
            instance_id, attr_item, attr_tree, dimension, attribute_size);

         // Display the raw attribute data if configured. Otherwise, just show the remaining unparsed data
         if (display_full_attribute_data)
         {
            proto_tree_add_item(attr_tree, hf_cip_attribute_data, tvb, local_offset + attribute_start, attribute_size, ENC_NA);
         }
         else if ((attribute_size - parsed_len) > 0)
         {
            proto_tree_add_item(attr_tree, hf_cip_attribute_data, tvb, local_offset + attribute_start + parsed_len, attribute_size - parsed_len, ENC_NA);
         }

         /* Round the attribute size up so the next attribute lines up on a 32-bit boundary */
         if (attribute_size % 4 != 0)
         {
             attribute_size = attribute_size + (4 - (attribute_size % 4));
         }
      }

      /* Move the local offset to the next attribute */
      local_offset += (attribute_size + increment_size);
   }
}

/*
 * Function name: dissect_group_sync_response
 *
 * Purpose: Dissect the group sync service response
 *
 * Returns: None
 */
static void
dissect_group_sync_response (tvbuff_t* tvb, proto_tree* tree, guint32 offset)
{
   proto_tree_add_item(tree, hf_cip_group_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

/*
 * Function name: dissect_devce_service
 *
 * Purpose: Dissect the service data block in a device to controller message
 *
 * Returns: The new offset into the message that follow on dissections should use
 * as their starting offset
 */
static guint32
dissect_devce_service(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint32 offset, guint32 size, guint32 instance_id)
{
   proto_tree *header_tree;

   /* Create the tree for the entire service data block */
   proto_item* item;
   header_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_service, &item, "Service Data Block");

   /* Display the transaction id value */
   proto_tree_add_item(header_tree, hf_cip_svc_transction, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the service code */
   guint32 service_code;
   proto_tree_add_item_ret_uint(header_tree, hf_cip_svc_code, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN, &service_code);

   /* Display the general status code */
   proto_tree_add_item(header_tree, hf_cip_svc_sts, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   /* Display the extended status code */
   proto_tree_add_item(header_tree, hf_cip_svc_ext_status, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);

   /* If the service is a set axis, get axis attribute response or group sync dissect it as well */
   if (size > 4)
   {
       switch (service_code)
       {
       case SC_GET_AXIS_ATTRIBUTE_LIST:
           dissect_get_axis_attr_list_response(pinfo, tvb, header_tree, offset + 4, size - 4, instance_id);
           break;
       case SC_SET_AXIS_ATTRIBUTE_LIST:
           dissect_set_axis_attr_list_response(tvb, header_tree, offset + 4, size - 4, instance_id);
           break;
       case SC_GROUP_SYNC:
           dissect_group_sync_response(tvb, header_tree, offset + 4);
           break;
       case SC_SET_CYCLIC_WRITE_LIST:
          dissect_set_cyclic_list_respone(tvb, header_tree, offset + 4, size - 4, instance_id, "Set Cyclic Write List Response");
          break;
       case SC_SET_CYCLIC_READ_LIST:
          dissect_set_cyclic_list_respone(tvb, header_tree, offset + 4, size - 4, instance_id, "Set Cyclic Read List Response");
          break;
       case SC_SET_ATT_LIST:
       {
          cip_simple_request_info_t motion_path;
          motion_path.iClass = CI_CLS_MOTION;
          motion_path.iInstance = instance_id;

          tvbuff_t* tvb_set_attr = tvb_new_subset_length(tvb, offset + 4, size - 4);
          dissect_cip_set_attribute_list_rsp(tvb_set_attr, pinfo, header_tree, item, 0, &motion_path);
          break;
       }
       default:
           /* Display the remainder of the service channel data */
           proto_tree_add_item(header_tree, hf_cip_svc_data, tvb, offset + 4, size - 4, ENC_NA);
           break;
       }
   }

   return offset + size;
}

/*
 * Function name: dissect_var_inst_header
 *
 * Purpose: Dissect the instance data header of a variable controller to device or
 * device to controller message
 *
 * Returns: void
 */
static void
dissect_var_inst_header(tvbuff_t* tvb, proto_tree* tree, guint32 offset, guint8* inst_number, guint32* cyc_size,
                        guint32* cyc_blk_size, guint32* evnt_size, guint32* servc_size)
{
   proto_tree *header_tree;

   /* Create the tree for the entire instance data header */
   *inst_number = tvb_get_guint8(tvb, offset);

   header_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8, ett_inst_data_header, NULL,
                                                "Instance Data Header - Instance: %d", *inst_number);

   /* Read the instance number field from the instance data header */
   proto_tree_add_item(header_tree, hf_var_devce_instance, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* The "size" fields in the instance data block header are all stored as number of 32-bit words the
   * block uses since all blocks should pad up to 32-bits so to convert to bytes each is multiplied by 4 */

   /* Read the instance block size field in bytes from the instance data header */
   proto_tree_add_item(header_tree, hf_var_devce_instance_block_size, tvb, offset + 2, 1, ENC_NA);

   /* Read the cyclic block size field in bytes from the instance data header */
   proto_tree_add_item(header_tree, hf_var_devce_cyclic_block_size, tvb, offset + 3, 1, ENC_NA);

   /* Read the cyclic command block size field in bytes from the instance data header */
   *cyc_size = (tvb_get_guint8(tvb, offset + 4) * 4);
   proto_tree_add_item(header_tree, hf_var_devce_cyclic_data_block_size, tvb, offset + 4, 1, ENC_NA);

   /* Read the cyclic write block size field in bytes from the instance data header */
   *cyc_blk_size = (tvb_get_guint8(tvb, offset + 5) * 4);
   proto_tree_add_item(header_tree, hf_var_devce_cyclic_rw_block_size, tvb, offset + 5, 1, ENC_NA);

   /* Read the event block size in bytes from the instance data header */
   *evnt_size = (tvb_get_guint8(tvb, offset + 6) * 4);
   proto_tree_add_item(header_tree, hf_var_devce_event_block_size, tvb, offset + 6, 1, ENC_NA);

   /* Read the service block size in bytes from the instance data header */
   *servc_size = (tvb_get_guint8(tvb, offset + 7) * 4);
   proto_tree_add_item(header_tree, hf_var_devce_service_block_size, tvb, offset + 7, 1, ENC_NA);
}

/*
 * Function name: dissect_var_cont_conn_header
 *
 * Purpose: Dissect the connection header of a variable controller to device message
 *
 * Returns: Offset to the start of the instance data block
 */
static guint32
dissect_var_cont_conn_header(tvbuff_t* tvb, proto_tree* tree, guint32* inst_count, guint32 offset)
{
   guint32     header_size;
   proto_tree *header_tree;

   /* Calculate the header size, start with the basic header size */
   header_size = 8;

   guint32 time_data_set = tvb_get_guint8(tvb, offset + 7);

   /* Check the time data set field for enabled bits. If either update period or
   * update time stamp fields are set, bump the header size by the appropriate size */
   if ( (time_data_set & TIME_DATA_SET_TIME_STAMP) == TIME_DATA_SET_TIME_STAMP )
   {
      header_size += 8;
   }
   if ( (time_data_set & TIME_DATA_SET_TIME_OFFSET) == TIME_DATA_SET_TIME_OFFSET )
   {
      header_size += 8;
   }

   /* Create the tree for the entire connection header */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, header_size, ett_cont_dev_header, NULL, "Connection Header");

   /* Add the connection header fields that are common to all types of messages */
   proto_tree_add_item(header_tree, hf_cip_format,   tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(header_tree, hf_cip_revision, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(header_tree, hf_cip_updateid, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   dissect_node_control(NULL, header_tree, NULL, tvb, offset + 3, 1);

   /* Add the instance count and last update id to the connection header tree */
   proto_tree_add_item_ret_uint(header_tree, hf_cip_instance_cnt, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN, inst_count);
   proto_tree_add_item(header_tree, hf_cip_last_update, tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);

   dissect_time_data_set(NULL, header_tree, NULL, tvb, offset + 7, 1);

   /* Move the offset to the byte just beyond the time data set field */
   offset = (offset + 7 + 1);

   /* Add the time values if they are present in the time data set header field */
   if ( (time_data_set & TIME_DATA_SET_TIME_STAMP) == TIME_DATA_SET_TIME_STAMP )
   {
      proto_tree_add_item(header_tree, hf_cip_cont_time_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset = (offset + 8);
   }

   if ( (time_data_set & TIME_DATA_SET_TIME_OFFSET) == TIME_DATA_SET_TIME_OFFSET )
   {
      proto_tree_add_item(header_tree, hf_cip_cont_time_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset = (offset + 8);
   }

   /* Return the number of bytes used so it can be used as an offset in the following dissections */
   return offset;
}

/*
 * Function name: dissect_var_devce_conn_header
 *
 * Purpose: Dissect the connection header of a variable device to controller message
 *
 * Returns: Offset to the start of the instance data block
 */
static guint32
dissect_var_devce_conn_header(tvbuff_t* tvb, proto_tree* tree, guint32* inst_count, guint32 offset)
{
   guint32     header_size;
   proto_tree *header_tree;

   /* Calculate the header size, start with the basic header size */
   header_size = 8;

   guint32 time_data_set = tvb_get_guint8(tvb, offset + 7);
   if ( (time_data_set & TIME_DATA_SET_TIME_STAMP) == TIME_DATA_SET_TIME_STAMP )
   {
      header_size += 8;
   }
   if ( (time_data_set & TIME_DATA_SET_TIME_OFFSET) == TIME_DATA_SET_TIME_OFFSET )
   {
      header_size += 8;
   }
   if ( (time_data_set & TIME_DATA_SET_UPDATE_DIAGNOSTICS) == TIME_DATA_SET_UPDATE_DIAGNOSTICS )
   {
      header_size += 4;
   }
   if ( (time_data_set & TIME_DATA_SET_TIME_DIAGNOSTICS) == TIME_DATA_SET_TIME_DIAGNOSTICS )
   {
      header_size += 16;
   }

   /* Create the tree for the entire connection header */
   header_tree = proto_tree_add_subtree(tree, tvb, offset, header_size, ett_cont_dev_header, NULL, "Connection Header");

   /* Add the connection header fields that are common to all types of messages */
   proto_tree_add_item(header_tree, hf_cip_format,   tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(header_tree, hf_cip_revision, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(header_tree, hf_cip_updateid, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);

   dissect_node_status(NULL, header_tree, NULL, tvb, offset + 3, 1);

   /* Add the instance count to the connection header tree */
   proto_tree_add_item_ret_uint(header_tree, hf_cip_instance_cnt, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN, inst_count);

   /* The device to controller header contains the node alarms and node faults fields as well. */
   proto_tree_add_item(header_tree, hf_cip_node_fltalarms, tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);

   /* Add the last update id to the connection header tree */
   proto_tree_add_item(header_tree, hf_cip_last_update, tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);

   dissect_time_data_set(NULL, header_tree, NULL, tvb, offset + 7, 1);

   /* Move the offset to the byte just beyond the time data set field */
   offset = (offset + 7 + 1);

   /* Add the time values if they are present in the time data set header field */
   if ( (time_data_set & TIME_DATA_SET_TIME_STAMP) == TIME_DATA_SET_TIME_STAMP )
   {
      proto_tree_add_item(header_tree, hf_cip_devc_time_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset = (offset + 8);
   }

   if ( (time_data_set & TIME_DATA_SET_TIME_OFFSET) == TIME_DATA_SET_TIME_OFFSET )
   {
      proto_tree_add_item(header_tree, hf_cip_devc_time_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset = (offset + 8);
   }

   if ( (time_data_set & TIME_DATA_SET_UPDATE_DIAGNOSTICS) == TIME_DATA_SET_UPDATE_DIAGNOSTICS )
   {
      /* If the time diagnostic bit is set then the header contains the count of lost updates, late updates, data
      * received time stamp and data transmit time stamp */
      proto_tree_add_item(header_tree, hf_cip_lost_update, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset = (offset + 1);

      /* Add the reserved bytes to the offset after adding the late updates to the display */
      proto_tree_add_item(header_tree, hf_cip_late_update, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset = (offset + 3);
   }

   if ( (time_data_set & TIME_DATA_SET_TIME_DIAGNOSTICS) == TIME_DATA_SET_TIME_DIAGNOSTICS )
   {
      proto_tree_add_item(header_tree, hf_cip_data_rx_time_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;

      proto_tree_add_item(header_tree, hf_cip_data_tx_time_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;
   }

   /* Return the number of bytes used so it can be used as an offset in the following dissections */
   return offset;
}


/*
 * Function name: dissect_cipmotion
 *
 * Purpose: Perform the top level dissection of the CIP Motion datagram, it is called by
 * Wireshark when the dissection rule registered in proto_reg_handoff_cipmotion is fired
 *
 * Returns: void
 */
static int
dissect_cipmotion(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
   cip_io_data_input* io_data_input = (cip_io_data_input*)data;

   guint32     con_format;
   guint32     update_id;
   proto_item *proto_item_top;
   proto_tree *proto_tree_top;
   guint32     offset = 0;

   guint8 ConnPoint = 2;
   if (io_data_input && io_data_input->conn_info)
   {
      ConnPoint = io_data_input->conn_info->ConnPoint;
   }

   /* Create display subtree for the protocol by creating an item and then
    * creating a subtree from the item, the subtree must have been registered
    * in proto_register_cipmotion already */
   proto_item_top = proto_tree_add_item(tree, proto_cipmotion, tvb, 0, -1, ENC_NA);
   proto_tree_top = proto_item_add_subtree(proto_item_top, ett_cipmotion);

   /* Add the CIP class 1 sequence number to the tree */
   proto_tree_add_item(proto_tree_top, hf_cip_class1_seqnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
   offset = (offset + 2);

   if (ConnPoint >= 3)
   {
       dissect_cip_run_idle(tvb, offset, proto_tree_top);
       offset += 4;
   }

   /* Pull the actual values for the connection format and update id from the
    * incoming message to be used in the column info */
   con_format = tvb_get_guint8(tvb, offset);
   update_id  = tvb_get_guint8(tvb, offset + 2);

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP Motion");

   /* Add connection format and update number to the info column */
   col_add_fstr( pinfo->cinfo, COL_INFO, "%s, Update Id: %d",
                 val_to_str(con_format, cip_con_format_vals, "Unknown connection format (%x)"), update_id );

   /* Attempt to classify the incoming header */
   if (( con_format == FORMAT_VAR_CONTROL_TO_DEVICE ) ||
       ( con_format == FORMAT_VAR_DEVICE_TO_CONTROL ))
   {
      /* Sizes of the individual channels within the connection */
      guint32 cyc_size, cyc_blk_size, evnt_size, servc_size;
      guint32 inst_count = 0, inst;
      guint32 format_rev = 0;

      /* Dissect the header fields */
      switch(con_format)
      {
      case FORMAT_VAR_CONTROL_TO_DEVICE:
         format_rev = tvb_get_guint8(tvb, offset + 1);
         offset = dissect_var_cont_conn_header(tvb, proto_tree_top, &inst_count, offset);
         break;
      case FORMAT_VAR_DEVICE_TO_CONTROL:
         format_rev = tvb_get_guint8(tvb, offset + 1);
         offset = dissect_var_devce_conn_header(tvb, proto_tree_top, &inst_count, offset);
         break;
      }

      if (format_rev != ConnPoint)
      {
         expert_add_info(pinfo, proto_item_top, &ei_format_rev_conn_pt);
      }

      /* Repeat the following dissections for each instance within the payload */
      for( inst = 0; inst < inst_count; inst++ )
      {
         /* Actual instance number from header field */
         guint8 instance;

         /* Dissect the instance data header */
         dissect_var_inst_header( tvb, proto_tree_top, offset, &instance,
                                    &cyc_size, &cyc_blk_size, &evnt_size, &servc_size );

         /* Increment the offset to just beyond the instance header */
         offset += 8;

         /* Dissect the cyclic command (actual) data if any exists */
         /* Dissect the cyclic write (read) data if any exists */
         /* Dissect the event data block if there is any event data */
         switch(con_format)
         {
         case FORMAT_VAR_CONTROL_TO_DEVICE:
            if ( cyc_size > 0 )
               offset = dissect_cntr_cyclic(tvb, proto_tree_top, offset, cyc_size);
            if ( cyc_blk_size > 0 )
               offset = dissect_cyclic_wt(tvb, proto_tree_top, offset, cyc_blk_size);
            if ( evnt_size > 0 )
               offset = dissect_cntr_event(tvb, proto_tree_top, offset, evnt_size);
            if ( servc_size > 0 )
               offset = dissect_cntr_service(tvb, pinfo, proto_tree_top, offset, servc_size, instance);
            break;
         case FORMAT_VAR_DEVICE_TO_CONTROL:
            if ( cyc_size > 0 )
               offset = dissect_device_cyclic(tvb, proto_tree_top, offset, cyc_size);
            if ( cyc_blk_size > 0 )
               offset = dissect_cyclic_rd( tvb, proto_tree_top, offset, cyc_blk_size );
            if ( evnt_size > 0 )
               offset = dissect_devce_event(tvb, proto_tree_top, offset, evnt_size);
            if ( servc_size > 0 )
               offset = dissect_devce_service(tvb, pinfo, proto_tree_top, offset, servc_size, instance);
            break;
         }

      } /* End of instance for( ) loop */
   }

   // Display any remaining unparsed data.
   int remain_len = tvb_reported_length_remaining(tvb, offset);
   if (remain_len > 0)
   {
      proto_tree_add_item(proto_tree_top, hf_cip_data, tvb, offset, remain_len, ENC_NA);
   }

   return tvb_captured_length(tvb);
}

static int dissect_cipmotion3(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
   enip_conn_val_t conn_info = {0};
   conn_info.ConnPoint = 3;

   cip_io_data_input io_data_input;
   io_data_input.conn_info = &conn_info;

   return dissect_cipmotion(tvb, pinfo, tree, &io_data_input);
}

int dissect_motion_configuration_block(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* item, int offset)
{
   proto_item* config_item;
   proto_tree* config_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_configuration_block, &config_item, "Motion Configuration Block");

   proto_tree_add_item(config_tree, hf_configuration_block_format_rev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   int parsed_len = 1;

   parsed_len += dissect_connection_configuration_bits(pinfo, config_tree, item, tvb, offset + parsed_len, 1);

   // 2 reserved bytes
   parsed_len += 2;

   proto_tree_add_item(config_tree, hf_configuration_block_drive_power_struct_id, tvb, offset + parsed_len, 4, ENC_LITTLE_ENDIAN);
   parsed_len += 4;

   proto_item_set_len(config_item, parsed_len);

   return parsed_len;
}

/*
 * Function name: proto_register_cipmotion
 *
 * Purpose: Register the protocol with Wireshark, a script will add this protocol
 * to the list of protocols during the build process. This function is where the
 * header fields and subtree identifiers are registered.
 *
 * Returns: void
 */
void
proto_register_cipmotion(void)
{
   /* This is a list of header fields that can be used in the dissection or
   * to use in a filter expression */
   static hf_register_info hf[] =
   {
      /* Connection format header field, the first byte in the message which
      * determines if the message is fixed or variable, controller to device,
      * device to controller, etc. */
      { &hf_cip_format,
        { "Connection Format", "cipm.format",
          FT_UINT8, BASE_DEC, VALS(cip_con_format_vals), 0,
          "Message connection format", HFILL }
      },

      /* Connection format revision header field */
      { &hf_cip_revision,
        { "Format Revision", "cipm.revision",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Message format revision", HFILL }
      },

      { &hf_cip_class1_seqnum,
        { "CIP Class 1 Sequence Count", "cipm.class1seqnum",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },

      { &hf_configuration_block_format_rev,
        { "Format Revision", "cipm.config.format_rev",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },

      { &hf_configuration_block_drive_power_struct_id,
        { "Drive Power Structure Class ID", "cipm.config.drive_class_id",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },

      { &hf_cip_updateid,
        { "Update Id", "cipm.updateid",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Transaction Number", HFILL }
      },
      { &hf_cip_instance_cnt,
        { "Instance Count", "cipm.instancecount",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_last_update,
        { "Last Update Id", "cipm.lastupdate",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_node_status,
        { "Node Status", "cipm.nodestatus",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_node_control,
        { "Node Control", "cipm.nodecontrol",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_node_control_remote,
        { "Remote Control", "cipm.remote",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01,
          "Node Control: Remote Control", HFILL}
      },
      { &hf_cip_node_control_sync,
        { "Sync Control", "cipm.sync",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
          "Node Control: Synchronous Operation", HFILL}
      },
      { &hf_cip_node_data_valid,
        { "Data Valid", "cipm.valid",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
          "Node Control: Data Valid", HFILL}
      },
      { &hf_cip_node_fault_reset,
        { "Node Fault Reset", "cipm.fltrst",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
          "Node Control: Node Fault Reset", HFILL}
      },
      { &hf_cip_node_device_faulted,
        { "Faulted", "cipm.flt",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
          "Node Control: Device Faulted", HFILL}
      },
      { &hf_cip_node_fltalarms,
        { "Node Faults and Alarms", "cipm.fltalarms",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_time_data_set,
        { "Time Data Set", "cipm.timedataset",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_time_data_stamp,
        { "Time Stamp", "cipm.time.stamp",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), TIME_DATA_SET_TIME_STAMP,
          "Time Data Set: Time Stamp", HFILL}
      },
      { &hf_cip_time_data_offset,
        { "Time Offset", "cipm.time.offset",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), TIME_DATA_SET_TIME_OFFSET,
          "Time Data Set: Time Offset", HFILL}
      },
      { &hf_cip_time_data_diag,
        { "Update Diagnostics", "cipm.time.update",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), TIME_DATA_SET_UPDATE_DIAGNOSTICS,
          "Time Data Set: Update Diagnostics", HFILL}
      },
      { &hf_cip_time_data_time_diag,
        { "Time Diagnostics", "cipm.time.diag",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), TIME_DATA_SET_TIME_DIAGNOSTICS,
          "Time Data Set: Time Diagnostics", HFILL}
      },

      { &hf_cip_cont_time_stamp,
        { "Controller Time Stamp", "cipm.ctrltimestamp",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Time Data Set: Controller Time Stamp", HFILL}
      },
      { &hf_cip_cont_time_offset,
        { "Controller Time Offset", "cipm.ctrltimeoffser",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Time Data Set: Controller Time Offset", HFILL}
      },
      { &hf_cip_data_rx_time_stamp,
        { "Data Received Time Stamp", "cipm.rxtimestamp",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Time Data Set: Data Received Time Stamp", HFILL}
      },
      { &hf_cip_data_tx_time_stamp,
        { "Data Transmit Time Stamp", "cipm.txtimestamp",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Time Data Set: Data Transmit Time Offset", HFILL}
      },
      { &hf_cip_devc_time_stamp,
        { "Device Time Stamp", "cipm.devctimestamp",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_nanosecond_nanoseconds, 0,
          "Time Data Set: Device Time Stamp", HFILL}
      },
      { &hf_cip_devc_time_offset,
        { "Device Time Offset", "cipm.devctimeoffser",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Time Data Set: Device Time Offset", HFILL}
      },
      { &hf_cip_lost_update,
        { "Lost Updates", "cipm.lostupdates",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Time Data Set: Lost Updates", HFILL}
      },
      { &hf_cip_late_update,
        { "Lost Updates", "cipm.lateupdates",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Time Data Set: Late Updates", HFILL}
      },

      { &hf_cip_motor_cntrl,
        { "Control Mode", "cipm.ctrlmode",
          FT_UINT8, BASE_DEC, VALS(cip_motor_control_vals), 0,
          "Cyclic Data Block: Motor Control Mode", HFILL }
      },

      { &hf_cip_feedback,
        { "Feedback Information", "cipm.feedback",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_feedback_mode,
        { "Feedback Mode", "cipm.feedback_mode",
          FT_UINT8, BASE_DEC, VALS(cip_feedback_mode_vals), FEEDBACK_MODE_BITS,
          NULL, HFILL }
      },
      { &hf_cip_feedback_data_type,
        { "Feedback Data Type", "cipm.feedback_data_type",
          FT_UINT8, BASE_DEC, VALS(cip_feedback_type_vals), FEEDBACK_DATA_TYPE_BITS,
          NULL, HFILL }
      },

      { &hf_connection_configuration_bits,
        { "Connection Configuration Bits", "cipm.ccb",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_connection_configuration_bits_power,
        { "Verify Power Ratings", "cipm.ccb.verify_power_ratings",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01,
          NULL, HFILL } },
      { &hf_connection_configuration_bits_safety_bit_valid,
        { "Networked Safety Bit Valid", "cipm.ccb.networked_safety_bit_valid",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
          NULL, HFILL } },
      { &hf_connection_configuration_bits_allow_network_safety,
        { "Allow Networked Safety", "cipm.ccb.allow_networked_safety",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
          NULL, HFILL } },

      { &hf_cip_axis_control,
        { "Axis Control", "cipm.axisctrl",
          FT_UINT8, BASE_DEC, VALS(cip_axis_control_vals), 0,
          "Cyclic Data Block: Axis Control", HFILL }
      },
      { &hf_cip_control_status,
        { "Control Status", "cipm.csts",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Axis Control Status", HFILL }
      },
      { &hf_cip_control_status_complete,
        { "Configuration Complete", "cipm.control_status.complete",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01,
          NULL, HFILL } },
      { &hf_cip_control_status_bus_up,
        { "Converter Bus Up", "cipm.control_status.bus_up",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
          NULL, HFILL } },
      { &hf_cip_control_status_bus_unload,
        { "Converter Bus Unload", "cipm.control_status.bus_unload",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
          NULL, HFILL } },
      { &hf_cip_control_status_power_loss,
        { "Converter AC Power Loss", "cipm.control_status.power_loss",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10,
          NULL, HFILL } },
      { &hf_cip_axis_response,
        { "Axis Response", "cipm.axisresp",
          FT_UINT8, BASE_DEC, VALS(cip_axis_response_vals), 0,
          "Cyclic Data Block: Axis Response", HFILL }
      },
      { &hf_cip_axis_resp_stat,
        { "Response Status", "cipm.respstat",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          "Cyclic Data Block: Axis Response Status", HFILL }
      },
      { &hf_cip_group_sync,
        { "Group Sync Status", "cipm.syncstatus",
          FT_UINT8, BASE_HEX, VALS(cip_sync_status_vals), 0,
          NULL, HFILL }
      },
      { &hf_cip_cmd_data_set,
        { "Command Data Set", "cipm.cmdset",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_act_data_set,
        { "Actual Data Set", "cipm.actset",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_sts_data_set,
        { "Status Data Set", "cipm.stsset",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_cmd_data_pos_cmd,
        { "Command Position", "cipm.cmd.pos",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), COMMAND_DATA_SET_POSITION,
          "Command Data Set: Command Position", HFILL}
      },
      { &hf_cip_cmd_data_vel_cmd,
        { "Command Velocity", "cipm.cmd.vel",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), COMMAND_DATA_SET_VELOCITY,
          "Command Data Set: Command Velocity", HFILL}
      },
      { &hf_cip_cmd_data_acc_cmd,
        { "Command Acceleration", "cipm.cmd.acc",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), COMMAND_DATA_SET_ACCELERATION,
          "Command Data Set: Command Acceleration", HFILL}
      },
      { &hf_cip_cmd_data_trq_cmd,
        { "Command Torque", "cipm.cmd.trq",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), COMMAND_DATA_SET_TORQUE,
          "Command Data Set: Command Torque", HFILL}
      },
      { &hf_cip_act_data_pos,
        { "Actual Position", "cipm.act.pos",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), ACTUAL_DATA_SET_POSITION,
          "Actual Data Set: Actual Position", HFILL}
      },
      { &hf_cip_act_data_vel,
        { "Actual Velocity", "cipm.act.vel",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), ACTUAL_DATA_SET_VELOCITY,
          "Actual Data Set: Actual Velocity", HFILL}
      },
      { &hf_cip_act_data_acc,
        { "Actual Acceleration", "cipm.act.acc",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), ACTUAL_DATA_SET_ACCELERATION,
          "Actual Data Set: Actual Acceleration", HFILL}
      },
      { &hf_cip_axis_fault,
        { "Axis Fault Code", "cipm.fault.code",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Status Data Set: Fault Code", HFILL }
      },
      { &hf_cip_fault_type,
        { "Axis Fault Type", "cipm.flttype",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Fault Type", HFILL}
      },
      { &hf_cip_fault_sub_code,
        { "Axis Fault Sub Code", "cipm.fltsubcode",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Fault Sub Code", HFILL}
      },
      { &hf_cip_fault_action,
        { "Axis Fault Action", "cipm.fltaction",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Fault Action", HFILL}
      },
      { &hf_cip_fault_time_stamp,
        { "Axis Fault Time Stamp", "cipm.flttimestamp",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Axis Status: Axis Fault Time Stamp", HFILL}
      },
      { &hf_cip_alarm_type,
        { "Axis Fault Type", "cipm.alarmtype",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Alarm Type", HFILL}
      },
      { &hf_cip_alarm_sub_code,
        { "Axis Alarm Sub Code", "cipm.alarmsubcode",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Alarm Sub Code", HFILL}
      },
      { &hf_cip_alarm_state,
        { "Axis Alarm State", "cipm.alarmstate",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Axis Status: Axis Alarm State", HFILL }
      },
      { &hf_cip_alarm_time_stamp,
        { "Axis Fault Time Stamp", "cipm.alarmtimestamp",
          FT_UINT64, BASE_DEC, NULL, 0,
          "Axis Status: Axis Alarm Time Stamp", HFILL}
      },
      { &hf_cip_axis_status,
        { "Axis Status", "cipm.axisstatus",
          FT_UINT32, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_axis_status_mfg,
        { "Axis Status Mfg", "cipm.axisstatusmfg",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Axis Status, Manufacturer Specific", HFILL}
      },
      { &hf_cip_axis_io_status,
        { "Axis I/O Status", "cipm.axisiostatus",
          FT_UINT32, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_axis_io_status_mfg,
        { "Axis I/O Status Mfg", "cipm.axisiostatusmfg",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Axis I/O Status, Manufacturer Specific", HFILL}
      },
      { &hf_cip_axis_safety_status,
        { "Axis Safety Status", "cipm.safetystatus",
          FT_UINT32, BASE_HEX, NULL, 0,
          NULL, HFILL}
      },
      { &hf_cip_axis_safety_status_mfg,
        { "Axis Safety Status Mfg", "cipm.safetystatusmfg",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Axis Safety Status, Manufacturer Specific", HFILL}
      },
      { &hf_cip_axis_safety_state,
        { "Axis Safety State", "cipm.safetystate",
          FT_UINT8, BASE_HEX, NULL, 0,
          "Axis Safety Sate", HFILL}
      },
      { &hf_cip_sts_flt,
        { "Axis Fault Codes", "cipm.sts.flt",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), STATUS_DATA_SET_AXIS_FAULT,
          "Status Data Set: Axis Fault Codes", HFILL}
      },
      { &hf_cip_sts_alrm,
        { "Axis Alarm Codes", "cipm.sts.alarm",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), STATUS_DATA_SET_AXIS_ALARM,
          "Status Data Set: Axis Alarm Codes", HFILL}
      },
      { &hf_cip_sts_sts,
        { "Axis Status", "cipm.sts.sts",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), STATUS_DATA_SET_AXIS_STATUS,
          "Status Data Set: Axis Status", HFILL}
      },
      { &hf_cip_sts_iosts,
        { "Axis I/O Status", "cipm.sts.iosts",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), STATUS_DATA_SET_AXIS_IO_STATUS,
          "Status Data Set: Axis I/O Status", HFILL}
      },
      { &hf_cip_sts_axis_safety,
        { "Axis Safety Status", "cipm.sts.safety",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), STATUS_DATA_SET_AXIS_SAFETY,
          "Status Data Set: Axis Safety Status", HFILL}
      },
      { &hf_cip_intrp,
        { "Command Target Update", "cipm.intrp",
          FT_UINT8, BASE_DEC, VALS(cip_interpolation_vals), COMMAND_CONTROL_TARGET_UPDATE,
          "Cyclic Data Block: Command Target Update", HFILL}
      },
      { &hf_cip_position_data_type,
        { "Command Position Data Type", "cipm.posdatatype",
          FT_UINT8, BASE_DEC, VALS(cip_pos_data_type_vals), COMMAND_CONTROL_POSITION_DATA_TYPE,
          "Cyclic Data Block: Command Position Data Type", HFILL }
      },
      { &hf_cip_axis_state,
        { "Axis State", "cipm.axste",
          FT_UINT8, BASE_DEC, VALS(cip_axis_state_vals), 0,
          "Cyclic Data Block: Axis State", HFILL}
      },
      { &hf_cip_command_control,
        { "Command Control", "cipm.cmdcontrol",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Command Control", HFILL }
      },
      { &hf_cip_cyclic_wrt_data,
        { "Write Data", "cipm.writedata",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Cyclic Write: Data", HFILL }
      },
      { &hf_cip_cyclic_rd_data,
        { "Read Data", "cipm.readdata",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Cyclic Read: Data", HFILL }
      },
      { &hf_cip_cyclic_write_blk,
        { "Write Block", "cipm.writeblk",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Write Block Id", HFILL }
      },
      { &hf_cip_cyclic_read_blk,
        { "Read Block", "cipm.readblk",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Read Block Id", HFILL}
      },
      { &hf_cip_cyclic_write_sts,
        { "Write Status", "cipm.writests",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Write Status", HFILL }
      },
      { &hf_cip_cyclic_read_sts,
        { "Read Status", "cipm.readsts",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Cyclic Data Block: Read Status", HFILL }
      },
      { &hf_cip_event_checking,
        { "Event Checking Control", "cipm.evntchkcontrol",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Event Channel: Event Checking Control", HFILL}
      },
      { &hf_cip_event_ack,
        { "Event Acknowledgement", "cipm.evntack",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Event Channel: Event Acknowledgement", HFILL}
      },
      { &hf_cip_event_status,
        { "Event Checking Status", "cipm.evntchkstatus",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Event Channel: Event Checking Status", HFILL}
      },
      { &hf_cip_event_id,
        { "Event Id", "cipm.evntack",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Event Channel: Event Id", HFILL }
      },
      { &hf_cip_event_pos,
        { "Event Position", "cipm.evntpos",
          FT_INT32, BASE_DEC, NULL, 0,
          "Event Channel: Event Position", HFILL}
      },
      { &hf_cip_event_ts,
        { "Event Time Stamp", "cipm.evntimestamp",
          FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_nanosecond_nanoseconds, 0,
          "Event Channel: Time Stamp", HFILL}
      },

      { &hf_cip_evnt_ctrl_reg1_pos,
        { "Reg 1 Pos Edge", "cipm.evnt.ctrl.reg1posedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000001,
          "Event Checking Control: Reg 1 Pos Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg1_neg,
        { "Reg 1 Neg Edge", "cipm.evnt.ctrl.reg1negedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000002,
          "Event Checking Control: Reg 1 Neg Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg2_pos,
        { "Reg 2 Pos Edge", "cipm.evnt.ctrl.reg2posedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000004,
          "Event Checking Control: Reg 2 Pos Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg2_neg,
        { "Reg 2 Neg Edge", "cipm.evnt.ctrl.reg2negedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000008,
          "Event Checking Control: Reg 2 Neg Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg1_posrearm,
        { "Reg 1 Pos Rearm", "cipm.evnt.ctrl.reg1posrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000100,
          "Event Checking Control: Reg 1 Pos Rearm", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg1_negrearm,
        { "Reg 1 Neg Rearm", "cipm.evnt.ctrl.reg1negrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000200,
          "Event Checking Control: Reg 1 Neg Rearm", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg2_posrearm,
        { "Reg 2 Pos Rearm", "cipm.evnt.ctrl.reg2posrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000400,
          "Event Checking Control: Reg 2 Pos Rearm", HFILL}
      },
      { &hf_cip_evnt_ctrl_reg2_negrearm,
        { "Reg 2 Neg Rearm", "cipm.evnt.ctrl.reg2negrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000800,
          "Event Checking Control: Reg 2 Neg Rearm", HFILL}
      },
      { &hf_cip_evnt_ctrl_marker_pos,
        { "Marker Pos Edge", "cipm.evnt.ctrl.mrkrpos",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00010000,
          "Event Checking Control: Marker Pos Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_marker_neg,
        { "Marker Neg Edge", "cipm.evnt.ctrl.mrkrneg",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00020000,
          "Event Checking Control: Marker Neg Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_pos,
        { "Home Pos Edge", "cipm.evnt.ctrl.homepos",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00040000,
          "Event Checking Control: Home Pos Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_neg,
        { "Home Neg Edge", "cipm.evnt.ctrl.homeneg",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00080000,
          "Event Checking Control: Home Neg Edge", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_pp,
        { "Home-Switch-Marker Plus Plus", "cipm.evnt.ctrl.homepp",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00100000,
          "Event Checking Control: Home-Switch-Marker Plus Plus", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_pm,
        { "Home-Switch-Marker Plus Minus", "cipm.evnt.ctrl.homepm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00200000,
          "Event Checking Control: Home-Switch-Marker Plus Minus", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_mp,
        { "Home-Switch-Marker Minus Plus", "cipm.evnt.ctrl.homemp",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00400000,
          "Event Checking Control: Home-Switch-Marker Minus Plus", HFILL}
      },
      { &hf_cip_evnt_ctrl_home_mm,
        { "Home-Switch-Marker Minus Minus", "cipm.evnt.ctrl.homemm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00800000,
          "Event Checking Control: Home-Switch-Marker Minus Minus", HFILL}
      },
      { &hf_cip_evnt_ctrl_acks,
        { "Event Block Count", "cipm.evnt.ctrl.acks",
          FT_UINT32, BASE_DEC, NULL, 0x70000000,
          "Event Checking Control: Event Block Count", HFILL}
      },
      { &hf_cip_evnt_extend_format,
        { "Extended Event Format", "cipm.evnt.extend",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x80000000,
          "Event Checking Control: Extended Event Format", HFILL}
      },

      { &hf_cip_evnt_sts_reg1_pos,
        { "Reg 1 Pos Edge", "cipm.evnt.sts.reg1posedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000001,
          "Event Checking Status: Reg 1 Pos Edge", HFILL}
      },
      { &hf_cip_evnt_sts_reg1_neg,
        { "Reg 1 Neg Edge", "cipm.evnt.sts.reg1negedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000002,
          "Event Checking Status: Reg 1 Neg Edge", HFILL }
      },
      { &hf_cip_evnt_sts_reg2_pos,
        { "Reg 2 Pos Edge", "cipm.evnt.sts.reg2posedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000004,
          "Event Checking Status: Reg 2 Pos Edge", HFILL}
      },
      { &hf_cip_evnt_sts_reg2_neg,
        { "Reg 2 Neg Edge", "cipm.evnt.sts.reg2negedge",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000008,
          "Event Checking Status: Reg 2 Neg Edge", HFILL}
      },
      { &hf_cip_evnt_sts_reg1_posrearm,
        { "Reg 1 Pos Rearm", "cipm.evnt.sts.reg1posrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000100,
          "Event Checking Status: Reg 1 Pos Rearm", HFILL}
      },
      { &hf_cip_evnt_sts_reg1_negrearm,
        { "Reg 1 Neg Rearm", "cipm.evnt.sts.reg1negrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000200,
          "Event Checking Status: Reg 1 Neg Rearm", HFILL}
      },
      { &hf_cip_evnt_sts_reg2_posrearm,
        { "Reg 2 Pos Rearm", "cipm.evnt.sts.reg2posrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000400,
          "Event Checking Status: Reg 2 Pos Rearm", HFILL}
      },
      { &hf_cip_evnt_sts_reg2_negrearm,
        { "Reg 2 Neg Rearm", "cipm.evnt.sts.reg2negrearm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000800,
          "Event Checking Status: Reg 2 Neg Rearm", HFILL}
      },
      { &hf_cip_evnt_sts_marker_pos,
        { "Marker Pos Edge", "cipm.evnt.sts.mrkrpos",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00010000,
          "Event Checking Status: Marker Pos Edge", HFILL}
      },
      { &hf_cip_evnt_sts_marker_neg,
        { "Marker Neg Edge", "cipm.evnt.sts.mrkrneg",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00020000,
          "Event Checking Status: Marker Neg Edge", HFILL }
      },
      { &hf_cip_evnt_sts_home_pos,
        { "Home Pos Edge", "cipm.evnt.sts.homepos",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00040000,
          "Event Checking Status: Home Pos Edge", HFILL}
      },
      { &hf_cip_evnt_sts_home_neg,
        { "Home Neg Edge", "cipm.evnt.sts.homeneg",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00080000,
          "Event Checking Status: Home Neg Edge", HFILL }
      },
      { &hf_cip_evnt_sts_home_pp,
        { "Home-Switch-Marker Plus Plus", "cipm.evnt.sts.homepp",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00100000,
          "Event Checking Status: Home-Switch-Marker Plus Plus", HFILL}
      },
      { &hf_cip_evnt_sts_home_pm,
        { "Home-Switch-Marker Plus Minus", "cipm.evnt.sts.homepm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00200000,
          "Event Checking Status: Home-Switch-Marker Plus Minus", HFILL}
      },
      { &hf_cip_evnt_sts_home_mp,
        { "Home-Switch-Marker Minus Plus", "cipm.evnt.sts.homemp",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00400000,
          "Event Checking Status: Home-Switch-Marker Minus Plus", HFILL}
      },
      { &hf_cip_evnt_sts_home_mm,
        { "Home-Switch-Marker Minus Minus", "cipm.evnt.sts.homemm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00800000,
          "Event Checking Status: Home-Switch-Marker Minus Minus", HFILL}
      },
      { &hf_cip_evnt_sts_nfs,
        { "Event Block Count", "cipm.evnt.sts.nfs",
          FT_UINT32, BASE_DEC, NULL, 0x70000000,
          "Event Checking Status: Event Block Count", HFILL}
      },

      { &hf_cip_evnt_sts_stat,
        { "Event Status", "cipm.evnt.stat",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          "Event Data Block: Event Status", HFILL }
      },
      { &hf_cip_evnt_type,
        { "Event Type", "cipm.evnt.type",
          FT_UINT8, BASE_DEC, VALS(cip_event_type_vals), 0,
          "Event Data Block: Event Type", HFILL}
      },
      { &hf_cip_svc_code,
        { "Service Code", "cipm.svc.code",
          FT_UINT8, BASE_HEX, VALS(cip_sc_vals), 0,
          "Service Data Block: Service Code", HFILL}
      },
      { &hf_cip_svc_sts,
        { "General Status", "cipm.svc.sts",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          "Service Data Block: General Status", HFILL }
      },
      { &hf_cip_svc_transction,
        { "Transaction Id", "cipm.svc.tranid",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Data Block: Transaction Id", HFILL }
      },
      { &hf_cip_svc_ext_status,
        { "Extended Status", "cipm.svc.extstatus",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Data Block: Extended Status", HFILL }
      },
      { &hf_cip_svc_data,
        { "Service Data", "cipm.svc.data",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Service Data Block: Data", HFILL }
      },
      { &hf_cip_attribute_data,
        { "Attribute Data", "cipm.attrdata",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Attribute Service: Data", HFILL }
      },
      { &hf_cip_ptp_grandmaster,
        { "Grandmaster", "cipm.grandmaster",
          FT_UINT64, BASE_HEX, NULL, 0,
          "Group Sync: Grandmaster Id", HFILL}
      },

      { &hf_cip_svc_get_axis_attr_sts,
        { "Attribute Status", "cipm.getaxisattr.sts",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          "Service Channel: Get Axis Attribute List Response Status", HFILL }
      },
      { &hf_get_axis_attr_list_attribute_cnt,
        { "Number of attributes", "cipm.getaxisattr.cnt",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Attribute Count", HFILL}
      },
      { &hf_get_axis_attr_list_attribute_id,
        { "Attribute ID", "cipm.getaxisattr.id",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Attribute ID", HFILL}
      },
      { &hf_get_axis_attr_list_dimension,
        { "Dimension", "cipm.getaxisattr.dimension",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Dimension", HFILL}
      },
      { &hf_get_axis_attr_list_element_size,
        { "Element size", "cipm.getaxisattr.element_size",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Element Size", HFILL}
      },
      { &hf_get_axis_attr_list_start_index,
        { "Start index", "cipm.getaxisattr.start_index",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Start index", HFILL}
      },
      { &hf_get_axis_attr_list_data_elements,
        { "Data elements", "cipm.getaxisattr.data_elements",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Get Axis Attribute List Data elements", HFILL}
      },

      { &hf_cip_svc_set_axis_attr_sts,
        { "Attribute Status", "cipm.setaxisattr.sts",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          "Service Channel: Set Axis Attribute List Response Status", HFILL }
      },
      { &hf_set_axis_attr_list_attribute_cnt,
        { "Number of attributes", "cipm.setaxisattr.cnt",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Attribute Count", HFILL}
      },
      { &hf_set_axis_attr_list_attribute_id,
        { "Attribute ID", "cipm.setaxisattr.id",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Attribute ID", HFILL}
      },
      { &hf_set_axis_attr_list_dimension,
        { "Dimension", "cipm.setaxisattr.dimension",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Dimension", HFILL}
      },
      { &hf_set_axis_attr_list_element_size,
        { "Element size", "cipm.setaxisattr.element_size",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Element Size", HFILL}
      },
      { &hf_set_axis_attr_list_start_index,
        { "Start index", "cipm.setaxisattr.start_index",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Start index", HFILL}
      },
      { &hf_set_axis_attr_list_data_elements,
        { "Data elements", "cipm.setaxisattr.data_elements",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Service Channel: Set Axis Attribute List Data elements", HFILL}
      },

      { &hf_set_cyclic_list_attribute_cnt,
        { "Number of attributes", "cipm.set_cyclic.cnt",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL}
      },
      { &hf_set_cyclic_list_attribute_id,
        { "Attribute ID", "cipm.set_cyclic.id",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL}
      },
      { &hf_set_cyclic_list_read_block_id,
        { "Cyclic Read Block ID", "cipm.set_cyclic.read_block_id",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL}
      },
      { &hf_set_cyclic_list_attr_sts,
        { "Attribute Status", "cipm.set_cyclic.sts",
          FT_UINT8, BASE_DEC | BASE_EXT_STRING, &cip_gs_vals_ext, 0,
          NULL, HFILL }
      },

      { &hf_var_devce_instance,
        { "Instance Number", "cipm.var_devce.header.instance",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Variable Device Header: Instance Number", HFILL}
      },
      { &hf_var_devce_instance_block_size,
        { "Instance Block Size", "cipm.var_devce.header.instance_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Instance Block Size", HFILL}
      },
      { &hf_var_devce_cyclic_block_size,
        { "Cyclic Block Size", "cipm.var_devce.header.cyclic_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Cyclic Block Size", HFILL}
      },
      { &hf_var_devce_cyclic_data_block_size,
        { "Cyclic Data Block Size", "cipm.var_devce.header.cyclic_data_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Cyclic Data Block Size", HFILL}
      },
      { &hf_var_devce_cyclic_rw_block_size,
        { "Cyclic Read/Write Block Size", "cipm.var_devce.header.cyclic_rw_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Cyclic Read/Write Block Size", HFILL}
      },
      { &hf_var_devce_event_block_size,
        { "Event Block Size", "cipm.var_devce.header.event_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Event Block Size", HFILL}
      },
      { &hf_var_devce_service_block_size,
        { "Service Block Size", "cipm.var_devce.header.service_block_size",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0,
          "Variable Device Header: Service Block Size", HFILL}
      },

      { &hf_cip_axis_alarm,
        { "Axis Alarm Code", "cipm.alarm.code",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Status Data Set: Alarm Code", HFILL }
      },
      { &hf_cip_axis_sts_local_ctrl,
        { "Local Control", "cipm.axis.local",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000001,
          "Axis Status Data Set: Local Control", HFILL }
      },
      { &hf_cip_axis_sts_alarm,
        { "Alarm", "cipm.axis.alarm",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000002,
          "Axis Status Data Set: Alarm", HFILL }
      },
      { &hf_cip_axis_sts_dc_bus,
        { "DC Bus", "cipm.axis.bus",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000004,
          "Axis Status Data Set: DC Bus", HFILL }
      },
      { &hf_cip_axis_sts_pwr_struct,
        { "Power Struct", "cipm.axis.pwr",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000008,
          "Axis Status Data Set: Power Struct", HFILL }
      },
      { &hf_cip_axis_sts_flux_up,
        { "Motor Flux Up", "cipm.axis.flx",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000010,
          "Axis Status Data Set: Motor Flux Up", HFILL }
      },
      { &hf_cip_axis_sts_tracking,
        { "Tracking", "cipm.axis.track",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000020,
          "Axis Status Data Set: Tracking", HFILL }
      },
      { &hf_cip_axis_sts_pos_lock,
        { "Pos Lock", "cipm.axis.poslock",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000040,
          "Axis Status Data Set: Pos Lock", HFILL }
      },
      { &hf_cip_axis_sts_vel_lock,
        { "Vel Lock", "cipm.axis.vellock",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000080,
          "Axis Status Data Set: Vel Lock", HFILL }
      },
      { &hf_cip_axis_sts_vel_standstill,
        { "Vel Standstill", "cipm.axis.nomo",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000100,
          "Axis Status Data Set: Vel Standstill", HFILL }
      },
      { &hf_cip_axis_sts_vel_threshold,
        { "Vel Threshold", "cipm.axis.vthresh",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000200,
          "Axis Status Data Set: Vel Threshold", HFILL }
      },
      { &hf_cip_axis_sts_vel_limit,
        { "Vel Limit", "cipm.axis.vlim",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000400,
          "Axis Status Data Set: Vel Limit", HFILL }
      },
      { &hf_cip_axis_sts_acc_limit,
        { "Acc Limit", "cipm.axis.alim",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000800,
          "Axis Status Data Set: Acc Limit", HFILL }
      },
      { &hf_cip_axis_sts_dec_limit,
        { "Decel Limit", "cipm.axis.dlim",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00001000,
          "Axis Status Data Set: Decel Limit", HFILL }
      },
      { &hf_cip_axis_sts_torque_threshold,
        { "Torque Threshold", "cipm.axis.tthresh",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00002000,
          "Axis Status Data Set: Torque Threshold", HFILL }
      },
      { &hf_cip_axis_sts_torque_limit,
        { "Torque Limit", "cipm.axis.tlim",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00004000,
          "Axis Status Data Set: Torque Limit", HFILL }
      },
      { &hf_cip_axis_sts_cur_limit,
        { "Current Limit", "cipm.axis.ilim",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00008000,
          "Axis Status Data Set: Current Limit", HFILL }
      },
      { &hf_cip_axis_sts_therm_limit,
        { "Thermal Limit", "cipm.axis.hot",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00010000,
          "Axis Status Data Set: Thermal Limit", HFILL }
      },
      { &hf_cip_axis_sts_feedback_integ,
        { "Feedback Integrity", "cipm.axis.fgood",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00020000,
          "Axis Status Data Set: Feedback Integrity", HFILL }
      },
      { &hf_cip_axis_sts_shutdown,
        { "Shutdown", "cipm.axis.sdwn",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00040000,
          "Axis Status Data Set: Shutdown", HFILL }
      },
      { &hf_cip_axis_sts_in_process,
        { "In Process", "cipm.axis.inp",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00080000,
          "Axis Status Data Set: In Process", HFILL }
      },
      { &hf_cip_axis_sts_dc_bus_unload,
        { "DC Bus Unload", "cipm.axis.dcunload",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00100000,
          "Axis Status Data Set: DC Bus Unload", HFILL }
      },
      { &hf_cip_axis_sts_ac_pwr_loss,
        { "AC Power Loss", "cipm.axis.acpwrloss",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00200000,
          "Axis Status Data Set: AC Power Loss", HFILL }
      },
      { &hf_cip_axis_sts_pos_cntrl_mode,
        { "Pos Control Mode", "cipm.axis.poscntrl",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00400000,
          "Axis Status Data Set: Position Control Mode", HFILL }
      },
      { &hf_cip_axis_sts_vel_cntrl_mode,
        { "Vel Control Mode", "cipm.axis.velcntrl",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00800000,
          "Axis Status Data Set: Velocity Control Mode", HFILL }
      },
      { &hf_cip_axis_sts_trq_cntrl_mode,
        { "Torque Control Mode", "cipm.axis.trqcntrl",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x01000000,
          "Axis Status Data Set: Torque Control Mode", HFILL }
      },

      // Attribute #740 - Axis Status 2.
      { &hf_cip_axis_status2,
      { "Axis Status 2", "cipm.axisstatus2",
         FT_UINT32, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_motor,
      { "Motoring", "cipm.axis2.motor",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000001,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_regenerate,
      { "Regenerating", "cipm.axis2.regen",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000002,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ride_thru,
      { "Ride Thru", "cipm.axis2.ridethru",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000004,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ac_line_sync,
      { "AC Line Sync", "cipm.axis2.acsync",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000008,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_bus_volt_lock,
      { "Bus Voltage Lock", "cipm.axis2.voltlock",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000010,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_react_pwr_only,
      { "Reactive Power Only Mode", "cipm.axis2.reactpwr",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000020,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_volt_ctrl_mode,
      { "Voltage Control Mode", "cipm.axis2.voltmode",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000040,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_pwr_loss,
      { "Power Loss", "cipm.axis2.pwrloss",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000080,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ac_volt_sag,
      { "AC Line Voltage Sag", "cipm.axis2.voltsag",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000100,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ac_phase_loss,
      { "AC Line Phase Loss", "cipm.axis2.phaseloss",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000200,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ac_freq_change,
      { "AC Line Frequency Change", "cipm.axis2.freqchange",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000400,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_ac_sync_loss,
      { "AC Line Sync Loss", "cipm.axis2.syncloss",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00000800,
         NULL, HFILL }
      },
      { &hf_cip_axis_sts2_single_phase,
      { "Single Phase", "cipm.axis2.singlephase",
         FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00001000,
         NULL, HFILL }
      },

      { &hf_cip_axis_sts2_bus_volt_limit,
        { "Bus Voltage Limit", "cipm.axis2.bus_volt_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00002000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_bus_volt_rate_limit,
        { "Bus Voltage Rate Limit", "cipm.axis2.bus_volt_rate_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00004000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_active_current_rate_limit,
        { "Active Current Rate Limit", "cipm.axis2.active_current_rate_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00008000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_reactive_current_rate_limit,
        { "Reactive Current Rate Limit", "cipm.axis2.reactive_current_rate_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00010000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_reactive_pwr_limit,
        { "Reactive Power Limit", "cipm.axis2.reactive_pwr_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00020000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_reactive_pwr_rate_limit,
        { "Reactive Power Rate Limit", "cipm.axis2.reactive_pwr_rate_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00040000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_active_current_limit,
        { "Active Current Limit", "cipm.axis2.active_current_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00080000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_reactive_current_limit,
        { "Reactive Current Limit", "cipm.axis2.reactive_current_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00100000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_motor_pwr_limit,
        { "Motoring Power Limit", "cipm.axis2.motor_pwr_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00200000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_regen_pwr_limit,
        { "Regenerative Power Limit", "cipm.axis2.regen_pwr_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00400000,
          NULL, HFILL }
      },
      { &hf_cip_axis_sts2_convert_therm_limit,
        { "Converter Thermal Limit", "cipm.axis2.convert_therm_limit",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00800000,
          NULL, HFILL }
      },

      { &hf_cip_act_pos,
        { "Actual Position", "cipm.actpos",
          FT_INT32, BASE_DEC, NULL, 0,
          "Cyclic Data Set: Actual Position", HFILL }
      },
      { &hf_cip_act_pos_64,
        { "Actual Position", "cipm.actpos",
          FT_INT64, BASE_DEC, NULL, 0,
          "Cyclic Data Set: Actual Position", HFILL }
        },
      { &hf_cip_act_vel,
        { "Actual Velocity", "cipm.actvel",
          FT_FLOAT, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Actual Velocity", HFILL }
      },
      { &hf_cip_act_accel,
        { "Actual Acceleration", "cipm.actaccel",
          FT_FLOAT, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Actual Acceleration", HFILL }
      },
      { &hf_cip_pos_cmd,
        { "Position Command", "cipm.posfcmd",
          FT_DOUBLE, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Position Command (LREAL)", HFILL }
      },
      { &hf_cip_pos_cmd_int,
        { "Position Command", "cipm.posicmd",
          FT_INT32, BASE_DEC, NULL, 0,
          "Cyclic Data Set: Position Command (DINT)", HFILL }
      },
      { &hf_cip_vel_cmd,
        { "Velocity Command", "cipm.velcmd",
          FT_FLOAT, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Velocity Command", HFILL }
      },
      { &hf_cip_accel_cmd,
        { "Acceleration Command", "cipm.accelcmd",
          FT_FLOAT, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Acceleration Command", HFILL }
      },
      { &hf_cip_trq_cmd,
        { "Torque Command", "cipm.torquecmd",
          FT_FLOAT, BASE_NONE, NULL, 0,
          "Cyclic Data Set: Torque Command", HFILL }
      },
      { &hf_cip_pos_trim,
        { "Position Trim", "cipm.postrim",
          FT_INT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_vel_trim,
        { "Velocity Trim", "cipm.veltrim",
          FT_FLOAT, BASE_NONE, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_accel_trim,
        { "Acceleration Trim", "cipm.acceltrim",
          FT_FLOAT, BASE_NONE, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_trq_trim,
        { "Torque Trim", "cipm.trqtrim",
          FT_FLOAT, BASE_NONE, NULL, 0,
          NULL, HFILL }
      },
      { &hf_cip_data,
        { "Data", "cipm.data",
        FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL }
      }
   };

   /* Setup protocol subtree array, these will help Wireshark remember
   * if the subtree should be expanded as the user moves through packets */
   static gint *cip_subtree[] = {
      &ett_cipmotion,
      &ett_cont_dev_header,
      &ett_control_status,
      &ett_node_control,
      &ett_node_status,
      &ett_time_data_set,
      &ett_inst_data_header,
      &ett_cyclic_data_block,
      &ett_feedback_mode,
      &ett_connection_configuration_bits,
      &ett_control_mode,
      &ett_feedback_config,
      &ett_command_data_set,
      &ett_actual_data_set,
      &ett_status_data_set,
      &ett_interp_control,
      &ett_cyclic_rd_wt,
      &ett_event,
      &ett_event_check_ctrl,
      &ett_event_check_sts,
      &ett_service,
      &ett_get_axis_attribute,
      &ett_set_axis_attribute,
      &ett_get_axis_attr_list,
      &ett_set_axis_attr_list,
      &ett_set_cyclic_list,
      &ett_group_sync,
      &ett_axis_status_set,
      &ett_command_control,
      &ett_configuration_block
   };

   static ei_register_info ei[] = {
      { &ei_format_rev_conn_pt, { "cipm.malformed.format_revision_mismatch", PI_MALFORMED, PI_WARN, "Format Revision does not match Connection Point", EXPFILL } },
   };

   /* Create a CIP Motion protocol handle */
   proto_cipmotion = proto_register_protocol(
     "Common Industrial Protocol, Motion",  /* Full name of protocol        */
     "CIP Motion",           /* Short name of protocol       */
     "cipm");                /* Abbreviated name of protocol */

   proto_cipmotion3 = proto_register_protocol_in_name_only(
     "Common Industrial Protocol, Motion - Rev 3",
     "CIP Motion - Rev 3",
     "cipm3",
     proto_cipmotion,
     FT_PROTOCOL);

   /* Register the header fields with the protocol */
   proto_register_field_array(proto_cipmotion, hf, array_length(hf));

   /* Register the subtrees for the protocol dissection */
   proto_register_subtree_array(cip_subtree, array_length(cip_subtree));

   expert_module_t* expert_cipm = expert_register_protocol(proto_cipmotion);
   expert_register_field_array(expert_cipm, ei, array_length(ei));

   module_t* cipm_module = prefs_register_protocol(proto_cipmotion, NULL);
   prefs_register_bool_preference(cipm_module, "display_full_attribute_data",
      "Display full attribute data in the Service Data Block",
      "Whether the CIP Motion dissector always display the full raw attribute data bytes",
      &display_full_attribute_data);

   cipmotion_handle = register_dissector("cipmotion", dissect_cipmotion, proto_cipmotion);
   cipmotion3_handle = register_dissector("cipmotion3", dissect_cipmotion3, proto_cipmotion3);
}

void proto_reg_handoff_cipmotion(void)
{
   dissector_add_for_decode_as("cip.io", cipmotion_handle);
   dissector_add_for_decode_as("cip.io", cipmotion3_handle);

   dissector_add_uint("cip.io.iface", CI_CLS_MOTION, cipmotion_handle);
}

/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 3
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=3 tabstop=8 expandtab:
* :indentSize=3:tabSize=8:noTabs=true:
*/
