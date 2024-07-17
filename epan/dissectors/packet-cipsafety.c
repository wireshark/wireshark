/* packet-cipsafety.c
 * Routines for CIP (Common Industrial Protocol) Safety dissection
 * CIP Safety Home: www.odva.org
 *
 * This dissector includes items from:
 *    CIP Volume 1: Common Industrial Protocol, Edition 3.24
 *    CIP Volume 5: CIP Safety, Edition 2.22
 *
 * Copyright 2011
 * Michael Mann <mmann@pyramidsolutions.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include <wsutil/pint.h>
#include <wsutil/crc8.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include "packet-cip.h"
#include "packet-cipsafety.h"


void proto_register_cipsafety(void);
void proto_reg_handoff_cipsafety(void);
/* The entry point to the actual dissection is: dissect_cipsafety */

/* Protocol handle for CIP Safety */
static int proto_cipsafety;
static int proto_cipsafety_base_data;
static int proto_cipsafety_extended_data;
static int proto_cipsafety_base_time_coord;
static int proto_cipsafety_extended_time_coord;
static int proto_cip_class_s_supervisor;
static int proto_cip_class_s_validator;
static int proto_cip;

static dissector_table_t subdissector_class_table;
static dissector_handle_t cip_class_s_supervisor_handle;
static dissector_handle_t cip_class_s_validator_handle;

/* CIP Safety field identifiers */
static int hf_cipsafety_data;
static int hf_cipsafety_mode_byte;
static int hf_cipsafety_mode_byte_run_idle;
static int hf_cipsafety_mode_byte_not_run_idle;
static int hf_cipsafety_mode_byte_tbd_2_bit;
static int hf_cipsafety_mode_byte_tbd_2_copy;
static int hf_cipsafety_mode_byte_ping_count;
static int hf_cipsafety_mode_byte_tbd;
static int hf_cipsafety_mode_byte_not_tbd;
static int hf_cipsafety_crc_s1;
static int hf_cipsafety_crc_s1_status;
static int hf_cipsafety_crc_s2;
static int hf_cipsafety_crc_s2_status;
static int hf_cipsafety_crc_s3;
static int hf_cipsafety_crc_s3_status;
static int hf_cipsafety_complement_crc_s3;
static int hf_cipsafety_complement_crc_s3_status;
static int hf_cipsafety_timestamp;
static int hf_cipsafety_ack_byte;
static int hf_cipsafety_ack_byte_ping_count_reply;
static int hf_cipsafety_ack_byte_reserved1;
static int hf_cipsafety_ack_byte_ping_response;
static int hf_cipsafety_ack_byte_reserved2;
static int hf_cipsafety_ack_byte_parity_even;
static int hf_cipsafety_ack_byte2;
static int hf_cipsafety_consumer_time_value;
static int hf_cipsafety_mcast_byte;
static int hf_cipsafety_mcast_byte_consumer_num;
static int hf_cipsafety_mcast_byte_reserved1;
static int hf_cipsafety_mcast_byte_mai;
static int hf_cipsafety_mcast_byte_reserved2;
static int hf_cipsafety_mcast_byte_parity_even;
static int hf_cipsafety_mcast_byte2;
static int hf_cipsafety_time_correction;
static int hf_cipsafety_crc_s5_0;
static int hf_cipsafety_crc_s5_1;
static int hf_cipsafety_crc_s5_2;
static int hf_cipsafety_crc_s5_status;
static int hf_cipsafety_complement_data;
static int hf_cip_safety_message_encoding;

/* CIP Safety header field identifiers */
static int hf_cip_reqrsp;
static int hf_cip_data;

/* Safety Supervisor header field identifiers */
static int hf_cip_ssupervisor_sc;
static int hf_cip_ssupervisor_recover_data;
static int hf_cip_ssupervisor_perform_diag_data;
static int hf_cip_ssupervisor_configure_request_password;
static int hf_cip_ssupervisor_configure_request_tunid;
static int hf_cip_ssupervisor_configure_request_tunid_snn_timestamp;
static int hf_cip_ssupervisor_configure_request_tunid_snn_date;
static int hf_cip_ssupervisor_configure_request_tunid_snn_time;
static int hf_cip_ssupervisor_configure_request_tunid_nodeid;
static int hf_cip_ssupervisor_configure_request_ounid;
static int hf_cip_ssupervisor_configure_request_ounid_snn_timestamp;
static int hf_cip_ssupervisor_configure_request_ounid_snn_date;
static int hf_cip_ssupervisor_configure_request_ounid_snn_time;
static int hf_cip_ssupervisor_configure_request_ounid_nodeid;
static int hf_cip_ssupervisor_validate_configuration_sccrc;
static int hf_cip_ssupervisor_validate_configuration_scts_timestamp;
static int hf_cip_ssupervisor_validate_configuration_scts_date;
static int hf_cip_ssupervisor_validate_configuration_scts_time;
static int hf_cip_ssupervisor_validate_configuration_ext_error;
static int hf_cip_ssupervisor_set_password_current_password;
static int hf_cip_ssupervisor_set_password_new_password;
static int hf_cip_ssupervisor_configure_lock_value;
static int hf_cip_ssupervisor_configure_lock_password;
static int hf_cip_ssupervisor_configure_lock_tunid;
static int hf_cip_ssupervisor_configure_lock_tunid_snn_timestamp;
static int hf_cip_ssupervisor_configure_lock_tunid_snn_date;
static int hf_cip_ssupervisor_configure_lock_tunid_snn_time;
static int hf_cip_ssupervisor_configure_lock_tunid_nodeid;
static int hf_cip_ssupervisor_mode_change_value;
static int hf_cip_ssupervisor_mode_change_password;
static int hf_cip_ssupervisor_reset_type;
static int hf_cip_ssupervisor_reset_password;
static int hf_cip_ssupervisor_reset_tunid;
static int hf_cip_ssupervisor_reset_tunid_tunid_snn_timestamp;
static int hf_cip_ssupervisor_reset_tunid_tunid_snn_date;
static int hf_cip_ssupervisor_reset_tunid_tunid_snn_time;
static int hf_cip_ssupervisor_reset_tunid_nodeid;
static int hf_cip_ssupervisor_reset_attr_bitmap;
static int hf_cip_ssupervisor_reset_attr_bitmap_macid;
static int hf_cip_ssupervisor_reset_attr_bitmap_baudrate;
static int hf_cip_ssupervisor_reset_attr_bitmap_tunid;
static int hf_cip_ssupervisor_reset_attr_bitmap_password;
static int hf_cip_ssupervisor_reset_attr_bitmap_cfunid;
static int hf_cip_ssupervisor_reset_attr_bitmap_ocpunid;
static int hf_cip_ssupervisor_reset_attr_bitmap_reserved;
static int hf_cip_ssupervisor_reset_attr_bitmap_extended;
static int hf_cip_ssupervisor_reset_password_data_size;
static int hf_cip_ssupervisor_reset_password_data;
static int hf_cip_ssupervisor_propose_tunid_tunid;
static int hf_cip_ssupervisor_propose_tunid_tunid_snn_timestamp;
static int hf_cip_ssupervisor_propose_tunid_tunid_snn_date;
static int hf_cip_ssupervisor_propose_tunid_tunid_snn_time;
static int hf_cip_ssupervisor_propose_tunid_tunid_nodeid;
static int hf_cip_ssupervisor_apply_tunid_tunid;
static int hf_cip_ssupervisor_apply_tunid_tunid_snn_timestamp;
static int hf_cip_ssupervisor_apply_tunid_tunid_snn_date;
static int hf_cip_ssupervisor_apply_tunid_tunid_snn_time;
static int hf_cip_ssupervisor_apply_tunid_tunid_nodeid;

static int hf_cip_ssupervisor_class_subclass;
static int hf_cip_ssupervisor_num_attr;
static int hf_cip_ssupervisor_attr_list;
static int hf_cip_ssupervisor_manufacture_name;
static int hf_cip_ssupervisor_manufacture_model_number;
static int hf_cip_ssupervisor_sw_rev_level;
static int hf_cip_ssupervisor_hw_rev_level;
static int hf_cip_ssupervisor_manufacture_serial_number;
static int hf_cip_ssupervisor_device_config;
static int hf_cip_ssupervisor_device_status;
static int hf_cip_ssupervisor_exception_status;
static int hf_cip_ssupervisor_exception_detail_ced_size;
static int hf_cip_ssupervisor_exception_detail_ced_detail;
static int hf_cip_ssupervisor_exception_detail_ded_size;
static int hf_cip_ssupervisor_exception_detail_ded_detail;
static int hf_cip_ssupervisor_exception_detail_med_size;
static int hf_cip_ssupervisor_exception_detail_med_detail;
static int hf_cip_ssupervisor_alarm_enable;
static int hf_cip_ssupervisor_warning_enable;
static int hf_cip_ssupervisor_time;
static int hf_cip_ssupervisor_clock_power_cycle_behavior;
static int hf_cip_ssupervisor_last_maintenance_date;
static int hf_cip_ssupervisor_next_scheduled_maintenance_date;
static int hf_cip_ssupervisor_scheduled_maintenance_expiration_timer;
static int hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable;
static int hf_cip_ssupervisor_run_hours;
static int hf_cip_ssupervisor_configuration_lock;
static int hf_cip_ssupervisor_configuration_unid_snn_timestamp;
static int hf_cip_ssupervisor_configuration_unid_snn_date;
static int hf_cip_ssupervisor_configuration_unid_snn_time;
static int hf_cip_ssupervisor_configuration_unid_nodeid;
static int hf_cip_ssupervisor_safety_configuration_id_snn_timestamp;
static int hf_cip_ssupervisor_safety_configuration_id_snn_date;
static int hf_cip_ssupervisor_safety_configuration_id_snn_time;
static int hf_cip_ssupervisor_safety_configuration_id_sccrc;
static int hf_cip_ssupervisor_target_unid_snn_timestamp;
static int hf_cip_ssupervisor_target_unid_snn_date;
static int hf_cip_ssupervisor_target_unid_snn_time;
static int hf_cip_ssupervisor_target_unid_nodeid;
static int hf_cip_ssupervisor_cp_owners_num_entries;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_timestamp;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_date;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_time;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_nodeid;
static int hf_cip_ssupervisor_cp_owners_app_path_size;
static int hf_cip_ssupervisor_proposed_tunid_snn_timestamp;
static int hf_cip_ssupervisor_proposed_tunid_snn_date;
static int hf_cip_ssupervisor_proposed_tunid_snn_time;
static int hf_cip_ssupervisor_proposed_tunid_nodeid;
static int hf_cip_ssupervisor_instance_subclass;


/* Safety Validator header field identifiers */
static int hf_cip_svalidator_sc;

static int hf_cip_svalidator_sconn_fault_count;
static int hf_cip_svalidator_state;
static int hf_cip_svalidator_type;
static int hf_cip_svalidator_type_pc;
static int hf_cip_svalidator_type_conn_type;
static int hf_cip_svalidator_ping_epi;
static int hf_cip_svalidator_time_coord_msg_min_mult_size;
static int hf_cip_svalidator_time_coord_msg_min_mult_item;
static int hf_cip_svalidator_network_time_multiplier_size;
static int hf_cip_svalidator_network_time_multiplier_item;
static int hf_cip_svalidator_timeout_multiplier_size;
static int hf_cip_svalidator_timeout_multiplier_item;
static int hf_cip_svalidator_max_consumer_num;
static int hf_cip_svalidator_data_conn_inst;
static int hf_cip_svalidator_coordination_conn_inst_size;
static int hf_cip_svalidator_coordination_conn_inst_item;
static int hf_cip_svalidator_correction_conn_inst;
static int hf_cip_svalidator_cco_binding;
static int hf_cip_svalidator_max_data_age;
static int hf_cip_svalidator_error_code;
static int hf_cip_svalidator_prod_cons_fault_count_size;
static int hf_cip_svalidator_prod_cons_fault_count_item;

static int hf_cip_sercosiii_link_snn;
static int hf_cip_sercosiii_link_communication_cycle_time;
static int hf_cip_sercosiii_link_interface_status;
static int hf_cip_sercosiii_link_error_count_mstps;
static int hf_cip_sercosiii_link_sercos_address;
static int hf_cip_sercosiii_link_error_count_p1;
static int hf_cip_sercosiii_link_error_count_p2;

/* Initialize the subtree pointers */
static int ett_cip_safety;
static int ett_path;
static int ett_cipsafety_mode_byte;
static int ett_cipsafety_ack_byte;
static int ett_cipsafety_mcast_byte;

static int ett_cip_class_s_supervisor;
static int ett_ssupervisor_rrsc;
static int ett_ssupervisor_cmd_data;
static int ett_ssupervisor_propose_tunid;
static int ett_ssupervisor_propose_tunid_snn;
static int ett_ssupervisor_configure_request_tunid;
static int ett_ssupervisor_configure_request_tunid_snn;
static int ett_ssupervisor_configure_request_ounid;
static int ett_ssupervisor_configure_request_ounid_snn;
static int ett_ssupervisor_configure_lock_tunid;
static int ett_ssupervisor_configure_lock_tunid_snn;
static int ett_ssupervisor_reset_tunid;
static int ett_ssupervisor_reset_tunid_snn;
static int ett_ssupervisor_apply_tunid;
static int ett_ssupervisor_apply_tunid_snn;
static int ett_exception_detail_common;
static int ett_exception_detail_device;
static int ett_exception_detail_manufacturer;
static int ett_ssupervisor_configuration_unid;
static int ett_ssupervisor_configuration_unid_snn;
static int ett_ssupervisor_target_unid;
static int ett_ssupervisor_target_unid_snn;
static int ett_ssupervisor_output_cp_owners;
static int ett_ssupervisor_output_cp_owners_ocpunid;
static int ett_ssupervisor_output_cp_owners_ocpunid_snn;
static int ett_ssupervisor_proposed_tunid;
static int ett_ssupervisor_proposed_tunid_snn;
static int ett_cip_ssupervisor_reset_attr_bitmap;

static int ett_cip_class_s_validator;
static int ett_svalidator_rrsc;
static int ett_svalidator_cmd_data;
static int ett_svalidator_type;

static expert_field ei_cipsafety_tbd_not_complemented;
static expert_field ei_cipsafety_tbd2_not_copied;
static expert_field ei_cipsafety_run_idle_not_complemented;
static expert_field ei_mal_io;
static expert_field ei_mal_sercosiii_link_error_count_p1p2;
static expert_field ei_cipsafety_not_complement_data;
static expert_field ei_cipsafety_crc_s1;
static expert_field ei_cipsafety_crc_s2;
static expert_field ei_cipsafety_crc_s3;
static expert_field ei_cipsafety_complement_crc_s3;
static expert_field ei_cipsafety_crc_s5;

static expert_field ei_mal_ssupervisor_exception_detail_ced;
static expert_field ei_mal_ssupervisor_exception_detail_ded;
static expert_field ei_mal_ssupervisor_exception_detail_med;
static expert_field ei_mal_ssupervisor_configuration_unid;
static expert_field ei_mal_ssupervisor_safety_configuration_id;
static expert_field ei_mal_ssupervisor_target_unid;
static expert_field ei_mal_ssupervisor_cp_owners;
static expert_field ei_mal_ssupervisor_cp_owners_entry;
static expert_field ei_mal_ssupervisor_cp_owners_app_path_size;
static expert_field ei_mal_ssupervisor_proposed_tunid;
static expert_field ei_info_ssupervisor_tunid_cancel;

static expert_field ei_mal_svalidator_type;
static expert_field ei_mal_svalidator_time_coord_msg_min_mult;
static expert_field ei_mal_svalidator_network_time_multiplier;
static expert_field ei_mal_svalidator_timeout_multiplier;
static expert_field ei_mal_svalidator_coordination_conn_inst;
static expert_field ei_mal_svalidator_prod_cons_fault_count;

static dissector_handle_t cipsafety_handle;
static dissector_handle_t cipsafety_base_data_handle;
static dissector_handle_t cipsafety_extended_data_handle;
static dissector_handle_t cipsafety_base_time_coord_handle;
static dissector_handle_t cipsafety_extended_time_coord_handle;

typedef struct cip_safety_packet_data {
   uint16_t rollover_value;
} cip_safety_packet_data_t;

#define MODE_BYTE_CRC_S1_MASK  0xE0
#define MODE_BYTE_CRC_S1_TIME_STAMP_MASK  0x1F
#define MODE_BYTE_CRC_S3_MASK  0xE0
#define MODE_BYTE_CRC_S5_BASE_MASK  0xE0
#define MODE_BYTE_CRC_S5_EXTENDED_MASK  0x1F

const value_string cipsafety_snn_date_vals[8] = {

   { 0,     "NULL SNN" },
   { 1,     "Manual Setting - Backplane" },
   { 2,     "Manual Setting - ControlNet" },
   { 4,     "Manual Setting - EtherNet/IP" },
   { 5,     "Manual Setting - DeviceNet" },
   { 6,     "Manual Setting - SERCOS III" },
   { 65535, "No SNN Set" },

   { 0,     NULL }
};

static const true_false_string cip_safety_vals_active_idle = {
   "Active",
   "Idle",
};

/* Translate function to string - CIP Service codes for Safety Supervisor */
static const value_string cip_sc_vals_ssupervisor[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_SSUPER_RECOVER,                "Recover" },
   { SC_SSUPER_PERFORM_DIAGNOSTICS,    "Perform Diagnostics" },
   { SC_SSUPER_CONFIGURE_REQUEST,      "Configure Request" },
   { SC_SSUPER_VALIDATE_CONFIGURATION, "Validate Configuration" },
   { SC_SSUPER_SET_PASSWORD,           "Set Password" },
   { SC_SSUPER_CONFIGURATION_LOCK,     "Configuration (Un)Lock" },
   { SC_SSUPER_MODE_CHANGE,            "Mode Change" },
   { SC_SSUPER_SAFETY_RESET,           "Safety Reset" },
   { SC_SSUPER_RESET_PASSWORD,         "Reset Password" },
   { SC_SSUPER_PROPOSE_TUNID,          "Propose TUNID" },
   { SC_SSUPER_APPLY_TUNID,            "Apply TUNID" },
   { SC_SSUPER_PROPOSE_TUNID_LIST,     "Propose TUNID List" },
   { SC_SSUPER_APPLY_TUNID_LIST,       "Apply TUNID List" },

   { 0,                       NULL }
};

#define SC_SVALID_RESET_ERROR                 0x4B

/* Translate function to string - CIP Service codes for Safety Validator */
static const value_string cip_sc_vals_svalidator[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_SVALID_RESET_ERROR,                "Reset Error" },

   { 0,                       NULL }
};

static const value_string cip_ssupervisor_validate_configuration_ext_error_vals[] = {
   { 1,        "CRC mismatch" },
   { 2,        "Invalid Configuration Parameter"     },
   { 3,        "TUNID Not Set"     },

   { 0,        NULL          }
};

static const value_string cip_ssupervisor_lock_vals[] = {
   { 0,        "Unlocked" },
   { 1,        "Locked"     },

   { 0,        NULL          }
};

static const value_string cip_ssupervisor_change_mode_vals[] = {
   { 0,        "Idle" },
   { 1,        "Executing"   },

   { 0,        NULL          }
};

static const value_string cip_ssupervisor_device_status_type_vals[] = {
   { 0,        "Undefined" },
   { 1,        "Self-Testing"   },
   { 2,        "Idle"   },
   { 3,        "Self-Test Exception"   },
   { 4,        "Executing"   },
   { 5,        "Abort"   },
   { 6,        "Critical Fault"   },
   { 7,        "Configuring"   },
   { 8,        "Waiting for TUNID"   },
   { 51,       "Waiting for TUNID with Torque Permitted" },
   { 52,       "Executing with Torque Permitted" },

   { 0,        NULL          }
};

static const value_string cip_ssupervisor_clock_power_cycle_type_vals[] = {
   { 0,        "Clock always resets" },
   { 1,        "Clock in NVS at power down"   },
   { 2,        "Clock is battery-backed"   },

   { 0,        NULL          }
};

static const value_string cip_svalidator_state_vals[] = {
   { 0,        "Unallocated" },
   { 1,        "Initializing"   },
   { 2,        "Established"   },
   { 3,        "Connection failed"   },

   { 0,        NULL          }
};

static const value_string cip_svalidator_type_pc_vals[] = {
   { 0,        "Producer" },
   { 1,        "Consumer" },

   { 0,        NULL          }
};

static const value_string cip_svalidator_type_conn_type_vals[] = {
   { 0,        "Unallocated" },
   { 1,        "Single-cast" },
   { 2,        "Multi-cast"  },

   { 0,        NULL          }
};

const range_string safety_max_consumer_numbers[] = {
   { 1, 1, "Single-cast" },
   { 2, 15, "Multicast" },

   { 0, 0, NULL }
};

enum message_encoding_type {
   MSG_ENCODING_BASE_1_2_BYTE_DATA,
   MSG_ENCODING_EXTENDED_1_2_BYTE_DATA,
   MSG_ENCODING_BASE_3_250_BYTE_DATA,
   MSG_ENCODING_EXTENDED_3_250_BYTE_DATA,
   MSG_ENCODING_BASE_TIME_STAMP,
   MSG_ENCODING_BASE_TIME_COORDINATION,
   MSG_ENCODING_EXTENDED_TIME_COORDINATION,
   MSG_ENCODING_BASE_TIME_CORRECTION,
   MSG_ENCODING_EXTENDED_TIME_CORRECTION,
};

static const value_string safety_message_encoding_vals[] = {
   { MSG_ENCODING_BASE_1_2_BYTE_DATA, "Base Format, 1 or 2 Byte Data Section" },
   { MSG_ENCODING_EXTENDED_1_2_BYTE_DATA, "Extended Format, 1 or 2 Byte Data Section" },
   { MSG_ENCODING_BASE_3_250_BYTE_DATA, "Base Format, 3 to 250 Byte Data Section" },
   { MSG_ENCODING_EXTENDED_3_250_BYTE_DATA, "Extended Format, 3 to 250 Byte Data Section" },
   { MSG_ENCODING_BASE_TIME_STAMP, "Base Format, Time Stamp Section" },
   { MSG_ENCODING_BASE_TIME_COORDINATION, "Base Format, Time Coordination Section" },
   { MSG_ENCODING_EXTENDED_TIME_COORDINATION, "Extended Format, Time Coordination Section" },
   { MSG_ENCODING_BASE_TIME_CORRECTION, "Base Format, Time Correction Section" },
   { MSG_ENCODING_EXTENDED_TIME_CORRECTION, "Extended Format, Time Correction Section" },

   { 0, NULL }
};

void cip_safety_128us_fmt(char *s, uint32_t value)
{
   // Each tick is 128us.
   snprintf(s, ITEM_LABEL_LENGTH, "%d (%.3fms)", value, value * 0.128);
}

void
dissect_unid(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item *pi,
             const char* snn_name, int hf_snn_timestamp,
             int hf_snn_date, int hf_snn_time, int hf_nodeid, int ett, int ett_snn)
{
   proto_tree *tree, *snn_tree;

   tree = proto_item_add_subtree(pi, ett);

   snn_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_snn, NULL, snn_name);
   dissect_cipsafety_snn(snn_tree, tvb, pinfo, offset, hf_snn_timestamp, hf_snn_date, hf_snn_time);

   proto_tree_add_item(tree, hf_nodeid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN);
}

void dissect_cipsafety_snn(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
                           int hf_real_datetime, int hf_date, int hf_time)
{
   uint16_t date;

   date = tvb_get_letohs(tvb, offset+4);

   if ((date >= 11688) && (date <= 65534))
   {
      /* value is an actual timestamp */
      dissect_cip_date_and_time(tree, tvb, offset, hf_real_datetime);
   }
   else
   {
      /* Treated as UINT16 and UINT32 values */
      proto_tree_add_item(tree, hf_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(tree, hf_date, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
   }
}

static void dissect_safety_supervisor_safety_reset(proto_tree* cmd_data_tree, tvbuff_t* tvb, int offset, packet_info* pinfo)
{
   uint32_t reset_type;
   proto_tree_add_item_ret_uint(cmd_data_tree, hf_cip_ssupervisor_reset_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &reset_type);

   proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password, tvb, offset + 1, 16, ENC_NA);
   proto_item* pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_tunid, tvb, offset + 17, 10, ENC_NA);
   dissect_unid(tvb, pinfo, offset + 17, pi, "TUNID SNN",
      hf_cip_ssupervisor_reset_tunid_tunid_snn_timestamp,
      hf_cip_ssupervisor_reset_tunid_tunid_snn_date,
      hf_cip_ssupervisor_reset_tunid_tunid_snn_time,
      hf_cip_ssupervisor_reset_tunid_nodeid,
      ett_ssupervisor_reset_tunid,
      ett_ssupervisor_reset_tunid_snn);

   /* Attribute bitmap only included on Reset Type 2 */
   if (reset_type == 2)
   {
      pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_attr_bitmap, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);

      proto_tree* bitmap_tree = proto_item_add_subtree(pi, ett_cip_ssupervisor_reset_attr_bitmap);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_macid, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_baudrate, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_tunid, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_password, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_cfunid, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_ocpunid, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_reserved, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_extended, tvb, offset + 27, 1, ENC_LITTLE_ENDIAN);
   }
}

static void detect_cancel_propose_apply_operation(tvbuff_t* tvb, int offset, packet_info* pinfo, proto_item* item)
{
   // Check for all FFs.
   uint64_t part1 = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN);
   uint16_t part2 = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
   if (part1 == 0xFFFFFFFFFFFFFFFF && part2 == 0xFFFF)
   {
      expert_add_info(pinfo, item, &ei_info_ssupervisor_tunid_cancel);
   }
}

/************************************************
 *
 * Dissector for CIP Safety Supervisor Object
 *
 ************************************************/
static void
dissect_cip_s_supervisor_data( proto_tree *item_tree,
                               tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item                *pi, *rrsc_item;
   proto_tree                *rrsc_tree, *cmd_data_tree;
   int                        req_path_size;
   int                        temp_data;
   uint8_t                    service, gen_status, add_stat_size;
   cip_simple_request_info_t  req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIPS Supervisor");

   /* Add Service code & Request/Response tree */
   service   = tvb_get_uint8( tvb, offset );
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_ssupervisor_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ), cip_sc_vals_ssupervisor , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7, cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_ssupervisor_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   load_cip_request_data(pinfo, &req_data);

   if (service & CIP_SC_RESPONSE_MASK)
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+4+add_stat_size,
                         item_length-4-add_stat_size, ett_ssupervisor_cmd_data, NULL, "Command Specific Data" );

         if( gen_status == CI_GRC_SUCCESS )
         {
            switch (service & CIP_SC_MASK)
            {
            case SC_SSUPER_VALIDATE_CONFIGURATION:
               proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_sccrc,
                         tvb, offset+4+add_stat_size, 4, ENC_LITTLE_ENDIAN);
               dissect_cipsafety_snn(cmd_data_tree,
                         tvb, pinfo, offset+4+add_stat_size+4,
                         hf_cip_ssupervisor_validate_configuration_scts_timestamp,
                         hf_cip_ssupervisor_validate_configuration_scts_date,
                         hf_cip_ssupervisor_validate_configuration_scts_time);
               break;
            }
         }
         else if ((gen_status == 0xD0) && ((service & CIP_SC_MASK) == SC_SSUPER_VALIDATE_CONFIGURATION))
         {
            if (add_stat_size > 0)
            {
               proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_ext_error,
                         tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
            }
         }
         else
         {
            /* Error responses */

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data,
                         tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
         }
      }

   } /* End of if reply */
   else
   {
      /* Request message */

      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2,
                                   ett_ssupervisor_cmd_data, NULL, "Command Specific Data" );

         /* Check what service code that received */
         switch (service)
         {
         case SC_SSUPER_RECOVER:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_recover_data,
                         tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
            break;
         case SC_SSUPER_PERFORM_DIAGNOSTICS:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_perform_diag_data,
                         tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
            break;
         case SC_SSUPER_CONFIGURE_REQUEST:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_password,
                         tvb, offset+2+req_path_size, 16, ENC_NA);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_tunid,
                         tvb, offset+2+req_path_size+16, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+16, pi, "TUNID SNN",
                         hf_cip_ssupervisor_configure_request_tunid_snn_timestamp,
                         hf_cip_ssupervisor_configure_request_tunid_snn_date,
                         hf_cip_ssupervisor_configure_request_tunid_snn_time,
                         hf_cip_ssupervisor_configure_request_tunid_nodeid,
                         ett_ssupervisor_configure_request_tunid,
                         ett_ssupervisor_configure_request_tunid_snn);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_ounid,
                                     tvb, offset+2+req_path_size+26, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+16, pi, "OUNID SNN",
                         hf_cip_ssupervisor_configure_request_ounid_snn_timestamp,
                         hf_cip_ssupervisor_configure_request_ounid_snn_date,
                         hf_cip_ssupervisor_configure_request_ounid_snn_time,
                         hf_cip_ssupervisor_configure_request_ounid_nodeid,
                         ett_ssupervisor_configure_request_ounid,
                         ett_ssupervisor_configure_request_ounid_snn);
            break;
         case SC_SSUPER_VALIDATE_CONFIGURATION:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_sccrc,
                         tvb, offset+2+req_path_size, 4, ENC_LITTLE_ENDIAN);
            dissect_cipsafety_snn(cmd_data_tree, tvb, pinfo, offset+2+req_path_size+4,
                         hf_cip_ssupervisor_validate_configuration_scts_timestamp,
                         hf_cip_ssupervisor_validate_configuration_scts_date,
                         hf_cip_ssupervisor_validate_configuration_scts_time);
            break;
         case SC_SSUPER_SET_PASSWORD:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_set_password_current_password,
                         tvb, offset+2+req_path_size, 16, ENC_NA);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_set_password_new_password,
                         tvb, offset+2+req_path_size+16, 16, ENC_NA);
            break;
         case SC_SSUPER_CONFIGURATION_LOCK:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_value,
                         tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_password,
                         tvb, offset+2+req_path_size+1, 16, ENC_NA);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_tunid,
                         tvb, offset+2+req_path_size+17, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+17, pi, "TUNID SNN",
                         hf_cip_ssupervisor_configure_lock_tunid_snn_timestamp,
                         hf_cip_ssupervisor_configure_lock_tunid_snn_date,
                         hf_cip_ssupervisor_configure_lock_tunid_snn_time,
                         hf_cip_ssupervisor_configure_lock_tunid_nodeid,
                         ett_ssupervisor_configure_lock_tunid,
                         ett_ssupervisor_configure_lock_tunid_snn);
            break;
         case SC_SSUPER_MODE_CHANGE:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_mode_change_value,
                         tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_mode_change_password,
                         tvb, offset+2+req_path_size+1, 16, ENC_NA);
            break;
         case SC_SSUPER_SAFETY_RESET:
            dissect_safety_supervisor_safety_reset(cmd_data_tree, tvb, offset + 2 + req_path_size, pinfo);
            break;
         case SC_SSUPER_RESET_PASSWORD:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password_data_size,
                         tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);
            temp_data = tvb_get_uint8(tvb, offset+2+req_path_size);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password_data,
                         tvb, offset+2+req_path_size+1, temp_data, ENC_NA);
            break;
         case SC_SSUPER_PROPOSE_TUNID:
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_propose_tunid_tunid,
                         tvb, offset+2+req_path_size, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size, pi, "TUNID SNN",
                         hf_cip_ssupervisor_propose_tunid_tunid_snn_timestamp,
                         hf_cip_ssupervisor_propose_tunid_tunid_snn_date,
                         hf_cip_ssupervisor_propose_tunid_tunid_snn_time,
                         hf_cip_ssupervisor_propose_tunid_tunid_nodeid,
                         ett_ssupervisor_propose_tunid,
                         ett_ssupervisor_propose_tunid_snn);

            detect_cancel_propose_apply_operation(tvb, offset + 2 + req_path_size, pinfo, pi);
            break;
         case SC_SSUPER_APPLY_TUNID:
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_apply_tunid_tunid,
                         tvb, offset+2+req_path_size, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size, pi, "TUNID SNN",
                         hf_cip_ssupervisor_apply_tunid_tunid_snn_timestamp,
                         hf_cip_ssupervisor_apply_tunid_tunid_snn_date,
                         hf_cip_ssupervisor_apply_tunid_tunid_snn_time,
                         hf_cip_ssupervisor_apply_tunid_tunid_nodeid,
                         ett_ssupervisor_apply_tunid,
                         ett_ssupervisor_apply_tunid_snn);

            detect_cancel_propose_apply_operation(tvb, offset + 2 + req_path_size, pinfo, pi);
            break;
         default:
            proto_tree_add_item(cmd_data_tree, hf_cip_data,
                         tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals_ssupervisor);
}

static int
dissect_cip_class_s_supervisor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_s_supervisor, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_s_supervisor );

   dissect_cip_s_supervisor_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

static int dissect_s_supervisor_exception_detail(proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int hf_size, int hf_data)
{
   uint32_t size;
   proto_tree_add_item_ret_uint(tree, hf_size, tvb, offset, 1, ENC_LITTLE_ENDIAN, &size);

   proto_tree_add_item(tree, hf_data, tvb, offset+1, size, ENC_NA );
   proto_item_set_len(item, size+1);

   return size+1;
}

static int dissect_s_supervisor_exception_detail_common(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   proto_item *pi;
   proto_tree *item_tree;
   int total_size = 0, size;

   item_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_exception_detail_common, &pi, "Common Exception Detail");
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_ced_size,
               hf_cip_ssupervisor_exception_detail_ced_detail);
   if (size == 0)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_exception_detail_ced);
      return total_len;
   }
   total_size += size;

   item_tree = proto_tree_add_subtree(tree, tvb, offset + total_size, 1, ett_exception_detail_device, &pi, "Device Exception Detail");
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset + total_size,
               hf_cip_ssupervisor_exception_detail_ded_size,
               hf_cip_ssupervisor_exception_detail_ded_detail);
   if (size == 0)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_exception_detail_ded);
      return total_len;
   }
   total_size += size;

   item_tree = proto_tree_add_subtree(tree, tvb, offset + total_size, 1, ett_exception_detail_manufacturer, &pi, "Manufacturer Exception Detail");
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset + total_size,
               hf_cip_ssupervisor_exception_detail_med_size,
               hf_cip_ssupervisor_exception_detail_med_detail);
   if (size == 0)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_exception_detail_med);
      return total_len;
   }
   total_size += size;

   return total_size;
}

static int dissect_s_supervisor_configuration_unid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item,
                                                   tvbuff_t *tvb, int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_configuration_unid);
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "CFUNID SNN",
                  hf_cip_ssupervisor_configuration_unid_snn_timestamp,
                  hf_cip_ssupervisor_configuration_unid_snn_date,
                  hf_cip_ssupervisor_configuration_unid_snn_time,
                  hf_cip_ssupervisor_configuration_unid_nodeid,
                  ett_ssupervisor_configuration_unid,
                  ett_ssupervisor_configuration_unid_snn);
   return 10;
}

static int dissect_s_supervisor_safety_configuration_id(packet_info *pinfo, proto_tree *tree _U_, proto_item *item,
                                                        tvbuff_t *tvb, int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_safety_configuration_id);
      return total_len;
   }

   proto_tree_add_item(tree, hf_cip_ssupervisor_safety_configuration_id_sccrc, tvb, offset, 4, ENC_LITTLE_ENDIAN);

   dissect_cipsafety_snn(tree, tvb, pinfo, offset + 4,
      hf_cip_ssupervisor_safety_configuration_id_snn_timestamp,
      hf_cip_ssupervisor_safety_configuration_id_snn_date,
      hf_cip_ssupervisor_safety_configuration_id_snn_time);

   return 10;
}

static int dissect_s_supervisor_target_unid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item,
                                            tvbuff_t *tvb, int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_target_unid);
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "TUNID SNN",
                  hf_cip_ssupervisor_target_unid_snn_timestamp,
                  hf_cip_ssupervisor_target_unid_snn_date,
                  hf_cip_ssupervisor_target_unid_snn_time,
                  hf_cip_ssupervisor_target_unid_nodeid,
                  ett_ssupervisor_target_unid,
                  ett_ssupervisor_target_unid_snn);
   return 10;
}

static int dissect_s_supervisor_output_connection_point_owners(packet_info *pinfo, proto_tree *tree, proto_item *item,
                                                               tvbuff_t *tvb, int offset, int total_len)
{
   uint16_t    i, num_entries;
   proto_item *entry_item, *app_path_item;
   proto_tree *entry_tree, *epath_tree;
   int         attr_len = 0, app_path_size;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_cp_owners);
      return total_len;
   }

   entry_item = proto_tree_add_item(tree, hf_cip_ssupervisor_cp_owners_num_entries,
                         tvb, offset, 2, ENC_LITTLE_ENDIAN );
   num_entries = tvb_get_letohs(tvb, offset);
   attr_len += 2;

   if (num_entries > 0)
   {
      entry_tree = proto_item_add_subtree(entry_item, ett_ssupervisor_output_cp_owners);

      for (i = 0; i < num_entries; i++)
      {
         if (total_len < attr_len+11)
         {
            expert_add_info(pinfo, item, &ei_mal_ssupervisor_cp_owners_entry);
            return total_len;
         }

         dissect_unid(tvb, pinfo, offset+attr_len, entry_item, "OCPUNID SNN",
                         hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_timestamp,
                         hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_date,
                         hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_time,
                         hf_cip_ssupervisor_output_cp_owners_ocpunid_nodeid,
                         ett_ssupervisor_output_cp_owners_ocpunid,
                         ett_ssupervisor_output_cp_owners_ocpunid_snn);
         attr_len += 10;

         proto_tree_add_item(entry_tree, hf_cip_ssupervisor_cp_owners_app_path_size,
                         tvb, offset+attr_len, 1, ENC_LITTLE_ENDIAN );
         app_path_size = tvb_get_uint8( tvb, offset+attr_len);
         attr_len += 1;

         if (total_len < attr_len+app_path_size)
         {
            expert_add_info(pinfo, item, &ei_mal_ssupervisor_cp_owners_app_path_size);
            return total_len;
         }

         epath_tree = proto_tree_add_subtree(entry_tree,
                         tvb, offset+attr_len, app_path_size, ett_path, &app_path_item, "Application Resource: ");
         dissect_epath(tvb, pinfo, epath_tree, app_path_item, offset+attr_len, app_path_size, false, true, NULL, NULL, NO_DISPLAY, NULL, false);
         attr_len += app_path_size;
      }
   }

   return attr_len;
}

static int dissect_s_supervisor_proposed_tunid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item,
                                               tvbuff_t *tvb, int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info(pinfo, item, &ei_mal_ssupervisor_proposed_tunid);
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "Proposed TUNID SNN",
                  hf_cip_ssupervisor_proposed_tunid_snn_timestamp,
                  hf_cip_ssupervisor_proposed_tunid_snn_date,
                  hf_cip_ssupervisor_proposed_tunid_snn_time,
                  hf_cip_ssupervisor_proposed_tunid_nodeid,
                  ett_ssupervisor_proposed_tunid,
                  ett_ssupervisor_proposed_tunid_snn);

   return 10;
}

/************************************************
 *
 * Dissector for CIP Safety Validator Object
 *
 ************************************************/
static int dissect_s_validator_type(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                                    int offset, int total_len)
{
   if (total_len < 1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_type);
      return total_len;
   }

   static int* const bits[] = {
      &hf_cip_svalidator_type_pc,
      &hf_cip_svalidator_type_conn_type,
      NULL
   };
   proto_tree_add_bitmask(tree, tvb, offset, hf_cip_svalidator_type, ett_svalidator_type, bits, ENC_LITTLE_ENDIAN);

   return 1;
}

static int dissect_s_validator_time_coord_msg_min_mult(packet_info *pinfo, proto_tree *tree, proto_item *item,
                                                       tvbuff_t *tvb, int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_time_coord_msg_min_mult_size,
                         tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_uint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_time_coord_msg_min_mult);
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_time_coord_msg_min_mult_item,
                         tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static int dissect_s_validator_network_time_multiplier(packet_info *pinfo, proto_tree *tree, proto_item *item,
                                                       tvbuff_t *tvb, int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_network_time_multiplier_size,
                       tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_uint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_network_time_multiplier);
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_network_time_multiplier_item,
                          tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static int dissect_s_validator_timeout_multiplier(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_timeout_multiplier_size,
                       tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_uint8( tvb, offset );

   if (total_len < size+1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_timeout_multiplier);
      return total_len;
   }

   for (i = 0; i < size; i++)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_timeout_multiplier_item,
                          tvb, offset+1+i, 1, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static int dissect_s_validator_coordination_conn_inst(packet_info *pinfo, proto_tree *tree, proto_item *item,
                                                      tvbuff_t *tvb, int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_coordination_conn_inst_size,
                       tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_uint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_coordination_conn_inst);
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_coordination_conn_inst_item,
                          tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static int dissect_s_validator_app_data_path(packet_info *pinfo, proto_tree *tree,
                                             proto_item *item _U_, tvbuff_t *tvb, int offset, int total_len)
{
   proto_item* pi;
   proto_tree* epath_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_path, &pi, "Application Data Path: ");
   dissect_epath(tvb, pinfo, epath_tree, pi, offset, total_len, false, false, NULL, NULL, NO_DISPLAY, NULL, false);
   return total_len;
}

static int dissect_s_validator_prod_cons_fault_count(packet_info *pinfo, proto_tree *tree, proto_item *item,
                                                     tvbuff_t *tvb, int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_prod_cons_fault_count_size,
                         tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_uint8( tvb, offset );

   if (total_len < size+1)
   {
      expert_add_info(pinfo, item, &ei_mal_svalidator_prod_cons_fault_count);
      return total_len;
   }

   for (i = 0; i < size; i++)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_prod_cons_fault_count_item,
                         tvb, offset+1+i, 1, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static void
dissect_cip_s_validator_data( proto_tree *item_tree,
                              tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item                *pi, *rrsc_item;
   proto_tree                *rrsc_tree, *cmd_data_tree;
   int                        req_path_size;
   uint8_t                    service, gen_status, add_stat_size;
   cip_simple_request_info_t  req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIPS Validator");

   /* Add Service code & Request/Response tree */
   service   = tvb_get_uint8( tvb, offset );
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_svalidator_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ),
                  cip_sc_vals_svalidator , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_svalidator_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   load_cip_request_data(pinfo, &req_data);

   if (service & CIP_SC_RESPONSE_MASK)
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size,
                                ett_ssupervisor_cmd_data, &pi, "Command Specific Data" );

         if( gen_status == CI_GRC_SUCCESS )
         {
            /* Success responses */
            if (((service & CIP_SC_MASK) == SC_GET_ATT_ALL) &&
                (req_data.iInstance != SEGMENT_VALUE_NOT_SET) &&
                (req_data.iInstance != 0))
            {
                dissect_cip_get_attribute_all_rsp(tvb, pinfo, cmd_data_tree, offset + 4 + add_stat_size, &req_data);
            }
            else
            {
               /* Add data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data,
                                   tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
            }
         }
         else
         {
            /* Error responses */

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data,
                                tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2,
                                                ett_ssupervisor_cmd_data, NULL, "Command Specific Data" );
         proto_tree_add_item(cmd_data_tree, hf_cip_data,
                         tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
      }

   }

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals_svalidator);
}

static int
dissect_cip_class_s_validator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_s_validator, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_s_validator );

   dissect_cip_s_validator_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

static bool
dissect_class_svalidator_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   unsigned char   service, service_code, ioilen, segment;
   cip_req_info_t* preq_info;
   uint32_t        classid = 0;
   int             offset  = 0;

   service = tvb_get_uint8( tvb, offset );
   service_code = service & CIP_SC_MASK;

   /* Handle GetAttributeAll and SetAttributeAll in CCO class */
   if (service_code == SC_GET_ATT_ALL)
   {
      if (service & CIP_SC_RESPONSE_MASK)
      {
         /* Service response */
         preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
         if ((preq_info != NULL) &&
             (preq_info->dissector == dissector_get_uint_handle( subdissector_class_table, CI_CLS_SAFETY_VALIDATOR)))
         {
            call_dissector(preq_info->dissector, tvb, pinfo, tree);
            return true;
         }
      }
      else
      {
         /* Service request */
         ioilen = tvb_get_uint8( tvb, offset + 1 );
         if (ioilen > 1)
         {
            segment = tvb_get_uint8( tvb, offset + 2 );
            if (((segment & CI_SEGMENT_TYPE_MASK) == CI_LOGICAL_SEGMENT) &&
                ((segment & CI_LOGICAL_SEG_TYPE_MASK) == CI_LOGICAL_SEG_CLASS_ID))
            {
               /* Logical Class ID, do a format check */
               switch ( segment & CI_LOGICAL_SEG_FORMAT_MASK )
               {
               case CI_LOGICAL_SEG_8_BIT:
                  classid = tvb_get_uint8( tvb, offset + 3 );
                  break;
               case CI_LOGICAL_SEG_16_BIT:
                  if ( ioilen >= 2 )
                     classid = tvb_get_letohs( tvb, offset + 4 );
                  break;
               case CI_LOGICAL_SEG_32_BIT:
                  if ( ioilen >= 3 )
                     classid = tvb_get_letohl( tvb, offset + 4 );
                  break;
               }
            }
         }

         if (classid == CI_CLS_SAFETY_VALIDATOR)
         {
            call_dissector(cip_class_s_validator_handle, tvb, pinfo, tree );
            return true;
         }

      }
   }

   return false;
}

/************************************************
 *
 * CRC handling
 *
 ************************************************/
static uint8_t compute_crc_s1_pid(const cip_connection_triad_t* triad)
{
    uint8_t temp_buf[8];
    memcpy(temp_buf, &triad->VendorID, 2);
    memcpy(&temp_buf[2], &triad->DeviceSerialNumber, 4);
    memcpy(&temp_buf[6], &triad->ConnSerialNumber, 2);

    return crc8_0x37(temp_buf, 8, 0);
}

static uint8_t compute_crc_s1_timestamp(uint8_t pid_seed, uint8_t mode_byte_mask, uint16_t timestamp)
{
    uint8_t mode_byte_crc = crc8_0x37(&mode_byte_mask, 1, pid_seed);
    uint8_t timestamp_crc = crc8_0x37((uint8_t*)&timestamp, 2, mode_byte_crc);

    return timestamp_crc;
}

static uint8_t compute_crc_s1_data(uint8_t pid_seed, uint8_t mode_byte_mask, const uint8_t *buf, int len)
{
    uint8_t mode_byte_crc = crc8_0x37(&mode_byte_mask, 1, pid_seed);

    return crc8_0x37(buf, len, mode_byte_crc);
}

static uint8_t compute_crc_s2_data(uint8_t pid_seed, uint8_t mode_byte_mask, uint8_t *comp_buf, int len)
{
    int i;
    uint8_t mode_byte_crc = crc8_0x3B(&mode_byte_mask, 1, pid_seed);

    for (i = 0; i < len; i++)
        comp_buf[i] ^= 0xFF;

    return crc8_0x3B(comp_buf, len, mode_byte_crc);
}

static uint16_t compute_crc_s3_pid(const cip_connection_triad_t* triad)
{
    uint8_t temp_buf[8];
    memcpy(temp_buf, &triad->VendorID, 2);
    memcpy(&temp_buf[2], &triad->DeviceSerialNumber, 4);
    memcpy(&temp_buf[6], &triad->ConnSerialNumber, 2);

    return crc16_0x080F_seed(temp_buf, 8, 0);
}

static uint16_t compute_crc_s3_base_data(uint16_t pid_seed, uint8_t mode_byte_mask, const uint8_t *buf, int len)
{
    uint16_t mode_byte_crc = crc16_0x080F_seed(&mode_byte_mask, 1, pid_seed);

    return crc16_0x080F_seed(buf, len, mode_byte_crc);
}

static uint16_t compute_crc_s3_extended_data(uint16_t pid_seed, uint16_t rollover_value, uint8_t mode_byte_mask, const uint8_t *buf, int len)
{
    uint16_t rollover_crc = crc16_0x080F_seed((uint8_t*)&rollover_value, 2, pid_seed);
    uint16_t mode_byte_crc = crc16_0x080F_seed(&mode_byte_mask, 1, rollover_crc);

    return crc16_0x080F_seed(buf, len, mode_byte_crc);
}

static uint16_t compute_crc_s3_time(uint16_t pid_seed, uint8_t ack_mcast_byte, uint16_t timestamp_value)
{
    uint16_t mode_byte_crc = crc16_0x080F_seed(&ack_mcast_byte, 1, pid_seed);
    uint16_t timestamp_crc;

    timestamp_crc = crc16_0x080F_seed((uint8_t*)&timestamp_value, 2, mode_byte_crc);

    return timestamp_crc;
}

static uint32_t compute_crc_s5_pid(const cip_connection_triad_t* triad)
{
    uint8_t temp_buf[8];
    memcpy(temp_buf, &triad->VendorID, 2);
    memcpy(&temp_buf[2], &triad->DeviceSerialNumber, 4);
    memcpy(&temp_buf[6], &triad->ConnSerialNumber, 2);

    return crc32_0x5D6DCB_seed(temp_buf, 8, 0);
}

static uint32_t compute_crc_s5_short_data(uint32_t pid_seed, uint16_t rollover_value, uint8_t mode_byte_mask, uint16_t timestamp_value, const uint8_t *buf, int len)
{
    uint32_t rollover_crc = crc32_0x5D6DCB_seed((uint8_t*)&rollover_value, 2, pid_seed);
    uint32_t mode_byte_crc = crc32_0x5D6DCB_seed(&mode_byte_mask, 1, rollover_crc);
    uint32_t data_crc, timestamp_crc;

    data_crc = crc32_0x5D6DCB_seed(buf, len, mode_byte_crc);
    timestamp_crc = crc32_0x5D6DCB_seed((uint8_t*)&timestamp_value, 2, data_crc);

    return timestamp_crc;
}

static uint32_t compute_crc_s5_long_data(uint32_t pid_seed, uint16_t rollover_value, uint8_t mode_byte_mask, uint16_t timestamp_value, uint8_t *comp_buf, int len)
{
    int i;
    uint32_t rollover_crc = crc32_0x5D6DCB_seed((uint8_t*)&rollover_value, 2, pid_seed);
    uint32_t mode_byte_crc = crc32_0x5D6DCB_seed(&mode_byte_mask, 1, rollover_crc);
    uint32_t comp_data_crc, timestamp_crc;

    for (i = 0; i < len; i++)
        comp_buf[i] ^= 0xFF;

    comp_data_crc = crc32_0x5D6DCB_seed(comp_buf, len, mode_byte_crc);
    timestamp_crc = crc32_0x5D6DCB_seed((uint8_t*)&timestamp_value, 2, comp_data_crc);

    return timestamp_crc;
}

static uint32_t compute_crc_s5_time(uint32_t pid_seed, uint8_t ack_mcast_byte, uint16_t timestamp_value)
{
    uint32_t mode_byte_crc = crc32_0x5D6DCB_seed(&ack_mcast_byte, 1, pid_seed);
    uint32_t timestamp_crc;

    timestamp_crc = crc32_0x5D6DCB_seed((uint8_t*)&timestamp_value, 2, mode_byte_crc);

    return timestamp_crc;
}

static bool verify_compliment_data(tvbuff_t *tvb, int data_offset, int complement_data_offset, int data_size)
{
    const uint8_t *data = tvb_get_ptr(tvb, data_offset, data_size);
    const uint8_t *complement_data = tvb_get_ptr(tvb, complement_data_offset, data_size);
    int i;

    for (i = 0; i < data_size; i++)
    {
        if ((data[i] ^ complement_data[i])!= 0xFF)
            return false;
    }

    return true;
}

static void validate_crc_s5(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, bool compute_crc,
   uint32_t crc_s5_0, uint32_t crc_s5_1, uint32_t crc_s5_2, uint32_t computed_crc_s5)
{
   proto_item* crc_s5_status_item;

   /* CRC-S5 doesn't use proto_tree_add_checksum because the checksum is broken up into multiple fields */
   if (compute_crc)
   {
      uint32_t value_s5 = crc_s5_0;
      value_s5 += ((crc_s5_1 << 8) & 0xFF00);
      value_s5 += ((crc_s5_2 << 16) & 0xFF0000);

      if (computed_crc_s5 == value_s5)
      {
         crc_s5_status_item = proto_tree_add_uint(tree, hf_cipsafety_crc_s5_status, tvb, 0, 0, PROTO_CHECKSUM_E_GOOD);
      }
      else
      {
         crc_s5_status_item = proto_tree_add_uint(tree, hf_cipsafety_crc_s5_status, tvb, 0, 0, PROTO_CHECKSUM_E_BAD);
         expert_add_info_format(pinfo, crc_s5_status_item, &ei_cipsafety_crc_s5, "%s [should be 0x%08x]", expert_get_summary(&ei_cipsafety_crc_s5), computed_crc_s5);
      }
   }
   else
   {
      crc_s5_status_item = proto_tree_add_uint(tree, hf_cipsafety_crc_s5_status, tvb, 0, 0, PROTO_CHECKSUM_E_UNVERIFIED);
   }

   proto_item_set_generated(crc_s5_status_item);
}

/************************************************
 *
 * Dissector for CIP Safety I/O Data
 *
 ************************************************/
static void
dissect_mode_byte( proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
   proto_item *mode_item, *run_idle_item, *tbd_item, *tbd2_item;
   proto_tree *mode_tree;
   uint8_t     mode_byte;

   mode_byte = tvb_get_uint8(tvb, offset);

   /* dissect Mode Byte bits */
   mode_item = proto_tree_add_item(tree, hf_cipsafety_mode_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   mode_tree = proto_item_add_subtree( mode_item, ett_cipsafety_mode_byte);

   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_ping_count,               tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_not_tbd,                  tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd_2_copy,               tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_not_run_idle,             tvb, offset, 1, ENC_LITTLE_ENDIAN);
   tbd_item  = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd,          tvb, offset, 1, ENC_LITTLE_ENDIAN);
   tbd2_item = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd_2_bit,    tvb, offset, 1, ENC_LITTLE_ENDIAN);
   run_idle_item = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_run_idle, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* verify Mode Byte bits */
   /* TBD */
   if ((((mode_byte & 0x20) >> 5) & 0x01) == (((mode_byte & 0x04) >> 2) & 0x01))
      expert_add_info(pinfo, tbd_item, &ei_cipsafety_tbd_not_complemented);

   /* TBD 2 */
   if ((((mode_byte & 0x40) >> 6) & 0x01) != (((mode_byte & 0x08) >> 3) & 0x01))
      expert_add_info(pinfo, tbd2_item, &ei_cipsafety_tbd2_not_copied);

   /* Run/Idle */
   if ((((mode_byte & 0x80) >> 7) & 0x01) == (((mode_byte & 0x10) >> 4) & 0x01))
      expert_add_info(pinfo, run_idle_item, &ei_cipsafety_run_idle_not_complemented);
}

static void
dissect_ack_byte( proto_tree *tree, tvbuff_t *tvb, int offset)
{
   // TODO: add ack_byte validation
   static int* const bits[] = {
      &hf_cipsafety_ack_byte_ping_count_reply,
      &hf_cipsafety_ack_byte_reserved1,
      &hf_cipsafety_ack_byte_ping_response,
      &hf_cipsafety_ack_byte_reserved2,
      &hf_cipsafety_ack_byte_parity_even,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cipsafety_ack_byte, ett_cipsafety_ack_byte, bits, ENC_LITTLE_ENDIAN);
}

static void
dissect_mcast_byte( proto_tree *tree, tvbuff_t *tvb, int offset)
{
   // TODO: add mcast_byte validation
   static int* const bits[] = {
      &hf_cipsafety_mcast_byte_consumer_num,
      &hf_cipsafety_mcast_byte_reserved1,
      &hf_cipsafety_mcast_byte_mai,
      &hf_cipsafety_mcast_byte_reserved2,
      &hf_cipsafety_mcast_byte_parity_even,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_cipsafety_mcast_byte, ett_cipsafety_mcast_byte, bits, ENC_LITTLE_ENDIAN);
}

// Base Format Time Correction Message
static void dissect_base_format_time_correction_message(proto_tree* tree, tvbuff_t* tvb, int offset)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_BASE_TIME_CORRECTION);
   proto_item_set_generated(it);

   dissect_mcast_byte(tree, tvb, offset);
   proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_cipsafety_mcast_byte2, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
}

// Extended Format Time Correction Message
static void dissect_extended_format_time_correction_message(proto_tree* tree, tvbuff_t* tvb, int offset)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_EXTENDED_TIME_CORRECTION);
   proto_item_set_generated(it);

   dissect_mcast_byte(tree, tvb, offset);
   proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, offset + 5, 1, ENC_LITTLE_ENDIAN);

   // TODO: Validate CRC S5.
}

// Base Format, Time Stamp Section Format
static void dissect_base_format_time_stamp_section(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int offset,
   bool compute_crc, uint8_t mode_byte, const cip_connection_triad_t* connection_triad)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_BASE_TIME_STAMP);
   proto_item_set_generated(it);

   proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, offset, 2, ENC_LITTLE_ENDIAN);
   uint16_t timestamp = tvb_get_letohs(tvb, offset);

   if (compute_crc)
   {
      uint8_t computed_crc_s1 = compute_crc_s1_timestamp(compute_crc_s1_pid(connection_triad),
         (mode_byte & MODE_BYTE_CRC_S1_TIME_STAMP_MASK),
         timestamp);
      proto_tree_add_checksum(tree, tvb, offset + 2,
         hf_cipsafety_crc_s1, hf_cipsafety_crc_s1_status, &ei_cipsafety_crc_s1, pinfo,
         computed_crc_s1, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, offset + 2,
         hf_cipsafety_crc_s1, hf_cipsafety_crc_s1_status, &ei_cipsafety_crc_s1,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }
}

// Base Format Time Coordination Message
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_base_format_time_coordination_message(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb,
   bool compute_crc, const cip_connection_triad_t* connection_triad)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_BASE_TIME_COORDINATION);
   proto_item_set_generated(it);

   dissect_ack_byte(tree, tvb, 0);
   uint8_t ack_byte = tvb_get_uint8(tvb, 0);

   proto_tree_add_item(tree, hf_cipsafety_consumer_time_value, tvb, 1, 2, ENC_LITTLE_ENDIAN);
   uint16_t timestamp = tvb_get_letohs(tvb, 1);

   proto_tree_add_item(tree, hf_cipsafety_ack_byte2, tvb, 3, 1, ENC_LITTLE_ENDIAN);

   if (compute_crc)
   {
      uint16_t computed_crc_s3 = compute_crc_s3_time(compute_crc_s3_pid(connection_triad), ack_byte, timestamp);
      proto_tree_add_checksum(tree, tvb, 4,
         hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3, pinfo,
         computed_crc_s3, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, 4,
         hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }
}

// Extended Format Time Coordination Message
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_extended_format_time_coordination_message(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb,
   bool compute_crc, const cip_connection_triad_t* connection_triad)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_EXTENDED_TIME_COORDINATION);
   proto_item_set_generated(it);

   dissect_ack_byte(tree, tvb, 0);
   uint8_t ack_byte = tvb_get_uint8(tvb, 0);

   proto_tree_add_item(tree, hf_cipsafety_consumer_time_value, tvb, 1, 2, ENC_LITTLE_ENDIAN);
   uint16_t timestamp = tvb_get_letohs(tvb, 1);

   uint32_t crc_s5_0, crc_s5_1, crc_s5_2;
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_0, tvb, 3, 1, ENC_LITTLE_ENDIAN, &crc_s5_0);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_1, tvb, 4, 1, ENC_LITTLE_ENDIAN, &crc_s5_1);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_2, tvb, 5, 1, ENC_LITTLE_ENDIAN, &crc_s5_2);

   uint32_t computed_crc_s5 = compute_crc_s5_time(compute_crc_s5_pid(connection_triad),
      ack_byte,
      timestamp);
   validate_crc_s5(pinfo, tree, tvb, compute_crc, crc_s5_0, crc_s5_1, crc_s5_2, computed_crc_s5);
}

// 1 or 2 Byte Data section, Base Format
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_base_format_1_or_2_byte_data(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int io_data_size,
   bool compute_crc, const cip_connection_triad_t* connection_triad)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_BASE_1_2_BYTE_DATA);
   proto_item_set_generated(it);

   proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_NA);
   dissect_mode_byte(tree, tvb, io_data_size, pinfo);
   uint8_t mode_byte = tvb_get_uint8(tvb, io_data_size);

   if (compute_crc)
   {
      uint8_t computed_crc_s1 = compute_crc_s1_data(compute_crc_s1_pid(connection_triad),
         (mode_byte & MODE_BYTE_CRC_S1_MASK),
         tvb_get_ptr(tvb, 0, io_data_size), io_data_size);

      proto_tree_add_checksum(tree, tvb, io_data_size + 1,
         hf_cipsafety_crc_s1, hf_cipsafety_crc_s1_status, &ei_cipsafety_crc_s1, pinfo,
         computed_crc_s1, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

      uint8_t computed_crc_s2 = compute_crc_s2_data(compute_crc_s1_pid(connection_triad),
         ((mode_byte ^ 0xFF) & MODE_BYTE_CRC_S1_MASK),
         /* I/O data is duplicated because it will be complemented inline */
         (uint8_t*)tvb_memdup(pinfo->pool, tvb, 0, io_data_size), io_data_size);

      proto_tree_add_checksum(tree, tvb, io_data_size + 2,
         hf_cipsafety_crc_s2, hf_cipsafety_crc_s2_status, &ei_cipsafety_crc_s2, pinfo,
         computed_crc_s2, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, io_data_size + 1,
         hf_cipsafety_crc_s1, hf_cipsafety_crc_s1_status, &ei_cipsafety_crc_s1,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
      proto_tree_add_checksum(tree, tvb, io_data_size + 2,
         hf_cipsafety_crc_s2, hf_cipsafety_crc_s2_status, &ei_cipsafety_crc_s2,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }
}

// 3 to 250 Byte Data section, Base Format
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_base_format_3_to_250_byte_data(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int io_data_size,
   bool compute_crc, const cip_connection_triad_t* connection_triad)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_BASE_3_250_BYTE_DATA);
   proto_item_set_generated(it);

   proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_NA);
   dissect_mode_byte(tree, tvb, io_data_size, pinfo);
   unsigned mode_byte = tvb_get_uint8(tvb, io_data_size);

   if (compute_crc)
   {
      uint16_t computed_crc_s3 = compute_crc_s3_base_data(compute_crc_s3_pid(connection_triad),
         mode_byte & MODE_BYTE_CRC_S3_MASK, tvb_get_ptr(tvb, 0, io_data_size), io_data_size);

      proto_tree_add_checksum(tree, tvb, io_data_size + 1,
         hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3, pinfo,
         computed_crc_s3, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, io_data_size + 1,
         hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }

   proto_item* complement_item = proto_tree_add_item(tree, hf_cipsafety_complement_data, tvb, io_data_size + 3, io_data_size, ENC_NA);
   if (!verify_compliment_data(tvb, 0, io_data_size + 3, io_data_size))
      expert_add_info(pinfo, complement_item, &ei_cipsafety_not_complement_data);

   if (compute_crc)
   {
      uint16_t computed_crc_s3 = compute_crc_s3_base_data(compute_crc_s3_pid(connection_triad),
         ((mode_byte ^ 0xFF) & MODE_BYTE_CRC_S3_MASK),
         tvb_get_ptr(tvb, io_data_size + 3, io_data_size), io_data_size);

      proto_tree_add_checksum(tree, tvb, (io_data_size * 2) + 3,
         hf_cipsafety_complement_crc_s3, hf_cipsafety_complement_crc_s3_status, &ei_cipsafety_complement_crc_s3, pinfo,
         computed_crc_s3, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, (io_data_size * 2) + 3,
         hf_cipsafety_complement_crc_s3, hf_cipsafety_complement_crc_s3_status, &ei_cipsafety_complement_crc_s3,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }
}

// 1 or 2 Byte Data Section, Extended Format
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_extended_format_1_or_2_byte_data(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int io_data_size,
   bool compute_crc, const cip_connection_triad_t* connection_triad, const cip_safety_packet_data_t* packet_data)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_EXTENDED_1_2_BYTE_DATA);
   proto_item_set_generated(it);

   proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_NA);
   dissect_mode_byte(tree, tvb, io_data_size, pinfo);
   unsigned mode_byte = tvb_get_uint8(tvb, io_data_size);

   uint32_t crc_s5_0, crc_s5_1, crc_s5_2;
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_0, tvb, io_data_size + 1, 1, ENC_LITTLE_ENDIAN, &crc_s5_0);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_1, tvb, io_data_size + 2, 1, ENC_LITTLE_ENDIAN, &crc_s5_1);
   proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, io_data_size + 3, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_2, tvb, io_data_size + 5, 1, ENC_LITTLE_ENDIAN, &crc_s5_2);

   uint16_t timestamp = tvb_get_letohs(tvb, io_data_size + 3);

   uint32_t computed_crc_s5 = 0;
   if (packet_data != NULL)
   {
      computed_crc_s5 = compute_crc_s5_short_data(compute_crc_s5_pid(connection_triad),
         packet_data->rollover_value,
         mode_byte & MODE_BYTE_CRC_S5_BASE_MASK,
         timestamp,
         tvb_get_ptr(tvb, 0, io_data_size),
         io_data_size);
   }

   validate_crc_s5(pinfo, tree, tvb, compute_crc, crc_s5_0, crc_s5_1, crc_s5_2, computed_crc_s5);
}

// 3 to 250 Byte Data section, Extended Format
// Note: All data starts from the beginning of the tvb buffer.
static void dissect_extended_format_3_to_250_byte_data(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int io_data_size,
   bool compute_crc, const cip_connection_triad_t* connection_triad, const cip_safety_packet_data_t* packet_data)
{
   proto_item* it = proto_tree_add_uint(tree, hf_cip_safety_message_encoding, tvb, 0, 0, MSG_ENCODING_EXTENDED_3_250_BYTE_DATA);
   proto_item_set_generated(it);

   proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_NA);
   dissect_mode_byte(tree, tvb, io_data_size, pinfo);
   unsigned mode_byte = tvb_get_uint8(tvb, io_data_size);

   uint16_t timestamp = tvb_get_letohs(tvb, (io_data_size * 2) + 5);

   if (compute_crc)
   {
      if (packet_data != NULL)
      {
         uint16_t computed_crc_s3 = compute_crc_s3_extended_data(compute_crc_s3_pid(connection_triad),
            packet_data->rollover_value,
            mode_byte & MODE_BYTE_CRC_S3_MASK,
            tvb_get_ptr(tvb, 0, io_data_size), io_data_size);

         proto_tree_add_checksum(tree, tvb, io_data_size + 1,
            hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3, pinfo,
            computed_crc_s3, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
      }
   }
   else
   {
      proto_tree_add_checksum(tree, tvb, io_data_size + 1,
         hf_cipsafety_crc_s3, hf_cipsafety_crc_s3_status, &ei_cipsafety_crc_s3,
         pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
   }

   proto_item* complement_item = proto_tree_add_item(tree, hf_cipsafety_complement_data, tvb, io_data_size + 3, io_data_size, ENC_NA);
   if (!verify_compliment_data(tvb, 0, io_data_size + 3, io_data_size))
      expert_add_info(pinfo, complement_item, &ei_cipsafety_not_complement_data);

   uint32_t crc_s5_0, crc_s5_1, crc_s5_2;
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_0, tvb, (io_data_size * 2) + 3, 1, ENC_LITTLE_ENDIAN, &crc_s5_0);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_1, tvb, (io_data_size * 2) + 4, 1, ENC_LITTLE_ENDIAN, &crc_s5_1);
   proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, (io_data_size * 2) + 5, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item_ret_uint(tree, hf_cipsafety_crc_s5_2, tvb, (io_data_size * 2) + 7, 1, ENC_LITTLE_ENDIAN, &crc_s5_2);

   uint32_t computed_crc_s5 = 0;
   if (packet_data != NULL)
   {
      computed_crc_s5 = compute_crc_s5_long_data(compute_crc_s5_pid(connection_triad),
         packet_data->rollover_value,
         mode_byte & MODE_BYTE_CRC_S5_EXTENDED_MASK,
         timestamp,
         /* I/O data is duplicated because it will be complemented inline */
         (uint8_t*)tvb_memdup(pinfo->pool, tvb, 0, io_data_size),
         io_data_size);
   }
   validate_crc_s5(pinfo, tree, tvb, compute_crc, crc_s5_0, crc_s5_1, crc_s5_2, computed_crc_s5);
}

// Note: This updates the running timestamp/rollover data in safety_info during the first pass.
static cip_safety_packet_data_t* get_timestamp_packet_data(packet_info* pinfo, cip_safety_info_t* safety_info, uint16_t timestamp)
{
   cip_safety_packet_data_t* packet_data = NULL;

   /* Determine if packet timestamp results in rollover count increment */
   if (!pinfo->fd->visited)
   {
      packet_data = wmem_new0(wmem_file_scope(), cip_safety_packet_data_t);

      if ((timestamp == 0) && !safety_info->eip_conn_info->safety.seen_non_zero_timestamp)
      {
         // The rollover value is zero, until the Time Coordination exchange is done.
         // When the timestamp is zero, that means we haven't seen the Time Coordination message.
         packet_data->rollover_value = 0;
      }
      else
      {
         safety_info->eip_conn_info->safety.seen_non_zero_timestamp = true;

         if (timestamp < safety_info->eip_conn_info->safety.running_timestamp_value)
         {
            safety_info->eip_conn_info->safety.running_rollover_value++;
         }

         /* Save the rollover value for CRC calculations */
         packet_data->rollover_value = safety_info->eip_conn_info->safety.running_rollover_value;
         safety_info->eip_conn_info->safety.running_timestamp_value = timestamp;
      }

      p_add_proto_data(wmem_file_scope(), pinfo, proto_cipsafety, 0, packet_data);
   }
   else
   {
      packet_data = (cip_safety_packet_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cipsafety, 0);
   }

   return packet_data;
}

enum cip_safety_data_type {CIP_SAFETY_DATA_TYPE_UNKNOWN, CIP_SAFETY_PRODUCE, CIP_SAFETY_CONSUME};
static enum cip_safety_data_type get_cip_safety_data_type(enum enip_connid_type conn_type, const cip_safety_epath_info_t* safety)
{
   if (conn_type == ECIDT_O2T && safety->originator_type == CIP_SAFETY_ORIGINATOR_PRODUCER)
   {
      return CIP_SAFETY_PRODUCE;
   }
   else if (conn_type == ECIDT_O2T && safety->originator_type == CIP_SAFETY_ORIGINATOR_CONSUMER)
   {
      return CIP_SAFETY_CONSUME;
   }
   else if (conn_type == ECIDT_T2O && safety->originator_type == CIP_SAFETY_ORIGINATOR_PRODUCER)
   {
      return CIP_SAFETY_CONSUME;
   }
   else if (conn_type == ECIDT_T2O && safety->originator_type == CIP_SAFETY_ORIGINATOR_CONSUMER)
   {
      return CIP_SAFETY_PRODUCE;
   }
   else
   {
      return CIP_SAFETY_DATA_TYPE_UNKNOWN;
   }
}

void add_safety_data_type_to_info_column(packet_info *pinfo, enum enip_connid_type conn_type, const cip_safety_epath_info_t* safety)
{
   enum cip_safety_data_type data_type = get_cip_safety_data_type(conn_type, safety);

   if (data_type == CIP_SAFETY_CONSUME)
   {
      col_append_str(pinfo->cinfo, COL_INFO, " [C->P]");
   }
   else  // CIP_SAFETY_PRODUCE
   {
      col_append_str(pinfo->cinfo, COL_INFO, " [P->C]");
   }
}

static void
dissect_cip_safety_data( proto_tree *tree, proto_item *item, tvbuff_t *tvb, int item_length, packet_info *pinfo, cip_safety_info_t* safety_info)
{
   int base_length, io_data_size;
   bool multicast = in4_addr_is_multicast(pntoh32(pinfo->dst.data));
   bool server_dir = false;
   enum enip_connid_type conn_type = ECIDT_UNKNOWN;
   enum cip_safety_format_type format = CIP_SAFETY_BASE_FORMAT;
   uint16_t timestamp;
   uint8_t mode_byte;
   bool short_format = true;
   bool compute_crc = ((safety_info != NULL) && (safety_info->compute_crc == true));
   cip_connection_triad_t connection_triad = {0};

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP Safety");

   /* determine the connection type as it affects the fields dissected */
   if (safety_info != NULL && safety_info->eip_conn_info != NULL)
   {
      conn_type = safety_info->conn_type;
      format = safety_info->eip_conn_info->safety.format;
      server_dir = (safety_info->eip_conn_info->TransportClass_trigger & CI_PRODUCTION_DIR_MASK) ? true : false;
   }

   /* compute the base packet length to determine what is actual I/O data */
   base_length = multicast ? 12 : 6;

   if (item_length < base_length) {
      expert_add_info(pinfo, item, &ei_mal_io);
      return;
   }

   if (((conn_type == ECIDT_O2T) && (server_dir == false)) ||
       ((conn_type == ECIDT_T2O) && (server_dir == true)))
   {
      if (compute_crc)
      {
         if ((conn_type == ECIDT_O2T) && (server_dir == false))
         {
            connection_triad = safety_info->eip_conn_info->triad;
         }
         else
         {
            connection_triad = safety_info->eip_conn_info->safety.target_triad;
         }
      }

      /* consumer data */
      proto_item_append_text(item, " [Consume]");
      col_append_str(pinfo->cinfo, COL_INFO, " [C->P]");

      switch (format)
      {
      case CIP_SAFETY_BASE_FORMAT:
         dissect_base_format_time_coordination_message(pinfo, tree, tvb, compute_crc, &connection_triad);
         break;
      case CIP_SAFETY_EXTENDED_FORMAT:
         dissect_extended_format_time_coordination_message(pinfo, tree, tvb, compute_crc, &connection_triad);
         break;
      }
   }
   else if (((conn_type == ECIDT_O2T) && (server_dir == true)) ||
            ((conn_type == ECIDT_T2O) && (server_dir == false)))
   {
      if (compute_crc)
      {
         if ((conn_type == ECIDT_O2T) && (server_dir == true))
         {
            connection_triad = safety_info->eip_conn_info->triad;
         }
         else
         {
            connection_triad = safety_info->eip_conn_info->safety.target_triad;
         }
      }

      if (item_length-base_length > 2)
         short_format = false;

      /* producer data */
      proto_item_append_text(item, " [Produce]");
      col_append_str(pinfo->cinfo, COL_INFO, " [P->C]");

      switch (format)
      {
      case CIP_SAFETY_BASE_FORMAT:
         if (short_format)
         {
            io_data_size = item_length-base_length;
            mode_byte = tvb_get_uint8(tvb, io_data_size);

            dissect_base_format_1_or_2_byte_data(pinfo, tree, tvb, io_data_size, compute_crc, &connection_triad);
            dissect_base_format_time_stamp_section(pinfo, tree, tvb, io_data_size + 3, compute_crc, mode_byte, &connection_triad);

            if (multicast)
            {
               dissect_base_format_time_correction_message(tree, tvb, item_length - 6);
            }
         }
         else
         {
            /* 3 to 250 Byte Data section, Base Format */
            if (item_length%2 == 1)
            {
               /* Malformed packet */
               expert_add_info(pinfo, item, &ei_mal_io);
               return;
            }

            io_data_size = multicast ? ((item_length-14)/2) : ((item_length-8)/2);
            mode_byte = tvb_get_uint8(tvb, io_data_size);

            dissect_base_format_3_to_250_byte_data(pinfo, tree, tvb, io_data_size, compute_crc, &connection_triad);
            dissect_base_format_time_stamp_section(pinfo, tree, tvb, (io_data_size * 2) + 5, compute_crc, mode_byte, &connection_triad);

            if (multicast)
            {
               dissect_base_format_time_correction_message(tree, tvb, (io_data_size * 2) + 5);
            }
         }
         break;
      case CIP_SAFETY_EXTENDED_FORMAT:
      {
         if (short_format)
         {
            io_data_size = item_length-base_length;
            timestamp = tvb_get_letohs(tvb, io_data_size+3);
         }
         else
         {
            io_data_size = multicast ? ((item_length-14)/2) : ((item_length-8)/2);
            timestamp = tvb_get_letohs(tvb, (io_data_size*2)+5);
         }

         cip_safety_packet_data_t* packet_data = NULL;
         if (compute_crc)
         {
            packet_data = get_timestamp_packet_data(pinfo, safety_info, timestamp);
         }

         if (short_format)
         {
            dissect_extended_format_1_or_2_byte_data(pinfo, tree, tvb, io_data_size, compute_crc, &connection_triad, packet_data);

            if (multicast)
            {
               dissect_extended_format_time_correction_message(tree, tvb, item_length - 6);
            }
         }
         else
         {
            /* 3 to 250 Byte Data section, Extended Format */
            if (item_length%2 == 1)
            {
               /* Malformed packet */
               expert_add_info(pinfo, item, &ei_mal_io);
               return;
            }

            dissect_extended_format_3_to_250_byte_data(pinfo, tree, tvb, io_data_size, compute_crc, &connection_triad, packet_data);

            if (multicast)
            {
               dissect_extended_format_time_correction_message(tree, tvb, (io_data_size * 2) + 8);
            }
         }
         break;
      }  // END case CIP_SAFETY_EXTENDED_FORMAT
      }  // END switch
   }
   else
   {
      /* Shouldn't happen, but at least dissect it as data */
      proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, item_length, ENC_NA);
   }
}

static int
dissect_cipsafety(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
   proto_item *ti;
   proto_tree *safety_tree;
   cip_safety_info_t* safety_info = (cip_safety_info_t*)data;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cipsafety, tvb, 0, -1, ENC_NA);
   safety_tree = proto_item_add_subtree( ti, ett_cip_safety);

   dissect_cip_safety_data(safety_tree, ti, tvb, tvb_reported_length(tvb), pinfo, safety_info);
   return tvb_captured_length(tvb);
}

static int dissect_cipsafety_base_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   cip_safety_info_t safety_info;
   cip_conn_info_t eip_conn_info;
   memset(&eip_conn_info, 0, sizeof(eip_conn_info));
   safety_info.eip_conn_info = &eip_conn_info;
   safety_info.compute_crc = false;

   // Set up parameters that will trigger dissect_cip_safety_data to parse the correct format.
   safety_info.conn_type = ECIDT_T2O;
   safety_info.eip_conn_info->TransportClass_trigger = 0;
   safety_info.eip_conn_info->safety.format = CIP_SAFETY_BASE_FORMAT;

   return dissect_cipsafety(tvb, pinfo, tree, &safety_info);
}

static int dissect_cipsafety_extended_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   cip_safety_info_t safety_info;
   cip_conn_info_t eip_conn_info;
   memset(&eip_conn_info, 0, sizeof(eip_conn_info));
   safety_info.eip_conn_info = &eip_conn_info;
   safety_info.compute_crc = false;

   // Set up parameters that will trigger dissect_cip_safety_data to parse the correct format.
   safety_info.conn_type = ECIDT_T2O;
   safety_info.eip_conn_info->TransportClass_trigger = 0;
   safety_info.eip_conn_info->safety.format = CIP_SAFETY_EXTENDED_FORMAT;

   return dissect_cipsafety(tvb, pinfo, tree, &safety_info);
}

static int dissect_cipsafety_base_time_coord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   cip_safety_info_t safety_info;
   cip_conn_info_t eip_conn_info;
   memset(&eip_conn_info, 0, sizeof(eip_conn_info));
   safety_info.eip_conn_info = &eip_conn_info;
   safety_info.compute_crc = false;

   // Set up parameters that will trigger dissect_cip_safety_data to parse the correct format.
   safety_info.conn_type = ECIDT_O2T;
   safety_info.eip_conn_info->TransportClass_trigger = 0;
   safety_info.eip_conn_info->safety.format = CIP_SAFETY_BASE_FORMAT;

   return dissect_cipsafety(tvb, pinfo, tree, &safety_info);
}

static int dissect_cipsafety_extended_time_coord(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   cip_safety_info_t safety_info;
   cip_conn_info_t eip_conn_info;
   memset(&eip_conn_info, 0, sizeof(eip_conn_info));
   safety_info.eip_conn_info = &eip_conn_info;
   safety_info.compute_crc = false;

   // Set up parameters that will trigger dissect_cip_safety_data to parse the correct format.
   safety_info.conn_type = ECIDT_O2T;
   safety_info.eip_conn_info->TransportClass_trigger = 0;
   safety_info.eip_conn_info->safety.format = CIP_SAFETY_EXTENDED_FORMAT;

   return dissect_cipsafety(tvb, pinfo, tree, &safety_info);
}

static int dissect_sercosiii_link_error_count_p1p2(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 4)
   {
      expert_add_info(pinfo, item, &ei_mal_sercosiii_link_error_count_p1p2);
      return total_len;
   }

   proto_tree_add_item(tree, hf_cip_sercosiii_link_error_count_p1, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(tree, hf_cip_sercosiii_link_error_count_p2, tvb, offset+2, 2, ENC_LITTLE_ENDIAN );
   return 4;
}

static int dissect_sercosiii_safety_network_number(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
    int offset, int total_len _U_)
{
    proto_tree_add_item(tree, hf_cip_sercosiii_link_snn, tvb, offset, 6, ENC_NA);
    return 6;
}

const attribute_info_t cip_safety_attribute_vals[] = {

   /* Safety Supervisor */
   {0x39, true, 99, -1, "Subclass", cip_uint, &hf_cip_ssupervisor_class_subclass, NULL},
   {0x39, false, 1, -1, "Number of Attributes", cip_usint, &hf_cip_ssupervisor_num_attr, NULL},
   {0x39, false, 2, -1, "Attribute List", cip_usint_array, &hf_cip_ssupervisor_attr_list, NULL},
   {0x39, false, 5, -1, "Manufacturer Name", cip_short_string, &hf_cip_ssupervisor_manufacture_name, NULL},
   {0x39, false, 6, -1, "Manufacturer Model Number", cip_short_string, &hf_cip_ssupervisor_manufacture_model_number, NULL},
   {0x39, false, 7, -1, "Software Revision Level", cip_short_string, &hf_cip_ssupervisor_sw_rev_level, NULL},
   {0x39, false, 8, -1, "Hardware Revision Level", cip_short_string, &hf_cip_ssupervisor_hw_rev_level, NULL},
   {0x39, false, 9, -1, "Manufacturer Serial Number", cip_short_string, &hf_cip_ssupervisor_manufacture_serial_number, NULL},
   {0x39, false, 10, -1, "Device Configuration", cip_short_string, &hf_cip_ssupervisor_device_config, NULL},
   {0x39, false, 11, -1, "Device Status", cip_usint, &hf_cip_ssupervisor_device_status, NULL},
   {0x39, false, 12, -1, "Exception Status", cip_byte, &hf_cip_ssupervisor_exception_status, NULL},
   {0x39, false, 13, -1, "Exception Detail Alarm", cip_dissector_func, NULL, dissect_s_supervisor_exception_detail_common},
   {0x39, false, 14, -1, "Exception Detail Warning", cip_dissector_func, NULL, dissect_s_supervisor_exception_detail_common},
   {0x39, false, 15, -1, "Alarm Enable", cip_bool, &hf_cip_ssupervisor_alarm_enable, NULL},
   {0x39, false, 16, -1, "Warning Enable", cip_bool, &hf_cip_ssupervisor_warning_enable, NULL},
   {0x39, false, 17, -1, "Time", cip_date_and_time, &hf_cip_ssupervisor_time, NULL},
   {0x39, false, 18, -1, "Clock Power Cycle Behavior", cip_usint, &hf_cip_ssupervisor_clock_power_cycle_behavior, NULL},
   {0x39, false, 19, -1, "Last Maintenance Date", cip_date, &hf_cip_ssupervisor_last_maintenance_date, NULL},
   {0x39, false, 20, -1, "Next Scheduled Maintenance Date", cip_date, &hf_cip_ssupervisor_next_scheduled_maintenance_date, NULL},
   {0x39, false, 21, -1, "Scheduled Maintenance Expiration Timer", cip_int, &hf_cip_ssupervisor_scheduled_maintenance_expiration_timer, NULL},
   {0x39, false, 22, -1, "Scheduled Maintenance Expiration Warning Enable", cip_bool, &hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable, NULL},
   {0x39, false, 23, -1, "Run Hours", cip_udint, &hf_cip_ssupervisor_run_hours, NULL},
   {0x39, false, 24, -1, "Configuration Lock", cip_bool, &hf_cip_ssupervisor_configuration_lock, NULL},
   {0x39, false, 25, -1, "Configuration UNID (CFUNID)", cip_dissector_func, NULL, dissect_s_supervisor_configuration_unid},
   {0x39, false, 26, -1, "Safety Configuration Identifier (SCID)", cip_dissector_func, NULL, dissect_s_supervisor_safety_configuration_id},
   {0x39, false, 27, -1, "Target UNID (TUNID)", cip_dissector_func, NULL, dissect_s_supervisor_target_unid},
   {0x39, false, 28, -1, "Output Connection Point Owners", cip_dissector_func, NULL, dissect_s_supervisor_output_connection_point_owners},
   {0x39, false, 29, -1, "Proposed TUNID", cip_dissector_func, NULL, dissect_s_supervisor_proposed_tunid},
   {0x39, false, 99, -1, "Subclass", cip_uint, &hf_cip_ssupervisor_instance_subclass, NULL},

   /* Safety Validator */
   {0x3A, true, 8, -1, "Safety Connection Fault Count", cip_uint, &hf_cip_svalidator_sconn_fault_count, NULL},
   {0x3A, false, 1, 0, "Safety Validator State", cip_usint, &hf_cip_svalidator_state, NULL},
   {0x3A, false, 2, 1, "Safety Validator Type", cip_dissector_func, NULL, dissect_s_validator_type},
   {0x3A, false, 3, 2, "Ping Interval EPI Multiplier", cip_uint, &hf_cip_svalidator_ping_epi, NULL},
   {0x3A, false, 4, 3, "Time Coord Msg Min Multiplier", cip_dissector_func, NULL, dissect_s_validator_time_coord_msg_min_mult},
   {0x3A, false, 5, 4, "Network Time Expectation Multiplier", cip_dissector_func, NULL, dissect_s_validator_network_time_multiplier},
   {0x3A, false, 6, 5, "Timeout Multiplier", cip_dissector_func, NULL, dissect_s_validator_timeout_multiplier},
   {0x3A, false, 7, 6, "Max Consumer Number", cip_usint, &hf_cip_svalidator_max_consumer_num, NULL},
   {0x3A, false, 8, 7, "Data Connection Instance", cip_uint, &hf_cip_svalidator_data_conn_inst, NULL},
   {0x3A, false, 9, 8, "Coordination Connection Instance", cip_dissector_func, NULL, dissect_s_validator_coordination_conn_inst},
   {0x3A, false, 10, 9, "Correction Connection Instance", cip_uint, &hf_cip_svalidator_correction_conn_inst, NULL},
   {0x3A, false, 11, 10, "CCO Binding", cip_uint, &hf_cip_svalidator_cco_binding, NULL},
   {0x3A, false, 12, 11, "Max Data Age", cip_uint, &hf_cip_svalidator_max_data_age, NULL},
   {0x3A, false, 13, 12, "Application Data Path", cip_dissector_func, NULL, dissect_s_validator_app_data_path},
   /* Note: Get Attributes All can't get to "Error Code", because dissect_s_validator_app_data_path() will use
      all remaining bytes. */
   {0x3A, false, 14, 13, "Error Code", cip_uint, &hf_cip_svalidator_error_code, NULL},
   {0x3A, false, 15, -1, "Producer/Consumer Fault Counters", cip_dissector_func, NULL, dissect_s_validator_prod_cons_fault_count},

   /* SERCOS III Link */
   {0x4C, false, 1, -1, "Safety Network Number", cip_dissector_func, NULL, dissect_sercosiii_safety_network_number},
   {0x4C, false, 2, -1, "Communication Cycle Time", cip_udint, &hf_cip_sercosiii_link_communication_cycle_time, NULL},
   {0x4C, false, 3, -1, "Interface Status", cip_word, &hf_cip_sercosiii_link_interface_status, NULL},
   {0x4C, false, 4, -1, "Error counter MST-P/S", cip_uint, &hf_cip_sercosiii_link_error_count_mstps, NULL},
   {0x4C, false, 5, -1, "Error counter Port1 and Port2", cip_dissector_func, NULL, dissect_sercosiii_link_error_count_p1p2},
   {0x4C, false, 6, -1, "SERCOS address", cip_uint, &hf_cip_sercosiii_link_sercos_address, NULL},
};

/*
 * Protocol initialization
 */

/*
 * Function name: proto_register_cipsafety
 *
 * Purpose: Register the protocol with Wireshark, a script will add this protocol
 * to the list of protocols during the build process. This function is where the
 * header fields and subtree identifiers are registered.
 *
 * Returns: void
 */
void
proto_register_cipsafety(void)
{
   /* This is a list of header fields that can be used in the dissection or
   * to use in a filter expression */
   static hf_register_info hf[] =
   {
      { &hf_cip_reqrsp,
        { "Request/Response", "cip.rr",
          FT_UINT8, BASE_HEX, VALS(cip_sc_rr), CIP_SC_RESPONSE_MASK, "Request or Response message", HFILL }
      },
      { &hf_cip_data,
        { "Data", "cip.data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },

      { &hf_cipsafety_data,
        { "Data", "cipsafety.data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte,
        { "Mode Byte", "cipsafety.mode_byte",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_ping_count,
        { "Ping Count", "cipsafety.mode_byte.ping_count",
          FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_not_tbd,
        { "Not TBD Bit", "cipsafety.mode_byte.not_tbd",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_tbd_2_copy,
        { "TBD 2 Bit Copy", "cipsafety.mode_byte.tbd_2_copy",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_not_run_idle,
        { "Not Run/Idle", "cipsafety.mode_byte.not_run_idle",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_tbd,
        { "TBD Bit", "cipsafety.mode_byte.tbd",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_tbd_2_bit,
        { "TBD 2 Bit", "cipsafety.mode_byte.tbd_2_bit",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
      },
      { &hf_cipsafety_mode_byte_run_idle,
        { "Run/Idle", "cipsafety.mode_byte.run_idle",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s1,
        { "CRC S1", "cipsafety.crc_s1",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s1_status,
        { "CRC S1 Status", "cipsafety.crc_s1.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s2,
        { "CRC S2", "cipsafety.crc_s2",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s2_status,
        { "CRC S2 Status", "cipsafety.crc_s2.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s3,
        { "CRC S3", "cipsafety.crc_s3",
          FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s3_status,
        { "CRC S3 Status", "cipsafety.crc_s3.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
      },
      { &hf_cipsafety_complement_crc_s3,
        { "Complement CRC S3", "cipsafety.complement_crc_s3",
          FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_complement_crc_s3_status,
        { "Complement CRC S3 Status", "cipsafety.complement_crc_s3.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
      },
      { &hf_cipsafety_timestamp,
        { "Timestamp", "cipsafety.timestamp",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte,
        { "ACK Byte", "cipsafety.ack_byte",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte_ping_count_reply,
        { "Ping Count Reply", "cipsafety.ack_byte.ping_count_reply",
          FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte_reserved1,
        { "Reserved", "cipsafety.ack_byte.reserved1",
          FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte_ping_response,
        { "Ping Response", "cipsafety.ack_byte.ping_response",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte_reserved2,
        { "Reserved", "cipsafety.ack_byte.reserved2",
          FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte_parity_even,
        { "Parity Even", "cipsafety.ack_byte.parity_even",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
      },
      { &hf_cipsafety_ack_byte2,
        { "ACK Byte 2", "cipsafety.ack_byte2",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_consumer_time_value,
        { "Consumer Time Value", "cipsafety.consumer_time_value",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte,
        { "MCAST Byte", "cipsafety.mcast_byte",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte_consumer_num,
        { "Consumer #", "cipsafety.mcast_byte.consumer_num",
          FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte_reserved1,
        { "Reserved", "cipsafety.mcast_byte.reserved1",
          FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte_mai,
        { "Multicast Active/Idle", "cipsafety.mcast_byte.active_idle",
          FT_BOOLEAN, 8, TFS(&cip_safety_vals_active_idle), 0x20, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte_reserved2,
        { "Reserved", "cipsafety.mcast_byte.reserved2",
          FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte_parity_even,
        { "Parity Even", "cipsafety.mcast_byte.parity_even",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
      },
      { &hf_cipsafety_mcast_byte2,
        { "MCAST Byte 2", "cipsafety.mcast_byte2",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_time_correction,
        { "Time Correction", "cipsafety.time_correction",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s5_0,
        { "CRC S5_0", "cipsafety.crc_s5_0",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s5_1,
        { "CRC S5_1", "cipsafety.crc_s5_1",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s5_2,
        { "CRC S5_2", "cipsafety.crc_s5_2",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cipsafety_crc_s5_status,
        { "CRC S5 Status", "cipsafety.crc_s5.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
      },
      { &hf_cipsafety_complement_data,
        { "Complement Data", "cipsafety.complement_data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },

      { &hf_cip_safety_message_encoding,
        { "Safety Message Encoding", "cipsafety.message_encoding",
          FT_UINT32, BASE_DEC, VALS(safety_message_encoding_vals), 0, NULL, HFILL }
      },

      { &hf_cip_sercosiii_link_snn,
        { "Data", "cipsafety.sercosiii_link.snn",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_communication_cycle_time,
        { "Communication Cycle Time", "cipsafety.sercosiii_link.communication_cycle_time",
          FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_interface_status,
        { "Interface Status", "cipsafety.sercosiii_link.interface_status",
          FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_error_count_mstps,
        { "Error Counter MST-P/S", "cipsafety.sercosiii_link.error_count_mstps",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_error_count_p1,
        { "Error Count Port 1", "cipsafety.sercosiii_link.error_count_p1",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_error_count_p2,
        { "Error Count Port 2", "cipsafety.sercosiii_link.error_count_p2",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_sercosiii_link_sercos_address,
        { "SERCOS Address", "cipsafety.sercosiii_link.sercos_address",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
   };

   static hf_register_info hf_ssupervisor[] = {
      { &hf_cip_ssupervisor_sc,
        { "Service", "cipsafety.ssupervisor.sc",
          FT_UINT8, BASE_HEX, VALS(cip_sc_vals_ssupervisor), CIP_SC_MASK, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_recover_data,
        { "Data", "cipsafety.ssupervisor.recover.data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_perform_diag_data,
        { "Data", "cipsafety.ssupervisor.perform_diag.data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_password,
        { "Password", "cipsafety.ssupervisor.configure_request.password",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_tunid,
        { "Target UNID", "cipsafety.ssupervisor.configure_request.tunid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_tunid_snn_timestamp,
        { "TUNID SNN Timestamp", "cipsafety.ssupervisor.configure_request.tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_tunid_snn_date,
        { "TUNID SNN (Manual) Date", "cipsafety.ssupervisor.configure_request.tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_tunid_snn_time,
        { "TUNID SNN (Manual) Time", "cipsafety.ssupervisor.configure_request.tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_tunid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.configure_request.tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_ounid,
        { "Originator UNID", "cipsafety.ssupervisor.configure_request.ounid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_ounid_snn_timestamp,
        { "OUNID SNN Timestamp", "cipsafety.ssupervisor.configure_request.ounid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_ounid_snn_date,
        { "OUNID SNN (Manual) Date", "cipsafety.ssupervisor.configure_request.ounid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_ounid_snn_time,
        { "OUNID SNN (Manual) Time", "cipsafety.ssupervisor.configure_request.ounid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_request_ounid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.configure_request.ounid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_validate_configuration_sccrc,
        { "SCCRC", "cipsafety.ssupervisor.validate_configuration.sccrc",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_validate_configuration_scts_timestamp,
        { "SCTS (Timestamp)", "cipsafety.ssupervisor.validate_configuration.scts.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_validate_configuration_scts_date,
        { "SCTS (Manual) Date", "cipsafety.ssupervisor.validate_configuration.scts.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_validate_configuration_scts_time,
        { "SCTS (Manual) Time", "cipsafety.ssupervisor.validate_configuration.scts.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_validate_configuration_ext_error,
        { "Extended Error", "cipsafety.ssupervisor.validate_configuration.ext_error",
          FT_UINT16, BASE_DEC, VALS(cip_ssupervisor_validate_configuration_ext_error_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_set_password_current_password,
        { "Current Password", "cipsafety.ssupervisor.set_password.current_pass",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_set_password_new_password,
        { "New Password", "cipsafety.ssupervisor.set_password.new_pass",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_value,
        { "Lock Value", "cipsafety.ssupervisor.configure_lock.lock",
          FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_lock_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_password,
        { "Password", "cipsafety.ssupervisor.configure_lock.password",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_tunid,
        { "Target UNID", "cipsafety.ssupervisor.configure_lock.tunid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_tunid_snn_timestamp,
        { "TUNID SNN Timestamp", "cipsafety.ssupervisor.configure_lock.tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_tunid_snn_date,
        { "TUNID SNN (Manual) Date", "cipsafety.ssupervisor.configure_lock.tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_tunid_snn_time,
        { "TUNID SNN (Manual) Time", "cipsafety.ssupervisor.configure_lock.tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configure_lock_tunid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.configure_lock.tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_mode_change_value,
        { "Value", "cipsafety.ssupervisor.mode_change.value",
          FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_change_mode_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_mode_change_password,
        { "Password", "cipsafety.ssupervisor.mode_change.password",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_type,
        { "Reset Type", "cipsafety.ssupervisor.reset.type",
          FT_UINT8, BASE_DEC, VALS(cip_reset_type_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_password,
        { "Password", "cipsafety.ssupervisor.reset.password",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_tunid,
        { "Target UNID", "cipsafety.ssupervisor.reset.tunid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_tunid_tunid_snn_timestamp,
        { "TUNID SNN Timestamp", "cipsafety.ssupervisor.reset.tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_tunid_tunid_snn_date,
        { "TUNID SNN (Manual) Date", "cipsafety.ssupervisor.reset.tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_tunid_tunid_snn_time,
        { "TUNID SNN (Manual) Time", "cipsafety.ssupervisor.reset.tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_tunid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.reset.tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap,
        { "Attribute Bit Map", "cipsafety.ssupervisor.reset.attr_bitmap",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_macid,
        { "Preserve MacID", "cipsafety.ssupervisor.reset.attr_bitmap.macid",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_baudrate,
        { "Preserve Baud Rate", "cipsafety.ssupervisor.reset.attr_bitmap.baudrate",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_tunid,
        { "Preserve TUNID", "cipsafety.ssupervisor.reset.attr_bitmap.tunid",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_password,
        { "Preserve Password", "cipsafety.ssupervisor.reset.attr_bitmap.password",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_cfunid,
        { "Preserve CFUNID", "cipsafety.ssupervisor.reset.attr_bitmap.cfunid",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_ocpunid,
        { "Preserve OPCUNID", "cipsafety.ssupervisor.reset.attr_bitmap.ocpunid",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_reserved,
        { "Reserved", "cipsafety.ssupervisor.reset.attr_bitmap.reserved",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_attr_bitmap_extended,
        { "Use Extended Map", "cipsafety.ssupervisor.reset.attr_bitmap.extended",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_password_data_size,
        { "Data Size", "cipsafety.ssupervisor.reset_password.data_size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_reset_password_data,
        { "Password Data", "cipsafety.ssupervisor.reset_password.password_data",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_propose_tunid_tunid,
        { "Target UNID", "cipsafety.ssupervisor.propose_tunid.tunid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_propose_tunid_tunid_snn_timestamp,
        { "TUNID SNN Timestamp", "cipsafety.ssupervisor.propose_tunid.tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_propose_tunid_tunid_snn_date,
        { "TUNID SNN (Manual) Date", "cipsafety.ssupervisor.propose_tunid.tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_propose_tunid_tunid_snn_time,
        { "TUNID SNN (Manual) Time", "cipsafety.ssupervisor.propose_tunid.tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_propose_tunid_tunid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.propose_tunid.tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_apply_tunid_tunid,
        { "Target UNID", "cipsafety.ssupervisor.apply_tunid.tunid",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_apply_tunid_tunid_snn_timestamp,
        { "TUNID SNN Timestamp", "cipsafety.ssupervisor.apply_tunid.tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_apply_tunid_tunid_snn_date,
        { "TUNID SNN (Manual) Date", "cipsafety.ssupervisor.apply_tunid.tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_apply_tunid_tunid_snn_time,
        { "TUNID SNN (Manual) Time", "cipsafety.ssupervisor.apply_tunid.tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_apply_tunid_tunid_nodeid,
        { "Node ID", "cipsafety.ssupervisor.apply_tunid.tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_class_subclass,
        { "Subclass", "cipsafety.ssupervisor.class_subclass",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_num_attr,
        { "Number of Attributes", "cipsafety.ssupervisor.num_attr",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_attr_list,
        { "Attributes List Item", "cipsafety.ssupervisor.attr_item",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_manufacture_name,
        { "Manufacturer Name", "cipsafety.ssupervisor.manufacture_name",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_manufacture_model_number,
        { "Manufacturer Model Number", "cipsafety.ssupervisor.manufacture_model_number",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_sw_rev_level,
        { "Software Revision Level", "cipsafety.ssupervisor.sw_rev_level",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_hw_rev_level,
        { "Hardware Revision Level", "cipsafety.ssupervisor.hw_rev_level",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_manufacture_serial_number,
        { "Manufacturer Serial Number", "cipsafety.ssupervisor.manufacture_serial_number",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_device_config,
        { "Device Configuration", "cipsafety.ssupervisor.device_config",
          FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_device_status,
        { "Device Status", "cipsafety.ssupervisor.device_status",
          FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_device_status_type_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_status,
        { "Exception Status", "cipsafety.ssupervisor.exception_status",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_ced_size,
        { "Common Exception Detail Size", "cipsafety.ssupervisor.exception_detail.ced.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_ced_detail,
        { "Common Exception Detail Data", "cipsafety.ssupervisor.exception_detail.ced.detail",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_ded_size,
        { "Device Exception Detail Size", "cipsafety.ssupervisor.exception_detail.ded.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_ded_detail,
        { "Device Exception Detail Data", "cipsafety.ssupervisor.exception_detail.ded.detail",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_med_size,
        { "Manufacturer Exception Detail Size", "cipsafety.ssupervisor.exception_detail.med.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_exception_detail_med_detail,
        { "Manufacturer Exception Detail Data", "cipsafety.ssupervisor.exception_detail.med.detail",
          FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_alarm_enable,
        { "Exception Detail Alarm", "cipsafety.ssupervisor.alarm_enable",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_warning_enable,
        { "Exception Detail Warning", "cipsafety.ssupervisor.warning_enable",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_time,
        { "Time", "cipsafety.ssupervisor.time",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_clock_power_cycle_behavior,
        { "Clock Power Cycle Behavior", "cipsafety.ssupervisor.clock_power_cycle_behavior",
          FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_clock_power_cycle_type_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_last_maintenance_date,
        { "Last Maintenance Date", "cipsafety.ssupervisor.last_maintenance_date",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_next_scheduled_maintenance_date,
        { "Next Scheduled Maintenance Date", "cipsafety.ssupervisor.next_scheduled_maintenance_date",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_scheduled_maintenance_expiration_timer,
        { "Scheduled Maintenance Expiration Timer", "cipsafety.ssupervisor.scheduled_maintenance_expiration_timer",
          FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable,
        { "Scheduled Maintenance Expiration Warning Enable", "cipsafety.ssupervisor.scheduled_maintenance_expiration_warning",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_run_hours,
        { "Run Hours", "cipsafety.ssupervisor.run_hours",
          FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configuration_lock,
        { "Configuration Lock", "cipsafety.ssupervisor.configuration_lock",
          FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_lock_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configuration_unid_snn_timestamp,
        { "Configuration UNID SNN Timestamp", "cipsafety.ssupervisor.configuration_unid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configuration_unid_snn_date,
        { "Configuration UNID SNN (Manual) Date", "cipsafety.ssupervisor.configuration_unid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configuration_unid_snn_time,
        { "Configuration UNID SNN (Manual) Time", "cipsafety.ssupervisor.configuration_unid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_configuration_unid_nodeid,
        { "Configuration UNID Node ID", "cipsafety.ssupervisor.configuration_unid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_safety_configuration_id_snn_timestamp,
        { "Safety Configuration ID SNN Timestamp", "cipsafety.ssupervisor.safety_configuration_id.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_safety_configuration_id_snn_date,
        { "Safety Configuration ID SNN (Manual) Date", "cipsafety.ssupervisor.safety_configuration_id.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_safety_configuration_id_snn_time,
        { "Safety Configuration ID SNN (Manual) Time", "cipsafety.ssupervisor.safety_configuration_id.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_safety_configuration_id_sccrc,
        { "Safety Configuration ID SCCRC", "cipsafety.ssupervisor.safety_configuration_id.sccrc",
         FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_target_unid_snn_timestamp,
        { "Target UNID SNN Timestamp", "cipsafety.ssupervisor.target_unid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_target_unid_snn_date,
        { "Target UNID SNN (Manual) Date", "cipsafety.ssupervisor.target_unid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_target_unid_snn_time,
        { "Target UNID SNN (Manual) Time", "cipsafety.ssupervisor.target_unid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_target_unid_nodeid,
        { "Target UNID Node ID", "cipsafety.ssupervisor.target_unid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_cp_owners_num_entries,
        { "Number of Array Entries", "cipsafety.ssupervisor.cp_owners.num_entries",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_timestamp,
        { "OCPUNID SNN Timestamp", "cipsafety.ssupervisor.cp_owners.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_date,
        { "OCPUNID SNN (Manual) Date", "cipsafety.ssupervisor.cp_owners.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_snn_time,
        { "OCPUNID SNN (Manual) Time", "cipsafety.ssupervisor.cp_owners.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_nodeid,
        { "OCPUNID Node ID", "cipsafety.ssupervisor.cp_owners.ocpunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_cp_owners_app_path_size,
        { "EPATH Size", "cipsafety.ssupervisor.cp_owners.epath_size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_proposed_tunid_snn_timestamp,
        { "Proposed TUNID SNN Timestamp", "cipsafety.ssupervisor.proposed_tunid.snn.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_proposed_tunid_snn_date,
        { "Proposed TUNID SNN (Manual) Date", "cipsafety.ssupervisor.proposed_tunid.snn.date",
          FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_proposed_tunid_snn_time,
        { "Proposed TUNID SNN (Manual) Time", "cipsafety.ssupervisor.proposed_tunid.snn.time",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_proposed_tunid_nodeid,
        { "Proposed TUNID Node ID", "cipsafety.ssupervisor.proposed_tunid.nodeid",
          FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_ssupervisor_instance_subclass,
        { "Subclass", "cipsafety.ssupervisor.instance_subclass",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      }
   };

   static hf_register_info hf_svalidator[] = {
      { &hf_cip_svalidator_sc,
        { "Service", "cipsafety.svalidator.sc",
          FT_UINT8, BASE_HEX, VALS(cip_sc_vals_svalidator), CIP_SC_MASK, NULL, HFILL }
      },

      { &hf_cip_svalidator_sconn_fault_count,
        { "Safety Connection Fault Count", "cipsafety.svalidator.sconn_fault_count",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_state,
        { "Safety Validator State", "cipsafety.svalidator.state",
          FT_UINT8, BASE_DEC, VALS(cip_svalidator_state_vals), 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_type,
        { "Safety Validator Type", "cipsafety.svalidator.type",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_type_pc,
        { "Producer/Consumer", "cipsafety.svalidator.type.pc",
          FT_UINT8, BASE_HEX, VALS(cip_svalidator_type_pc_vals), 0x80, NULL, HFILL }
      },
      { &hf_cip_svalidator_type_conn_type,
        { "Safety Connection Type", "cipsafety.svalidator.type.conn_type",
          FT_UINT8, BASE_DEC, VALS(cip_svalidator_type_conn_type_vals), 0x7F, NULL, HFILL }
      },
      { &hf_cip_svalidator_ping_epi,
        { "Ping Interval EPI Multiplier", "cipsafety.svalidator.ping_epi",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_time_coord_msg_min_mult_size,
        { "Time Coord Msg Min Multiplier Array Size", "cipsafety.svalidator.time_coord_msg_min_mult.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_time_coord_msg_min_mult_item,
        { "Time Coord Msg Min Multiplier", "cipsafety.svalidator.time_coord_msg_min_mult.item",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_network_time_multiplier_size,
        { "Network Time Expectation Multiplier Array Size", "cipsafety.svalidator.network_time_multiplier.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_network_time_multiplier_item,
        { "Network Time Expectation Multiplier", "cipsafety.svalidator.network_time_multiplier.item",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_timeout_multiplier_size,
        { "Timeout Multiplier Array Size", "cipsafety.svalidator.timeout_multiplier.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_timeout_multiplier_item,
        { "Timeout Multiplier", "cipsafety.svalidator.timeout_multiplier.item",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_max_consumer_num,
        { "Max Consumer Number", "cipsafety.svalidator.max_consumer_num",
          FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(safety_max_consumer_numbers), 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_data_conn_inst,
        { "Data Connection Instance", "cipsafety.svalidator.data_conn_inst",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_coordination_conn_inst_size,
        { "Coordination Connection Instance Size", "cipsafety.svalidator.coordination_conn_inst.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_coordination_conn_inst_item,
        { "Coordination Connection Instance Item", "cipsafety.svalidator.coordination_conn_inst.item",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_correction_conn_inst,
        { "Correction Connection Instance", "cipsafety.svalidator.correction_conn_inst",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_cco_binding,
        { "CCO Binding", "cipsafety.svalidator.cco_binding",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_max_data_age,
        { "Max Data Age", "cipsafety.svalidator.max_data_age",
          FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_error_code,
        { "Error Code", "cipsafety.svalidator.error_code",
          FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_prod_cons_fault_count_size,
        { "Producer/Consumer Counter Array Size", "cipsafety.svalidator.prod_cons_fault_count.size",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      },
      { &hf_cip_svalidator_prod_cons_fault_count_item,
        { "Producer/Consumer Fault Counter", "cipsafety.svalidator.prod_cons_fault_count.item",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
      }
   };

   static int *ett[] = {
      &ett_cip_safety,
      &ett_path,
      &ett_cipsafety_mode_byte,
      &ett_cipsafety_ack_byte,
      &ett_cipsafety_mcast_byte
   };

   static int *ett_ssupervisor[] = {
      &ett_cip_class_s_supervisor,
      &ett_ssupervisor_rrsc,
      &ett_ssupervisor_cmd_data,
      &ett_ssupervisor_propose_tunid,
      &ett_ssupervisor_propose_tunid_snn,
      &ett_ssupervisor_configure_request_tunid,
      &ett_ssupervisor_configure_request_tunid_snn,
      &ett_ssupervisor_configure_request_ounid,
      &ett_ssupervisor_configure_request_ounid_snn,
      &ett_ssupervisor_configure_lock_tunid,
      &ett_ssupervisor_configure_lock_tunid_snn,
      &ett_ssupervisor_reset_tunid,
      &ett_ssupervisor_reset_tunid_snn,
      &ett_ssupervisor_apply_tunid,
      &ett_ssupervisor_apply_tunid_snn,
      &ett_exception_detail_common,
      &ett_exception_detail_device,
      &ett_exception_detail_manufacturer,
      &ett_ssupervisor_configuration_unid,
      &ett_ssupervisor_configuration_unid_snn,
      &ett_ssupervisor_target_unid,
      &ett_ssupervisor_target_unid_snn,
      &ett_ssupervisor_output_cp_owners,
      &ett_ssupervisor_output_cp_owners_ocpunid,
      &ett_ssupervisor_output_cp_owners_ocpunid_snn,
      &ett_ssupervisor_proposed_tunid,
      &ett_ssupervisor_proposed_tunid_snn,
      &ett_cip_ssupervisor_reset_attr_bitmap
   };

   static int *ett_svalidator[] = {
      &ett_cip_class_s_validator,
      &ett_svalidator_rrsc,
      &ett_svalidator_cmd_data,
      &ett_svalidator_type
   };

   static ei_register_info ei[] = {
      { &ei_cipsafety_tbd_not_complemented, { "cipsafety.tbd_not_complemented", PI_PROTOCOL, PI_ERROR, "TBD bit not complemented", EXPFILL }},
      { &ei_cipsafety_tbd2_not_copied, { "cipsafety.tbd2_not_copied", PI_PROTOCOL, PI_ERROR, "TBD2 bit not copied", EXPFILL }},
      { &ei_cipsafety_run_idle_not_complemented, { "cipsafety.run_idle_not_complemented", PI_PROTOCOL, PI_ERROR, "Run/Idle bit not complemented", EXPFILL }},
      { &ei_mal_io, { "cipsafety.malformed.io", PI_MALFORMED, PI_ERROR, "Malformed CIP Safety I/O packet", EXPFILL }},
      { &ei_mal_sercosiii_link_error_count_p1p2, { "cipsafety.malformed.sercosiii_link.error_count_p1p2", PI_MALFORMED, PI_ERROR, "Malformed SERCOS III Attribute 5", EXPFILL }},
      { &ei_cipsafety_not_complement_data, { "cipsafety.not_complement_data", PI_PROTOCOL, PI_ERROR, "Data not complemented", EXPFILL }},
      { &ei_cipsafety_crc_s1, { "cipsafety.crc_s1.incorrect", PI_PROTOCOL, PI_ERROR, "CRC-S1 incorrect", EXPFILL }},
      { &ei_cipsafety_crc_s2, { "cipsafety.crc_s2.incorrect", PI_PROTOCOL, PI_ERROR, "CRC-S2 incorrect", EXPFILL }},
      { &ei_cipsafety_crc_s3, { "cipsafety.crc_s3.incorrect", PI_PROTOCOL, PI_ERROR, "CRC-S3 incorrect", EXPFILL }},
      { &ei_cipsafety_complement_crc_s3, { "cipsafety.complement_crc_s3.incorrect", PI_PROTOCOL, PI_ERROR, "Complement CRC-S3 incorrect", EXPFILL }},
      { &ei_cipsafety_crc_s5, { "cipsafety.crc_s5.incorrect", PI_PROTOCOL, PI_ERROR, "CRC-S5 incorrect", EXPFILL }},
      };

   static ei_register_info ei_ssupervisor[] = {
      { &ei_mal_ssupervisor_exception_detail_ced, { "cipsafety.ssupervisor.malformed.exception_detail.ced", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Exception Detail (Common Exception Detail)", EXPFILL }},
      { &ei_mal_ssupervisor_exception_detail_ded, { "cipsafety.ssupervisor.malformed.exception_detail.ded", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Exception Detail (Device Exception Detail)", EXPFILL }},
      { &ei_mal_ssupervisor_exception_detail_med, { "cipsafety.ssupervisor.malformed.exception_detail.med", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Exception Detail (Manufacturer Exception Detail)", EXPFILL }},
      { &ei_mal_ssupervisor_configuration_unid, { "cipsafety.ssupervisor.malformed.configuration_unid", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Configuration UNID", EXPFILL }},
      { &ei_mal_ssupervisor_safety_configuration_id, { "cipsafety.ssupervisor.malformed.safety_configuration_id", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Safety Configuration Identifier", EXPFILL }},
      { &ei_mal_ssupervisor_target_unid, { "cipsafety.ssupervisor.malformed.target_unid", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Target UNID", EXPFILL }},
      { &ei_mal_ssupervisor_cp_owners, { "cipsafety.ssupervisor.malformed.cp_owners", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Output Connection Point Owners", EXPFILL }},
      { &ei_mal_ssupervisor_cp_owners_entry, { "cipsafety.ssupervisor.malformed.cp_owners.entry", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Output Connection Point Owners (UNID)", EXPFILL }},
      { &ei_mal_ssupervisor_cp_owners_app_path_size, { "cipsafety.ssupervisor.malformed.cp_owners.app_path_size", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Output Connection Point Owners (EPATH)", EXPFILL }},
      { &ei_mal_ssupervisor_proposed_tunid, { "cipsafety.ssupervisor.malformed.proposed_tunid", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Supervisor Proposed TUNID", EXPFILL }},
      { &ei_info_ssupervisor_tunid_cancel, { "cipsafety.ssupervisor.info.cancel_propose_apply", PI_PROTOCOL, PI_WARN,
                        "Cancel Proposed/Apply Operation", EXPFILL } },
   };

   static ei_register_info ei_svalidator[] = {
      { &ei_mal_svalidator_type, { "cipsafety.ssupervisor.malformed.svalidator.type", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Type", EXPFILL }},
      { &ei_mal_svalidator_time_coord_msg_min_mult, { "cipsafety.ssupervisor.malformed.svalidator.time_coord_msg_min_mult", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Time Coord Msg Min Multiplier", EXPFILL }},
      { &ei_mal_svalidator_network_time_multiplier, { "cipsafety.ssupervisor.malformed.svalidator.network_time_multiplier", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Network Time Expectation Multiplier", EXPFILL }},
      { &ei_mal_svalidator_timeout_multiplier, { "cipsafety.ssupervisor.malformed.svalidator.timeout_multiplier", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Timeout Multiplier", EXPFILL }},
      { &ei_mal_svalidator_coordination_conn_inst, { "cipsafety.ssupervisor.malformed.svalidator.coordination_conn_inst", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Coordination Connection Instance", EXPFILL }},
      { &ei_mal_svalidator_prod_cons_fault_count, { "cipsafety.ssupervisor.malformed.svalidator.prod_cons_fault_count", PI_MALFORMED, PI_ERROR,
                        "Malformed Safety Validator Produce/Consume Fault Counters", EXPFILL }},
   };

   expert_module_t* expert_cip_safety;
   expert_module_t* expert_cip_class_s_supervisor;
   expert_module_t* expert_cip_class_s_validator;

   /* Create a CIP Safety protocol handle */
   proto_cipsafety = proto_register_protocol("Common Industrial Protocol, Safety", "CIP Safety", "cipsafety");
   proto_register_field_array(proto_cipsafety, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   expert_cip_safety = expert_register_protocol(proto_cipsafety);
   expert_register_field_array(expert_cip_safety, ei, array_length(ei));

   cipsafety_handle = register_dissector( "cipsafety", dissect_cipsafety, proto_cipsafety);

   // Register different protocols for "Decode As".
   proto_cipsafety_base_data = proto_register_protocol_in_name_only("Common Industrial Protocol, Safety - Base - Data",
      "CIP Safety - Base - Data",
      "cipsafety_bd",
      proto_cipsafety,
      FT_PROTOCOL);
   cipsafety_base_data_handle = register_dissector("cipsafety_bd", dissect_cipsafety_base_data, proto_cipsafety_base_data);

   proto_cipsafety_extended_data = proto_register_protocol_in_name_only("Common Industrial Protocol, Safety - Extended - Data",
      "CIP Safety - Extended - Data",
      "cipsafety_ed",
      proto_cipsafety,
      FT_PROTOCOL);
   cipsafety_extended_data_handle = register_dissector("cipsafety_ed", dissect_cipsafety_extended_data, proto_cipsafety_extended_data);

   proto_cipsafety_base_time_coord = proto_register_protocol_in_name_only("Common Industrial Protocol, Safety - Base - Time Coordination",
      "CIP Safety - Base - Time Coordination",
      "cipsafety_bt",
      proto_cipsafety,
      FT_PROTOCOL);
   cipsafety_base_time_coord_handle = register_dissector("cipsafety_bt", dissect_cipsafety_base_time_coord, proto_cipsafety_base_time_coord);

   proto_cipsafety_extended_time_coord = proto_register_protocol_in_name_only("Common Industrial Protocol, Safety - Extended - Time Coordination",
      "CIP Safety - Extended - Time Coordination",
      "cipsafety_et",
      proto_cipsafety,
      FT_PROTOCOL);
   cipsafety_extended_time_coord_handle = register_dissector("cipsafety_et", dissect_cipsafety_extended_time_coord, proto_cipsafety_extended_time_coord);


   /* Register CIP Safety objects */
   proto_cip_class_s_supervisor = proto_register_protocol("CIP Safety Supervisor",
       "CIPSSupervisor", "cipssupervisor");
   cip_class_s_supervisor_handle = register_dissector("cipssupervisor",  dissect_cip_class_s_supervisor, proto_cip_class_s_supervisor );
   proto_register_field_array(proto_cip_class_s_supervisor, hf_ssupervisor, array_length(hf_ssupervisor));
   proto_register_subtree_array(ett_ssupervisor, array_length(ett_ssupervisor));
   expert_cip_class_s_supervisor = expert_register_protocol(proto_cip_class_s_supervisor);
   expert_register_field_array(expert_cip_class_s_supervisor, ei_ssupervisor, array_length(ei_ssupervisor));

   proto_cip_class_s_validator = proto_register_protocol("CIP Safety Validator",
       "CIPSValidator", "cipsvalidator");
   cip_class_s_validator_handle = register_dissector("cipsvalidator",  dissect_cip_class_s_validator, proto_cip_class_s_validator );
   proto_register_field_array(proto_cip_class_s_validator, hf_svalidator, array_length(hf_svalidator));
   proto_register_subtree_array(ett_svalidator, array_length(ett_svalidator));
   expert_cip_class_s_validator = expert_register_protocol(proto_cip_class_s_validator);
   expert_register_field_array(expert_cip_class_s_validator, ei_svalidator, array_length(ei_svalidator));
}

/*
 * Function name: proto_reg_handoff_cipsafety
 *
 * Purpose: This function will setup the automatic dissection of the CIP Safety datagram,
 * it is called by Wireshark when the protocol is registered
 *
 * Returns: void
 */
void
proto_reg_handoff_cipsafety(void)
{
   /* Register dissector handle for Safety Supervisor */
   dissector_add_uint( "cip.class.iface", CI_CLS_SAFETY_SUPERVISOR, cip_class_s_supervisor_handle );

   /* Register dissector handle for Safety Validator */
   dissector_add_uint( "cip.class.iface", CI_CLS_SAFETY_VALIDATOR, cip_class_s_validator_handle );
   heur_dissector_add("cip.sc", dissect_class_svalidator_heur, "CIP Safety Validator", "s_validator_cip", proto_cip_class_s_validator, HEURISTIC_ENABLE);

   /* Register dissector for I/O data handling */
   dissector_add_for_decode_as("cip.io", cipsafety_base_data_handle );
   dissector_add_for_decode_as("cip.io", cipsafety_extended_data_handle );
   dissector_add_for_decode_as("cip.io", cipsafety_base_time_coord_handle );
   dissector_add_for_decode_as("cip.io", cipsafety_extended_time_coord_handle );

   proto_cip = proto_get_id_by_filter_name( "cip" );
   subdissector_class_table = find_dissector_table("cip.class.iface");
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
