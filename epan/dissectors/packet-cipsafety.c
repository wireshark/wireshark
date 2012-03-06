/* packet-cipsafety.c
 * Routines for CIP (Common Industrial Protocol) Safety dissection
 * CIP Safety Home: www.odva.org
 *
 * Copyright 2011
 * Michael Mann <mmann@pyramidsolutions.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-cip.h"
#include "packet-enip.h"
#include "packet-cipsafety.h"

/* The entry point to the actual disection is: dissect_cipsafety */

/* Protocol handle for CIP Safety */
static int proto_cipsafety                = -1;
static int proto_cip_class_s_supervisor   = -1;
static int proto_cip_class_s_validator    = -1;
static int proto_cip                      = -1;

static dissector_handle_t cip_class_s_supervisor_handle;
static dissector_handle_t cip_class_s_validator_handle;

/* CIP Safety field identifiers */
static int hf_cipsafety_data                 = -1;
static int hf_cipsafety_mode_byte            = -1;
static int hf_cipsafety_mode_byte_run_idle   = -1;
static int hf_cipsafety_mode_byte_not_run_idle = -1;
static int hf_cipsafety_mode_byte_tbd_2_bit  = -1;
static int hf_cipsafety_mode_byte_tbd_2_copy = -1;
static int hf_cipsafety_mode_byte_ping_count = -1;
static int hf_cipsafety_mode_byte_tbd        = -1;
static int hf_cipsafety_mode_byte_not_tbd    = -1;
static int hf_cipsafety_crc_s1               = -1;
static int hf_cipsafety_crc_s2               = -1;
static int hf_cipsafety_crc_s3               = -1;
static int hf_cipsafety_timestamp            = -1;
static int hf_cipsafety_ack_byte             = -1;
static int hf_cipsafety_ack_byte_ping_count_reply = -1;
static int hf_cipsafety_ack_byte_reserved1   = -1;
static int hf_cipsafety_ack_byte_ping_response = -1;
static int hf_cipsafety_ack_byte_reserved2   = -1;
static int hf_cipsafety_ack_byte_parity_even = -1;
static int hf_cipsafety_ack_byte2            = -1;
static int hf_cipsafety_consumer_time_value  = -1;
static int hf_cipsafety_mcast_byte           = -1;
static int hf_cipsafety_mcast_byte_consumer_num = -1;
static int hf_cipsafety_mcast_byte_reserved1 = -1;
static int hf_cipsafety_mcast_byte_mai       = -1;
static int hf_cipsafety_mcast_byte_reserved2 = -1;
static int hf_cipsafety_mcast_byte_parity_even = -1;
static int hf_cipsafety_mcast_byte2          = -1;
static int hf_cipsafety_time_correction      = -1;
static int hf_cipsafety_crc_s5_0             = -1;
static int hf_cipsafety_crc_s5_1             = -1;
static int hf_cipsafety_crc_s5_2             = -1;
static int hf_cipsafety_complement_data      = -1;

/* CIP Safety header field identifiers */
static int hf_cip_reqrsp            = -1;
static int hf_cip_data              = -1;

/* Safety Supervisor header field identifiers */
static int hf_cip_ssupervisor_sc = -1;
static int hf_cip_ssupervisor_recover_data = -1;
static int hf_cip_ssupervisor_perform_diag_data = -1;
static int hf_cip_ssupervisor_configure_request_password = -1;
static int hf_cip_ssupervisor_configure_request_tunid = -1;
static int hf_cip_ssupervisor_configure_request_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_configure_request_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_configure_request_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_configure_request_tunid_macid = -1;
static int hf_cip_ssupervisor_configure_request_ounid = -1;
static int hf_cip_ssupervisor_configure_request_ounid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_configure_request_ounid_ssn_date = -1;
static int hf_cip_ssupervisor_configure_request_ounid_ssn_time = -1;
static int hf_cip_ssupervisor_configure_request_ounid_macid = -1;
static int hf_cip_ssupervisor_validate_configuration_sccrc = -1;
static int hf_cip_ssupervisor_validate_configuration_scts_timestamp = -1;
static int hf_cip_ssupervisor_validate_configuration_scts_date = -1;
static int hf_cip_ssupervisor_validate_configuration_scts_time = -1;
static int hf_cip_ssupervisor_validate_configuration_ext_error = -1;
static int hf_cip_ssupervisor_set_password_current_password = -1;
static int hf_cip_ssupervisor_set_password_new_password = -1;
static int hf_cip_ssupervisor_configure_lock_value = -1;
static int hf_cip_ssupervisor_configure_lock_password = -1;
static int hf_cip_ssupervisor_configure_lock_tunid = -1;
static int hf_cip_ssupervisor_configure_lock_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_configure_lock_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_configure_lock_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_configure_lock_tunid_macid = -1;
static int hf_cip_ssupervisor_mode_change_value = -1;
static int hf_cip_ssupervisor_mode_change_password = -1;
static int hf_cip_ssupervisor_reset_type = -1;
static int hf_cip_ssupervisor_reset_password = -1;
static int hf_cip_ssupervisor_reset_tunid = -1;
static int hf_cip_ssupervisor_reset_tunid_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_reset_tunid_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_reset_tunid_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_reset_tunid_macid = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_macid = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_baudrate = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_tunid = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_password = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_cfunid = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_ocpunid = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_reserved = -1;
static int hf_cip_ssupervisor_reset_attr_bitmap_extended = -1;
static int hf_cip_ssupervisor_reset_password_data_size = -1;
static int hf_cip_ssupervisor_reset_password_data = -1;
static int hf_cip_ssupervisor_propose_tunid_tunid = -1;
static int hf_cip_ssupervisor_propose_tunid_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_propose_tunid_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_propose_tunid_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_propose_tunid_tunid_macid = -1;
static int hf_cip_ssupervisor_apply_tunid_tunid = -1;
static int hf_cip_ssupervisor_apply_tunid_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_apply_tunid_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_apply_tunid_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_apply_tunid_tunid_macid = -1;

static int hf_cip_ssupervisor_class_subclass = -1;
static int hf_cip_ssupervisor_num_attr = -1;
static int hf_cip_ssupervisor_attr_list = -1;
static int hf_cip_ssupervisor_manufacture_name = -1;
static int hf_cip_ssupervisor_manufacture_model_number = -1;
static int hf_cip_ssupervisor_sw_rev_level = -1;
static int hf_cip_ssupervisor_hw_rev_level = -1;
static int hf_cip_ssupervisor_manufacture_serial_number = -1;
static int hf_cip_ssupervisor_device_config = -1;
static int hf_cip_ssupervisor_device_status = -1;
static int hf_cip_ssupervisor_exception_status = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_ced_size = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_ced_detail = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_ded_size = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_ded_detail = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_med_size = -1;
static int hf_cip_ssupervisor_exception_detail_alarm_med_detail = -1;
static int hf_cip_ssupervisor_exception_detail_warning_ced_size = -1;
static int hf_cip_ssupervisor_exception_detail_warning_ced_detail = -1;
static int hf_cip_ssupervisor_exception_detail_warning_ded_size = -1;
static int hf_cip_ssupervisor_exception_detail_warning_ded_detail = -1;
static int hf_cip_ssupervisor_exception_detail_warning_med_size = -1;
static int hf_cip_ssupervisor_exception_detail_warning_med_detail = -1;
static int hf_cip_ssupervisor_alarm_enable = -1;
static int hf_cip_ssupervisor_warning_enable = -1;
static int hf_cip_ssupervisor_time = -1;
static int hf_cip_ssupervisor_clock_power_cycle_behavior = -1;
static int hf_cip_ssupervisor_last_maintenance_date = -1;
static int hf_cip_ssupervisor_next_scheduled_maintenance_date = -1;
static int hf_cip_ssupervisor_scheduled_maintenance_expiration_timer = -1;
static int hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable = -1;
static int hf_cip_ssupervisor_run_hours = -1;
static int hf_cip_ssupervisor_configuration_lock = -1;
static int hf_cip_ssupervisor_configuration_unid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_configuration_unid_ssn_date = -1;
static int hf_cip_ssupervisor_configuration_unid_ssn_time = -1;
static int hf_cip_ssupervisor_configuration_unid_macid = -1;
static int hf_cip_ssupervisor_safety_configuration_id_ssn_timestamp = -1;
static int hf_cip_ssupervisor_safety_configuration_id_ssn_date = -1;
static int hf_cip_ssupervisor_safety_configuration_id_ssn_time = -1;
static int hf_cip_ssupervisor_safety_configuration_id_macid = -1;
static int hf_cip_ssupervisor_target_unid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_target_unid_ssn_date = -1;
static int hf_cip_ssupervisor_target_unid_ssn_time = -1;
static int hf_cip_ssupervisor_target_unid_macid = -1;
static int hf_cip_ssupervisor_cp_owners_num_entries = -1;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_date = -1;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_time = -1;
static int hf_cip_ssupervisor_output_cp_owners_ocpunid_macid = -1;
static int hf_cip_ssupervisor_cp_owners_app_path_size = -1;
static int hf_cip_ssupervisor_proposed_tunid_ssn_timestamp = -1;
static int hf_cip_ssupervisor_proposed_tunid_ssn_date = -1;
static int hf_cip_ssupervisor_proposed_tunid_ssn_time = -1;
static int hf_cip_ssupervisor_proposed_tunid_macid = -1;
static int hf_cip_ssupervisor_instance_subclass = -1;


/* Safety Validator header field identifiers */
static int hf_cip_svalidator_sc = -1;

static int hf_cip_svalidator_sconn_fault_count = -1;
static int hf_cip_svalidator_state = -1;
static int hf_cip_svalidator_type = -1;
static int hf_cip_svalidator_type_pc = -1;
static int hf_cip_svalidator_type_conn_type = -1;
static int hf_cip_svalidator_ping_eri = -1;
static int hf_cip_svalidator_time_coord_msg_min_mult_size = -1;
static int hf_cip_svalidator_time_coord_msg_min_mult_item = -1;
static int hf_cip_svalidator_network_time_multiplier_size = -1;
static int hf_cip_svalidator_network_time_multiplier_item = -1;
static int hf_cip_svalidator_timeout_multiplier_size = -1;
static int hf_cip_svalidator_timeout_multiplier_item = -1;
static int hf_cip_svalidator_max_consumer_num = -1;
static int hf_cip_svalidator_data_conn_inst = -1;
static int hf_cip_svalidator_coordination_conn_inst_size = -1;
static int hf_cip_svalidator_coordination_conn_inst_item = -1;
static int hf_cip_svalidator_correction_conn_inst = -1;
static int hf_cip_svalidator_cco_binding = -1;
static int hf_cip_svalidator_max_data_age = -1;
static int hf_cip_svalidator_error_code = -1;
static int hf_cip_svalidator_prod_cons_fault_count_size = -1;
static int hf_cip_svalidator_prod_cons_fault_count_item = -1;

static int hf_cip_sercosiii_link_snn = -1;
static int hf_cip_sercosiii_link_communication_cycle_time = -1;
static int hf_cip_sercosiii_link_interface_status = -1;
static int hf_cip_sercosiii_link_error_count_mstps = -1;
static int hf_cip_sercosiii_link_sercos_address = -1;
static int hf_cip_sercosiii_link_error_count_p1 = -1;
static int hf_cip_sercosiii_link_error_count_p2 = -1;

static int hf_tcpip_snn_timestamp = -1;
static int hf_tcpip_snn_date = -1;
static int hf_tcpip_snn_time = -1;

/* Initialize the subtree pointers */
static gint ett_cip_safety                = -1;
static gint ett_cipsafety_mode_byte       = -1;
static gint ett_cipsafety_ack_byte        = -1;
static gint ett_cipsafety_mcast_byte      = -1;

static gint ett_cip_class_s_supervisor    = -1;
static gint ett_ssupervisor_rrsc          = -1;
static gint ett_ssupervisor_cmd_data      = -1;
static gint ett_ssupervisor_propose_tunid = -1;
static gint ett_ssupervisor_propose_tunid_ssn = -1;
static gint ett_ssupervisor_configure_request_tunid = -1;
static gint ett_ssupervisor_configure_request_tunid_ssn = -1;
static gint ett_ssupervisor_configure_request_ounid = -1;
static gint ett_ssupervisor_configure_request_ounid_ssn = -1;
static gint ett_ssupervisor_configure_lock_tunid = -1;
static gint ett_ssupervisor_configure_lock_tunid_ssn = -1;
static gint ett_ssupervisor_reset_tunid = -1;
static gint ett_ssupervisor_reset_tunid_ssn = -1;
static gint ett_ssupervisor_apply_tunid = -1;
static gint ett_ssupervisor_apply_tunid_ssn = -1;
static gint ett_exception_detail_alarm_common = -1;
static gint ett_exception_detail_alarm_device = -1;
static gint ett_exception_detail_alarm_manufacturer = -1;
static gint ett_exception_detail_warning_common = -1;
static gint ett_exception_detail_warning_device = -1;
static gint ett_exception_detail_warning_manufacturer = -1;
static gint ett_ssupervisor_configuration_unid = -1;
static gint ett_ssupervisor_configuration_unid_ssn = -1;
static gint ett_ssupervisor_safety_configuration_id = -1;
static gint ett_ssupervisor_safety_configuration_id_ssn = -1;
static gint ett_ssupervisor_target_unid = -1;
static gint ett_ssupervisor_target_unid_ssn = -1;
static gint ett_ssupervisor_output_cp_owners = -1;
static gint ett_ssupervisor_output_cp_owners_ocpunid = -1;
static gint ett_ssupervisor_output_cp_owners_ocpunid_ssn = -1;
static gint ett_ssupervisor_proposed_tunid = -1;
static gint ett_ssupervisor_proposed_tunid_ssn = -1;
static gint ett_cip_ssupervisor_reset_attr_bitmap = -1;

static gint ett_cip_class_s_validator     = -1;
static gint ett_svalidator_rrsc           = -1;
static gint ett_svalidator_cmd_data       = -1;
static gint ett_svalidator_type           = -1;

const value_string cipsafety_ssn_date_vals[8] = {

   { 0,     "NULL SSN" },
   { 1,     "Manual Setting - Backplane" },
   { 2,     "Manual Setting - ControlNet" },
   { 4,     "Manual Setting - EtherNet/IP" },
   { 5,     "Manual Setting - DeviceNet" },
   { 6,     "Manual Setting - SERCOS III" },
   { 65535, "No SSN Set" },

   { 0,     NULL }
};

static const true_false_string cip_safety_vals_active_idle = {
   "Idle",
   "Active"
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
   { 3,        "Self-Testing Exception"   },
   { 4,        "Executing"   },
   { 5,        "Abort"   },
   { 6,        "Critical Fault"   },
   { 7,        "Configuring"   },
   { 8,        "Waiting for TUNID"   },

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

void
dissect_unid(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_item *pi, const char* ssn_name, int hf_ssn_timestamp,
             int hf_ssn_date, int hf_ssn_time, int hf_macid, gint ett, gint ett_ssn)
{
   proto_tree *tree, *ssn_tree;
   proto_item *ssn_item;

   tree = proto_item_add_subtree(pi, ett);

   ssn_item = proto_tree_add_text(tree, tvb, offset, 6, "%s", ssn_name);
   ssn_tree = proto_item_add_subtree(ssn_item, ett_ssn);
   dissect_cipsafety_ssn(ssn_tree, tvb, pinfo, offset, hf_ssn_timestamp, hf_ssn_date, hf_ssn_time);

   proto_tree_add_item(tree, hf_macid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN);
}

void dissect_cipsafety_ssn(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int hf_real_datetime, int hf_date, int hf_time)
{
   guint16 date;

   date = tvb_get_letohs( tvb, offset);

   if ((date >= 11688) && (date <= 65534))
   {
      /* value is an actual timestamp */
      dissect_cip_date_and_time(tree, tvb, offset, hf_real_datetime);
   }
   else
   {
      /* Treated as UINT16 and UINT32 values */
      proto_tree_add_item(tree, hf_date, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(tree, hf_time, tvb, offset+2, 4, ENC_LITTLE_ENDIAN);
   }
}

/************************************************
 *
 * Dissector for CIP Safety Supervisor Object
 *
 ************************************************/
static void
dissect_cip_s_supervisor_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item;
   proto_tree *rrsc_tree, *cmd_data_tree, *bitmap_tree;
   int req_path_size;
   int temp_data;
   guint8 service, gen_status, add_stat_size;
   cip_req_info_t* preq_info;
   cip_simple_request_info_t req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIPS Supervisor");

   /* Add Service code & Request/Response tree */
   service = tvb_get_guint8( tvb, offset );
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_ssupervisor_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ), cip_sc_vals_ssupervisor , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7, cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_ssupervisor_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   preq_info = (cip_req_info_t*)p_get_proto_data(pinfo->fd, proto_cip);
   if ((preq_info != NULL) &&
       (preq_info->ciaData != NULL))
   {
      memcpy(&req_data, preq_info->ciaData, sizeof(cip_simple_request_info_t));
   }
   else
   {
      req_data.iClass = (guint32)-1;
      req_data.iInstance = (guint32)-1;
      req_data.iAttribute = (guint32)-1;
      req_data.iMember = (guint32)-1;
   }

   if(service & 0x80 )
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_ssupervisor_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            switch (service & 0x7F)
            {
            case SC_SSUPER_VALIDATE_CONFIGURATION:
               proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_sccrc, tvb, offset+4+add_stat_size, 4, ENC_LITTLE_ENDIAN);
               dissect_cipsafety_ssn(cmd_data_tree, tvb, pinfo, offset+4+add_stat_size+4, hf_cip_ssupervisor_validate_configuration_scts_timestamp,
                                 hf_cip_ssupervisor_validate_configuration_scts_date, hf_cip_ssupervisor_validate_configuration_scts_time);
               break;
            }
         }
         else if ((gen_status == 0xD0) && ((service & 0x7F) == SC_SSUPER_VALIDATE_CONFIGURATION))
         {
            if (add_stat_size > 0)
            {
               proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_ext_error, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
            }
         }
         else
         {
            /* Error responses */

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
         }
      }

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_ssupervisor , "Unknown Service (0x%02x)") );
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_ssupervisor_cmd_data );

         /* Check what service code that received */
         switch (service)
         {
         case SC_SSUPER_RECOVER:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_recover_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
            break;
         case SC_SSUPER_PERFORM_DIAGNOSTICS:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_perform_diag_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
            break;
         case SC_SSUPER_CONFIGURE_REQUEST:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_password, tvb, offset+2+req_path_size, 16, ENC_NA);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_tunid, tvb, offset+2+req_path_size+16, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+16, pi, "TUNID SSN", hf_cip_ssupervisor_configure_request_tunid_ssn_timestamp,
               hf_cip_ssupervisor_configure_request_tunid_ssn_date, hf_cip_ssupervisor_configure_request_tunid_ssn_time,
               hf_cip_ssupervisor_configure_request_tunid_macid, ett_ssupervisor_configure_request_tunid, ett_ssupervisor_configure_request_tunid_ssn);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_request_ounid, tvb, offset+2+req_path_size+26, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+16, pi, "OUNID SSN", hf_cip_ssupervisor_configure_request_ounid_ssn_timestamp,
                         hf_cip_ssupervisor_configure_request_ounid_ssn_date, hf_cip_ssupervisor_configure_request_ounid_ssn_time,
                         hf_cip_ssupervisor_configure_request_ounid_macid, ett_ssupervisor_configure_request_ounid, ett_ssupervisor_configure_request_ounid_ssn);
            break;
         case SC_SSUPER_VALIDATE_CONFIGURATION:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_validate_configuration_sccrc, tvb, offset+2+req_path_size, 4, ENC_LITTLE_ENDIAN);
            dissect_cipsafety_ssn(cmd_data_tree, tvb, pinfo, offset+2+req_path_size+4, hf_cip_ssupervisor_validate_configuration_scts_timestamp,
                                 hf_cip_ssupervisor_validate_configuration_scts_date, hf_cip_ssupervisor_validate_configuration_scts_time);
            break;
         case SC_SSUPER_SET_PASSWORD:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_set_password_current_password, tvb, offset+2+req_path_size, 16, ENC_NA);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_set_password_new_password, tvb, offset+2+req_path_size+16, 16, ENC_NA);
            break;
         case SC_SSUPER_CONFIGURATION_LOCK:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_value, tvb, offset+2+req_path_size+1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_password, tvb, offset+2+req_path_size+1, 16, ENC_NA);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_configure_lock_tunid, tvb, offset+2+req_path_size+17, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+17, pi, "TUNID SSN", hf_cip_ssupervisor_configure_lock_tunid_ssn_timestamp,
                         hf_cip_ssupervisor_configure_lock_tunid_ssn_date, hf_cip_ssupervisor_configure_lock_tunid_ssn_time,
                         hf_cip_ssupervisor_configure_lock_tunid_macid, ett_ssupervisor_configure_lock_tunid, ett_ssupervisor_configure_lock_tunid_ssn);
            break;
         case SC_SSUPER_MODE_CHANGE:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_mode_change_value, tvb, offset+2+req_path_size+1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_mode_change_password, tvb, offset+2+req_path_size+1, 16, ENC_NA);
            break;
         case SC_SSUPER_SAFETY_RESET:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_type, tvb, offset+2+req_path_size+1, 1, ENC_LITTLE_ENDIAN);
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+1 );
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password, tvb, offset+2+req_path_size+1, 16, ENC_NA);
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_tunid, tvb, offset+2+req_path_size+17, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size+17, pi, "TUNID SSN", hf_cip_ssupervisor_reset_tunid_tunid_ssn_timestamp,
                         hf_cip_ssupervisor_reset_tunid_tunid_ssn_date, hf_cip_ssupervisor_reset_tunid_tunid_ssn_time,
                         hf_cip_ssupervisor_reset_tunid_macid, ett_ssupervisor_reset_tunid, ett_ssupervisor_reset_tunid_ssn);
            /* Attribute bitmap only included on Reset Type 2 */
            if (temp_data == 2)
            {
               pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_attr_bitmap, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               bitmap_tree = proto_item_add_subtree(pi, ett_cip_ssupervisor_reset_attr_bitmap);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_macid, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_baudrate, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_tunid, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_password, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_cfunid, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_ocpunid, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_reserved, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(bitmap_tree, hf_cip_ssupervisor_reset_attr_bitmap_extended, tvb, offset+2+req_path_size+27, 1, ENC_LITTLE_ENDIAN);
            }
            break;
         case SC_SSUPER_RESET_PASSWORD:
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password_data_size, tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);
            temp_data = tvb_get_guint8(tvb, offset+2+req_path_size);
            proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_reset_password_data, tvb, offset+2+req_path_size+1, temp_data, ENC_NA);
            break;
         case SC_SSUPER_PROPOSE_TUNID:
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_propose_tunid_tunid, tvb, offset+2+req_path_size, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size, pi, "TUNID SSN", hf_cip_ssupervisor_propose_tunid_tunid_ssn_timestamp,
                         hf_cip_ssupervisor_propose_tunid_tunid_ssn_date, hf_cip_ssupervisor_propose_tunid_tunid_ssn_time,
                         hf_cip_ssupervisor_propose_tunid_tunid_macid, ett_ssupervisor_propose_tunid, ett_ssupervisor_propose_tunid_ssn);
            break;
         case SC_SSUPER_APPLY_TUNID:
            pi = proto_tree_add_item(cmd_data_tree, hf_cip_ssupervisor_apply_tunid_tunid, tvb, offset+2+req_path_size, 10, ENC_NA);
            dissect_unid(tvb, pinfo, offset+2+req_path_size, pi, "TUNID SSN", hf_cip_ssupervisor_apply_tunid_tunid_ssn_timestamp,
                         hf_cip_ssupervisor_apply_tunid_tunid_ssn_date, hf_cip_ssupervisor_apply_tunid_tunid_ssn_time,
                         hf_cip_ssupervisor_apply_tunid_tunid_macid, ett_ssupervisor_apply_tunid, ett_ssupervisor_apply_tunid_ssn);
            break;
         default:
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

}

static int
dissect_cip_class_s_supervisor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_s_supervisor, tvb, 0, -1, ENC_NA);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_s_supervisor );

      dissect_cip_s_supervisor_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

int dissect_s_supervisor_exception_detail(proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int hf_size, int hf_data)
{
   int size;

   proto_tree_add_item(tree, hf_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset);
   proto_tree_add_item(tree, hf_data, tvb, offset+1, size, ENC_NA );
   proto_item_set_len(item, size+1);

   return size+1;
}

int dissect_s_supervisor_exception_detail_alarm(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   proto_item *pi;
   proto_tree *item_tree;
   int total_size = 0, size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Common Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_alarm_common);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_alarm_ced_size, hf_cip_ssupervisor_exception_detail_alarm_ced_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 13 (Common Exception Detail)");
      return total_len;
   }
   total_size += size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Device Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_alarm_device);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_alarm_ded_size, hf_cip_ssupervisor_exception_detail_alarm_ded_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 13 (Device Exception Detail)");
      return total_len;
   }
   total_size += size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Manufacturer Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_alarm_manufacturer);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_alarm_med_size, hf_cip_ssupervisor_exception_detail_alarm_med_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 13 (Manufacturer Exception Detail)");
      return total_len;
   }
   total_size += size;

   return total_size;
}

int dissect_s_supervisor_exception_detail_warning(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   proto_item *pi;
   proto_tree *item_tree;
   int total_size = 0, size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Common Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_warning_common);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_warning_ced_size, hf_cip_ssupervisor_exception_detail_warning_ced_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 14 (Common Exception Detail)");
      return total_len;
   }
   total_size += size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Device Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_warning_device);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_warning_ded_size, hf_cip_ssupervisor_exception_detail_warning_ded_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 14 (Device Exception Detail)");
      return total_len;
   }
   total_size += size;

   pi = proto_tree_add_text(tree, tvb, offset, 1, "Manufacturer Exception Detail");
   item_tree = proto_item_add_subtree(pi, ett_exception_detail_warning_manufacturer);
   size = dissect_s_supervisor_exception_detail(item_tree, pi, tvb, offset,
               hf_cip_ssupervisor_exception_detail_warning_med_size, hf_cip_ssupervisor_exception_detail_warning_med_detail);
   if (size == 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 14 (Manufacturer Exception Detail)");
      return total_len;
   }
   total_size += size;

   return total_size;
}

int dissect_s_supervisor_configuration_unid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 25");
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "CFUNID SSN", hf_cip_ssupervisor_configuration_unid_ssn_timestamp,
                  hf_cip_ssupervisor_configuration_unid_ssn_date, hf_cip_ssupervisor_configuration_unid_ssn_time,
                  hf_cip_ssupervisor_configuration_unid_macid, ett_ssupervisor_configuration_unid, ett_ssupervisor_configuration_unid_ssn);
   return 10;
}

int dissect_s_supervisor_safety_configuration_id(packet_info *pinfo, proto_tree *tree _U_, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 26");
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "SCID SSN", hf_cip_ssupervisor_safety_configuration_id_ssn_timestamp,
                  hf_cip_ssupervisor_safety_configuration_id_ssn_date, hf_cip_ssupervisor_safety_configuration_id_ssn_time,
                  hf_cip_ssupervisor_safety_configuration_id_macid, ett_ssupervisor_safety_configuration_id, ett_ssupervisor_safety_configuration_id_ssn);
   return 10;
}

int dissect_s_supervisor_target_unid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 27");
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "TUNID SSN", hf_cip_ssupervisor_target_unid_ssn_timestamp,
                  hf_cip_ssupervisor_target_unid_ssn_date, hf_cip_ssupervisor_target_unid_ssn_time,
                  hf_cip_ssupervisor_target_unid_macid, ett_ssupervisor_target_unid, ett_ssupervisor_target_unid_ssn);
   return 10;
}

int dissect_s_supervisor_output_connection_point_owners(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   guint16 i, num_entries;
   proto_item *entry_item, *app_path_item;
   proto_tree *entry_tree;
   int attr_len = 0, app_path_size;

   if (total_len < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 28");
      return total_len;
   }

   entry_item = proto_tree_add_item(tree, hf_cip_ssupervisor_cp_owners_num_entries, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   num_entries = tvb_get_letohs(tvb, offset);
   attr_len += 2;

   if (num_entries > 0)
   {
      entry_tree = proto_item_add_subtree(entry_item, ett_ssupervisor_output_cp_owners);

      for (i = 0; i < num_entries; i++)
      {
         if (total_len < attr_len+11)
         {
            expert_add_info_format(pinfo, entry_item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 28 (UNID)");
            return total_len;
         }

         dissect_unid(tvb, pinfo, offset+attr_len, entry_item, "OCPUNID SSN", hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_timestamp,
                        hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_date, hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_time,
                        hf_cip_ssupervisor_output_cp_owners_ocpunid_macid, ett_ssupervisor_output_cp_owners_ocpunid, ett_ssupervisor_output_cp_owners_ocpunid_ssn);
         attr_len += 10;

         proto_tree_add_item(entry_tree, hf_cip_ssupervisor_cp_owners_app_path_size, tvb, offset+attr_len, 1, ENC_LITTLE_ENDIAN );
         app_path_size = tvb_get_guint8( tvb, offset+attr_len);
         attr_len += 1;

         if (total_len < attr_len+app_path_size)
         {
            expert_add_info_format(pinfo, entry_item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 28 (EPATH)");
            return total_len;
         }

         app_path_item = proto_tree_add_text(entry_tree, tvb, offset+attr_len, app_path_size, "Application Resource: ");
         dissect_epath( tvb, pinfo, app_path_item, offset+attr_len, app_path_size, FALSE, TRUE, NULL, NULL);
         attr_len += app_path_size;
      }
   }

   return attr_len;
}

int dissect_s_supervisor_proposed_tunid(packet_info *pinfo, proto_tree *tree _U_, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 10)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Supervisor Attribute 29");
      return total_len;
   }

   dissect_unid(tvb, pinfo, offset, item, "Proposed TUNID SSN", hf_cip_ssupervisor_proposed_tunid_ssn_timestamp,
                  hf_cip_ssupervisor_proposed_tunid_ssn_date, hf_cip_ssupervisor_proposed_tunid_ssn_time,
                  hf_cip_ssupervisor_proposed_tunid_macid, ett_ssupervisor_proposed_tunid, ett_ssupervisor_proposed_tunid_ssn);
   return 10;
}

/************************************************
 *
 * Dissector for CIP Safety Validator Object
 *
 ************************************************/
int dissect_s_validator_type(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   proto_item *pi;
   proto_tree *item_tree;

   if (total_len < 1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 2");
      return total_len;
   }

   pi = proto_tree_add_item(tree, hf_cip_svalidator_type, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   item_tree = proto_item_add_subtree(pi, ett_svalidator_type);
   proto_tree_add_item(item_tree, hf_cip_svalidator_type_pc, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(item_tree, hf_cip_svalidator_type_conn_type, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   return 1;
}

int dissect_s_validator_time_coord_msg_min_mult(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_time_coord_msg_min_mult_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 4");
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_time_coord_msg_min_mult_item, tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

int dissect_s_validator_network_time_multiplier(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_network_time_multiplier_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 5");
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_network_time_multiplier_item, tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

int dissect_s_validator_timeout_multiplier(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_timeout_multiplier_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset );

   if (total_len < size+1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 6");
      return total_len;
   }

   for (i = 0; i < size; i++)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_timeout_multiplier_item, tvb, offset+1+i, 1, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

int dissect_s_validator_coordination_conn_inst(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_coordination_conn_inst_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset )*2;

   if (total_len < size+1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 9");
      return total_len;
   }

   for (i = 0; i < size; i+=2)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_coordination_conn_inst_item, tvb, offset+1+i, 2, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

int dissect_s_validator_app_data_path(packet_info *pinfo, proto_tree *tree _U_, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   dissect_epath(tvb, pinfo, item, offset, total_len, FALSE, FALSE, NULL, NULL);
   return total_len;
}

int dissect_s_validator_prod_cons_fault_count(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   int i, size;

   proto_tree_add_item(tree, hf_cip_svalidator_prod_cons_fault_count_size, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   size = tvb_get_guint8( tvb, offset );

   if (total_len < size+1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Safety Validator Attribute 15");
      return total_len;
   }

   for (i = 0; i < size; i++)
   {
      proto_tree_add_item(tree, hf_cip_svalidator_prod_cons_fault_count_item, tvb, offset+1+i, 1, ENC_LITTLE_ENDIAN );
   }

   return (size+1);
}

static void
dissect_cip_s_validator_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item;
   proto_tree *rrsc_tree, *cmd_data_tree;
   int req_path_size, gaa_offset;
   guint8 service, gen_status, add_stat_size;
   cip_req_info_t* preq_info;
   cip_simple_request_info_t req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIPS Supervisor");

   /* Add Service code & Request/Response tree */
   service = tvb_get_guint8( tvb, offset );
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_svalidator_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_svalidator , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_svalidator_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   preq_info = (cip_req_info_t*)p_get_proto_data(pinfo->fd, proto_cip);
   if ((preq_info != NULL) &&
       (preq_info->ciaData != NULL))
   {
      memcpy(&req_data, preq_info->ciaData, sizeof(cip_simple_request_info_t));
   }
   else
   {
      req_data.iClass = (guint32)-1;
      req_data.iInstance = (guint32)-1;
      req_data.iAttribute = (guint32)-1;
      req_data.iMember = (guint32)-1;
   }

   if(service & 0x80 )
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_ssupervisor_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            /* Success responses */
            if (((service & 0x7F) == SC_GET_ATT_ALL) &&
                (req_data.iInstance != (guint32)-1) &&
                (req_data.iInstance != 0))
            {
               /* Get Attribute All (instance) response */
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_state, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN );
               gaa_offset = 1;
               gaa_offset += dissect_s_validator_type(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, 1);
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_ping_eri, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               gaa_offset += dissect_s_validator_time_coord_msg_min_mult(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, item_length-4-add_stat_size-gaa_offset);
               gaa_offset += dissect_s_validator_timeout_multiplier(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, item_length-4-add_stat_size-gaa_offset);
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_max_consumer_num, tvb, offset+4+add_stat_size+gaa_offset, 1, ENC_LITTLE_ENDIAN );
               gaa_offset += 1;
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_data_conn_inst, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               gaa_offset += dissect_s_validator_coordination_conn_inst(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, item_length-4-add_stat_size-gaa_offset);
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_correction_conn_inst, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_cco_binding, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_max_data_age, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               gaa_offset += dissect_s_validator_app_data_path(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, item_length-4-add_stat_size-gaa_offset);
               proto_tree_add_item(cmd_data_tree, hf_cip_svalidator_error_code, tvb, offset+4+add_stat_size+gaa_offset, 2, ENC_LITTLE_ENDIAN );
               gaa_offset += 2;
               /*gaa_offset +=*/ dissect_s_validator_prod_cons_fault_count(pinfo, cmd_data_tree, pi, tvb, offset+4+add_stat_size+gaa_offset, item_length-4-add_stat_size-gaa_offset);
            }
            else
            {
               /* Add data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
            }
         }
         else
         {
            /* Error responses */

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_svalidator , "Unknown Service (0x%02x)") );
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_ssupervisor_cmd_data );
         proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
      }

   }

}

static int
dissect_cip_class_s_validator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_s_validator, tvb, 0, -1, ENC_NA);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_s_validator );

      dissect_cip_s_validator_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

static gboolean
dissect_class_svalidator_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   unsigned char service, service_code, ioilen, segment;
   cip_req_info_t* preq_info;
   guint32 classid = 0;
   int offset = 0;

   service = tvb_get_guint8( tvb, offset );
   service_code = service & 0x7F;

   /* Handle GetAttributeAll and SetAttributeAll in CCO class */
   if (service_code == SC_GET_ATT_ALL)
   {
      if (service & 0x80)
      {
         /* Service response */
         preq_info = (cip_req_info_t*)p_get_proto_data(pinfo->fd, proto_cip);
         if ((preq_info != NULL) &&
             (preq_info->dissector == dissector_get_uint_handle( subdissector_class_table, CI_CLS_SAFETY_VALIDATOR)))
         {
            call_dissector(preq_info->dissector, tvb, pinfo, tree);
            return TRUE;
         }
      }
      else
      {
         /* Service request */
         ioilen = tvb_get_guint8( tvb, offset + 1 );
         if (ioilen > 1)
         {
            segment = tvb_get_guint8( tvb, offset + 2 );
            if (((segment & CI_SEGMENT_TYPE_MASK) == CI_LOGICAL_SEGMENT) &&
                ((segment & CI_LOGICAL_SEG_TYPE_MASK) == CI_LOGICAL_SEG_CLASS_ID))
            {
               /* Logical Class ID, do a format check */
               switch ( segment & CI_LOGICAL_SEG_FORMAT_MASK )
               {
               case CI_LOGICAL_SEG_8_BIT:
                  classid = tvb_get_guint8( tvb, offset + 3 );
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
            return TRUE;
         }

      }
   }

   return FALSE;
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
   guint8 mode_byte;

   mode_byte = tvb_get_guint8(tvb, offset);

   /* dissect Mode Byte bits */
   mode_item = proto_tree_add_item(tree, hf_cipsafety_mode_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   mode_tree = proto_item_add_subtree( mode_item, ett_cipsafety_mode_byte);

   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_ping_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_not_tbd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd_2_copy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_not_run_idle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   tbd_item = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   tbd2_item = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_tbd_2_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   run_idle_item = proto_tree_add_item(mode_tree, hf_cipsafety_mode_byte_run_idle, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* verify Mode Byte bits */
   /* TBD */
   if ((((mode_byte & 0x20) >> 5) & 0x01) == (((mode_byte & 0x04) >> 2) & 0x01))
      expert_add_info_format(pinfo, tbd_item, PI_PROTOCOL, PI_WARN, "TBD_2_bit not complemented");

   /* TBD 2 */
   if ((((mode_byte & 0x40) >> 6) & 0x01) != (((mode_byte & 0x08) >> 3) & 0x01))
      expert_add_info_format(pinfo, tbd2_item, PI_PROTOCOL, PI_WARN, "TBD bit not copied");

   /* Run/Idle */
   if ((((mode_byte & 0x80) >> 7) & 0x01) == (((mode_byte & 0x10) >> 4) & 0x01))
      expert_add_info_format(pinfo, run_idle_item, PI_PROTOCOL, PI_WARN, "Run/Idle bit not complemented");
}

static void
dissect_ack_byte( proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo _U_)
{
   proto_item *ack_item;
   proto_tree *ack_tree;
/********************
   Placeholder reminder to add ack_byte validation

   guint8 ack_byte;

   ack_byte = tvb_get_guint8(tvb, offset);
*/

   /* dissect Ack Byte bits */
   ack_item = proto_tree_add_item(tree, hf_cipsafety_ack_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   ack_tree = proto_item_add_subtree( ack_item, ett_cipsafety_ack_byte);

   proto_tree_add_item(ack_tree, hf_cipsafety_ack_byte_ping_count_reply, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(ack_tree, hf_cipsafety_ack_byte_reserved1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(ack_tree, hf_cipsafety_ack_byte_ping_response, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(ack_tree, hf_cipsafety_ack_byte_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(ack_tree, hf_cipsafety_ack_byte_parity_even, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_mcast_byte( proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo _U_)
{
   proto_item *mcast_item;
   proto_tree *mcast_tree;
/********************
   Placeholder reminder to add mcast_byte validation
   guint8 mcast_byte;

   mcast_byte = tvb_get_guint8(tvb, offset);
*/

   /* dissect MCast Byte bits */
   mcast_item = proto_tree_add_item(tree, hf_cipsafety_mcast_byte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   mcast_tree = proto_item_add_subtree( mcast_item, ett_cipsafety_mcast_byte);

   proto_tree_add_item(mcast_tree, hf_cipsafety_mcast_byte_consumer_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mcast_tree, hf_cipsafety_mcast_byte_reserved1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mcast_tree, hf_cipsafety_mcast_byte_mai, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mcast_tree, hf_cipsafety_mcast_byte_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(mcast_tree, hf_cipsafety_mcast_byte_parity_even, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_cip_safety_data( proto_tree *tree, proto_item *item, tvbuff_t *tvb, int item_length, packet_info *pinfo)
{
   int base_length, io_data_size;
   gboolean multicast = (((pntohl(pinfo->dst.data)) & 0xf0000000) == 0xe0000000);
   gboolean server_dir = FALSE;
   enum enip_connid_type conn_type = ECIDT_UNKNOWN;
   enum cip_safety_format_type format = CIP_SAFETY_BASE_FORMAT;
   cip_safety_info_t* safety_info = (cip_safety_info_t*)p_get_proto_data( pinfo->fd, proto_cipsafety );

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP Safety");

   /* determine the connection type as it affects the fields dissected */
   if (safety_info != NULL)
   {
      conn_type = safety_info->conn_type;
      format = safety_info->format;
      server_dir = safety_info->server_dir;
   }

   /* compute the base packet length to determine what is actual I/O data */
   base_length = multicast ? 12 : 6;

   if (((conn_type == ECIDT_O2T) && (server_dir == FALSE)) ||
       ((conn_type == ECIDT_T2O) && (server_dir == TRUE)))
   {
      /* consumer data */
      dissect_ack_byte(tree, tvb, 0, pinfo);
      proto_tree_add_item(tree, hf_cipsafety_consumer_time_value, tvb, 1, 2, ENC_LITTLE_ENDIAN);

      switch (format)
      {
      case CIP_SAFETY_BASE_FORMAT:
         proto_tree_add_item(tree, hf_cipsafety_ack_byte2, tvb, 3, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, 4, 2, ENC_LITTLE_ENDIAN);
         break;
      case CIP_SAFETY_EXTENDED_FORMAT:
         proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, 3, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, 4, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, 5, 1, ENC_LITTLE_ENDIAN);
         break;
      }
   }
   else if (((conn_type == ECIDT_O2T) && (server_dir == TRUE)) ||
            ((conn_type == ECIDT_T2O) && (server_dir == FALSE)))
   {
      /* producer data */
      switch (format)
      {
      case CIP_SAFETY_BASE_FORMAT:
         if (item_length-base_length <= 2)
         {
            /* Short Format (1-2 bytes I/O data) */
            proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, item_length-base_length, ENC_LITTLE_ENDIAN);
            dissect_mode_byte(tree, tvb, item_length-base_length, pinfo);

            proto_tree_add_item(tree, hf_cipsafety_crc_s1, tvb, item_length-base_length+1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s2, tvb, item_length-base_length+2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, item_length-base_length+3, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s1, tvb, item_length-base_length+5, 1, ENC_LITTLE_ENDIAN);

            if (multicast)
            {
               dissect_mcast_byte(tree, tvb, item_length-6, pinfo);
               proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, item_length-5, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_mcast_byte2, tvb, item_length-3, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, item_length-2, 2, ENC_LITTLE_ENDIAN);
            }
         }
         else
         {
            /* Long Format (3-250 bytes I/O data) */
            if (item_length%2 == 1)
            {
               /* Malformed packet */
               expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed CIP Safety I/O packet");
               return;
            }

            io_data_size = multicast ? ((item_length-14)/2) : ((item_length-8)/2);

            proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_LITTLE_ENDIAN);
            dissect_mode_byte(tree, tvb, io_data_size, pinfo);
            proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, io_data_size+1, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_complement_data, tvb, io_data_size+3, io_data_size, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, (io_data_size*2)+3, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, (io_data_size*2)+5, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s1, tvb, (io_data_size*2)+7, 1, ENC_LITTLE_ENDIAN);

            if (multicast)
            {
               dissect_mcast_byte(tree, tvb, (io_data_size*2)+5, pinfo);
               proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, (io_data_size*2)+6, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_mcast_byte2, tvb, (io_data_size*2)+8, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, (io_data_size*2)+9, 2, ENC_LITTLE_ENDIAN);
            }
         }
         break;
      case CIP_SAFETY_EXTENDED_FORMAT:
         if (item_length-base_length <= 2)
         {
            /* Short Format (1-2 bytes I/O data) */
            proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, item_length-base_length, ENC_LITTLE_ENDIAN);
            dissect_mode_byte(tree, tvb, item_length-base_length, pinfo);

            proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, item_length-base_length+1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, item_length-base_length+2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, item_length-base_length+3, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, item_length-base_length+5, 1, ENC_LITTLE_ENDIAN);

            if (multicast)
            {
               dissect_mcast_byte(tree, tvb, item_length-6, pinfo);
               proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, item_length-5, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, item_length-3, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, item_length-2, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, item_length-1, 1, ENC_LITTLE_ENDIAN);
            }
         }
         else
         {
            /* Long Format (3-250 bytes I/O data) */
            if (item_length%2 == 1)
            {
               /* Malformed packet */
               expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed CIP Safety I/O packet");
               return;
            }

            io_data_size = multicast ? ((item_length-14)/2) : ((item_length-8)/2);

            proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, io_data_size, ENC_LITTLE_ENDIAN);
            dissect_mode_byte(tree, tvb, io_data_size, pinfo);

            proto_tree_add_item(tree, hf_cipsafety_crc_s3, tvb, io_data_size+1, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_complement_data, tvb, io_data_size+3, io_data_size, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, (io_data_size*2)+3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, (io_data_size*2)+4, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_timestamp, tvb, (io_data_size*2)+5, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, (io_data_size*2)+7, 1, ENC_LITTLE_ENDIAN);

            if (multicast)
            {
               dissect_mcast_byte(tree, tvb, (io_data_size*2)+8, pinfo);
               proto_tree_add_item(tree, hf_cipsafety_time_correction, tvb, (io_data_size*2)+9, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_0, tvb, (io_data_size*2)+11, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_1, tvb, (io_data_size*2)+12, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(tree, hf_cipsafety_crc_s5_2, tvb, (io_data_size*2)+13, 1, ENC_LITTLE_ENDIAN);
            }
         }
         break;
      }
   }
   else
   {
      /* Shouldn't happen, but at least dissect it as data */
      proto_tree_add_item(tree, hf_cipsafety_data, tvb, 0, item_length, ENC_LITTLE_ENDIAN);
   }
}

static void
dissect_cipsafety(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *safety_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cipsafety, tvb, 0, -1, ENC_NA);
      safety_tree = proto_item_add_subtree( ti, ett_cip_safety);

      dissect_cip_safety_data(safety_tree, ti, tvb, tvb_length(tvb), pinfo );
   }
}

int dissect_sercosiii_link_error_count_p1p2(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 4)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed SERCOS III Attribute 5");
      return total_len;
   }

   proto_tree_add_item(tree, hf_cip_sercosiii_link_error_count_p1, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(tree, hf_cip_sercosiii_link_error_count_p2, tvb, offset+2, 2, ENC_LITTLE_ENDIAN );
   return 4;
}

int dissect_tcpip_ssn(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 6)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed TCP/IP Object Attribute 7");
      return total_len;
   }

   dissect_cipsafety_ssn(tree, tvb, pinfo, offset, hf_tcpip_snn_timestamp, hf_tcpip_snn_date, hf_tcpip_snn_time);
   return 6;
}

attribute_info_t cip_safety_attribute_vals[52] = {

   /* Safety Supervisor */
   {0x39, TRUE, 99, "Subclass", cip_uint, &hf_cip_ssupervisor_class_subclass, NULL},
   {0x39, FALSE, 1, "Number of Attributes", cip_usint, &hf_cip_ssupervisor_num_attr, NULL},
   {0x39, FALSE, 2, "Attribute List", cip_usint_array, &hf_cip_ssupervisor_attr_list, NULL},
   {0x39, FALSE, 5, "Manufacturer Name", cip_short_string, &hf_cip_ssupervisor_manufacture_name, NULL},
   {0x39, FALSE, 6, "Manufacturer Model Number", cip_short_string, &hf_cip_ssupervisor_manufacture_model_number, NULL},
   {0x39, FALSE, 7, "Software Revision Level", cip_short_string, &hf_cip_ssupervisor_sw_rev_level, NULL},
   {0x39, FALSE, 8, "Hardware Revision Level", cip_short_string, &hf_cip_ssupervisor_hw_rev_level, NULL},
   {0x39, FALSE, 9, "Manufacturer Serial Number", cip_short_string, &hf_cip_ssupervisor_manufacture_serial_number, NULL},
   {0x39, FALSE, 10, "Device Configuration", cip_short_string, &hf_cip_ssupervisor_device_config, NULL},
   {0x39, FALSE, 11, "Device Status", cip_usint, &hf_cip_ssupervisor_device_status, NULL},
   {0x39, FALSE, 12, "Exception Status", cip_byte, &hf_cip_ssupervisor_exception_status, NULL},
   {0x39, FALSE, 13, "Exception Detail Alarm", cip_dissector_func, NULL, dissect_s_supervisor_exception_detail_alarm},
   {0x39, FALSE, 14, "Exception Detail Warning", cip_dissector_func, NULL, dissect_s_supervisor_exception_detail_warning},
   {0x39, FALSE, 15, "Alarm Enable", cip_bool, &hf_cip_ssupervisor_alarm_enable, NULL},
   {0x39, FALSE, 16, "Warning Enable", cip_bool, &hf_cip_ssupervisor_warning_enable, NULL},
   {0x39, FALSE, 17, "Time", cip_date_and_time, &hf_cip_ssupervisor_time, NULL},
   {0x39, FALSE, 18, "Clock Power Cycle Behavior", cip_usint, &hf_cip_ssupervisor_clock_power_cycle_behavior, NULL},
   {0x39, FALSE, 19, "Last Maintenance Date", cip_date, &hf_cip_ssupervisor_last_maintenance_date, NULL},
   {0x39, FALSE, 20, "Next Scheduled Maintenance Date", cip_date, &hf_cip_ssupervisor_next_scheduled_maintenance_date, NULL},
   {0x39, FALSE, 21, "Scheduled Maintenance Expiration Timer", cip_int, &hf_cip_ssupervisor_scheduled_maintenance_expiration_timer, NULL},
   {0x39, FALSE, 22, "Scheduled Maintenance Expiration Warning Enable", cip_bool, &hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable, NULL},
   {0x39, FALSE, 23, "Run Hours", cip_udint, &hf_cip_ssupervisor_run_hours, NULL},
   {0x39, FALSE, 24, "Configuration Lock", cip_bool, &hf_cip_ssupervisor_configuration_lock, NULL},
   {0x39, FALSE, 25, "Configuration UNID", cip_dissector_func, NULL, dissect_s_supervisor_configuration_unid},
   {0x39, FALSE, 26, "Safety Configuration Identifier", cip_dissector_func, NULL, dissect_s_supervisor_safety_configuration_id},
   {0x39, FALSE, 27, "Target UNID", cip_dissector_func, NULL, dissect_s_supervisor_target_unid},
   {0x39, FALSE, 28, "Output Connection Point Owners", cip_dissector_func, NULL, dissect_s_supervisor_output_connection_point_owners},
   {0x39, FALSE, 29, "Proposed TUNID", cip_dissector_func, NULL, dissect_s_supervisor_proposed_tunid},
   {0x39, FALSE, 99, "Subclass", cip_uint, &hf_cip_ssupervisor_instance_subclass, NULL},

   /* Safety Validator */
   {0x3A, TRUE, 8, "Safety Connection Fault Count", cip_uint, &hf_cip_svalidator_sconn_fault_count, NULL},
   {0x3A, FALSE, 1, "Safety Validator State", cip_usint, &hf_cip_svalidator_state, NULL},
   {0x3A, FALSE, 2, "Safety Validator Type", cip_dissector_func, NULL, dissect_s_validator_type},
   {0x3A, FALSE, 3, "Ping Interval ERI Multiplier", cip_uint, &hf_cip_svalidator_ping_eri, NULL},
   {0x3A, FALSE, 4, "Time Coord Msg Min Multiplier", cip_dissector_func, NULL, dissect_s_validator_time_coord_msg_min_mult},
   {0x3A, FALSE, 5, "Network Time Expectation Multiplier", cip_dissector_func, NULL, dissect_s_validator_network_time_multiplier},
   {0x3A, FALSE, 6, "Timeout Multiplier", cip_dissector_func, NULL, dissect_s_validator_timeout_multiplier},
   {0x3A, FALSE, 7, "Max Consumer Number", cip_usint, &hf_cip_svalidator_max_consumer_num, NULL},
   {0x3A, FALSE, 8, "Data Connection Instance", cip_uint, &hf_cip_svalidator_data_conn_inst, NULL},
   {0x3A, FALSE, 9, "Coordination Connection Instance", cip_dissector_func, NULL, dissect_s_validator_coordination_conn_inst},
   {0x3A, FALSE, 10, "Correction Connection Instance", cip_uint, &hf_cip_svalidator_correction_conn_inst, NULL},
   {0x3A, FALSE, 11, "CCO Binding", cip_uint, &hf_cip_svalidator_cco_binding, NULL},
   {0x3A, FALSE, 12, "Max Data Age", cip_uint, &hf_cip_svalidator_max_data_age, NULL},
   {0x3A, FALSE, 13, "Application Data Path", cip_dissector_func, NULL, dissect_s_validator_app_data_path},
   {0x3A, FALSE, 14, "Error Code", cip_uint, &hf_cip_svalidator_error_code, NULL},
   {0x3A, FALSE, 15, "Producer/Consumer Fault Counters", cip_dissector_func, NULL, dissect_s_validator_prod_cons_fault_count},

   /* Sercos III Link */
   {0x4C, FALSE, 1, "Safety Network Number", cip_byte_array, &hf_cip_sercosiii_link_snn, NULL},
   {0x4C, FALSE, 2, "Communication Cycle Time", cip_dint, &hf_cip_sercosiii_link_communication_cycle_time, NULL},
   {0x4C, FALSE, 3, "Interface Status", cip_word, &hf_cip_sercosiii_link_interface_status, NULL},
   {0x4C, FALSE, 4, "Error counter MST-P/S", cip_int, &hf_cip_sercosiii_link_error_count_mstps, NULL},
   {0x4C, FALSE, 5, "Error counter Port1 and Port2", cip_dissector_func, NULL, dissect_sercosiii_link_error_count_p1p2},
   {0x4C, FALSE, 6, "SERCOS address", cip_int, &hf_cip_sercosiii_link_sercos_address, NULL},

   /* TCP/IP object (CIP-Safety specific) */
   {0xF5, FALSE, 7, "Safety Network Number", cip_dissector_func, NULL, dissect_tcpip_ssn}
};

/*
 * Protocol initialization
 */

static void
cipsafety_init_protocol(void)
{
   proto_cip = proto_get_id_by_filter_name( "cip" );
}

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
      { &hf_cip_reqrsp, { "Request/Response", "cip.rr", FT_UINT8, BASE_HEX, VALS(cip_sc_rr), 0x80, "Request or Response message", HFILL }},
      { &hf_cip_data, { "Data", "cip.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

      { &hf_cipsafety_data, { "Data", "enip.connection_transport_data", FT_BYTES, BASE_NONE, NULL, 0, "Connection Transport Data", HFILL }},
      { &hf_cipsafety_mode_byte, { "Mode Byte", "cipsafety.mode_byte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_ping_count, { "Ping Count", "cipsafety.mode_byte.ping_count", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_not_tbd, { "Not TBD Bit", "cipsafety.mode_byte.not_tbd", FT_BOOLEAN, BASE_DEC, NULL, 0x04, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_tbd_2_copy, { "TBD 2 Bit Copy", "cipsafety.mode_byte.tbd_2_copy", FT_BOOLEAN, BASE_DEC, NULL, 0x08, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_not_run_idle, { "Not Run/Idle", "cipsafety.mode_byte.not_run_idle", FT_BOOLEAN, BASE_DEC, NULL, 0x10, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_tbd, { "TBD Bit", "cipsafety.mode_byte.tbd", FT_BOOLEAN, BASE_DEC, NULL, 0x20, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_tbd_2_bit, { "TBD 2 Bit", "cipsafety.mode_byte.tbd_2_bit", FT_BOOLEAN, BASE_DEC, NULL, 0x40, NULL, HFILL }},
      { &hf_cipsafety_mode_byte_run_idle, { "Run/Idle", "cipsafety.mode_byte.run_idle", FT_BOOLEAN, BASE_DEC, NULL, 0x80, NULL, HFILL }},
      { &hf_cipsafety_crc_s1, { "CRC S1", "cipsafety.crc_s1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_crc_s2, { "CRC S2", "cipsafety.crc_s2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_crc_s3, { "CRC S3", "cipsafety.crc_s3", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_timestamp, { "Timestamp", "cipsafety.timestamp", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_ack_byte, { "ACK Byte", "cipsafety.ack_byte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_ack_byte_ping_count_reply, { "Ping Count Reply", "cipsafety.ack_byte.ping_count_reply", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
      { &hf_cipsafety_ack_byte_reserved1, { "Reserved", "cipsafety.ack_byte.reserved1", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }},
      { &hf_cipsafety_ack_byte_ping_response, { "Ping Response", "cipsafety.ack_byte.ping_response", FT_BOOLEAN, BASE_DEC, NULL, 0x08, NULL, HFILL }},
      { &hf_cipsafety_ack_byte_reserved2, { "Reserved", "cipsafety.ack_byte.reserved2", FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL }},
      { &hf_cipsafety_ack_byte_parity_even, { "Parity Even", "cipsafety.ack_byte.parity_even", FT_BOOLEAN, BASE_DEC, NULL, 0x80, NULL, HFILL }},
      { &hf_cipsafety_ack_byte2, { "ACK Byte 2", "cipsafety.ack_byte2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_consumer_time_value, { "Consumer Time Value", "cipsafety.consumer_time_value", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte, { "MCAST Byte", "cipsafety.mcast_byte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte_consumer_num, { "Consumer #", "cipsafety.mcast_byte.consumer_num", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte_reserved1, { "Reserved", "cipsafety.mcast_byte.reserved1", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte_mai, { "Multicast Active/Idle", "cipsafety.mcast_byte.active_idle", FT_BOOLEAN, 8, TFS(&cip_safety_vals_active_idle), 0x20, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte_reserved2, { "Reserved", "cipsafety.mcast_byte.reserved2", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte_parity_even, { "Parity Even", "cipsafety.mcast_byte.parity_even", FT_BOOLEAN, BASE_DEC, NULL, 0x80, NULL, HFILL }},
      { &hf_cipsafety_mcast_byte2, { "MCAST Byte 2", "cipsafety.mcast_byte2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_time_correction, { "Time Correction", "cipsafety.time_correction", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_crc_s5_0, { "CRC S5_0", "cipsafety.crc_s5_0", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_crc_s5_1, { "CRC S5_1", "cipsafety.crc_s5_1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_crc_s5_2, { "CRC S5_2", "cipsafety.crc_s5_2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cipsafety_complement_data, { "Complement Data", "cipsafety.complement_data", FT_BYTES, BASE_NONE, NULL, 0, "Connection Transport Data", HFILL }},

      { &hf_cip_sercosiii_link_snn, { "Data", "cipsafety.sercosiii_link.snn", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_communication_cycle_time, { "Communication Cycle Time", "cipsafety.sercosiii_link.communication_cycle_time", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_interface_status, { "Communication Cycle Time", "cipsafety.sercosiii_link.interface_status", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_error_count_mstps, { "Error Counter MST-P/S", "cipsafety.sercosiii_link.error_count_mstps", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_error_count_p1, { "Error Count Port 1", "cipsafety.sercosiii_link.error_count_p1", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_error_count_p2, { "Error Count Port 2", "cipsafety.sercosiii_link.error_count_p2", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sercosiii_link_sercos_address, { "SERCOS Address", "cipsafety.sercosiii_link.sercos_address", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},

      { &hf_tcpip_snn_timestamp, { "Safety Network Number (Timestamp)", "cip.tcpip.snn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_tcpip_snn_date, { "Safety Network Number (Manual) Date", "cip.tcpip.snn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_tcpip_snn_time, { "Safety Network Number (Manual) Time", "cip.tcpip.snn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
   };

   static hf_register_info hf_ssupervisor[] = {
      { &hf_cip_ssupervisor_sc, { "Service", "cipsafety.ssupervisor.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_ssupervisor), 0x7F, NULL, HFILL }},
      { &hf_cip_ssupervisor_recover_data, { "Data", "cipsafety.ssupervisor.recover.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_perform_diag_data, { "Data", "cipsafety.ssupervisor.perform_diag.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_password, { "Password", "cipsafety.ssupervisor.configure_request.password", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_tunid, { "Target UNID", "cipsafety.ssupervisor.configure_request.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_tunid_ssn_timestamp, { "TUNID SSN Timestamp", "cipsafety.ssupervisor.configure_request.tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_tunid_ssn_date, { "TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.configure_request.tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_tunid_ssn_time, { "TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.configure_request.tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_tunid_macid, { "MAC ID", "cipsafety.ssupervisor.configure_request.tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_ounid, { "Originator UNID", "cipsafety.ssupervisor.configure_request.ounid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_ounid_ssn_timestamp, { "OUNID SSN Timestamp", "cipsafety.ssupervisor.configure_request.ounid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_ounid_ssn_date, { "OUNID SSN  (Manual) Date", "cipsafety.ssupervisor.configure_request.ounid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_ounid_ssn_time, { "OUNID SSN  (Manual) Time", "cipsafety.ssupervisor.configure_request.ounid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_request_ounid_macid, { "MAC ID", "cipsafety.ssupervisor.configure_request.ounid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_validate_configuration_sccrc, { "SCCRC", "cipsafety.ssupervisor.validate_configuration.sccrc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_validate_configuration_scts_timestamp, { "SCTS (Timestamp)", "cipsafety.ssupervisor.validate_configuration.scts.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_validate_configuration_scts_date, { "SCTS (Manual) Date", "cipsafety.ssupervisor.validate_configuration.scts.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_validate_configuration_scts_time, { "SCTS (Manual) Time", "cipsafety.ssupervisor.validate_configuration.scts.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_validate_configuration_ext_error, { "Extended Error", "cipsafety.ssupervisor.validate_configuration.ext_error", FT_UINT16, BASE_DEC, VALS(cip_ssupervisor_validate_configuration_ext_error_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_set_password_current_password, { "Current Password", "cipsafety.ssupervisor.set_password.current_pass", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_set_password_new_password, { "New Password", "cipsafety.ssupervisor.set_password.new_pass", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_value, { "Lock Value", "cipsafety.ssupervisor.configure_lock.lock", FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_lock_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_password, { "Password", "cipsafety.ssupervisor.configure_lock.password", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_tunid, { "Target UNID", "cipsafety.ssupervisor.configure_lock.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_tunid_ssn_timestamp, { "TUNID SSN Timestamp", "cipsafety.ssupervisor.configure_lock.tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_tunid_ssn_date, { "TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.configure_lock.tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_tunid_ssn_time, { "TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.configure_lock.tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configure_lock_tunid_macid, { "MAC ID", "cipsafety.ssupervisor.configure_lock.tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_mode_change_value, { "Value", "cipsafety.ssupervisor.mode_change.value", FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_change_mode_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_mode_change_password, { "Password", "cipsafety.ssupervisor.mode_change.password", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_type, { "Reset Type", "cipsafety.ssupervisor.reset.type", FT_UINT8, BASE_DEC, VALS(cip_reset_type_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_password, { "Password", "cipsafety.ssupervisor.reset.password", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_tunid, { "Target UNID", "cipsafety.ssupervisor.reset.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_tunid_tunid_ssn_timestamp, { "TUNID SSN Timestamp", "cipsafety.ssupervisor.reset.tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_tunid_tunid_ssn_date, { "TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.reset.tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_tunid_tunid_ssn_time, { "TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.reset.tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_tunid_macid, { "MAC ID", "cipsafety.ssupervisor.reset.tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap, { "Attribute Bit Map", "cipsafety.ssupervisor.reset.attr_bitmap", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_macid, { "Preserve MacID", "cipsafety.ssupervisor.reset.attr_bitmap.macid", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_baudrate, { "Preserve Baud Rate", "cipsafety.ssupervisor.reset.attr_bitmap.baudrate", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_tunid, { "Preserve TUNID", "cipsafety.ssupervisor.reset.attr_bitmap.tunid", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_password, { "Preserve Password", "cipsafety.ssupervisor.reset.attr_bitmap.password", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_cfunid, { "Preserve CFUNID", "cipsafety.ssupervisor.reset.attr_bitmap.cfunid", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_ocpunid, { "Preserve OPCUNID", "cipsafety.ssupervisor.reset.attr_bitmap.ocpunid", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x20, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_reserved, { "Reserved", "cipsafety.ssupervisor.reset.attr_bitmap.reserved", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x40, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_attr_bitmap_extended, { "Use Extended Map", "cipsafety.ssupervisor.reset.attr_bitmap.extended", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x80, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_password_data_size, { "Data Size", "cipsafety.ssupervisor.reset_password.data_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_reset_password_data, { "Password Data", "cipsafety.ssupervisor.reset_password.password_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_propose_tunid_tunid, { "Target UNID", "cipsafety.ssupervisor.propose_tunid.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_propose_tunid_tunid_ssn_timestamp, { "TUNID SSN Timestamp", "cipsafety.ssupervisor.propose_tunid.tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_propose_tunid_tunid_ssn_date, { "TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.propose_tunid.tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_propose_tunid_tunid_ssn_time, { "TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.propose_tunid.tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_propose_tunid_tunid_macid, { "MAC ID", "cipsafety.ssupervisor.propose_tunid.tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_apply_tunid_tunid, { "Target UNID", "cipsafety.ssupervisor.apply_tunid.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_apply_tunid_tunid_ssn_timestamp, { "TUNID SSN Timestamp", "cipsafety.ssupervisor.apply_tunid.tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_apply_tunid_tunid_ssn_date, { "TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.apply_tunid.tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_apply_tunid_tunid_ssn_time, { "TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.apply_tunid.tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_apply_tunid_tunid_macid, { "MAC ID", "cipsafety.ssupervisor.apply_tunid.tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_class_subclass, { "Subclass", "cipsafety.ssupervisor.class_subclass", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_num_attr, { "Number of Attributes", "cipsafety.ssupervisor.num_attr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_attr_list, { "Attributes List Item", "cipsafety.ssupervisor.attr_item", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_manufacture_name, { "Manufacturer Name", "cipsafety.ssupervisor.manufacture_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_manufacture_model_number, { "Manufacturer Model Number", "cipsafety.ssupervisor.manufacture_model_number", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_sw_rev_level, { "Software Revision Level", "cipsafety.ssupervisor.sw_rev_level", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_hw_rev_level, { "Hardware Revision Level", "cipsafety.ssupervisor.hw_rev_level", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_manufacture_serial_number, { "Manufacturer Serial Number", "cipsafety.ssupervisor.manufacture_serial_number", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_device_config, { "Device Configuration", "cipsafety.ssupervisor.device_config", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_device_status, { "Device Status", "cipsafety.ssupervisor.device_status", FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_device_status_type_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_status, { "Exception Status", "cipsafety.ssupervisor.exception_status", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_ced_size, { "Common Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_alarm.ced.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_ced_detail, { "Common Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_alarm.ced.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_ded_size, { "Device Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_alarm.ded.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_ded_detail, { "Device Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_alarm.ded.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_med_size, { "Manufacturer Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_alarm.med.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_alarm_med_detail, { "Manufacturer Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_alarm.med.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_ced_size, { "Common Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_warning.ced.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_ced_detail, { "Common Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_warning.ced.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_ded_size, { "Device Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_warning.ded.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_ded_detail, { "Device Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_warning.ded.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_med_size, { "Manufacturer Exeception Detail Size", "cipsafety.ssupervisor.exception_detail_warning.med.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_exception_detail_warning_med_detail, { "Manufacturer Exeception Detail Data", "cipsafety.ssupervisor.exception_detail_warning.med.detail", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_alarm_enable, { "Exception Detail Alarm", "cipsafety.ssupervisor.alarm_enable", FT_BOOLEAN, BASE_DEC, TFS(&tfs_true_false), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_warning_enable, { "Exception Detail Warning", "cipsafety.ssupervisor.warning_enable", FT_BOOLEAN, BASE_DEC, TFS(&tfs_true_false), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_time, { "Time", "cipsafety.ssupervisor.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_clock_power_cycle_behavior, { "Clock Power Cycle Behavior", "cipsafety.ssupervisor.clock_power_cycle_behavior", FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_clock_power_cycle_type_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_last_maintenance_date, { "Last Maintenance Date", "cipsafety.ssupervisor.last_maintenance_date", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_next_scheduled_maintenance_date, { "Next Scheduled Maintenance Date", "cipsafety.ssupervisor.next_scheduled_maintenance_date", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_scheduled_maintenance_expiration_timer, { "Scheduled Maintenance Expiration Timer", "cipsafety.ssupervisor.scheduled_maintenance_expiration_timer", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_scheduled_maintenance_expiration_warning_enable, { "Scheduled Maintenance Expiration Warning Enable", "cipsafety.ssupervisor.scheduled_maintenance_expiration_warning", FT_BOOLEAN, BASE_DEC, TFS(&tfs_enabled_disabled), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_run_hours, { "Run Hours", "cipsafety.ssupervisor.run_hours", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configuration_lock, { "Configuration Lock", "cipsafety.ssupervisor.configuration_lock", FT_UINT8, BASE_DEC, VALS(cip_ssupervisor_lock_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configuration_unid_ssn_timestamp, { "Configuration UNID SSN Timestamp", "cipsafety.ssupervisor.configuration_unid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configuration_unid_ssn_date, { "Configuration UNID SSN  (Manual) Date", "cipsafety.ssupervisor.configuration_unid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configuration_unid_ssn_time, { "Configuration UNID SSN  (Manual) Time", "cipsafety.ssupervisor.configuration_unid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_configuration_unid_macid, { "Configuration UNID MAC ID", "cipsafety.ssupervisor.configuration_unid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_safety_configuration_id_ssn_timestamp, { "Safety Configuration ID SSN Timestamp", "cipsafety.ssupervisor.safety_configuration_id.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_safety_configuration_id_ssn_date, { "Safety Configuration ID SSN  (Manual) Date", "cipsafety.ssupervisor.safety_configuration_id.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_safety_configuration_id_ssn_time, { "Safety Configuration ID SSN  (Manual) Time", "cipsafety.ssupervisor.safety_configuration_id.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_safety_configuration_id_macid, { "Safety Configuration ID MAC ID", "cipsafety.ssupervisor.safety_configuration_id.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_target_unid_ssn_timestamp, { "Target UNID SSN Timestamp", "cipsafety.ssupervisor.target_unid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_target_unid_ssn_date, { "Target UNID SSN  (Manual) Date", "cipsafety.ssupervisor.target_unid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_target_unid_ssn_time, { "Target UNID SSN  (Manual) Time", "cipsafety.ssupervisor.target_unid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_target_unid_macid, { "Target UNID MAC ID", "cipsafety.ssupervisor.target_unid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_cp_owners_num_entries, { "Number of Array Entries", "cipsafety.ssupervisor.cp_owners.num_entries", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_timestamp, { "OCPUNID SSN Timestamp", "cipsafety.ssupervisor.cp_owners.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_date, { "OCPUNID SSN  (Manual) Date", "cipsafety.ssupervisor.cp_owners.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_ssn_time, { "OCPUNID SSN  (Manual) Time", "cipsafety.ssupervisor.cp_owners.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_output_cp_owners_ocpunid_macid, { "OCPUNID MAC ID", "cipsafety.ssupervisor.cp_owners.ocpunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_cp_owners_app_path_size, { "EPATH Size", "cipsafety.ssupervisor.cp_owners.epath_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_proposed_tunid_ssn_timestamp, { "Proposed TUNID SSN Timestamp", "cipsafety.ssupervisor.proposed_tunid.ssn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_proposed_tunid_ssn_date, { "Proposed TUNID SSN  (Manual) Date", "cipsafety.ssupervisor.proposed_tunid.ssn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_ssn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_proposed_tunid_ssn_time, { "Proposed TUNID SSN  (Manual) Time", "cipsafety.ssupervisor.proposed_tunid.ssn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_proposed_tunid_macid, { "Proposed TUNID MAC ID", "cipsafety.ssupervisor.proposed_tunid.macid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ssupervisor_instance_subclass, { "Subclass", "cipsafety.ssupervisor.instance_subclass", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }}
   };

   static hf_register_info hf_svalidator[] = {
      { &hf_cip_svalidator_sc, { "Service", "cipsafety.svalidator.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_svalidator), 0x7F, NULL, HFILL }},

      { &hf_cip_svalidator_sconn_fault_count, { "Safety Connection Fault Count", "cipsafety.svalidator.sconn_fault_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_state, { "Safety Validator State", "cipsafety.svalidator.state", FT_UINT8, BASE_DEC, VALS(cip_svalidator_state_vals), 0, NULL, HFILL }},
      { &hf_cip_svalidator_type, { "Safety Validator Type", "cipsafety.svalidator.type", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_type_pc, { "Producer/Consumer", "cipsafety.svalidator.type.pc", FT_UINT8, BASE_HEX, VALS(cip_svalidator_type_pc_vals), 0x80, NULL, HFILL }},
      { &hf_cip_svalidator_type_conn_type, { "Safety Connection Type", "cipsafety.svalidator.type.conn_type", FT_UINT8, BASE_DEC, VALS(cip_svalidator_type_conn_type_vals), 0x7F, NULL, HFILL }},
      { &hf_cip_svalidator_ping_eri, { "Ping Interval EPI Multipler", "cipsafety.svalidator.ping_eri", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_time_coord_msg_min_mult_size, { "Time Coord Msg Min Multiplier Size", "cipsafety.svalidator.time_coord_msg_min_mult.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_time_coord_msg_min_mult_item, { "Time Coord Msg Min Multiplier Item", "cipsafety.svalidator.time_coord_msg_min_mult.item", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_network_time_multiplier_size, { "Network Time Expectation Multipler Size", "cipsafety.svalidator.network_time_multiplier.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_network_time_multiplier_item, { "Network Time Expectation Multipler Item", "cipsafety.svalidator.network_time_multiplier.item", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_timeout_multiplier_size, { "Timeout Multiplier Size", "cipsafety.svalidator.timeout_multiplier.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_timeout_multiplier_item, { "Timeout Multiplier Item", "cipsafety.svalidator.timeout_multiplier.item", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_max_consumer_num, { "Max Consumer Number", "cipsafety.svalidator.max_consumer_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_data_conn_inst, { "Data Connection Instance", "cipsafety.svalidator.data_conn_inst", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_coordination_conn_inst_size, { "Coordination Connection Instance Size", "cipsafety.svalidator.coordination_conn_inst.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_coordination_conn_inst_item, { "Coordination Connection Instance Item", "cipsafety.svalidator.coordination_conn_inst.item", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_correction_conn_inst, { "Correction Connection Instance", "cipsafety.svalidator.correction_conn_inst", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_cco_binding, { "CCO Binding", "cipsafety.svalidator.cco_binding", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_max_data_age, { "Max Data Age", "cipsafety.svalidator.max_data_age", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_error_code, { "Error Code", "cipsafety.svalidator.error_code", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_prod_cons_fault_count_size, { "Producer/Consumer Counter Size", "cipsafety.svalidator.prod_cons_fault_count.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_svalidator_prod_cons_fault_count_item, { "Producer/Consumer Counter Item", "cipsafety.svalidator.prod_cons_fault_count.item", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }}
   };

   static gint *ett[] = {
      &ett_cip_safety,
      &ett_cipsafety_mode_byte,
      &ett_cipsafety_ack_byte,
      &ett_cipsafety_mcast_byte
   };

   static gint *ett_ssupervisor[] = {
      &ett_cip_class_s_supervisor,
      &ett_ssupervisor_rrsc,
      &ett_ssupervisor_cmd_data,
      &ett_ssupervisor_propose_tunid,
      &ett_ssupervisor_propose_tunid_ssn,
      &ett_ssupervisor_configure_request_tunid,
      &ett_ssupervisor_configure_request_tunid_ssn,
      &ett_ssupervisor_configure_request_ounid,
      &ett_ssupervisor_configure_request_ounid_ssn,
      &ett_ssupervisor_configure_lock_tunid,
      &ett_ssupervisor_configure_lock_tunid_ssn,
      &ett_ssupervisor_reset_tunid,
      &ett_ssupervisor_reset_tunid_ssn,
      &ett_ssupervisor_apply_tunid,
      &ett_ssupervisor_apply_tunid_ssn,
      &ett_exception_detail_alarm_common,
      &ett_exception_detail_alarm_device,
      &ett_exception_detail_alarm_manufacturer,
      &ett_exception_detail_warning_common,
      &ett_exception_detail_warning_device,
      &ett_exception_detail_warning_manufacturer,
      &ett_ssupervisor_configuration_unid,
      &ett_ssupervisor_configuration_unid_ssn,
      &ett_ssupervisor_safety_configuration_id,
      &ett_ssupervisor_safety_configuration_id_ssn,
      &ett_ssupervisor_target_unid,
      &ett_ssupervisor_target_unid_ssn,
      &ett_ssupervisor_output_cp_owners,
      &ett_ssupervisor_output_cp_owners_ocpunid,
      &ett_ssupervisor_output_cp_owners_ocpunid_ssn,
      &ett_ssupervisor_proposed_tunid,
      &ett_ssupervisor_proposed_tunid_ssn,
      &ett_cip_ssupervisor_reset_attr_bitmap
   };

   static gint *ett_svalidator[] = {
      &ett_cip_class_s_validator,
      &ett_svalidator_rrsc,
      &ett_svalidator_cmd_data,
      &ett_svalidator_type
   };

   /* Create a CIP Safety protocol handle */
   proto_cipsafety = proto_register_protocol("Common Industrial Protocol, Safety", "CIP Safety", "cipsafety");
   proto_register_field_array(proto_cipsafety, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   register_init_routine(&cipsafety_init_protocol);
   register_dissector( "cipsafety", dissect_cipsafety, proto_cipsafety);

   /* Register CIP Safety objects */
   proto_cip_class_s_supervisor = proto_register_protocol("CIP Safety Supervisor",
       "CIPSSupervisor", "cipssupervisor");
   proto_register_field_array(proto_cip_class_s_supervisor, hf_ssupervisor, array_length(hf_ssupervisor));
   proto_register_subtree_array(ett_ssupervisor, array_length(ett_ssupervisor));

   proto_cip_class_s_validator = proto_register_protocol("CIP Safety Validator",
       "CIPSValidator", "cipsvalidator");
   proto_register_field_array(proto_cip_class_s_validator, hf_svalidator, array_length(hf_svalidator));
   proto_register_subtree_array(ett_svalidator, array_length(ett_svalidator));
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
   /* Create and register dissector handle for Safety Supervisor */
   cip_class_s_supervisor_handle = new_create_dissector_handle( dissect_cip_class_s_supervisor, proto_cip_class_s_supervisor );
   dissector_add_uint( "cip.class.iface", CI_CLS_SAFETY_SUPERVISOR, cip_class_s_supervisor_handle );

   /* Create and register dissector handle for Safety Validator */
   cip_class_s_validator_handle = new_create_dissector_handle( dissect_cip_class_s_validator, proto_cip_class_s_validator );
   dissector_add_uint( "cip.class.iface", CI_CLS_SAFETY_VALIDATOR, cip_class_s_validator_handle );
   heur_dissector_add("cip.sc", dissect_class_svalidator_heur, proto_cip_class_s_validator);
}


/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
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
