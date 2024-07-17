/* packet-cip.c
 * Routines for Common Industrial Protocol (CIP) dissection
 * CIP Home: www.odva.org
 *
 * This dissector includes items from:
 *    CIP Volume 1: Common Industrial Protocol, Edition 3.34
 *    CIP Volume 5: CIP Safety, Edition 2.25
 *    CIP Volume 7A: Integration of Modbus Devices into the CIP Architecture, Edition 1.9
 *    CIP Volume 8: CIP Security, Edition 1.11
 *
 * Copyright 2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * Added support for Connection Configuration Object
 *   ryan wamsley * Copyright 2007
 *
 * Object dependend services based on IOI
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
 *
 * Improved support for CoCo, CM, MB objects
 * Heuristic object support for common services
 *   Michael Mann * Copyright 2011
 *
 * Added support for PCCC Objects
 *   Jared Rittle - Cisco Talos
 *   Copyright 2017
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// There are multiple different ways to add functionality based on CIP class-specific behavior:
// 1. Dissector Table "cip.io.iface" - Use this when Class 0/1 I/O needs different parsing based on
//    the CIP Class in the Forward Open
// 2. Dissector Table "cip.connection.class" - Use this when Class 2/3 data needs different parsing
//    based on the CIP Class in the Forward Open
// 3. Dissector Table "cip.class.iface" - Use this when a CIP Class has significantly different
//    behavior that would be best handled through a separate dissector
// 4. Dissector Table "cip.data_segment.iface" - Unknown. This may be removed in the future
// 5. attribute_info_t: Use this to add handling for an attribute, using a 3 tuple key (Class, Instance, Attribute)
//    See 'cip_attribute_vals' for an example.
// 6. cip_service_info_t: Use this to add handling for a service, using a 2 tuple key (Class, Service)
//    See 'cip_obj_spec_service_table' for an example.

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/wmem_scopes.h>
#include "packet-cip.h"
#include "packet-cipmotion.h"
#include "packet-cipsafety.h"
#include "packet-mbtcp.h"

void proto_register_cip(void);
void proto_reg_handoff_cip(void);

typedef struct mr_mult_req_info {
   uint8_t service;
   int num_services;
   cip_req_info_t *requests;
} mr_mult_req_info_t;

static dissector_handle_t cip_handle;
static dissector_handle_t cip_class_generic_handle;
static dissector_handle_t cip_class_cm_handle;
static dissector_handle_t cip_class_pccc_handle;
static dissector_handle_t cip_class_mb_handle;
static dissector_handle_t modbus_handle;
static dissector_handle_t cip_class_cco_handle;
static heur_dissector_list_t  heur_subdissector_service;

static bool cip_enhanced_info_column = true;

/* Initialize the protocol and registered fields */
static int proto_cip;
static int proto_cip_class_generic;
static int proto_cip_class_cm;
static int proto_cip_class_pccc;
static int proto_cip_class_mb;
static int proto_cip_class_cco;
static int proto_enip;
static int proto_modbus;

int hf_attr_class_revision;
int hf_attr_class_max_instance;
int hf_attr_class_num_instance;
int hf_attr_class_opt_attr_num;
int hf_attr_class_attr_num;
int hf_attr_class_opt_service_num;
int hf_attr_class_service_code;
int hf_attr_class_num_class_attr;
int hf_attr_class_num_inst_attr;
static int hf_cip_data;
static int hf_cip_service;
static int hf_cip_service_code;
static int hf_cip_reqrsp;
static int hf_cip_epath;
static int hf_cip_genstat;
static int hf_cip_addstat_size;
static int hf_cip_add_stat;
static int hf_cip_request_path_size;

static int hf_cip_cm_sc;
static int hf_cip_cm_genstat;
static int hf_cip_cm_addstat_size;
static int hf_cip_cm_add_status;
static int hf_cip_cm_ext_status;
static int hf_cip_cm_priority;
static int hf_cip_cm_tick_time;
static int hf_cip_cm_timeout_tick;
static int hf_cip_cm_timeout;
static int hf_cip_cm_ot_connid;
static int hf_cip_cm_to_connid;
static int hf_cip_connid;
static int hf_cip_cm_conn_serial_num;
static int hf_cip_cm_orig_serial_num;
static int hf_cip_cm_vendor;
static int hf_cip_cm_timeout_multiplier;
static int hf_cip_cm_ot_rpi;
static int hf_cip_cm_ot_timeout;
static int hf_cip_cm_ot_net_params32;
static int hf_cip_cm_ot_net_params16;
static int hf_cip_cm_to_rpi;
static int hf_cip_cm_to_timeout;

static int hf_cip_safety_nte_ms;

static int hf_cip_cm_to_net_params32;
static int hf_cip_cm_to_net_params16;
static int hf_cip_cm_transport_type_trigger;
static int hf_cip_cm_conn_path_size;
static int hf_cip_cm_ot_api;
static int hf_cip_cm_to_api;
static int hf_cip_cm_app_reply_size;
static int hf_cip_cm_app_reply_data;
static int hf_cip_cm_consumer_number;
static int hf_cip_cm_targ_vendor_id;
static int hf_cip_cm_targ_dev_serial_num;
static int hf_cip_cm_targ_conn_serial_num;
static int hf_cip_cm_initial_timestamp;
static int hf_cip_cm_initial_rollover;
static int hf_cip_cm_remain_path_size;
static int hf_cip_cm_msg_req_size;
static int hf_cip_cm_route_path_size;
static int hf_cip_cm_fwo_con_size;
static int hf_cip_cm_lfwo_con_size;
static int hf_cip_cm_fwo_fixed_var;
static int hf_cip_cm_lfwo_fixed_var;
static int hf_cip_cm_fwo_prio;
static int hf_cip_cm_lfwo_prio;
static int hf_cip_cm_fwo_typ;
static int hf_cip_cm_lfwo_typ;
static int hf_cip_cm_fwo_own;
static int hf_cip_cm_lfwo_own;
static int hf_cip_cm_fwo_dir;
static int hf_cip_cm_fwo_trigg;
static int hf_cip_cm_fwo_class;
static int hf_cip_cm_gco_conn;
static int hf_cip_cm_gco_coo_conn;
static int hf_cip_cm_gco_roo_conn;
static int hf_cip_cm_gco_last_action;
static int hf_cip_cm_ext112_ot_rpi_type;
static int hf_cip_cm_ext112_to_rpi_type;
static int hf_cip_cm_ext112_ot_rpi;
static int hf_cip_cm_ext112_to_rpi;
static int hf_cip_cm_ext126_size;
static int hf_cip_cm_ext127_size;
static int hf_cip_cm_ext128_size;

static int hf_cip_pccc_sc;
static int hf_cip_pccc_req_id_len;
static int hf_cip_pccc_cip_vend_id;
static int hf_cip_pccc_cip_serial_num;
static int hf_cip_pccc_cmd_code;
static int hf_cip_pccc_sts_code;
static int hf_cip_pccc_ext_sts_code;
static int hf_cip_pccc_tns_code;
static int hf_cip_pccc_fnc_code_06;
static int hf_cip_pccc_fnc_code_07;
static int hf_cip_pccc_fnc_code_0f;
static int hf_cip_pccc_byte_size;
static int hf_cip_pccc_file_num;
static int hf_cip_pccc_file_type;
static int hf_cip_pccc_element_num;
static int hf_cip_pccc_subelement_num;
#if 0
static int hf_cip_pccc_cpu_mode_3a;
#endif
static int hf_cip_pccc_cpu_mode_80;
static int hf_cip_pccc_resp_code;
static int hf_cip_pccc_execute_multi_count;
static int hf_cip_pccc_execute_multi_len;
static int hf_cip_pccc_execute_multi_fnc;
static int hf_cip_pccc_data;

static int hf_cip_mb_sc;
static int hf_cip_mb_read_coils_start_addr;
static int hf_cip_mb_read_coils_num_coils;
static int hf_cip_mb_read_coils_data;
static int hf_cip_mb_read_discrete_inputs_start_addr;
static int hf_cip_mb_read_discrete_inputs_num_inputs;
static int hf_cip_mb_read_discrete_inputs_data;
static int hf_cip_mb_read_holding_register_start_addr;
static int hf_cip_mb_read_holding_register_num_registers;
static int hf_cip_mb_read_holding_register_data;
static int hf_cip_mb_read_input_register_start_addr;
static int hf_cip_mb_read_input_register_num_registers;
static int hf_cip_mb_read_input_register_data;
static int hf_cip_mb_write_coils_start_addr;
static int hf_cip_mb_write_coils_outputs_forced;
static int hf_cip_mb_write_coils_num_coils;
static int hf_cip_mb_write_coils_data;
static int hf_cip_mb_write_registers_start_addr;
static int hf_cip_mb_write_registers_outputs_forced;
static int hf_cip_mb_write_registers_num_registers;
static int hf_cip_mb_write_registers_data;
static int hf_cip_mb_data;

static int hf_cip_cco_con_type;
static int hf_cip_cco_ot_rtf;
static int hf_cip_cco_to_rtf;
static int hf_cip_cco_sc;
static int hf_cip_cco_format_number;
static int hf_cip_cco_edit_signature;
static int hf_cip_cco_con_flags;
static int hf_cip_cco_tdi_vendor;
static int hf_cip_cco_tdi_devtype;
static int hf_cip_cco_tdi_prodcode;
static int hf_cip_cco_tdi_compatibility;
static int hf_cip_cco_tdi_comp_bit;
static int hf_cip_cco_tdi_majorrev;
static int hf_cip_cco_tdi_minorrev;
static int hf_cip_cco_pdi_vendor;
static int hf_cip_cco_pdi_devtype;
static int hf_cip_cco_pdi_prodcode;
static int hf_cip_cco_pdi_compatibility;
static int hf_cip_cco_pdi_comp_bit;
static int hf_cip_cco_pdi_majorrev;
static int hf_cip_cco_pdi_minorrev;
static int hf_cip_cco_cs_data_index;
static int hf_cip_cco_ot_rpi;
static int hf_cip_cco_to_rpi;
static int hf_cip_cco_ot_net_param16;
static int hf_cip_cco_to_net_param16;
static int hf_cip_cco_fwo_own;
static int hf_cip_cco_fwo_typ;
static int hf_cip_cco_fwo_prio;
static int hf_cip_cco_fwo_fixed_var;
static int hf_cip_cco_fwo_con_size;
static int hf_cip_cco_ot_net_param32;
static int hf_cip_cco_to_net_param32;
static int hf_cip_cco_lfwo_own;
static int hf_cip_cco_lfwo_typ;
static int hf_cip_cco_lfwo_prio;
static int hf_cip_cco_lfwo_fixed_var;
static int hf_cip_cco_lfwo_con_size;
static int hf_cip_cco_conn_path_size;
static int hf_cip_cco_proxy_config_size;
static int hf_cip_cco_target_config_size;
static int hf_cip_cco_iomap_format_number;
static int hf_cip_cco_iomap_size;
static int hf_cip_cco_connection_disable;
static int hf_cip_cco_net_conn_param_attr;
static int hf_cip_cco_timeout_multiplier;
static int hf_cip_cco_transport_type_trigger;
static int hf_cip_cco_fwo_dir;
static int hf_cip_cco_fwo_trigger;
static int hf_cip_cco_fwo_class;
static int hf_cip_cco_proxy_config_data;
static int hf_cip_cco_target_config_data;
static int hf_cip_cco_iomap_attribute;
static int hf_cip_cco_safety;
static int hf_cip_cco_change_type;
static int hf_cip_cco_connection_name;
static int hf_cip_cco_ext_status;

static int hf_cip_path_segment;
static int hf_cip_path_segment_type;
static int hf_cip_port_ex_link_addr;
static int hf_cip_port;
static int hf_cip_port_extended;
static int hf_cip_link_address_size;
static int hf_cip_link_address_byte;
static int hf_cip_link_address_string;
static int hf_cip_logical_seg_type;
static int hf_cip_logical_seg_format;
static int hf_cip_class8;
static int hf_cip_class16;
static int hf_cip_class32;
static int hf_cip_instance8;
static int hf_cip_instance16;
static int hf_cip_instance32;
static int hf_cip_member8;
static int hf_cip_member16;
static int hf_cip_member32;
static int hf_cip_attribute8;
static int hf_cip_attribute16;
static int hf_cip_attribute32;
static int hf_cip_conpoint8;
static int hf_cip_conpoint16;
static int hf_cip_conpoint32;
static int hf_cip_serviceid8;
static int hf_cip_ekey_format;
static int hf_cip_ekey_vendor;
static int hf_cip_ekey_devtype;
static int hf_cip_ekey_prodcode;
static int hf_cip_ekey_compatibility;
static int hf_cip_ekey_comp_bit;
static int hf_cip_ekey_majorrev;
static int hf_cip_ekey_minorrev;
static int hf_cip_ekey_serial_number;
static int hf_cip_ext_logical8;
static int hf_cip_ext_logical16;
static int hf_cip_ext_logical32;
static int hf_cip_ext_logical_type;
static int hf_cip_data_seg_type;
static int hf_cip_data_seg_size_simple;
static int hf_cip_data_seg_size_extended;
static int hf_cip_data_seg_item;
static int hf_cip_symbol;
static int hf_cip_symbol_size;
static int hf_cip_symbol_ascii;
static int hf_cip_symbol_extended_format;
static int hf_cip_symbol_numeric_format;
static int hf_cip_symbol_double_size;
static int hf_cip_symbol_triple_size;
static int hf_cip_numeric_usint;
static int hf_cip_numeric_uint;
static int hf_cip_numeric_udint;
static int hf_cip_network_seg_type;
static int hf_cip_seg_schedule;
static int hf_cip_seg_fixed_tag;
static int hf_cip_seg_prod_inhibit_time;
static int hf_cip_seg_prod_inhibit_time_us;
static int hf_cip_seg_network_size;
static int hf_cip_seg_network_subtype;
static int hf_cip_seg_safety_format;
static int hf_cip_seg_safety_reserved;
static int hf_cip_seg_safety_configuration_crc;
static int hf_cip_seg_safety_configuration_timestamp;
static int hf_cip_seg_safety_configuration_date;
static int hf_cip_seg_safety_configuration_time;
static int hf_cip_seg_safety_time_correction_epi;
static int hf_cip_seg_safety_time_correction_net_params;
static int hf_cip_seg_safety_time_correction_own;
static int hf_cip_seg_safety_time_correction_typ;
static int hf_cip_seg_safety_time_correction_prio;
static int hf_cip_seg_safety_time_correction_fixed_var;
static int hf_cip_seg_safety_time_correction_con_size;
static int hf_cip_seg_safety_tunid;
static int hf_cip_seg_safety_tunid_snn_timestamp;
static int hf_cip_seg_safety_tunid_snn_date;
static int hf_cip_seg_safety_tunid_snn_time;
static int hf_cip_seg_safety_tunid_nodeid;
static int hf_cip_seg_safety_ounid;
static int hf_cip_seg_safety_ounid_snn_timestamp;
static int hf_cip_seg_safety_ounid_snn_date;
static int hf_cip_seg_safety_ounid_snn_time;
static int hf_cip_seg_safety_ounid_nodeid;
static int hf_cip_seg_safety_ping_epi_multiplier;
static int hf_cip_seg_safety_time_coord_msg_min_multiplier;
static int hf_cip_seg_safety_network_time_expected_multiplier;
static int hf_cip_seg_safety_timeout_multiplier;
static int hf_cip_seg_safety_max_consumer_number;
static int hf_cip_seg_safety_conn_param_crc;
static int hf_cip_seg_safety_time_correction_conn_id;
static int hf_cip_seg_safety_max_fault_number;
static int hf_cip_seg_safety_init_timestamp;
static int hf_cip_seg_safety_init_rollover;
static int hf_cip_seg_safety_data;
static int hf_cip_class_max_inst32;
static int hf_cip_class_num_inst32;
static int hf_cip_reserved8;
static int hf_cip_reserved24;
static int hf_cip_pad8;

static int hf_cip_sc_get_attr_list_attr_count;
static int hf_cip_sc_get_attr_list_attr_status;
static int hf_cip_sc_set_attr_list_attr_count;
static int hf_cip_sc_set_attr_list_attr_status;
static int hf_cip_sc_reset_param;
static int hf_cip_sc_create_instance;
static int hf_cip_sc_mult_serv_pack_num_services;
static int hf_cip_sc_mult_serv_pack_offset;
static int hf_cip_find_next_object_max_instance;
static int hf_cip_find_next_object_num_instances;
static int hf_cip_find_next_object_instance_item;
static int hf_cip_sc_group_sync_is_sync;

/* Parsed Attributes */
static int hf_id_vendor_id;
static int hf_id_device_type;
static int hf_id_product_code;
static int hf_id_major_rev;
static int hf_id_minor_rev;
static int hf_id_status;
static int hf_id_serial_number;
static int hf_id_product_name;
static int hf_id_state;
static int hf_id_config_value;
static int hf_id_heartbeat;
static int hf_id_status_owned;
static int hf_id_status_conf;
static int hf_id_status_extended1;
static int hf_id_status_minor_fault_rec;
static int hf_id_status_minor_fault_unrec;
static int hf_id_status_major_fault_rec;
static int hf_id_status_major_fault_unrec;
static int hf_id_status_extended2;
static int hf_msg_rout_num_classes;
static int hf_msg_rout_classes;
static int hf_msg_rout_num_available;
static int hf_msg_rout_num_active;
static int hf_msg_rout_active_connections;
static int hf_conn_mgr_open_requests;
static int hf_conn_mgr_open_format_rejects;
static int hf_conn_mgr_open_resource_rejects;
static int hf_conn_mgr_other_open_rejects;
static int hf_conn_mgr_close_requests;
static int hf_conn_close_format_requests;
static int hf_conn_mgr_close_other_requests;
static int hf_conn_mgr_conn_timouts;
static int hf_conn_mgr_num_conn_entries;
static int hf_conn_mgr_num_conn_entries_bytes;
static int hf_conn_mgr_conn_open_bits;
static int hf_conn_mgr_cpu_utilization;
static int hf_conn_mgr_max_buff_size;
static int hf_conn_mgr_buff_size_remaining;
static int hf_stringi_number_char;
static int hf_stringi_language_char;
static int hf_stringi_char_string_struct;
static int hf_stringi_char_set;
static int hf_stringi_international_string;
static int hf_file_filename;
static int hf_time_sync_ptp_enable;
static int hf_time_sync_is_synchronized;
static int hf_time_sync_sys_time_micro;
static int hf_time_sync_sys_time_nano;
static int hf_time_sync_offset_from_master;
static int hf_time_sync_max_offset_from_master;
static int hf_time_sync_mean_path_delay_to_master;
static int hf_time_sync_gm_clock_clock_id;
static int hf_time_sync_gm_clock_clock_class;
static int hf_time_sync_gm_clock_time_accuracy;
static int hf_time_sync_gm_clock_offset_scaled_log_variance;
static int hf_time_sync_gm_clock_current_utc_offset;
static int hf_time_sync_gm_clock_time_property_flags;
static int hf_time_sync_gm_clock_time_property_flags_leap61;
static int hf_time_sync_gm_clock_time_property_flags_leap59;
static int hf_time_sync_gm_clock_time_property_flags_current_utc_valid;
static int hf_time_sync_gm_clock_time_property_flags_ptp_timescale;
static int hf_time_sync_gm_clock_time_property_flags_time_traceable;
static int hf_time_sync_gm_clock_time_property_flags_freq_traceable;
static int hf_time_sync_gm_clock_time_source;
static int hf_time_sync_gm_clock_priority1;
static int hf_time_sync_gm_clock_priority2;
static int hf_time_sync_parent_clock_clock_id;
static int hf_time_sync_parent_clock_port_number;
static int hf_time_sync_parent_clock_observed_offset_scaled_log_variance;
static int hf_time_sync_parent_clock_observed_phase_change_rate;
static int hf_time_sync_local_clock_clock_id;
static int hf_time_sync_local_clock_clock_class;
static int hf_time_sync_local_clock_time_accuracy;
static int hf_time_sync_local_clock_offset_scaled_log_variance;
static int hf_time_sync_local_clock_current_utc_offset;
static int hf_time_sync_local_clock_time_property_flags;
static int hf_time_sync_local_clock_time_property_flags_leap61;
static int hf_time_sync_local_clock_time_property_flags_leap59;
static int hf_time_sync_local_clock_time_property_flags_current_utc_valid;
static int hf_time_sync_local_clock_time_property_flags_ptp_timescale;
static int hf_time_sync_local_clock_time_property_flags_time_traceable;
static int hf_time_sync_local_clock_time_property_flags_freq_traceable;
static int hf_time_sync_local_clock_time_source;
static int hf_time_sync_num_ports;
static int hf_time_sync_port_state_info_num_ports;
static int hf_time_sync_port_state_info_port_num;
static int hf_time_sync_port_state_info_port_state;
static int hf_time_sync_port_enable_cfg_num_ports;
static int hf_time_sync_port_enable_cfg_port_num;
static int hf_time_sync_port_enable_cfg_port_enable;
static int hf_time_sync_port_log_announce_num_ports;
static int hf_time_sync_port_log_announce_port_num;
static int hf_time_sync_port_log_announce_interval;
static int hf_time_sync_port_log_sync_num_ports;
static int hf_time_sync_port_log_sync_port_num;
static int hf_time_sync_port_log_sync_port_log_sync_interval;
static int hf_time_sync_priority1;
static int hf_time_sync_priority2;
static int hf_time_sync_domain_number;
static int hf_time_sync_clock_type;
static int hf_time_sync_clock_type_ordinary;
static int hf_time_sync_clock_type_boundary;
static int hf_time_sync_clock_type_end_to_end;
static int hf_time_sync_clock_type_management;
static int hf_time_sync_clock_type_slave_only;
static int hf_time_sync_manufacture_id_oui;
static int hf_time_sync_manufacture_id_reserved;
static int hf_time_sync_prod_desc_size;
static int hf_time_sync_prod_desc_str;
static int hf_time_sync_revision_data_size;
static int hf_time_sync_revision_data_str;
static int hf_time_sync_user_desc_size;
static int hf_time_sync_user_desc_str;
static int hf_time_sync_port_profile_id_info_num_ports;
static int hf_time_sync_port_profile_id_info_port_num;
static int hf_time_sync_port_profile_id_info_profile_id;
static int hf_time_sync_port_phys_addr_info_num_ports;
static int hf_time_sync_port_phys_addr_info_port_num;
static int hf_time_sync_port_phys_addr_info_phys_proto;
static int hf_time_sync_port_phys_addr_info_addr_size;
static int hf_time_sync_port_phys_addr_info_phys_addr;
static int hf_time_sync_port_proto_addr_info_num_ports;
static int hf_time_sync_port_proto_addr_info_port_num;
static int hf_time_sync_port_proto_addr_info_network_proto;
static int hf_time_sync_port_proto_addr_info_addr_size;
static int hf_time_sync_port_proto_addr_info_port_proto_addr;
static int hf_time_sync_steps_removed;
static int hf_time_sync_sys_time_and_offset_time;
static int hf_time_sync_sys_time_and_offset_offset;
static int hf_port_entry_port;
static int hf_port_type;
static int hf_port_number;
static int hf_port_min_node_num;
static int hf_port_max_node_num;
static int hf_port_name;
static int hf_port_num_comm_object_entries;
static int hf_path_len_usint;
static int hf_path_len_uint;

static int hf_32bitheader;
static int hf_32bitheader_roo;
static int hf_32bitheader_coo;
static int hf_32bitheader_run_idle;

static int hf_cip_connection;
static int hf_cip_fwd_open_in;
static int hf_cip_fwd_close_in;

/* Initialize the subtree pointers */
static int ett_cip;
static int ett_cip_class_generic;
static int ett_cip_class_cm;
static int ett_cip_class_pccc;
static int ett_cip_class_mb;
static int ett_cip_class_cco;

static int ett_path;
static int ett_path_seg;
static int ett_mcsc;
static int ett_cia_path;
static int ett_data_seg;
static int ett_port_path;
static int ett_network_seg;
static int ett_network_seg_safety;
static int ett_network_seg_safety_time_correction_net_params;
static int ett_cip_seg_safety_tunid;
static int ett_cip_seg_safety_tunid_snn;
static int ett_cip_seg_safety_ounid;
static int ett_cip_seg_safety_ounid_snn;

static int ett_rrsc;
static int ett_status_item;
static int ett_add_status_item;
static int ett_cmd_data;

static int ett_cip_get_attributes_all_item;
static int ett_cip_get_attribute_list;
static int ett_cip_get_attribute_list_item;
static int ett_cip_set_attribute_list;
static int ett_cip_set_attribute_list_item;
static int ett_cip_mult_service_packet;
static int ett_cip_msp_offset;

static int ett_cm_rrsc;
static int ett_cm_ncp;
static int ett_cm_mes_req;
static int ett_cm_cmd_data;
static int ett_cm_ttt;
static int ett_cm_add_status_item;
static int ett_cip_cm_pid;
static int ett_cip_cm_safety;

static int ett_pccc_rrsc;
static int ett_pccc_req_id;
static int ett_pccc_cmd_data;

static int ett_mb_rrsc;
static int ett_mb_cmd_data;

static int ett_cco_iomap;
static int ett_cco_con_status;
static int ett_cco_con_flag;
static int ett_cco_tdi;
static int ett_cco_pdi;
static int ett_cco_ncp;
static int ett_cco_rrsc;
static int ett_cco_cmd_data;
static int ett_cco_ttt;

static int ett_time_sync_gm_clock_flags;
static int ett_time_sync_local_clock_flags;
static int ett_time_sync_port_state_info;
static int ett_time_sync_port_enable_cfg;
static int ett_time_sync_port_log_announce;
static int ett_time_sync_port_log_sync;
static int ett_time_sync_clock_type;
static int ett_time_sync_port_profile_id_info;
static int ett_time_sync_port_phys_addr_info;
static int ett_time_sync_port_proto_addr_info;
static int ett_id_status;
static int ett_32bitheader_tree;

static int ett_connection_info;

static expert_field ei_mal_identity_revision;
static expert_field ei_mal_identity_status;
static expert_field ei_mal_msg_rout_num_classes;
static expert_field ei_mal_time_sync_gm_clock;
static expert_field ei_mal_time_sync_parent_clock;
static expert_field ei_mal_time_sync_local_clock;
static expert_field ei_mal_time_sync_port_state_info;
static expert_field ei_mal_time_sync_port_state_info_ports;
static expert_field ei_mal_time_sync_port_enable_cfg;
static expert_field ei_mal_time_sync_port_enable_cfg_ports;
static expert_field ei_mal_time_sync_port_log_announce;
static expert_field ei_mal_time_sync_port_log_announce_ports;
static expert_field ei_mal_time_sync_port_log_sync;
static expert_field ei_mal_time_sync_port_log_sync_ports;
static expert_field ei_mal_time_sync_clock_type;
static expert_field ei_mal_time_sync_manufacture_id;
static expert_field ei_mal_time_sync_prod_desc;
static expert_field ei_mal_time_sync_prod_desc_64;
static expert_field ei_mal_time_sync_prod_desc_size;
static expert_field ei_mal_time_sync_revision_data;
static expert_field ei_mal_time_sync_revision_data_32;
static expert_field ei_mal_time_sync_revision_data_size;
static expert_field ei_mal_time_sync_user_desc;
static expert_field ei_mal_time_sync_user_desc_128;
static expert_field ei_mal_time_sync_user_desc_size;
static expert_field ei_mal_time_sync_port_profile_id_info;
static expert_field ei_mal_time_sync_port_profile_id_info_ports;
static expert_field ei_mal_time_sync_port_phys_addr_info;
static expert_field ei_mal_time_sync_port_phys_addr_info_ports;
static expert_field ei_mal_time_sync_port_proto_addr_info;
static expert_field ei_mal_time_sync_port_proto_addr_info_ports;
static expert_field ei_mal_time_sync_sys_time_and_offset;
static expert_field ei_proto_log_seg_format;
static expert_field ei_mal_incomplete_epath;
static expert_field ei_proto_electronic_key_format;
static expert_field ei_proto_special_segment_format;
static expert_field ei_proto_log_seg_type;
static expert_field ei_proto_log_sub_seg_type;
static expert_field ei_proto_ext_string_format;
static expert_field ei_proto_ext_network;
static expert_field ei_proto_seg_type;
static expert_field ei_proto_unsupported_datatype;
static expert_field ei_mal_serv_gal;
static expert_field ei_mal_serv_gal_count;
static expert_field ei_mal_serv_sal;
static expert_field ei_mal_serv_sal_count;
static expert_field ei_mal_msp_services;
static expert_field ei_mal_msp_inv_offset;
static expert_field ei_mal_msp_missing_services;
static expert_field ei_mal_serv_find_next_object;
static expert_field ei_mal_serv_find_next_object_count;
static expert_field ei_mal_rpi_no_data;
static expert_field ei_mal_fwd_close_missing_data;
static expert_field ei_mal_opt_attr_list;
static expert_field ei_mal_opt_service_list;
static expert_field ei_mal_padded_epath_size;
static expert_field ei_mal_missing_string_data;

static expert_field ei_cip_null_fwd_open;
static expert_field ei_cip_safety_open_type1;
static expert_field ei_cip_safety_open_type2a;
static expert_field ei_cip_safety_open_type2b;
static expert_field ei_cip_no_fwd_close;
static expert_field ei_cip_safety_input;
static expert_field ei_cip_safety_output;
static expert_field ei_cip_listen_input_connection;

//// Concurrent Connections
static int hf_cip_cm_cc_version;

static int hf_cip_cc_packet_length;
static int hf_cip_cc_packet_options;
static int hf_cip_cc_packet_type;
static int hf_cip_cc_packet_keepalive;
static int hf_cip_cc_packet_keepalive_hop_count;
static int hf_cip_cc_packet_reserved;
static int hf_cip_cc_packet_seq_number;
static int hf_cip_cc_crc;

// Parameters for Concurrent Extended Network Segment
static int hf_ext_net_seg_hops_count;
static int hf_ext_net_seg_length;
static int hf_ext_net_seg_hop;
static int hf_ext_net_seg_hop_egress_cip_port;
static int hf_ext_net_seg_hop_link_adr_type;
static int hf_ext_net_seg_hop_number_of_linkadr;
static int hf_ext_net_seg_link_address;
static int hf_ext_net_seg_link_ipv4;
static int hf_ext_net_seg_link_hostname;

static int proto_cc;

/* Define the tree for the frame */
static int ett_cc_header;
static int ett_cc_hop;

static expert_field ei_cc_invalid_header_type;

static const value_string cc_link_adr_type[] = {
    { 0, "8-bit numeric link addresses" },
    { 1, "IPv4 addresses" },
    { 2, "Hostnames" },

    { 0, NULL }
};

static const value_string cc_packet_type_vals[] = {
    { 0, "Invalid" },
    { 1, "Concurrent Connection Packet Format" },

    { 0, NULL }
};

static int* ett_cc[] =
{
    &ett_cc_header,
    &ett_cc_hop,
};

static dissector_table_t   subdissector_class_table;
static dissector_table_t   subdissector_symbol_table;

/* Translate function to string - CIP Service codes */
static const value_string cip_sc_vals[] = {
   GENERIC_SC_LIST

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for CM */
static const value_string cip_sc_vals_cm[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_CM_FWD_CLOSE,            "Forward Close" },
   { SC_CM_FWD_OPEN,             "Forward Open" },
   { SC_CM_UNCON_SEND,           "Unconnected Send" },
   { SC_CM_LARGE_FWD_OPEN,       "Large Forward Open" },
   { SC_CM_GET_CONN_DATA,        "Get Connection Data" },
   { SC_CM_SEARCH_CONN_DATA,     "Search Connection Data" },
   { SC_CM_GET_CONN_OWNER,       "Get Connection Owner" },
   { SC_CM_CONCURRENT_FWD_OPEN,  "Concurrent Forward Open" },
   { SC_CM_CONCURRENT_FWD_CLOSE, "Concurrent Forward Close" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for PCCC */
static const value_string cip_sc_vals_pccc[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_PCCC_EXECUTE_PCCC,     "Execute PCCC" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for MB */
static const value_string cip_sc_vals_mb[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_MB_READ_DISCRETE_INPUTS,    "Read Discrete" },
   { SC_MB_READ_COILS,              "Read Coils" },
   { SC_MB_READ_INPUT_REGISTERS,    "Read Input Registers" },
   { SC_MB_READ_HOLDING_REGISTERS,  "Read Holding Registers" },
   { SC_MB_WRITE_COILS,             "Write Coils" },
   { SC_MB_WRITE_HOLDING_REGISTERS, "Write Holding Registers" },
   { SC_MB_PASSTHROUGH,             "Modbus Passthrough" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for CCO */
static const value_string cip_sc_vals_cco[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_CCO_KICK_TIMER,           "Kick Timer" },
   { SC_CCO_OPEN_CONN,            "Open Connection" },
   { SC_CCO_CLOSE_CONN,           "Close Connection" },
   { SC_CCO_STOP_CONN,            "Stop Connection" },
   { SC_CCO_CHANGE_START,         "Change Start" },
   { SC_CCO_GET_STATUS,           "Get Status" },
   { SC_CCO_CHANGE_COMPLETE,      "Change Complete" },
   { SC_CCO_AUDIT_CHANGE,         "Audit Changes" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Request/Response */
const value_string cip_sc_rr[] = {
   { 0,        "Request"  },
   { 1,        "Response" },

   { 0,        NULL }
};

/* Translate function to string - Compatibility */
static const value_string cip_com_bit_vals[] = {
   { 0,        "Bit Cleared" },
   { 1,        "Bit Set"     },

   { 0,        NULL          }
};

const value_string cip_reset_type_vals[] = {
   { 0,        "Cycle Power" },
   { 1,        "Factory Default" },
   { 2,        "Keep Communication Parameters" },

   { 0,        NULL          }
};

/* Translate function to string - Connection priority */
const value_string cip_con_prio_vals[] = {
   { 0,        "Low Priority"  },
   { 1,        "High Priority" },
   { 2,        "Scheduled"     },
   { 3,        "Urgent"        },

   { 0,        NULL            }
};

/* Translate function to string - Connection size fixed or variable */
static const value_string cip_con_fw_vals[] = {
   { 0,        "Fixed"    },
   { 1,        "Variable" },

   { 0,        NULL       }
};

/* Translate function to string - Connection owner */
static const value_string cip_con_owner_vals[] = {
   { 0,        "Non-Redundant" },
   { 1,        "Redundant" },

   { 0,        NULL        }
};

/* Translate function to string - Connection type*/
static const value_string cip_con_vals[] = {
   { 0,        "Originator" },
   { 1,        "Target" },

   { 0,        NULL        }
};

/* Translate function to string - Production trigger */
static const value_string cip_con_trigg_vals[] = {
   { 0,        "Cyclic" },
   { 1,        "Change-Of-State" },
   { 2,        "Application Object" },

   { 0,        NULL        }
};

/* Translate function to string - Transport class */
static const value_string cip_con_class_vals[] = {
   { 0,        "0" },
   { 1,        "1" },
   { 2,        "2" },
   { 3,        "3" },

   { 0,        NULL        }
};

/* Translate function to string - Connection type */
const value_string cip_con_type_vals[] = {
   { CONN_TYPE_NULL,        "Null"           },
   { CONN_TYPE_MULTICAST,   "Multicast"      },
   { CONN_TYPE_P2P,         "Point to Point" },
   { CONN_TYPE_RESERVED,    "Reserved"       },

   { 0,        NULL             }
};

/* Translate function to string - Timeout Multiplier */
const value_string cip_con_time_mult_vals[] = {
   { 0,        "*4"   },
   { 1,        "*8"   },
   { 2,        "*16"  },
   { 3,        "*32"  },
   { 4,        "*64"  },
   { 5,        "*128" },
   { 6,        "*256" },
   { 7,        "*512" },

   { 0,        NULL    }
};

/* Translate function to string - Connection Last Action */
static const value_string cip_con_last_action_vals[] = {
   { 0,        "No Owner"           },
   { 1,        "Owner Is Idle Mode" },
   { 2,        "Owner Is Run Mode"  },
   { 255,      "Implementation not supported" },

   { 0,        NULL             }
};

/* Translate function to string - real time transfer format type */
static const value_string cip_con_rtf_vals[] = {
   { 0,        "32-bit Header"  },
   { 1,        "Zero data length idle mode"},
   { 2,        "Modeless"  },
   { 3,        "Heartbeat"  },
   { 5,        "Safety"  },

   { 0,        NULL             }
};

/* Translate function to string - CCO change type */
static const value_string cip_cco_change_type_vals[] = {
   { 0,        "Full"           },
   { 1,        "Incremental"    },

   { 0,        NULL             }
};

static const value_string cip_time_sync_clock_class_vals[] = {
   { 6,        "Primary Reference"          },
   { 7,        "Primary Reference (Hold)"   },
   { 52,       "Degraded Reference A (Master only)"  },
   { 187,      "Degraded Reference B (Master/Slave)" },
   { 248,      "Default"                    },
   { 255,      "Slave Only"                 },

   { 0,        NULL             }
};

static const value_string cip_time_sync_time_accuracy_vals[] = {
   { 0x20,   "Accurate to within 25ns"  },
   { 0x21,   "Accurate to within 100ns" },
   { 0x22,   "Accurate to within 250ns" },
   { 0x23,   "Accurate to within 1us"   },
   { 0x24,   "Accurate to within 2.5us" },
   { 0x25,   "Accurate to within 10us"  },
   { 0x26,   "Accurate to within 25us"  },
   { 0x27,   "Accurate to within 100us" },
   { 0x28,   "Accurate to within 250us" },
   { 0x29,   "Accurate to within 1ms"   },
   { 0x2A,   "Accurate to within 2.5ms" },
   { 0x2B,   "Accurate to within 10ms"  },
   { 0x2C,   "Accurate to within 25ms"  },
   { 0x2D,   "Accurate to within 100ms" },
   { 0x2E,   "Accurate to within 250ms" },
   { 0x2F,   "Accurate to within 1s"    },
   { 0x30,   "Accurate to within 10s"   },
   { 0x31,   "Accurate to >10s"         },
   { 0,      NULL             }
};

static const value_string cip_time_sync_time_source_vals[] = {
   { 0x10,   "Atomic Clock"        },
   { 0x20,   "GPS"                 },
   { 0x30,   "Terrestrial Radio"   },
   { 0x40,   "PTP"                 },
   { 0x50,   "NTP"                 },
   { 0x60,   "Hand Set"            },
   { 0x90,   "Other"               },
   { 0xA0,   "Internal Oscillator" },
   { 0,      NULL             }
};

static const value_string cip_time_sync_port_state_vals[] = {
   { 1,      "INITIALIZING" },
   { 2,      "FAULTY"       },
   { 3,      "DISABLED"     },
   { 4,      "LISTENING"    },
   { 5,      "PRE_MASTER"   },
   { 6,      "MASTER"       },
   { 7,      "PASSIVE"      },
   { 8,      "UNCALIBRATED" },
   { 9,      "SLAVE"        },
   { 0,      NULL           }
};

static const value_string cip_time_sync_network_protocol_vals[] = {
   { 1,      "UDP/IPv4"     },
   { 2,      "UDP/IPv6"     },
   { 3,      "IEEE 802.3"   },
   { 4,      "DeviceNet"    },
   { 5,      "ControlNet"   },
   { 0xFFFF, "Local or Unknown protocol"   },
   { 0,      NULL           }
};

static const value_string cip_path_seg_vals[] = {
   { ((CI_PORT_SEGMENT>>5)&7),       "Port Segment" },
   { ((CI_LOGICAL_SEGMENT>>5)&7),    "Logical Segment" },
   { ((CI_NETWORK_SEGMENT>>5)&7),    "Network Segment" },
   { ((CI_SYMBOLIC_SEGMENT>>5)&7),   "Symbolic Segment" },
   { ((CI_DATA_SEGMENT>>5)&7),       "Data Segment" },
   { 5,             "Constructed Data Type" },
   { 6,             "Elementary Data Type" },
   { 7,             "Reserved" },

   { 0,                          NULL }
};

static const value_string cip_logical_segment_type_vals[] = {
   { ((CI_LOGICAL_SEG_CLASS_ID>>2)&7),      "Class ID" },
   { ((CI_LOGICAL_SEG_INST_ID>>2)&7),       "Instance ID" },
   { ((CI_LOGICAL_SEG_MBR_ID>>2)&7),        "Member ID" },
   { ((CI_LOGICAL_SEG_CON_POINT>>2)&7),     "Connection Point" },
   { ((CI_LOGICAL_SEG_ATTR_ID>>2)&7),       "Attribute ID" },
   { ((CI_LOGICAL_SEG_SPECIAL>>2)&7),       "Special" },
   { ((CI_LOGICAL_SEG_SERV_ID>>2)&7),       "Service ID" },
   { ((CI_LOGICAL_SEG_EXT_LOGICAL>>2)&7),   "Extended Logical" },

   { 0,                          NULL }
};

static const value_string cip_logical_segment_format_vals[] = {
   { CI_LOGICAL_SEG_8_BIT,           "8-bit Logical Segment" },
   { CI_LOGICAL_SEG_16_BIT,          "16-bit Logical Segment" },
   { CI_LOGICAL_SEG_32_BIT,          "32-bit Logical Segment" },
   { CI_LOGICAL_SEG_RES_2,           "Reserved" },

   { 0,                          NULL }
};

static const value_string cip_logical_seg_vals[] = {
   {((CI_LOGICAL_SEG_CLASS_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_8_BIT), "8-Bit Class Segment"},
   {((CI_LOGICAL_SEG_CLASS_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_16_BIT), "16-Bit Class Segment"},
   {((CI_LOGICAL_SEG_CLASS_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_32_BIT), "32-Bit Class Segment"},

   {((CI_LOGICAL_SEG_INST_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_8_BIT), "8-Bit Instance Segment"},
   {((CI_LOGICAL_SEG_INST_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_16_BIT), "16-Bit Instance Segment"},
   {((CI_LOGICAL_SEG_INST_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_32_BIT), "32-Bit Instance Segment"},

   {((CI_LOGICAL_SEG_MBR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_8_BIT), "8-Bit Member Segment"},
   {((CI_LOGICAL_SEG_MBR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_16_BIT), "16-Bit Member Segment"},
   {((CI_LOGICAL_SEG_MBR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_32_BIT), "32-Bit Member Segment"},

   {((CI_LOGICAL_SEG_CON_POINT & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_8_BIT), "8-Bit Connection Point Segment"},
   {((CI_LOGICAL_SEG_CON_POINT & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_16_BIT), "16-Bit Connection Point Segment"},
   {((CI_LOGICAL_SEG_CON_POINT & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_32_BIT), "32-Bit Connection Point Segment"},

   {((CI_LOGICAL_SEG_ATTR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_8_BIT), "8-Bit Attribute Segment"},
   {((CI_LOGICAL_SEG_ATTR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_16_BIT), "16-Bit Attribute Segment"},
   {((CI_LOGICAL_SEG_ATTR_ID & CI_LOGICAL_SEG_TYPE_MASK)|CI_LOGICAL_SEG_32_BIT), "32-Bit Attribute Segment"},

   {((CI_LOGICAL_SEG_SERV_ID & CI_LOGICAL_SEG_TYPE_MASK) | CI_LOGICAL_SEG_8_BIT), "8-Bit Service ID Segment"},

   {CI_LOGICAL_SEG_SPECIAL, "Electronic Key Segment"},

   {((CI_LOGICAL_SEG_EXT_LOGICAL & CI_LOGICAL_SEG_TYPE_MASK) | CI_LOGICAL_SEG_8_BIT), "8-Bit Extended Logical Segment"},
   {((CI_LOGICAL_SEG_EXT_LOGICAL & CI_LOGICAL_SEG_TYPE_MASK) | CI_LOGICAL_SEG_16_BIT), "16-Bit Extended Logical Segment"},
   {((CI_LOGICAL_SEG_EXT_LOGICAL & CI_LOGICAL_SEG_TYPE_MASK) | CI_LOGICAL_SEG_32_BIT), "32-Bit Extended Logical Segment"},

   { 0,                          NULL }
};

static const value_string cip_ext_logical_segment_format_vals[] = {
    { 0,          "Reserved" },
    { 1,          "Array Index" },
    { 2,          "Indirect Array Index" },
    { 3,          "Bit Index" },
    { 4,          "Indirect Bit Index" },
    { 5,          "Structure Member Number" },
    { 6,          "Structure Member Handle" },

    { 0,                          NULL }
};

static const value_string cip_data_segment_type_vals[] = {
   {CI_DATA_SEG_SIMPLE, "Simple Data Segment"},
   {CI_DATA_SEG_SYMBOL, "ANSI Extended Symbol Segment"},

   { 0,                          NULL }
};

static const value_string cip_network_segment_type_vals[] = {
   {CI_NETWORK_SEG_SCHEDULE,     "Schedule Segment"},
   {CI_NETWORK_SEG_FIXED_TAG,    "Fixed Tag Segment"},
   {CI_NETWORK_SEG_PROD_INHI,    "Production Inhibit Time in Milliseconds"},
   {CI_NETWORK_SEG_SAFETY,       "Safety Segment"},
   {CI_NETWORK_SEG_PROD_INHI_US, "Production Inhibit Time in Microseconds"},
   {CI_NETWORK_SEG_EXTENDED,     "Extended Network Segment"},

   { 0,                          NULL }
};

static const value_string cip_symbolic_format_vals[] = {
    { 1,          "Double Byte Segment" },
    { 2,          "Triple Byte Segment" },
    { 6,          "Numeric Segment" },

    { 0,          NULL }
};

static const value_string cip_symbolic_numeric_format_vals[] = {
    { 6,          "USINT" },
    { 7,          "UINT" },
    { 8,          "UDINT" },

    { 0,          NULL }
};

static const value_string cip_safety_segment_format_type_vals[] = {
   {0,    "Target Format"},
   {1,    "Router Format"},
   {2,    "Extended Format"},

   { 0,                          NULL }
};

static const value_string cip_cm_rpi_type_vals[] = {
   {0,   "RPI acceptable"},
   {1,   "Unspecified"},
   {2,   "Minimum acceptable RPI"},
   {3,   "Maximum acceptable RPI"},
   {4,   "Required RPI to correct mismatch"},

   { 0,                          NULL }
};

/* Translate function to string - CIP General Status codes */
static const value_string cip_gs_vals[] = {
   { CI_GRC_SUCCESS,             "Success" },
   { CI_GRC_FAILURE,             "Connection failure" },
   { CI_GRC_NO_RESOURCE,         "Resource unavailable" },
   { CI_GRC_BAD_DATA,            "Invalid parameter value" },
   { CI_GRC_BAD_PATH,            "Path segment error" },
   { CI_GRC_BAD_CLASS_INSTANCE,  "Path destination unknown" },
   { CI_GRC_PARTIAL_DATA,        "Partial transfer" },
   { CI_GRC_CONN_LOST,           "Connection lost" },
   { CI_GRC_BAD_SERVICE,         "Service not supported" },
   { CI_GRC_BAD_ATTR_DATA,       "Invalid attribute value" },
   { CI_GRC_ATTR_LIST_ERROR,     "Attribute list error" },
   { CI_GRC_ALREADY_IN_MODE,     "Already in requested mode/state" },
   { CI_GRC_BAD_OBJ_MODE,        "Object state conflict" },
   { CI_GRC_OBJ_ALREADY_EXISTS,  "Object already exists" },
   { CI_GRC_ATTR_NOT_SETTABLE,   "Attribute not settable" },
   { CI_GRC_PERMISSION_DENIED,   "Privilege violation" },
   { CI_GRC_DEV_IN_WRONG_STATE,  "Device state conflict" },
   { CI_GRC_REPLY_DATA_TOO_LARGE,"Reply data too large" },
   { CI_GRC_FRAGMENT_PRIMITIVE,  "Fragmentation of a primitive value" },
   { CI_GRC_CONFIG_TOO_SMALL,    "Not enough data" },
   { CI_GRC_UNDEFINED_ATTR,      "Attribute not supported" },
   { CI_GRC_CONFIG_TOO_BIG,      "Too much data" },
   { CI_GRC_OBJ_DOES_NOT_EXIST,  "Object does not exist" },
   { CI_GRC_NO_FRAGMENTATION,    "Service fragmentation sequence not in progress" },
   { CI_GRC_DATA_NOT_SAVED,      "No stored attribute data" },
   { CI_GRC_DATA_WRITE_FAILURE,  "Store operation failure" },
   { CI_GRC_REQUEST_TOO_LARGE,   "Routing failure, request packet too large" },
   { CI_GRC_RESPONSE_TOO_LARGE,  "Routing failure, response packet too large" },
   { CI_GRC_MISSING_LIST_DATA,   "Missing attribute list entry data" },
   { CI_GRC_INVALID_LIST_STATUS, "Invalid attribute value list" },
   { CI_GRC_SERVICE_ERROR,       "Embedded service error" },
   { CI_GRC_CONN_RELATED_FAILURE,"Vendor specific error" },
   { CI_GRC_INVALID_PARAMETER,   "Invalid parameter" },
   { CI_GRC_WRITE_ONCE_FAILURE,  "Write-once value or medium already written" },
   { CI_GRC_INVALID_REPLY,       "Invalid reply received" },
   { CI_GRC_BUFFER_OVERFLOW,     "Buffer overflow" },
   { CI_GRC_MESSAGE_FORMAT,      "Invalid message format" },
   { CI_GRC_BAD_KEY_IN_PATH,     "Key failure in path" },
   { CI_GRC_BAD_PATH_SIZE,       "Path size invalid" },
   { CI_GRC_UNEXPECTED_ATTR,     "Unexpected attribute in list" },
   { CI_GRC_INVALID_MEMBER,      "Invalid Member ID" },
   { CI_GRC_MEMBER_NOT_SETTABLE, "Member not settable" },
   { CI_GRC_G2_SERVER_FAILURE,   "Group 2 only server general failure" },
   { CI_GRC_UNKNOWN_MB_ERROR,    "Unknown Modbus error" },
   { CI_GRC_ATTRIBUTE_NOT_GET,   "Attribute not gettable" },

   { 0,                          NULL }
};

value_string_ext cip_gs_vals_ext = VALUE_STRING_EXT_INIT(cip_gs_vals);

/* Connection Manager Extended Status codes */
#define CM_ES_DUP_FWD_OPEN                            0x100
#define CM_ES_CLASS_AND_TRIGGER                       0x103
#define CM_ES_OWNERSHIP_CONFLICT                      0x106
#define CM_ES_TARGET_CONN_NOT_FOUND                   0x107
#define CM_ES_INVALID_NET_CONN_PARAM                  0x108
#define CM_ES_INVALID_CONNECTION_SIZE                 0x109
#define CM_ES_TARGET_CONNECTION_NOT_CONFIGURED        0x110
#define CM_ES_RPI_NOT_SUPPORTED                       0x111
#define CM_ES_RPI_NOT_ACCEPTABLE                      0x112
#define CM_ES_OUT_OF_CONNECTIONS                      0x113
#define CM_ES_VENDOR_ID_OR_PRODUCT_CODE_MISMATCH      0x114
#define CM_ES_DEVICE_TYPE_MISMATCH                    0x115
#define CM_ES_REVISION_MISMATCH                       0x116
#define CM_ES_INVALID_PROD_CONS_APP_PATH              0x117
#define CM_ES_INVALID_OR_INCONSISTENT_CONF_APP_PATH   0x118
#define CM_ES_NON_LISTEN_ONLY_CONN_NOT_OPENED         0x119
#define CM_ES_TARGET_OBJECT_OUT_OF_CONNECTIONS        0x11A
#define CM_ES_RPI_SMALLER_THAN_PROD_INHIBIT_TIME      0x11B
#define CM_ES_TRANSPORT_CLASS_NOT_SUPPORTED           0x11C
#define CM_ES_PRODUCTION_TRIGGER_NOT_SUPPORTED        0x11D
#define CM_ES_DIRECTION_NOT_SUPPORTED                 0x11E
#define CM_ES_INVALID_OT_NET_CONN_FIX_VAR             0x11F
#define CM_ES_INVALID_TO_NET_CONN_FIX_VAR             0x120
#define CM_ES_INVALID_OT_NET_CONN_PRIORITY            0x121
#define CM_ES_INVALID_TO_NET_CONN_PRIORITY            0x122
#define CM_ES_INVALID_OT_NET_CONN_TYPE                0x123
#define CM_ES_INVALID_TO_NET_CONN_TYPE                0x124
#define CM_ES_INVALID_OT_NET_CONN_REDUNDANT_OWNER     0x125
#define CM_ES_INVALID_CONFIGURATION_SIZE              0x126
#define CM_ES_INVALID_OT_SIZE                         0x127
#define CM_ES_INVALID_TO_SIZE                         0x128
#define CM_ES_INVALID_CONFIGURATION_APP_PATH          0x129
#define CM_ES_INVALID_CONSUMING_APP_PATH              0x12A
#define CM_ES_INVALID_PRODUCING_APP_PATH              0x12B
#define CM_ES_CONFIGURATION_SYMBOL_NOT_EXIST          0x12C
#define CM_ES_CONSUMING_SYMBOL_NOT_EXIST              0x12D
#define CM_ES_PRODUCING_SYMBOL_NOT_EXIST              0x12E
#define CM_ES_INCONSISTENT_APP_PATH_COMBO             0x12F
#define CM_ES_INCONSISTENT_CONSUME_DATA_FORMAT        0x130
#define CM_ES_INCONSISTENT_PRODUCE_DATA_FORMAT        0x131
#define CM_ES_NULL_FORWARD_OPEN_NOT_SUPPORTED         0x132
#define CM_ES_CONNECTION_TIMED_OUT                    0x203
#define CM_ES_UNCONNECTED_REQUEST_TIMED_OUT           0x204
#define CM_ES_PARAMETER_ERROR_IN_UNCONNECTED_REQUEST  0x205
#define CM_ES_MESSAGE_TOO_LARGE_FOR_UNCONNECTED_SEND  0x206
#define CM_ES_UNCONNECTED_ACK_WITHOUT_REPLY           0x207
#define CM_ES_NO_BUFFER_MEMORY_AVAILABLE              0x301
#define CM_ES_NETWORK_BANDWIDTH_NOT_AVAIL_FOR_DATA    0x302
#define CM_ES_NO_CONSUMED_CONN_ID_FILTER_AVAILABLE    0x303
#define CM_ES_NOT_CONFIGURED_TO_SEND_SCHEDULED_DATA   0x304
#define CM_ES_SCHEDULE_SIGNATURE_MISMATCH             0x305
#define CM_ES_SCHEDULE_SIGNATURE_VALIDATION_NOT_POSS  0x306
#define CM_ES_PORT_NOT_AVAILABLE                      0x311
#define CM_ES_LINK_ADDRESS_NOT_VALID                  0x312
#define CM_ES_INVALID_SEGMENT_IN_CONN_PATH            0x315
#define CM_ES_FWD_CLOSE_CONN_PATH_MISMATCH            0x316
#define CM_ES_SCHEDULING_NOT_SPECIFIED                0x317
#define CM_ES_LINK_ADDRESS_TO_SELF_INVALID            0x318
#define CM_ES_SECONDARY_RESOURCES_UNAVAILABLE         0x319
#define CM_ES_RACK_CONNECTION_ALREADY_ESTABLISHED     0x31A
#define CM_ES_MODULE_CONNECTION_ALREADY_ESTABLISHED   0x31B
#define CM_ES_MISCELLANEOUS                           0x31C
#define CM_ES_REDUNDANT_CONNECTION_MISMATCH           0x31D
#define CM_ES_NO_CONSUMER_RES_AVAIL_IN_PROD_MODULE    0x31E
#define CM_ES_NO_CONSUMER_RES_CONF_IN_PROD_MODULE     0x31F
#define CM_ES_NETWORK_LINK_OFFLINE                    0x800
#define CM_ES_INCOMPATIBLE_MULTICAST_RPI              0x801
#define CM_ES_INVALID_SAFETY_CONN_SIZE                0x802
#define CM_ES_INVALID_SAFETY_CONN_FORMAT              0x803
#define CM_ES_INVALID_TIME_CORRECTION_CONN_PARAM      0x804
#define CM_ES_INVALID_PING_INTERVAL_EPI_MULTIPLIER    0x805
#define CM_ES_TIME_COORDINATION_MSG_MIN_MULTIPLIER    0x806
#define CM_ES_NETWORK_TIME_EXPECTATION_MULTIPLIER     0x807
#define CM_ES_TIMEOUT_MULTIPLIER                      0x808
#define CM_ES_INVALID_MAX_CONSUMER_NUMBER             0x809
#define CM_ES_INVALID_CPCRC                           0x80A
#define CM_ES_TIME_CORRECTION_CONN_ID_INVALID         0x80B
#define CM_ES_SCID_MISMATCH                           0x80C
#define CM_ES_TUNID_NOT_SET                           0x80D
#define CM_ES_TUNID_MISMATCH                          0x80E
#define CM_ES_CONFIGURATION_OPERATION_NOT_ALLOWED     0x80F
#define CM_ES_NO_TARGET_APP_DATA_AVAILABLE            0x810
#define CM_ES_NO_ORIG_APP_DATA_AVAILABLE              0x811
#define CM_ES_NODE_ADDRESS_CHANGED_AFTER_SCHEDULED    0x812
#define CM_ES_NOT_CONFIGURED_MULTICAST                0x813
#define CM_ES_INVALID_PROD_CONS_DATA_FORMAT           0x814
#define CM_ES_EGRESS_RULE_DENY                        0x916
#define CM_ES_EGRESS_RULE_CIPHER_NOT_ALLOWED          0x917
#define CM_ES_NO_MATCHING_INGRESS_RULE                0x918
#define CM_ES_INGRESS_RULE_DENY                       0x919
#define CM_ES_INGRESS_RULE_DENY_NON_SECURE            0x91A
#define CM_ES_NO_MATCHING_EGRESS_RULE                 0x91B

/* Translate function to string - CIP Extended Status codes */
static const value_string cip_cm_ext_st_vals[] = {
   { CM_ES_DUP_FWD_OPEN,                           "Connection in use or duplicate Forward Open" },
   { CM_ES_CLASS_AND_TRIGGER,                      "Transport class and trigger combination not supported" },
   { CM_ES_OWNERSHIP_CONFLICT,                     "Ownership conflict" },
   { CM_ES_TARGET_CONN_NOT_FOUND,                  "Target connection not found" },
   { CM_ES_INVALID_NET_CONN_PARAM,                 "Invalid network connection parameter" },
   { CM_ES_INVALID_CONNECTION_SIZE,                "Invalid connection size" },
   { CM_ES_TARGET_CONNECTION_NOT_CONFIGURED,       "Target for connection not configured" },
   { CM_ES_RPI_NOT_SUPPORTED,                      "RPI not supported" },
   { CM_ES_RPI_NOT_ACCEPTABLE,                     "RPI value(s) not acceptable" },
   { CM_ES_OUT_OF_CONNECTIONS,                     "Out of connections" },
   { CM_ES_VENDOR_ID_OR_PRODUCT_CODE_MISMATCH,     "Vendor ID or product code mismatch" },
   { CM_ES_DEVICE_TYPE_MISMATCH,                   "Device type mismatch" },
   { CM_ES_REVISION_MISMATCH,                      "Revision mismatch" },
   { CM_ES_INVALID_PROD_CONS_APP_PATH,             "Invalid produced or consumed application path" },
   { CM_ES_INVALID_OR_INCONSISTENT_CONF_APP_PATH,  "Invalid or inconsistent configuration application path" },
   { CM_ES_NON_LISTEN_ONLY_CONN_NOT_OPENED,        "Non-listen only connection not opened" },
   { CM_ES_TARGET_OBJECT_OUT_OF_CONNECTIONS,       "Target object out of connections" },
   { CM_ES_RPI_SMALLER_THAN_PROD_INHIBIT_TIME,     "RPI is smaller than the production inhibit time" },
   { CM_ES_TRANSPORT_CLASS_NOT_SUPPORTED,          "Transport class not supported" },
   { CM_ES_PRODUCTION_TRIGGER_NOT_SUPPORTED,       "Production trigger not supported" },
   { CM_ES_DIRECTION_NOT_SUPPORTED,                "Direction not supported" },
   { CM_ES_INVALID_OT_NET_CONN_FIX_VAR,            "Invalid O->T Fixed/Variable" },
   { CM_ES_INVALID_TO_NET_CONN_FIX_VAR,            "Invalid T->O Fixed/Variable" },
   { CM_ES_INVALID_OT_NET_CONN_PRIORITY,           "Invalid O->T Priority" },
   { CM_ES_INVALID_TO_NET_CONN_PRIORITY,           "Invalid T->O Priority" },
   { CM_ES_INVALID_OT_NET_CONN_TYPE,               "Invalid O->T connection type" },
   { CM_ES_INVALID_TO_NET_CONN_TYPE,               "Invalid T->O connection type" },
   { CM_ES_INVALID_OT_NET_CONN_REDUNDANT_OWNER,    "Invalid O->T redundant owner" },
   { CM_ES_INVALID_CONFIGURATION_SIZE,             "Invalid configuration size" },
   { CM_ES_INVALID_OT_SIZE,                        "Invalid O->T size" },
   { CM_ES_INVALID_TO_SIZE,                        "Invalid T->O size" },
   { CM_ES_INVALID_CONFIGURATION_APP_PATH,         "Invalid configuration application path" },
   { CM_ES_INVALID_CONSUMING_APP_PATH,             "Invalid consuming application path" },
   { CM_ES_INVALID_PRODUCING_APP_PATH,             "Invalid producing application path" },
   { CM_ES_CONFIGURATION_SYMBOL_NOT_EXIST,         "Configuration symbol does not exist" },
   { CM_ES_CONSUMING_SYMBOL_NOT_EXIST,             "Consuming symbol does not exist" },
   { CM_ES_PRODUCING_SYMBOL_NOT_EXIST,             "Producing symbol does not exist" },
   { CM_ES_INCONSISTENT_APP_PATH_COMBO,            "Inconsistent application path combination" },
   { CM_ES_INCONSISTENT_CONSUME_DATA_FORMAT,       "Inconsistent consume data format" },
   { CM_ES_INCONSISTENT_PRODUCE_DATA_FORMAT,       "Inconsistent produce data format" },
   { CM_ES_NULL_FORWARD_OPEN_NOT_SUPPORTED,        "NULL ForwardOpen not supported" },
   { CM_ES_CONNECTION_TIMED_OUT,                   "Connection timed out" },
   { CM_ES_UNCONNECTED_REQUEST_TIMED_OUT,          "Unconnected request timed out" },
   { CM_ES_PARAMETER_ERROR_IN_UNCONNECTED_REQUEST, "Parameter error in unconnected request" },
   { CM_ES_MESSAGE_TOO_LARGE_FOR_UNCONNECTED_SEND, "Message too large for UnconnectedSend" },
   { CM_ES_UNCONNECTED_ACK_WITHOUT_REPLY,          "Unconnected acknowledged without reply" },
   { CM_ES_NO_BUFFER_MEMORY_AVAILABLE,             "No buffer memory available" },
   { CM_ES_NETWORK_BANDWIDTH_NOT_AVAIL_FOR_DATA,   "Network bandwidth not available for data" },
   { CM_ES_NO_CONSUMED_CONN_ID_FILTER_AVAILABLE,   "No consumed connection ID filter available" },
   { CM_ES_NOT_CONFIGURED_TO_SEND_SCHEDULED_DATA,  "Not configured to send scheduled priority data" },
   { CM_ES_SCHEDULE_SIGNATURE_MISMATCH,            "Schedule signature mismatch" },
   { CM_ES_SCHEDULE_SIGNATURE_VALIDATION_NOT_POSS, "Schedule signature validation not possible" },
   { CM_ES_PORT_NOT_AVAILABLE,                     "Port not available" },
   { CM_ES_LINK_ADDRESS_NOT_VALID,                 "Link address not valid" },
   { CM_ES_INVALID_SEGMENT_IN_CONN_PATH,           "Invalid segment in connection path" },
   { CM_ES_FWD_CLOSE_CONN_PATH_MISMATCH,           "ForwardClose connection path mismatch" },
   { CM_ES_SCHEDULING_NOT_SPECIFIED,               "Scheduling not specified" },
   { CM_ES_LINK_ADDRESS_TO_SELF_INVALID,           "Link address to self invalid" },
   { CM_ES_SECONDARY_RESOURCES_UNAVAILABLE,        "Secondary resources unavailable" },
   { CM_ES_RACK_CONNECTION_ALREADY_ESTABLISHED,    "Rack connection already established" },
   { CM_ES_MODULE_CONNECTION_ALREADY_ESTABLISHED,  "Module connection already established" },
   { CM_ES_MISCELLANEOUS,                          "Miscellaneous" },
   { CM_ES_REDUNDANT_CONNECTION_MISMATCH,          "Redundant connection mismatch" },
   { CM_ES_NO_CONSUMER_RES_AVAIL_IN_PROD_MODULE,   "No more user configurable link consumer resources available in the producing module" },
   { CM_ES_NO_CONSUMER_RES_CONF_IN_PROD_MODULE,    "No more user configurable link consumer resources configured in the producing module" },
   { CM_ES_NETWORK_LINK_OFFLINE,                   "Network link offline" },
   { CM_ES_INCOMPATIBLE_MULTICAST_RPI,             "Incompatible Multicast RPI" },
   { CM_ES_INVALID_SAFETY_CONN_SIZE,               "Invalid Safety Connection Size" },
   { CM_ES_INVALID_SAFETY_CONN_FORMAT,             "Invalid Safety Connection Format" },
   { CM_ES_INVALID_TIME_CORRECTION_CONN_PARAM,     "Invalid Time Correction Connection Parameters" },
   { CM_ES_INVALID_PING_INTERVAL_EPI_MULTIPLIER,   "Invalid Ping Interval EPI Multiplier" },
   { CM_ES_TIME_COORDINATION_MSG_MIN_MULTIPLIER,   "Time Coordination Msg Min Multiplier" },
   { CM_ES_NETWORK_TIME_EXPECTATION_MULTIPLIER,    "Network Time Expectation Multiplier" },
   { CM_ES_TIMEOUT_MULTIPLIER,                     "Timeout Multiplier" },
   { CM_ES_INVALID_MAX_CONSUMER_NUMBER,            "Invalid Max Consumer Number" },
   { CM_ES_INVALID_CPCRC,                          "Invalid CPCRC" },
   { CM_ES_TIME_CORRECTION_CONN_ID_INVALID,        "Time Correction Connection ID Invalid" },
   { CM_ES_SCID_MISMATCH,                          "SCID Mismatch" },
   { CM_ES_TUNID_NOT_SET,                          "TUNID not set" },
   { CM_ES_TUNID_MISMATCH,                         "TUNID Mismatch" },
   { CM_ES_CONFIGURATION_OPERATION_NOT_ALLOWED,    "Configuration operation not allowed" },
   { CM_ES_NO_TARGET_APP_DATA_AVAILABLE,           "No target application data available" },
   { CM_ES_NO_ORIG_APP_DATA_AVAILABLE,             "No originator application data available" },
   { CM_ES_NODE_ADDRESS_CHANGED_AFTER_SCHEDULED,   "Node address has changed since the network was scheduled" },
   { CM_ES_NOT_CONFIGURED_MULTICAST,               "Not configured for off-subnet multicast" },
   { CM_ES_INVALID_PROD_CONS_DATA_FORMAT,          "Invalid produce/consume data format" },
   { CM_ES_EGRESS_RULE_DENY,                       "Egress Rule deny" },
   { CM_ES_EGRESS_RULE_CIPHER_NOT_ALLOWED,         "Egress Rule Cipher not allowed" },
   { CM_ES_NO_MATCHING_INGRESS_RULE,               "No matching Ingress Rules" },
   { CM_ES_INGRESS_RULE_DENY,                      "Ingress Rule deny" },
   { CM_ES_INGRESS_RULE_DENY_NON_SECURE,           "Ingress Rule deny non-secure" },
   { CM_ES_NO_MATCHING_EGRESS_RULE,                "No matching Egress Rule" },

   { 0,                          NULL }
};

value_string_ext cip_cm_ext_st_vals_ext = VALUE_STRING_EXT_INIT(cip_cm_ext_st_vals);

/* Translate function to string - PCCC Status codes */
static const value_string cip_pccc_gs_st_vals[] = {
   { PCCC_GS_SUCCESS,                         "Success" },
   { PCCC_GS_ILLEGAL_CMD,                     "Illegal command or format" },
   { PCCC_GS_HOST_COMMS,                      "Host has a problem and will not communicate" },
   { PCCC_GS_MISSING_REMOTE_NODE,             "Remote node host is missing, disconnected, or shut down" },
   { PCCC_GS_HARDWARE_FAULT,                  "Host could not complete function due to hardware fault" },
   { PCCC_GS_ADDRESSING_ERROR,                "Addressing problem or memory protect rungs" },
   { PCCC_GS_CMD_PROTECTION,                  "Function not allowed due to command protection selection" },
   { PCCC_GS_PROGRAM_MODE,                    "Processor is in Program mode" },
   { PCCC_GS_MISSING_COMPATIBILITY_FILE,      "Compatibility mode file missing or communication zone problem" },
   { PCCC_GS_BUFFER_FULL_1,                   "Remote node cannot buffer command" },
   { PCCC_GS_WAIT_ACK,                        "Wait ACK (1775-KA buffer full)" },
   { PCCC_GS_REMOTE_DOWNLOAD_ERROR,           "Remote node problem due to download" },
   { PCCC_GS_BUFFER_FULL_2,                   "Wait ACK (1775-KA buffer full)" },
   { PCCC_GS_NOT_USED_1,                      "Not used" },
   { PCCC_GS_NOT_USED_2,                      "Not used" },
   { PCCC_GS_USE_EXTSTS,                      "Error code in the EXT STS byte" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_gs_st_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_gs_st_vals);

/* Translate function to string - PCCC Extended Status codes */
static const value_string cip_pccc_es_st_vals[] = {
   { PCCC_ES_ILLEGAL_VALUE,                        "A field has an illegal value" },
   { PCCC_ES_SHORT_ADDRESS,                        "Less levels specified in address than minimum for any address" },
   { PCCC_ES_LONG_ADDRESS,                         "More levels specified in address than system supports" },
   { PCCC_ES_NOT_FOUND,                            "Symbol not found" },
   { PCCC_ES_BAD_FORMAT,                           "Symbol is of improper format" },
   { PCCC_ES_BAD_POINTER,                          "Address doesn't point to something usable" },
   { PCCC_ES_BAD_SIZE,                             "File is wrong size" },
   { PCCC_ES_SITUATION_CHANGED,                    "Cannot complete request, situation has changed since the start of the command" },
   { PCCC_ES_DATA_TOO_LARGE,                       "Data or file is too large" },
   { PCCC_ES_TRANS_TOO_LARGE,                      "Transaction size plus word address is too large" },
   { PCCC_ES_ACCESS_DENIED,                        "Access denied, improper privilege" },
   { PCCC_ES_NOT_AVAILABLE,                        "Condition cannot be generated - resource is not available" },
   { PCCC_ES_ALREADY_EXISTS,                       "Condition already exists - resource is already available" },
   { PCCC_ES_NO_EXECUTION,                         "Command cannot be executed" },
   { PCCC_ES_HIST_OVERFLOW,                        "Histogram overflow" },
   { PCCC_ES_NO_ACCESS,                            "No access" },
   { PCCC_ES_ILLEGAL_DATA_TYPE,                    "Illegal data type" },
   { PCCC_ES_INVALID_DATA,                         "Invalid parameter or invalid data" },
   { PCCC_ES_BAD_REFERENCE,                        "Address reference exists to deleted area" },
   { PCCC_ES_EXECUTION_FAILURE,                    "Command execution failure for unknown reason; possible PLC-3 histogram overflow" },
   { PCCC_ES_CONVERSION_ERROR,                     "Data conversion error" },
   { PCCC_ES_NO_COMMS,                             "Scanner not able to communicate with 1771 rack adapter" },
   { PCCC_ES_TYPE_MISMATCH,                        "Type mismatch" },
   { PCCC_ES_BAD_RESPONSE,                         "1771 module response was not valid" },
   { PCCC_ES_DUP_LABEL,                            "Duplicated label" },
   { PCCC_ES_FILE_ALREADY_OPEN,                    "File is open; another node owns it" },
   { PCCC_ES_PROGRAM_ALREADY_OWNED,                "Another node is the program owner" },
   { PCCC_ES_RESERVED_1,                           "Reserved" },
   { PCCC_ES_RESERVED_2,                           "Reserved" },
   { PCCC_ES_PROTECTION_VIOLATION,                 "Data table element protection violation" },
   { PCCC_ES_TMP_INTERNAL_ERROR,                   "Temporary internal problem" },
   { PCCC_ES_RACK_FAULT,                           "Remote rack fault" },
   { PCCC_ES_TIMEOUT,                              "Timeout" },
   { PCCC_ES_UNKNOWN,                              "Unknown error" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_es_st_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_es_st_vals);

/* Translate PCCC Function Codes */
static const value_string cip_pccc_fnc_06_vals[] = {
    { PCCC_FNC_06_00, "Echo" },
    { PCCC_FNC_06_01, "Read diagnostic counters" },
    { PCCC_FNC_06_02, "Set variables" },
    { PCCC_FNC_06_03, "Diagnostic status" },
    { PCCC_FNC_06_04, "Set timeout" },
    { PCCC_FNC_06_05, "Set NAKs" },
    { PCCC_FNC_06_06, "Set ENQs" },
    { PCCC_FNC_06_07, "Reset diagnostic counters" },
    { PCCC_FNC_06_08, "Set data table size" },
    { PCCC_FNC_06_09, "Read link parameters" },
    { PCCC_FNC_06_0A, "Set link parameters" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_fnc_06_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_fnc_06_vals);

static const value_string cip_pccc_fnc_07_vals[] = {
    { PCCC_FNC_07_00, "Disable outputs" },
    { PCCC_FNC_07_01, "Enable outputs" },
    { PCCC_FNC_07_03, "Enable PLC scanning" },
    { PCCC_FNC_07_04, "Enter download mode" },
    { PCCC_FNC_07_05, "Exit download/upload mode" },
    { PCCC_FNC_07_06, "Enter upload mode" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_fnc_07_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_fnc_07_vals);

static const value_string cip_pccc_fnc_0f_vals[] = {
    { PCCC_FNC_0F_00, "Word range write" },
    { PCCC_FNC_0F_01, "Word range read" },
    { PCCC_FNC_0F_02, "Bit write" },
    { PCCC_FNC_0F_03, "File write" },
    { PCCC_FNC_0F_04, "File read" },
    { PCCC_FNC_0F_05, "Download request" },
    { PCCC_FNC_0F_06, "Upload" },
    { PCCC_FNC_0F_07, "Shutdown" },
    { PCCC_FNC_0F_08, "Physical write" },
    { PCCC_FNC_0F_09, "Physical read" },
    { PCCC_FNC_0F_0A, "Restart request" },
    { PCCC_FNC_0F_11, "Get edit resource" },
    { PCCC_FNC_0F_12, "Return edit resource" },
    { PCCC_FNC_0F_17, "Read bytes physical" },
    { PCCC_FNC_0F_18, "Write bytes physical" },
    { PCCC_FNC_0F_26, "Read-modify-write" },
    { PCCC_FNC_0F_29, "Read section size" },
    { PCCC_FNC_0F_3A, "Set CPU mode" },
    { PCCC_FNC_0F_41, "Disable forces" },
    { PCCC_FNC_0F_50, "Download all request" },
    { PCCC_FNC_0F_52, "Download completed" },
    { PCCC_FNC_0F_53, "Upload all request (upload)" },
    { PCCC_FNC_0F_55, "Upload completed" },
    { PCCC_FNC_0F_57, "Initialize memory" },
    { PCCC_FNC_0F_5E, "Modify PLC-2 compatibility file" },
    { PCCC_FNC_0F_67, "Typed write" },
    { PCCC_FNC_0F_68, "Typed read" },
    { PCCC_FNC_0F_79, "Read-modify-write N" },
    { PCCC_FNC_0F_80, "Change CPU mode" },
    { PCCC_FNC_0F_81, "Open file" },
    { PCCC_FNC_0F_82, "Close file" },
    { PCCC_FNC_0F_88, "Execute Multiple Commands" },
    { PCCC_FNC_0F_8F, "Apply port configuration" },
    { PCCC_FNC_0F_A1, "Protected typed logical read with two address fields" },
    { PCCC_FNC_0F_A2, "Protected typed logical read with three address fields" },
    { PCCC_FNC_0F_A7, "Protected typed file read" },
    { PCCC_FNC_0F_A9, "Protected typed logical write with two address fields" },
    { PCCC_FNC_0F_AA, "Protected typed logical write with three address fields" },
    { PCCC_FNC_0F_AB, "Protected typed logical masked-write with three address fields" },
    { PCCC_FNC_0F_AF, "Protected typed file write" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_fnc_0f_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_fnc_0f_vals);

/* Translate PCCC File Types */
static const value_string cip_pccc_file_types_vals[] = {
   { PCCC_FILE_TYPE_LOGIC,               "Ladder Logic File" },
   { PCCC_FILE_TYPE_CHANNEL_CONFIG,      "Channel Configuration File" },
   { PCCC_FILE_TYPE_FUNCTION_ES1,        "EtherNet/IP Function File" },
   { PCCC_FILE_TYPE_ONLINE_EDIT,         "Online Editing File" },
   { PCCC_FILE_TYPE_FUNCTION_IOS,        "IOS Function File" },
   { PCCC_FILE_TYPE_DATA_OUTPUT,         "Output Data File" },
   { PCCC_FILE_TYPE_DATA_INPUT,          "Input Data File" },
   { PCCC_FILE_TYPE_DATA_STATUS,         "Status Data File" },
   { PCCC_FILE_TYPE_DATA_BINARY,         "Binary Data File" },
   { PCCC_FILE_TYPE_DATA_TIMER,          "Timer Data File" },
   { PCCC_FILE_TYPE_DATA_COUNTER,        "Counter Data File" },
   { PCCC_FILE_TYPE_DATA_INTEGER,        "Integer Data File" },
   { PCCC_FILE_TYPE_DATA_FLOAT,          "Float Data File" },
   { PCCC_FILE_TYPE_FORCE_OUTPUT,        "Output Force File" },
   { PCCC_FILE_TYPE_FORCE_INPUT,         "Input Force File" },
   { PCCC_FILE_TYPE_FUNCTION_ES0,        "ES0 Function File" },
   { PCCC_FILE_TYPE_FUNCTION_STI,        "STI Function File" },
   { PCCC_FILE_TYPE_FUNCTION_EII,        "EII Function File" },
   { PCCC_FILE_TYPE_FUNCTION_RTC,        "RTC Function File" },
   { PCCC_FILE_TYPE_FUNCTION_BHI,        "BHI Function File" },
   { PCCC_FILE_TYPE_FUNCTION_MMI,        "Memory Module Function File" },
   { PCCC_FILE_TYPE_FUNCTION_LCD,        "Built-in LCD Function File" },
   { PCCC_FILE_TYPE_FUNCTION_PTOX,       "PTOX Function File" },
   { PCCC_FILE_TYPE_FUNCTION_PWMX,       "PWMX Function File" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_file_type_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_file_types_vals);

/* Translate PCCC CPU Modes */
#if 0
static const value_string cip_pccc_cpu_mode_3a_vals[] = {
   { PCCC_CPU_3A_PROGRAM,           "Remote Program" },
   { PCCC_CPU_3A_RUN,               "Remote Run" },

   { 0,                          NULL }
};

value_string_ext cip_pccc_cpu_mode_3a_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_cpu_mode_3a_vals);
#endif

static const value_string cip_pccc_cpu_mode_80_vals[] = {
   { PCCC_CPU_80_PROGRAM,           "Remote Program" },
   { PCCC_CPU_80_RUN,               "Remote Run" },
   { PCCC_CPU_80_TEST_CONT,         "Remote Test Continuous" },
   { PCCC_CPU_80_TEST_SINGLE,       "Remote Test Single" },
   { PCCC_CPU_80_TEST_DEBUG,        "Remote Test Debug" },

   { 0,                          NULL }
};

static value_string_ext cip_pccc_cpu_mode_80_vals_ext = VALUE_STRING_EXT_INIT(cip_pccc_cpu_mode_80_vals);

/* Translate Vendor IDs */
static const value_string cip_vendor_vals[] = {
   {    1,   "Rockwell Automation/Allen-Bradley" },
   {    2,   "Namco Controls Corp." },
   {    3,   "Honeywell International Inc." },
   {    4,   "Parker Hannifin Corporation" },
   {    5,   "Rockwell Automation/Reliance Elec." },
   {    6,   "Reserved" },
   {    7,   "SMC Corporation" },
   {    8,   "Molex Incorporated" },
   {    9,   "Western Reserve Controls Inc." },
   {   10,   "Advanced Micro Controls Inc. (AMCI)" },
   {   11,   "ASCO Pneumatic Controls" },
   {   12,   "Banner Engineering Corporation" },
   {   13,   "Belden Wire & Cable Company" },
   {   14,   "Cooper Interconnect" },
   {   16,   "Daniel Woodhead Co." },
   {   17,   "Dearborn Group Inc." },
   {   18,   "Reserved" },
   {   19,   "Helm Instrument Company" },
   {   20,   "Huron Net Works" },
   {   21,   "Belden Deutschland GmbH" },
   {   22,   "Online Development, Inc. (OLDI)" },
   {   23,   "Vorne Industries, Inc." },
   {   24,   "ODVA" },
   {   25,   "Reserved" },
   {   26,   "Festo" },
   {   27,   "Reserved" },
   {   28,   "Reserved" },
   {   30,   "Unico, Inc." },
   {   31,   "Ross Controls" },
   {   33,   "Reserved" },
   {   34,   "Hohner Corp." },
   {   35,   "Micro Mo Electronics, Inc." },
   {   36,   "MKS Instruments, Inc." },
   {   37,   "Yaskawa Electric America formerly Magnetek Drives" },
   {   38,   "Reserved" },
   {   39,   "AVG Automation (Uticor)" },
   {   40,   "WAGO Corporation" },
   {   41,   "Celerity, Inc." },
   {   42,   "IMI Norgren Limited" },
   {   43,   "BALLUFF" },
   {   44,   "Yaskawa America, Inc." },
   {   45,   "Eurotherm by Schneider Electric" },
   {   46,   "ABB, Inc." },
   {   47,   "Omron Corporation" },
   {   48,   "TURCK" },
   {   49,   "Grayhill Inc." },
   {   50,   "Real Time Automation" },
   {   51,   "Reserved" },
   {   52,   "ASCO Numatics" },
   {   53,   "LÜTZE" },
   {   54,   "Reserved" },
   {   55,   "Reserved" },
   {   56,   "Softing" },
   {   57,   "Pepperl+Fuchs" },
   {   58,   "Spectrum Controls, Inc." },
   {   59,   "D.I.P. Inc. MKS Inst." },
   {   60,   "Applied Motion Products, Inc." },
   {   61,   "Sencon Inc." },
   {   62,   "High Country Tek" },
   {   63,   "SWAC Automation Consult GmbH" },
   {   64,   "Clippard Instrument Laboratory" },
   {   65,   "Reserved" },
   {   66,   "Reserved" },
   {   67,   "Reserved" },
   {   68,   "Eaton Electrical" },
   {   69,   "Reserved" },
   {   70,   "Reserved" },
   {   71,   "Toshiba Corporation" },
   {   72,   "Control Technology Incorporated" },
   {   73,   "TCS (NZ) Ltd." },
   {   74,   "Hitachi, Ltd." },
   {   75,   "ABB Robotics" },
   {   76,   "NKE Corporation" },
   {   77,   "Rockwell Software, Inc." },
   {   78,   "Escort Memory Systems (A Datalogic Group Co.)" },
   {   79,   "Leviton" },
   {   80,   "Industrial Devices Corporation" },
   {   81,   "IXXAT Automation GmbH" },
   {   82,   "Mitsubishi Electric Automation, Inc." },
   {   83,   "OPTO 22" },
   {   84,   "Reserved" },
   {   85,   "Reserved" },
   {   86,   "Horner Electric" },
   {   87,   "Buerkert Fluid Control Systems" },
   {   88,   "Reserved" },
   {   89,   "Industrial Indexing Systems, Inc." },
   {   90,   "HMS Networks" },
   {   91,   "Robicon" },
   {   92,   "Helix Technology (Granville-Phillips)" },
   {   93,   "Arlington Laboratory" },
   {   94,   "Advantech Corporation" },
   {   95,   "Square D Company" },
   {   96,   "Digital Electronics Corp." },
   {   97,   "Danfoss Drives A/S" },
   {   98,   "Reserved" },
   {   99,   "Reserved" },
   {  100,   "AVENTICS" },
   {  101,   "Applied Materials, Inc." },
   {  102,   "SWCC Showa Cable Systems Co., Ltd." },
   {  103,   "Pacific Scientific (API Controls Inc.)" },
   {  104,   "Sharp Manufacturing Systems Corporation" },
   {  105,   "Olflex Wire & Cable, Inc." },
   {  106,   "Reserved" },
   {  107,   "Unitrode" },
   {  108,   "Beckhoff Automation" },
   {  109,   "National Instruments" },
   {  110,   "Mykrolis Corporation (Millipore)" },
   {  111,   "International Motion Controls Corp." },
   {  112,   "Reserved" },
   {  113,   "SEG Kempen GmbH" },
   {  114,   "Reserved" },
   {  115,   "Reserved" },
   {  116,   "Temposonics, LLC" },
   {  117,   "Krones, Inc" },
   {  119,   "EXOR Electronic R & D" },
   {  120,   "SIEI S.p.A." },
   {  121,   "KUKA Deutschland GmbH" },
   {  122,   "Reserved" },
   {  123,   "SEC (Samsung Electronics Co., Ltd)" },
   {  124,   "Binary Electronics Ltd" },
   {  125,   "Flexible Machine Controls" },
   {  126,   "Reserved" },
   {  127,   "ABB Inc. (Entrelec)" },
   {  128,   "MAC Valves, Inc." },
   {  129,   "AUMA Riester GmbH & Co. KG" },
   {  130,   "JTEKT Corporation" },
   {  131,   "Reserved" },
   {  132,   "Reserved" },
   {  133,   "Balogh T.A.G., Corporation" },
   {  134,   "TR Electronic" },
   {  135,   "UNIPULSE Corporation" },
   {  136,   "Reserved" },
   {  137,   "Reserved" },
   {  138,   "Conxall Corporation Inc." },
   {  139,   "Reserved" },
   {  140,   "Reserved" },
   {  141,   "Kuramo Electric Co., Ltd." },
   {  142,   "Creative Micro Designs" },
   {  143,   "GE Industrial Systems" },
   {  144,   "Leybold GmbH" },
   {  145,   "Siemens Energy & Automation/Drives" },
   {  146,   "Kodensha Ltd" },
   {  147,   "Motion Engineering, Inc." },
   {  148,   "Honda Engineering Co., Ltd" },
   {  149,   "EIM Valve Controls" },
   {  150,   "Melec Inc." },
   {  151,   "Sony Manufacturing Systems Corporation" },
   {  152,   "North American Mfg." },
   {  153,   "Watlow" },
   {  154,   "Japan Radio Co., Ltd" },
   {  155,   "NADEX Co., Ltd" },
   {  156,   "Ametek Automation & Process Technologies" },
   {  157,   "Facts, Inc." },
   {  158,   "KVASER AB" },
   {  159,   "IDEC Corporation" },
   {  160,   "Mitsubishi Heavy Industries Ltd" },
   {  161,   "Mitsubishi Electric Corporation" },
   {  162,   "HORIBA STEC, Co., Ltd." },
   {  163,   "esd electronics gmbh" },
   {  164,   "DAIHEN Corporation" },
   {  165,   "Tyco Valves & Controls/Keystone" },
   {  166,   "EBARA Corporation" },
   {  168,   "Reserved" },
   {  169,   "Hokuyo Automatic Co., Ltd." },
   {  170,   "Pyramid Solutions, Inc." },
   {  171,   "Denso Wave Incorporated" },
   {  172,   "HLS Hard-Line Solutions Inc" },
   {  173,   "Caterpillar, Inc." },
   {  174,   "PDL Electronics Ltd." },
   {  175,   "Reserved" },
   {  176,   "Red Lion" },
   {  177,   "CANON ANELVA Corporation" },
   {  178,   "Toyo Denki Seizo KK" },
   {  179,   "Sanyo Denki Co., Ltd." },
   {  180,   "Hitachi Metals, Ltd. (formerly Advanced Energy Japan K.K.)" },
   {  181,   "Pilz GmbH & Co KG" },
   {  182,   "Marsh Bellofram-Bellofram PCD Division" },
   {  183,   "Reserved" },
   {  184,   "M-SYSTEM Co., Ltd." },
   {  185,   "Nissin Electric Co., Ltd." },
   {  186,   "Hitachi Metals Ltd." },
   {  187,   "Oriental Motor Co., Ltd" },
   {  188,   "A&D Company Limited" },
   {  189,   "Phasetronics, Inc." },
   {  190,   "Cummins Engine Company" },
   {  191,   "Deltron Inc." },
   {  192,   "Geneer Corporation" },
   {  193,   "Anatol Automation, Inc." },
   {  194,   "Reserved" },
   {  195,   "Reserved" },
   {  196,   "Medar, Inc." },
   {  197,   "XP Power LLC" },
   {  198,   "Advanced Energy Industries, Inc." },
   {  199,   "Reserved" },
   {  200,   "DAIDEN Co., Ltd" },
   {  201,   "CKD Corporation" },
   {  202,   "Toyo Electric Corporation" },
   {  203,   "Reserved" },
   {  204,   "AuCom Electronics Ltd" },
   {  205,   "Sinfonia Technology Co., Ltd." },
   {  206,   "Vector Informatik GmbH" },
   {  207,   "Reserved" },
   {  208,   "Moog Inc." },
   {  209,   "Contemporary Controls" },
   {  210,   "Tokyo Sokki Kenkyujo Co., Ltd" },
   {  211,   "Schenck Process Group" },
   {  212,   "The Oilgear Company" },
   {  213,   "Reserved" },
   {  214,   "ASM Japan K.K." },
   {  215,   "HIRATA Corp." },
   {  216,   "Panasonic Industrial Devices SUNX Co., Ltd." },
   {  217,   "Meidensha Corporation" },
   {  218,   "NIDEC SANKYO CORPORATION (Sankyo Seiki Mfg. Co., Ltd)" },
   {  219,   "KAMRO Corp." },
   {  220,   "NSD Co., Ltd." },
   {  221,   "EBARA Technologies Inc." },
   {  222,   "Reserved" },
   {  223,   "Reserved" },
   {  224,   "SG Co., Ltd" },
   {  225,   "Vaasa Institute of Technology" },
   {  226,   "MKS Instruments (ENI Technology)" },
   {  227,   "Tateyama System Laboratory Co., Ltd." },
   {  228,   "QLOG Corporation" },
   {  229,   "Matric Limited Inc." },
   {  230,   "NSD Corporation" },
   {  231,   "Reserved" },
   {  232,   "Sumitomo Wiring Systems, Ltd" },
   {  233,   "Group 3 Technology Ltd" },
   {  234,   "CTI Cryogenics" },
   {  235,   "POLSYS CORP" },
   {  236,   "Ampere Inc." },
   {  237,   "Reserved" },
   {  238,   "Simplatroll Ltd" },
   {  239,   "Reserved" },
   {  240,   "Reserved" },
   {  241,   "Leading Edge Design" },
   {  242,   "Humphrey Products" },
   {  243,   "Schneider Electric" },
   {  244,   "Westlock Controls Corp." },
   {  245,   "Nihon Weidmuller Co., Ltd" },
   {  246,   "Brooks Instrument" },
   {  247,   "Reserved" },
   {  248,   "Eaton Industries GmbH (formerly Moeller GmbH)" },
   {  249,   "Varian Vacuum Products" },
   {  250,   "Yokogawa Electric Corporation" },
   {  251,   "Electrical Design Daiyu Co., Ltd" },
   {  252,   "Omron Software Co., Ltd." },
   {  253,   "EDWARDS" },
   {  254,   "Control Technology Corporation" },
   {  255,   "Bosch Rexroth" },
   {  256,   "TURCK (formerly InterlinkBT)" },
   {  257,   "Control Techniques PLC" },
   {  258,   "Hardy Process Solutions" },
   {  259,   "LS ELECTRIC" },
   {  260,   "E.O.A. Systems Inc." },
   {  261,   "Reserved" },
   {  262,   "New Cosmos Electric Co., Ltd." },
   {  263,   "Sense Sense Eletronica LTDA" },
   {  264,   "Xycom, Inc." },
   {  265,   "Baldor Electric" },
   {  266,   "Reserved" },
   {  267,   "Patlite Corporation" },
   {  268,   "Reserved" },
   {  269,   "Mogami Wire & Cable Corporation" },
   {  270,   "Welding Technology Corporation" },
   {  271,   "Reserved" },
   {  272,   "Deutschmann Automation GmbH" },
   {  273,   "ICP Panel-Tec Inc." },
   {  274,   "Bray International, Inc" },
   {  275,   "Reserved" },
   {  276,   "Status Technologies" },
   {  277,   "Trio Motion Technology ltd" },
   {  278,   "Sherrex Systems Ltd" },
   {  279,   "Adept Technology, Inc." },
   {  280,   "Spang Power Electronics" },
   {  281,   "Reserved" },
   {  282,   "Acrosser Technology Co., Ltd" },
   {  283,   "Hilscher GmbH" },
   {  284,   "IMAX Corporation" },
   {  285,   "Electronic Innovation, Inc. (Falter Engineering)" },
   {  286,   "Netlogic Inc." },
   {  287,   "Bosch Rexroth AG" },
   {  288,   "Reserved" },
   {  289,   "Reserved" },
   {  290,   "Murata  Machinery Ltd." },
   {  291,   "MTT Company Ltd." },
   {  292,   "Kanematsu Semiconductor Corp." },
   {  293,   "Takebishi Electric Sales Co." },
   {  294,   "Tokyo Electron Device Ltd" },
   {  295,   "PFU Limited" },
   {  296,   "Hakko Automation Co., Ltd." },
   {  297,   "Advanet Inc." },
   {  298,   "Tokyo Electron Software Technologies Ltd." },
   {  299,   "Reserved" },
   {  300,   "Shinagawa Electric Wire Co., Ltd." },
   {  301,   "Yokogawa M&C Corporation" },
   {  302,   "KONAN Electric Co., Ltd." },
   {  303,   "Binar Elektronik AB" },
   {  304,   "Furukawa Electric Co." },
   {  305,   "Cooper Energy Services" },
   {  306,   "Schleicher GmbH & Co." },
   {  307,   "Hirose Electric Co., Ltd" },
   {  308,   "Western Servo Design Inc." },
   {  309,   "ProSoft Technology" },
   {  310,   "Reserved" },
   {  311,   "Towa Shoko Co., Ltd" },
   {  312,   "Kyopal Co., Ltd" },
   {  313,   "Extron Co." },
   {  314,   "Wieland Electric GmbH" },
   {  315,   "SEW Eurodrive GmbH" },
   {  316,   "Aera Corporation" },
   {  317,   "STA Reutlingen" },
   {  318,   "Reserved" },
   {  319,   "Fuji Electric Group" },
   {  320,   "Reserved" },
   {  321,   "Reserved" },
   {  322,   "ifm electronic gmbh" },
   {  323,   "Reserved" },
   {  324,   "IDEACOD-Hohner Automation S.A." },
   {  325,   "CommScope Inc." },
   {  326,   "Intelligent Platforms, LLC." },
   {  327,   "Matsushita Electric Industrial Co., Ltd" },
   {  328,   "Okaya Electronics Corporation" },
   {  329,   "KASHIYAMA Industries, Ltd" },
   {  330,   "JVC" },
   {  331,   "Interface Corporation" },
   {  332,   "Grape Systems Inc." },
   {  333,   "Reserved" },
   {  334,   "Reserved" },
   {  335,   "Toshiba IT & Control Systems Corporation" },
   {  336,   "Sanyo Machine Works, Ltd." },
   {  337,   "Vansco Electronics Ltd." },
   {  338,   "Dart Container Corp." },
   {  339,   "Livingston & Co., Inc." },
   {  340,   "Alfa Laval LKM as" },
   {  341,   "BF ENTRON Ltd. (British Federal)" },
   {  342,   "Bekaert Engineering NV" },
   {  343,   "Ferran  Scientific Inc." },
   {  344,   "KEBA Industrial Automation GmbH" },
   {  345,   "Endress + Hauser" },
   {  346,   "Lincoln Electric Company" },
   {  347,   "ABB ALSTOM Power UK Ltd. (EGT)" },
   {  348,   "Berger Lahr GmbH" },
   {  349,   "Reserved" },
   {  350,   "Federal Signal Corp." },
   {  351,   "Kawasaki Robotics (USA), Inc." },
   {  352,   "Bently Nevada Corporation" },
   {  354,   "FRABA Posital" },
   {  355,   "Elsag Bailey, Inc." },
   {  356,   "FANUC Robotics America" },
   {  357,   "Reserved" },
   {  358,   "Surface Combustion, Inc." },
   {  359,   "Reserved" },
   {  360,   "AILES Electronics Ind. Co., Ltd." },
   {  361,   "Wonderware Corporation" },
   {  362,   "Particle Measuring Systems, Inc." },
   {  363,   "Reserved" },
   {  364,   "Reserved" },
   {  365,   "BITS Co., Ltd" },
   {  366,   "Japan Aviation Electronics Industry Ltd" },
   {  367,   "Keyence Corporation" },
   {  368,   "Kuroda Precision Industries Ltd." },
   {  369,   "Mitsubishi Electric Semiconductor Application" },
   {  370,   "Nippon Seisen Cable, Ltd." },
   {  371,   "Omron ASO Co., Ltd" },
   {  372,   "Seiko Seiki Co., Ltd." },
   {  373,   "Sumitomo Heavy Industries, Ltd." },
   {  374,   "Tango Computer Service Corporation" },
   {  375,   "Technology Service, Inc." },
   {  376,   "Toshiba Information Systems (Japan) Corporation" },
   {  377,   "TOSHIBA Schneider Inverter Corporation" },
   {  378,   "Toyooki Kogyo Co., Ltd." },
   {  379,   "XEBEC" },
   {  380,   "Madison Cable Corporation" },
   {  381,   "Hitati Engineering & Services Co., Ltd" },
   {  382,   "TEM-TECH Lab Co., Ltd" },
   {  383,   "International Laboratory Corporation" },
   {  384,   "Dyadic Systems Co., Ltd." },
   {  385,   "SETO Electronics Industry Co., Ltd" },
   {  386,   "Tokyo Electron Kyushu Limited" },
   {  387,   "KEI System Co., Ltd" },
   {  388,   "Reserved" },
   {  389,   "Asahi Engineering Co., Ltd" },
   {  390,   "Contrex Inc." },
   {  391,   "Paradigm Controls Ltd." },
   {  392,   "Reserved" },
   {  393,   "Ohm Electric Co., Ltd." },
   {  394,   "RKC Instrument Inc." },
   {  395,   "Suzuki Motor Corporation" },
   {  396,   "Custom Servo Motors Inc." },
   {  397,   "PACE Control Systems" },
   {  398,   "Selectron Systems AG" },
   {  399,   "Reserved" },
   {  400,   "LINTEC Co., Ltd." },
   {  401,   "Hitachi Cable Ltd." },
   {  402,   "BUSWARE Direct" },
   {  403,   "Eaton Electric B.V. (former Holec Holland N.V.)" },
   {  404,   "VAT Vacuum Valves AG" },
   {  405,   "Omron Robotics and Safety Technologies, Inc." },
   {  406,   "Alfa Instrumentos Eletronicos Ltda" },
   {  407,   "TWK Elektronik GmbH" },
   {  408,   "ABB Welding Systems AB" },
   {  409,   "BYSTRONIC Maschinen AG" },
   {  410,   "Kimura Electric Co., Ltd" },
   {  411,   "Nissei Plastic Industrial Co., Ltd" },
   {  412,   "Reserved" },
   {  413,   "Kistler-Morse" },
   {  414,   "Proteus Industries Inc." },
   {  415,   "IDC Corporation" },
   {  416,   "Nordson Corporation" },
   {  417,   "Rapistan Systems" },
   {  418,   "LP-Elektronik GmbH" },
   {  419,   "GERBI & FASE S.p.A.(Fase Saldatura)" },
   {  420,   "Phoenix Digital Corporation" },
   {  421,   "Z-World Engineering" },
   {  422,   "Honda R&D Co., Ltd." },
   {  423,   "Bionics Instrument Co., Ltd." },
   {  424,   "Teknic, Incorporated" },
   {  425,   "R.Stahl, Inc." },
   {  426,   "Reserved" },
   {  427,   "Ryco Graphic Manufacturing Inc." },
   {  428,   "Giddings & Lewis, Inc." },
   {  429,   "Koganei Corporation" },
   {  430,   "Reserved" },
   {  431,   "Nichigoh Communication Electric Wire Co., Ltd." },
   {  433,   "Fujikura Ltd." },
   {  434,   "AD Link Technology Inc." },
   {  435,   "Valmet Flow Control Inc (formerly StoneL)" },
   {  436,   "Computer Optical Products, Inc." },
   {  437,   "CONOS Inc." },
   {  438,   "Erhardt+Leimer GmbH" },
   {  439,   "UNIQUE Co. Ltd" },
   {  440,   "Roboticsware, Inc." },
   {  441,   "Nachi Fujikoshi Corporation" },
   {  442,   "Hengstler GmbH" },
   {  443,   "Vacon Plc" },
   {  444,   "SUNNY GIKEN Inc." },
   {  445,   "Lenze Drive Systems GmbH" },
   {  446,   "CD Systems B.V." },
   {  447,   "FMT/Aircraft Gate Support Systems AB" },
   {  448,   "Axiomatic Technologies Corp" },
   {  449,   "Embedded System Products, Inc." },
   {  450,   "Reserved" },
   {  451,   "Mencom Corporation" },
   {  452,   "Kollmorgen" },
   {  453,   "Panasonic Connect Co., Ltd." },
   {  454,   "Dengensha Mfg. Co. Ltd." },
   {  455,   "Quinn Systems Ltd." },
   {  456,   "Tellima Technology Ltd" },
   {  457,   "MDT, Software" },
   {  458,   "Taiwan Keiso Co., Ltd" },
   {  459,   "Pinnacle Systems" },
   {  460,   "Ascom Hasler Mailing Sys" },
   {  461,   "INSTRUMAR Limited" },
   {  462,   "Reserved" },
   {  463,   "Navistar International Transportation Corp" },
   {  464,   "TRUMPF Huettinger" },
   {  465,   "OCM Technology Inc." },
   {  466,   "Professional Supply Inc." },
   {  467,   "Control Solutions" },
   {  468,   "Baumer IVO GmbH & Co. KG" },
   {  469,   "Worcester Controls Corporation" },
   {  470,   "Pyramid Technical Consultants, Inc." },
   {  471,   "Eilersen Electric A/S" },
   {  472,   "Apollo Fire Detectors Limited" },
   {  473,   "Avtron Manufacturing, Inc." },
   {  474,   "Reserved" },
   {  475,   "Tokyo Keiso Co., Ltd." },
   {  476,   "Daishowa Swiki Co., Ltd." },
   {  477,   "Kojima Instruments Inc." },
   {  478,   "Shimadzu Corporation" },
   {  479,   "Tatsuta Electric Wire & Cable Co., Ltd." },
   {  480,   "MECS Corporation" },
   {  481,   "Tahara Electric" },
   {  482,   "JTEKT ELECTRONICS CORPORATION" },
   {  483,   "Clever Devices" },
   {  484,   "GCD Hardware & Software GmbH" },
   {  485,   "Reserved" },
   {  486,   "Miller Electric Mfg Co." },
   {  487,   "GEA Tuchenhagen GmbH" },
   {  488,   "Riken Keiki Co., Ltd." },
   {  489,   "Keisokugiken Corporation" },
   {  490,   "Fuji Machine Mfg. Co., Ltd" },
   {  491,   "Reserved" },
   {  492,   "Nidec-Shimpo Corp." },
   {  493,   "UTEC Corporation" },
   {  494,   "Sanyo Electric Co. Ltd." },
   {  495,   "Reserved" },
   {  496,   "Reserved" },
   {  497,   "Okano Electric Wire Co. Ltd" },
   {  498,   "Shimaden Co. Ltd." },
   {  499,   "Teddington Controls Ltd" },
   {  500,   "Reserved" },
   {  501,   "YASKAWA Europe (formerly VIPA GmbH)" },
   {  502,   "Warwick Manufacturing Group" },
   {  503,   "Danaher Controls" },
   {  504,   "Reserved" },
   {  505,   "Reserved" },
   {  506,   "American Science & Engineering" },
   {  507,   "Accutron Controls International Inc." },
   {  508,   "Norcott Technologies Ltd" },
   {  509,   "TB Woods, Inc" },
   {  510,   "Proportion-Air, Inc." },
   {  511,   "SICK Stegmann GmbH" },
   {  512,   "Reserved" },
   {  513,   "Edwards Signaling" },
   {  514,   "Sumitomo Metal Industries, Ltd" },
   {  515,   "Cosmo Instruments Co., Ltd." },
   {  516,   "Denshosha Co., Ltd." },
   {  517,   "Kaijo Corp." },
   {  518,   "Michiproducts Co., Ltd." },
   {  519,   "Miura Corporation" },
   {  520,   "TG Information Network Co., Ltd." },
   {  521,   "Fujikin, Inc." },
   {  522,   "Estic Corp." },
   {  523,   "GS Hydraulic Sales" },
   {  524,   "Leuze Electronic GmbH & Co. KG" },
   {  525,   "MTE Limited" },
   {  526,   "Hyde Park Electronics, Inc." },
   {  527,   "Pfeiffer Vacuum GmbH" },
   {  528,   "Cyberlogic Technologies" },
   {  529,   "OKUMA Corporation FA Systems Division" },
   {  530,   "Reserved" },
   {  531,   "Kokusai Electric Corporation" },
   {  532,   "SHINKO TECHNOS" },
   {  533,   "Itoh Denki Co., Ltd." },
   {  534,   "Colorado Flow Tech Inc." },
   {  535,   "Love Controls Division/Dwyer Inst." },
   {  536,   "Alstom Drives and Controls" },
   {  537,   "The Foxboro Company" },
   {  538,   "Tescom Corporation" },
   {  539,   "Reserved" },
   {  540,   "Atlas Copco Airpower NV" },
   {  541,   "Reserved" },
   {  542,   "Autojet Technologies" },
   {  543,   "Prima Electronics S.p.A." },
   {  544,   "PMA GmbH" },
   {  545,   "Shimafuji Electric Co., Ltd" },
   {  546,   "Oki Electric Industry Co., Ltd" },
   {  547,   "Kyushu Matsushita Electric Co., Ltd" },
   {  548,   "JMACS" },
   {  549,   "Tsuken Electric Ind Co., Ltd" },
   {  550,   "Tamadic Co." },
   {  551,   "MAATEL SA" },
   {  552,   "OKUMA America" },
   {  553,   "Control Techniques PLC-NA" },
   {  554,   "TPC Wire & Cable" },
   {  555,   "ATI Industrial Automation" },
   {  556,   "Microcontrol (Australia) Pty Ltd" },
   {  557,   "Serra Soldadura, S.A." },
   {  558,   "Southwest Research Institute" },
   {  559,   "Cabinplant International" },
   {  560,   "Minebea Intec" },
   {  561,   "Comau S.p.A." },
   {  562,   "Phoenix Contact" },
   {  563,   "Yokogawa MAT Corporation" },
   {  564,   "asahi sangyo co., ltd." },
   {  565,   "Valcom" },
   {  566,   "Akita Myotoku Ltd." },
   {  567,   "OBARA Corp." },
   {  568,   "Suetron Electronic GmbH" },
   {  569,   "Reserved" },
   {  570,   "Serck Controls Limited" },
   {  571,   "Fairchild Industrial Products Company" },
   {  572,   "ARO Welding Technologies S.A.S." },
   {  573,   "M2C GmbH" },
   {  574,   "Shin Caterpillar Mitsubishi Ltd." },
   {  575,   "Santest Co., Ltd." },
   {  576,   "Cosmotechs Co., Ltd." },
   {  577,   "Hitachi Electric Systems" },
   {  578,   "Smartscan Ltd" },
   {  579,   "Woodhead Software & Electronics France" },
   {  580,   "Athena Controls, Inc." },
   {  581,   "Norgren Automation Solutions, LLC (previously Syron Engineering & Manufacturing, Inc.)" },
   {  582,   "Asahi Optical Co., Ltd." },
   {  583,   "Sansha Electric Mfg. Co.,Ltd." },
   {  584,   "CKD Nikki Denso Co,. Ltd." },
   {  585,   "Star Micronics, Co., Ltd." },
   {  586,   "Ecotecnia Socirtat Corp." },
   {  587,   "Lenze" },
   {  588,   "West Instruments Limited" },
   {  589,   "LinMot" },
   {  590,   "Delta Computer Systems, Inc." },
   {  591,   "FANUC CORPORATION" },
   {  592,   "Hearn-Gu Lee" },
   {  593,   "ABB AG" },
   {  594,   "Orion Machinery Co., Ltd." },
   {  595,   "Reserved" },
   {  596,   "Wire-Pro, Inc." },
   {  597,   "Beijing Huakong Technology Co. Ltd." },
   {  598,   "Yokoyama Shokai Co., Ltd." },
   {  599,   "Toyogiken Co., Ltd." },
   {  600,   "Coester Equipamentos Eletronicos Ltda." },
   {  601,   "Kawasaki Robot" },
   {  602,   "Electroplating Engineers of Japan Ltd." },
   {  603,   "Robox S.p.a." },
   {  604,   "Spraying Systems Company" },
   {  605,   "Benshaw Inc." },
   {  606,   "ZPA-DP A.S." },
   {  607,   "Wired Rite Systems" },
   {  608,   "Tandis Research, Inc." },
   {  609,   "SSD Drives GmbH" },
   {  610,   "ULVAC Japan Ltd." },
   {  611,   "DYNAX Corporation" },
   {  612,   "Nor-Cal Products, Inc." },
   {  613,   "Aros Electronics AB" },
   {  614,   "Jun-Tech Co., Ltd." },
   {  615,   "HAN-MI Co. Ltd." },
   {  616,   "uniNtech (formerly SungGi Internet)" },
   {  617,   "Hae Pyung Electronics Reserch Institute" },
   {  618,   "Milwaukee Electronics" },
   {  619,   "OBERG Industries" },
   {  620,   "Parker Hannifin/Compumotor Division" },
   {  621,   "TECHNO DIGITAL CORPORATION" },
   {  622,   "Network Supply Co., Ltd." },
   {  623,   "Union Electronics Co., Ltd." },
   {  624,   "Tritronics Services PM Ltd." },
   {  625,   "Rockwell Automation/Sprecher+Schuh" },
   {  626,   "Panasonic Corporation/Motor Company" },
   {  627,   "Rolls-Royce Energy Systems, Inc." },
   {  628,   "JEONGIL INTERCOM CO., LTD" },
   {  629,   "Interroll Software & Electronics GmbH" },
   {  630,   "Hubbell Wiring Device-Kellems (Delaware)" },
   {  631,   "Intelligent Motion Systems" },
   {  632,   "Reserved" },
   {  633,   "INFICON AG" },
   {  634,   "Hirschmann, a Belden brand" },
   {  635,   "The Siemon Company" },
   {  636,   "YAMAHA Motor Co. Ltd." },
   {  637,   "aska corporation" },
   {  638,   "Woodhead Connectivity" },
   {  639,   "Trimble AB" },
   {  640,   "Murrelektronik GmbH" },
   {  641,   "Creatrix Labs, Inc." },
   {  642,   "TopWorx" },
   {  643,   "Kumho Industrial Co., Ltd." },
   {  644,   "Wind River Systems, Inc." },
   {  645,   "Bihl + Wiedemann GmbH" },
   {  646,   "Harmonic Drive Systems Inc." },
   {  647,   "Rikei Corporation" },
   {  648,   "BL Autotec, Ltd." },
   {  649,   "Hana Information & Technology Co., Ltd." },
   {  650,   "Seoil Electric Co., Ltd." },
   {  651,   "Fife Corporation" },
   {  652,   "Shanghai Electrical Apparatus Research Institute" },
   {  653,   "Detector Electronics" },
   {  654,   "Parasense Development Centre" },
   {  655,   "Reserved" },
   {  656,   "Reserved" },
   {  657,   "Six Tau S.p.A." },
   {  658,   "Aucos GmbH" },
   {  659,   "Rotork Controls Ltd." },
   {  660,   "Automationdirect.com" },
   {  661,   "Thermo BLH" },
   {  662,   "System Controls, Ltd." },
   {  663,   "Univer S.p.A." },
   {  664,   "MKS-Tenta Technology" },
   {  665,   "Lika Electronic" },
   {  666,   "Mettler-Toledo" },
   {  667,   "DXL USA Inc." },
   {  668,   "Rockwell Automation/Entek IRD Intl." },
   {  669,   "Nippon Otis Elevator Company" },
   {  670,   "Sinano Electric, Co., Ltd." },
   {  671,   "Sony Manufacturing Systems" },
   {  672,   "Reserved" },
   {  673,   "CONTEC CO., LTD." },
   {  674,   "Automated Solutions" },
   {  675,   "Controlweigh" },
   {  677,   "Fincor Electronics" },
   {  678,   "Cognex Corporation" },
   {  679,   "Qualiflow" },
   {  680,   "Weidmuller, Inc." },
   {  681,   "Morinaga Milk Industry Co., Ltd." },
   {  682,   "Takagi Industrial Co., Ltd." },
   {  683,   "Wittenstein SE" },
   {  684,   "Sena Technologies, Inc." },
   {  685,   "Reserved" },
   {  686,   "SPX Flow Technology Germany GmbH" },
   {  687,   "Creator Teknisk Utvedkling AB" },
   {  688,   "Reserved" },
   {  689,   "Mibu Denki Industrial Co., Ltd." },
   {  690,   "Takamastsu Machineer Section" },
   {  691,   "Littelfuse" },
   {  692,   "Reserved" },
   {  693,   "Holjeron" },
   {  694,   "Pfeiffer Vacuum SAS" },
   {  695,   "Taesan LCD Co., Ltd." },
   {  696,   "POSCON" },
   {  697,   "VMIC" },
   {  698,   "Matsushita Electric Works, Ltd." },
   {  699,   "IAI Corporation" },
   {  700,   "Horst GmbH" },
   {  701,   "MicroControl GmbH & Co." },
   {  702,   "Leine & Linde AB" },
   {  703,   "Reserved" },
   {  704,   "EC Elettronica Srl" },
   {  705,   "VIT Software HB" },
   {  706,   "Bronkhorst High-Tech B.V." },
   {  707,   "Optex Co., Ltd." },
   {  708,   "Yosio Electronic Co." },
   {  709,   "Terasaki Electric Co., Ltd." },
   {  710,   "Sodick Co., Ltd." },
   {  711,   "MTS Systems Corporation-Automation Division" },
   {  712,   "Mesa Systemtechnik" },
   {  713,   "SHIN HO SYSTEM Co., Ltd." },
   {  714,   "Goyo Electronics Co, Ltd." },
   {  715,   "Loreme" },
   {  716,   "SAB Brockskes GmbH & Co. KG" },
   {  717,   "Trumpf Laser GmbH" },
   {  718,   "Niigata Electronic Instruments Co., Ltd." },
   {  719,   "Yokogawa Digital Computer Corporation" },
   {  720,   "O.N. Electronic Co., Ltd." },
   {  721,   "Industrial Control Communication, Inc." },
   {  722,   "ABB, Inc." },
   {  723,   "ElectroWave USA, Inc." },
   {  724,   "Industrial Network Controls, LLC" },
   {  725,   "KDT Systems Co., Ltd." },
   {  726,   "SEFA Technology Inc." },
   {  727,   "Nippon POP Rivets and Fasteners Ltd." },
   {  728,   "Yamato Scale Co., Ltd." },
   {  729,   "Zener Electric" },
   {  730,   "GSE Scale Systems" },
   {  731,   "ISAS (Integrated Switchgear & Sys. Pty Ltd)" },
   {  732,   "Beta LaserMike Limited" },
   {  733,   "TOEI Electric Co., Ltd." },
   {  734,   "Hakko Electronics Co., Ltd" },
   {  735,   "Reserved" },
   {  736,   "RFID, Inc." },
   {  737,   "Adwin Corporation" },
   {  738,   "Osaka Vacuum, Ltd." },
   {  739,   "A-Kyung Motion, Inc." },
   {  740,   "Camozzi Automation spa" },
   {  741,   "Crevis Co., LTD" },
   {  742,   "Rice Lake Weighing Systems" },
   {  743,   "Linux Network Services" },
   {  744,   "KEB Automation KG" },
   {  745,   "Hagiwara Electric Co., Ltd." },
   {  746,   "Glass Inc. International" },
   {  748,   "DVT Corporation" },
   {  749,   "Woodward Governor" },
   {  750,   "Mosaic Systems, Inc." },
   {  751,   "Laserline GmbH" },
   {  752,   "COM-TEC, Inc." },
   {  753,   "Weed Instrument" },
   {  754,   "Prof-face European Technology Center" },
   {  755,   "Fuji Automation Co., Ltd." },
   {  756,   "Matsutame Co., Ltd." },
   {  757,   "Hitachi Via Mechanics, Ltd." },
   {  758,   "Dainippon Screen Mfg. Co. Ltd." },
   {  759,   "FLS Automation A/S" },
   {  760,   "ABB Stotz Kontakt GmbH" },
   {  761,   "Technical Marine Service" },
   {  762,   "Advanced Automation Associates, Inc." },
   {  763,   "Baumer Ident GmbH" },
   {  764,   "Tsubakimoto Chain Co." },
   {  765,   "Reserved" },
   {  766,   "Furukawa Co., Ltd." },
   {  767,   "Active Power" },
   {  768,   "CSIRO Mining Automation" },
   {  769,   "Matrix Integrated Systems" },
   {  770,   "Digitronic Automationsanlagen GmbH" },
   {  771,   "SICK STEGMANN Inc." },
   {  772,   "TAE-Antriebstechnik GmbH" },
   {  773,   "Electronic Solutions" },
   {  774,   "Rocon L.L.C." },
   {  775,   "Dijitized Communications Inc." },
   {  776,   "Asahi Organic Chemicals Industry Co., Ltd." },
   {  777,   "Hodensha" },
   {  778,   "HARTING, Inc. of North America" },
   {  779,   "Kuebler GmbH" },
   {  780,   "Yamatake Corporation" },
   {  781,   "JEOL" },
   {  782,   "Yamatake Industrial Systems Co., Ltd." },
   {  783,   "HAEHNE Elektronische Messgerate GmbH" },
   {  784,   "Ci Technologies Pty Ltd (for Pelamos Industries)" },
   {  785,   "N. SCHLUMBERGER & CIE" },
   {  786,   "Teijin Seiki Co., Ltd." },
   {  787,   "DAIKIN Industries, Ltd" },
   {  788,   "RyuSyo Industrial Co., Ltd." },
   {  789,   "SAGINOMIYA SEISAKUSHO, INC." },
   {  790,   "Seishin Engineering Co., Ltd." },
   {  791,   "Japan Support System Ltd." },
   {  792,   "Decsys" },
   {  793,   "Metronix Messgeraete und Elektronik GmbH" },
   {  794,   "ROPEX Industrie - Elektronik GmbH" },
   {  795,   "Vaccon Company, Inc." },
   {  796,   "Siemens Industry, Inc." },
   {  797,   "Ten X Technology, Inc." },
   {  798,   "TE Connectivity" },
   {  799,   "Delta Electronics, Inc." },
   {  800,   "Denker" },
   {  801,   "Autonics Corporation" },
   {  802,   "JFE Electronic Engineering Pty. Ltd." },
   {  803,   "Reserved" },
   {  804,   "Electro-Sensors, Inc." },
   {  805,   "Digi International, Inc." },
   {  806,   "Texas Instruments" },
   {  807,   "ADTEC Plasma Technology Co., Ltd" },
   {  808,   "SICK AG" },
   {  809,   "Ethernet Peripherals, Inc." },
   {  810,   "Animatics Corporation" },
   {  811,   "Reserved" },
   {  812,   "Process Control Corporation" },
   {  813,   "SystemV. Inc." },
   {  814,   "Danaher Motion SRL" },
   {  815,   "SHINKAWA Sensor Technology, Inc." },
   {  816,   "Tesch GmbH & Co. KG" },
   {  817,   "Reserved" },
   {  818,   "Trend Controls Systems Ltd." },
   {  819,   "Guangzhou ZHIYUAN Electronic Co., Ltd." },
   {  820,   "Mykrolis Corporation" },
   {  821,   "Bethlehem Steel Corporation" },
   {  822,   "KK ICP" },
   {  823,   "Takemoto Denki Corporation" },
   {  824,   "Montalvo Corporation" },
   {  825,   "Reserved" },
   {  826,   "LEONI Special Cables GmbH" },
   {  827,   "Reserved" },
   {  828,   "ONO SOKKI CO.,LTD." },
   {  829,   "RS Automation Co., Ltd." },
   {  830,   "SHINDENGEN ELECTRIC MFG. CO. LTD" },
   {  831,   "Origin Electric Co. Ltd." },
   {  832,   "Quest Technical Solutions, Inc." },
   {  833,   "LS Cable" },
   {  834,   "NORD Electronic DRIVESYSTEMS GmbH" },
   {  835,   "Northwire Inc." },
   {  836,   "Engel Elektroantriebe GmbH" },
   {  837,   "The Stanley Works" },
   {  838,   "Celesco Transducer Products, Inc." },
   {  839,   "Chugoku Electric Wire and Cable Co." },
   {  840,   "Kongsberg Simrad AS" },
   {  841,   "Panduit Corporation" },
   {  842,   "Spellman High Voltage Electronics Corp." },
   {  843,   "Kokusai Electric Alpha Co., Ltd." },
   {  844,   "Brooks Automation, Inc." },
   {  845,   "ANYWIRE CORPORATION" },
   {  846,   "Honda Electronics Co. Ltd" },
   {  847,   "REO AG" },
   {  848,   "Heraeus Noblelight Fusion UV Inc." },
   {  849,   "ASI Advanced Semiconductor Instruments GmbH" },
   {  850,   "Datalogic, Inc." },
   {  851,   "SoftPLC Corporation" },
   {  852,   "Dynisco Instruments LLC" },
   {  853,   "WEG" },
   {  854,   "Teledyne LeCroy (formerly Frontline Test Equipment)" },
   {  855,   "Tamagawa Seiki Co., Ltd." },
   {  856,   "Multi Computing Co., Ltd." },
   {  857,   "RVSI" },
   {  858,   "Commercial Timesharing Inc." },
   {  859,   "Tennessee Rand Automation LLC" },
   {  860,   "Wacogiken Co., Ltd" },
   {  861,   "Reflex Integration Inc." },
   {  862,   "Siemens AG, A&D PI Flow Instruments" },
   {  863,   "G. Bachmann Electronic GmbH" },
   {  864,   "Entegris, Inc." },
   {  865,   "Schweitzer Engineering Laboratories" },
   {  866,   "ATR Industrie-Elektronik GmbH Co." },
   {  867,   "PLASMATECH Co., Ltd" },
   {  868,   "Reserved" },
   {  869,   "GEMUE GmbH & Co. KG" },
   {  870,   "Alcorn McBride Inc." },
   {  871,   "MORI SEIKI CO., LTD" },
   {  872,   "NodeTech Systems Ltd" },
   {  873,   "Emhart Teknologies" },
   {  874,   "Cervis, Inc." },
   {  875,   "MSA Safety" },
   {  876,   "NEDAP Power Supplies" },
   {  877,   "Nippon Sanso Corporation" },
   {  878,   "Mitomi Giken Co., Ltd." },
   {  879,   "PULS GmbH" },
   {  880,   "Reserved" },
   {  881,   "Japan Control Engineering Ltd" },
   {  882,   "Embedded Systems Korea (Former Zues Emtek Co Ltd.)" },
   {  883,   "Automa SRL" },
   {  884,   "Harms+Wende GmbH & Co KG" },
   {  885,   "R. STAHL" },
   {  886,   "Microwave Data Systems" },
   {  887,   "Bernecker + Rainer Industrie-Elektronik GmbH" },
   {  888,   "Hiprom Technologies" },
   {  889,   "Reserved" },
   {  890,   "Nitta Corporation" },
   {  891,   "Kontron Modular Computers GmbH" },
   {  892,   "Marlin Controls" },
   {  893,   "Elcis Encoder s.r.l." },
   {  894,   "Acromag, Inc." },
   {  895,   "Avery Weigh-Tronix" },
   {  896,   "Reserved" },
   {  897,   "Reserved" },
   {  899,   "Practicon Ltd." },
   {  900,   "SCHUNK GmbH & Co. KG" },
   {  901,   "MYNAH Technologies" },
   {  902,   "Defontaine Groupe" },
   {  903,   "Emerson Process Management Power & Water Solutions" },
   {  904,   "F.A. Elec" },
   {  905,   "Hottinger Baldwin Messtechnik GmbH" },
   {  906,   "Teledyne DALSA" },
   {  907,   "London Electronics Ltd." },
   {  908,   "HSD SpA" },
   {  909,   "Pepperl+Fuchs Comtrol" },
   {  910,   "TEAM, S.A. (Tecnica Electronica de Automatismo Y Medida)" },
   {  911,   "Regulateurs Europa Ltd" },
   {  912,   "Reserved" },
   {  913,   "Reserved" },
   {  914,   "Micro Motion" },
   {  915,   "Eckelmann AG" },
   {  916,   "Hanyoung Nux" },
   {  917,   "CFT Ransburg Japan KK" },
   {  918,   "Kun Hung Electric Co. Ltd." },
   {  919,   "Brimos wegbebakening b.v." },
   {  920,   "NITTO SEIKO CO., LTD." },
   {  921,   "Datasensing S.r.l." },
   {  922,   "Yamazaki Machinery Works" },
   {  923,   "Schmidt Technology" },
   {  924,   "Parker Hannifin SpA (SBC Division)" },
   {  925,   "HIMA Paul Hildebrandt GmbH" },
   {  926,   "RivaTek, Inc." },
   {  927,   "Misumi Corporation" },
   {  928,   "GE Multilin" },
   {  929,   "Measurement Computing Corporation" },
   {  930,   "Jetter AG" },
   {  931,   "Tokyo Electronics Systems Corporation" },
   {  932,   "Togami Electric Mfg. Co., Ltd." },
   {  933,   "HK Systems" },
   {  934,   "CDA Systems Ltd." },
   {  935,   "Aerotech Inc." },
   {  936,   "JVL A/S" },
   {  937,   "NovaTech Process Solutions LLC" },
   {  938,   "Reserved" },
   {  939,   "Cisco Systems" },
   {  940,   "Grid Connect" },
   {  941,   "ITW Automotive Finishing" },
   {  942,   "HanYang System" },
   {  943,   "ABB K.K. Technical Center" },
   {  944,   "Taiyo Cable (Dongguan) Co., Ltd." },
   {  945,   "Reserved" },
   {  946,   "SEREN IPS INC" },
   {  947,   "Belden" },
   {  948,   "ControlNet International" },
   {  949,   "Gefran S.P.A." },
   {  950,   "ABB (Jokab Safety)" },
   {  951,   "SUMITA OPTICAL GLASS, INC." },
   {  952,   "Biffi Italia srl" },
   {  953,   "Beck IPC GmbH" },
   {  954,   "Copley Controls" },
   {  955,   "Fagor Automation S. Coop." },
   {  956,   "DARCOM" },
   {  957,   "Frick Controls (div. of York International)" },
   {  958,   "SymCom, Inc." },
   {  959,   "Infranor" },
   {  960,   "Kyosan Electric Mfg" },
   {  961,   "Varian Vacuum Technologies" },
   {  962,   "Messung Systems" },
   {  963,   "Xantrex Technology, Inc." },
   {  964,   "StarThis Inc." },
   {  965,   "NF Chiyoda Electronics Co., Ltd." },
   {  966,   "Flowserve Corporation" },
   {  967,   "Spyder Controls Corp." },
   {  968,   "IBA AG" },
   {  969,   "SHIMOHIRA ELECTRIC MFG.CO.,LTD" },
   {  970,   "Reserved" },
   {  971,   "Siemens L&A" },
   {  972,   "Eaton Automation GmbH (formerly Micro Innovation)" },
   {  973,   "Switchgear & Instrumentation" },
   {  974,   "Pre-Tech Co., Ltd." },
   {  975,   "National Semiconductor" },
   {  976,   "Invensys Operations Management" },
   {  977,   "Ametek HDR Power Systems" },
   {  978,   "Reserved" },
   {  979,   "TETRA-K Corporation" },
   {  980,   "C&M Corporation" },
   {  981,   "Siempelkamp Maschinen" },
   {  982,   "Reserved" },
   {  983,   "Daifuku Co., Ltd" },
   {  984,   "Electro-Matic Products Inc." },
   {  985,   "BUSSAN MICROELECTRONICS CORP." },
   {  986,   "ELAU AG" },
   {  987,   "Hetronic USA" },
   {  988,   "NIIGATA POWER SYSTEMS Co., Ltd." },
   {  989,   "Software Horizons Inc." },
   {  990,   "B3 Systems, Inc." },
   {  991,   "Moxa, Inc." },
   {  992,   "Reserved" },
   {  993,   "S4 Integration" },
   {  994,   "Elettro Stemi S.R.L." },
   {  995,   "AquaSensors" },
   {  996,   "Ifak System GmbH" },
   {  997,   "SANKEI MANUFACTURING Co.,LTD." },
   {  998,   "Emerson Network Power Co., Ltd." },
   {  999,   "Fairmount Automation, Inc." },
   { 1000,   "Bird Electronic Corporation" },
   { 1001,   "Nabtesco Corporation" },
   { 1002,   "AGM Electronics, Inc." },
   { 1003,   "ARCX Inc." },
   { 1004,   "DELTA I/O Co." },
   { 1005,   "Chun IL Electric Ind. Co." },
   { 1006,   "N-Tron Corporation, a Red Lion Company" },
   { 1007,   "Nippon Pneumatics/Fludics System CO.,LTD." },
   { 1008,   "DDK Ltd." },
   { 1009,   "Seiko Epson Corporation" },
   { 1010,   "halstrup-walcher GmbH" },
   { 1011,   "ITT" },
   { 1012,   "Ground Fault Systems bv" },
   { 1013,   "Scolari Engineering S.p.A." },
   { 1014,   "Vialis Traffic bv" },
   { 1015,   "Weidmueller Group" },
   { 1016,   "Shanghai Sibotech Automation Co. Ltd" },
   { 1017,   "AEG Power Solutions GmbH" },
   { 1018,   "Komatsu Electronics Inc." },
   { 1019,   "Souriau" },
   { 1020,   "Baumuller Chicago Corp." },
   { 1021,   "J. Schmalz GmbH" },
   { 1022,   "SEN Corporation" },
   { 1023,   "Korenix Technology Co. Ltd" },
   { 1024,   "Cooper Power Tools" },
   { 1025,   "INNOBIS" },
   { 1026,   "Shinho System" },
   { 1027,   "Xm Services Ltd." },
   { 1028,   "KVC Co., Ltd." },
   { 1029,   "Sanyu Seiki Co., Ltd." },
   { 1030,   "TuxPLC" },
   { 1031,   "Northern Network Solutions" },
   { 1032,   "Converteam GmbH" },
   { 1033,   "Symbol Technologies" },
   { 1034,   "S-TEAM Lab" },
   { 1035,   "Maguire Products, Inc." },
   { 1036,   "AC&T" },
   { 1037,   "MITSUBISHI HEAVY INDUSTRIES, LTD. KOBE SHIPYARD & MACHINERY WORKS" },
   { 1038,   "Hurletron Inc." },
   { 1039,   "Chunichi Denshi Co., Ltd" },
   { 1040,   "Cardinal Scale Mfg. Co." },
   { 1041,   "METZ CONNECT USA Inc." },
   { 1042,   "Base2" },
   { 1043,   "ASRC Aerospace" },
   { 1044,   "Beijing Stone Automation" },
   { 1045,   "Changshu Switchgear Manufacture Ltd." },
   { 1046,   "METRONIX Corp." },
   { 1047,   "WIT" },
   { 1048,   "ORMEC Systems Corp." },
   { 1049,   "ASATech (China) Inc." },
   { 1050,   "Controlled Systems Limited" },
   { 1051,   "Mitsubishi Heavy Ind. Digital System Co., Ltd. (M.H.I.)" },
   { 1052,   "Electrogrip" },
   { 1053,   "TDS Automation" },
   { 1054,   "T&C Power Conversion, Inc." },
   { 1055,   "Robostar Co., Ltd" },
   { 1056,   "Scancon A/S" },
   { 1057,   "Haas Automation, Inc." },
   { 1058,   "Eshed Technology" },
   { 1059,   "Delta Electronic Inc." },
   { 1060,   "Innovasic" },
   { 1061,   "SoftDEL Systems Limited" },
   { 1062,   "FiberFin, Inc." },
   { 1063,   "Nicollet Technologies Corp." },
   { 1064,   "B.F. Systems" },
   { 1065,   "Empire Wire and Supply LLC" },
   { 1066,   "ENDO KOGYO CO., LTD" },
   { 1067,   "Elmo Motion Control LTD" },
   { 1068,   "Reserved" },
   { 1069,   "Asahi Keiki Co., Ltd." },
   { 1070,   "Joy Mining Machinery" },
   { 1071,   "MPM Engineering Ltd." },
   { 1072,   "Wolke Inks & Printers GmbH" },
   { 1073,   "Mitsubishi Electric Engineering Co., Ltd." },
   { 1074,   "COMET AG" },
   { 1075,   "Real Time Objects & Systems, LLC" },
   { 1076,   "MISCO Refractometer" },
   { 1077,   "JT Engineering Inc." },
   { 1078,   "Automated Packing Systems" },
   { 1079,   "Niobrara R&D Corp." },
   { 1080,   "Garmin Ltd." },
   { 1081,   "Japan Mobile Platform Co., Ltd" },
   { 1082,   "Advosol Inc." },
   { 1083,   "ABB Global Services Limited" },
   { 1084,   "Sciemetric Instruments Inc." },
   { 1085,   "Tata Elxsi Ltd." },
   { 1086,   "Mechatronics Co.,Ltd" },
   { 1087,   "Cooper Bussmann" },
   { 1088,   "Trinite Automatisering B.V." },
   { 1089,   "Peek Traffic B.V." },
   { 1090,   "Acrison, Inc." },
   { 1091,   "Applied Robotics, Inc." },
   { 1092,   "FireBus LLC" },
   { 1093,   "Sevenstar" },
   { 1094,   "Magnetek" },
   { 1095,   "Omron Microscan Systems, Inc." },
   { 1096,   "Air Water Inc." },
   { 1097,   "SensoPart Industriesensorik GmbH" },
   { 1098,   "Tiefenbach Control Systems GmbH" },
   { 1099,   "INOXPA S.A" },
   { 1100,   "Zurich University of Applied Sciences" },
   { 1101,   "Ethernet Direct" },
   { 1102,   "GSI-Micro-E Systems" },
   { 1103,   "S-Net Automation Co., Ltd." },
   { 1104,   "Power Electronics S.L." },
   { 1105,   "Renesas Electronics" },
   { 1106,   "NSWCCD-SSES" },
   { 1107,   "Porter Engineering Ltd." },
   { 1108,   "Meggitt Airdynamics, Inc." },
   { 1109,   "Inductive Automation" },
   { 1110,   "Neural ID" },
   { 1111,   "EEPod LLC" },
   { 1112,   "Hitachi Industrial Equipment Systems Co.,Ltd." },
   { 1113,   "Salem Automation" },
   { 1114,   "port GmbH" },
   { 1115,   "B & PLUS" },
   { 1116,   "Graco Inc." },
   { 1117,   "Altera Corporation" },
   { 1118,   "Technology Brewing Corporation" },
   { 1119,   "Reserved" },
   { 1120,   "Reserved" },
   { 1121,   "CSE Servelec" },
   { 1122,   "Reserved" },
   { 1123,   "Reserved" },
   { 1124,   "Fluke Networks" },
   { 1125,   "Tetra Pak Packaging Solutions SpA" },
   { 1126,   "Racine Federated, Inc." },
   { 1127,   "Pureron Japan Co., Ltd." },
   { 1128,   "Reserved" },
   { 1129,   "Reserved" },
   { 1130,   "Brother Industries, Ltd." },
   { 1131,   "Reserved" },
   { 1132,   "Leroy Automation" },
   { 1133,   "Reserved" },
   { 1134,   "THK Co., Ltd." },
   { 1135,   "Reserved" },
   { 1136,   "Reserved" },
   { 1137,   "TR-Electronic GmbH" },
   { 1138,   "ASCON S.p.A." },
   { 1139,   "Toledo do Brasil Industria de Balancas Ltda." },
   { 1140,   "Caterpillar Global Mining Europe GmbH" },
   { 1141,   "Emerson Process Management Valve Automation" },
   { 1142,   "Alstom Transport" },
   { 1143,   "Reserved" },
   { 1144,   "Matrox Electronic Systems" },
   { 1145,   "Littelfuse" },
   { 1146,   "PLASMART, Inc." },
   { 1147,   "Miyachi Corporation" },
   { 1148,   "Reserved" },
   { 1149,   "Reserved" },
   { 1150,   "Promess Incorporated" },
   { 1151,   "COPA-DATA GmbH" },
   { 1152,   "Precision Engine Controls Corporation" },
   { 1153,   "Alga Automacao e controle LTDA" },
   { 1154,   "Lapp Group" },
   { 1155,   "ICES" },
   { 1156,   "Philips Lighting bv" },
   { 1157,   "Aseptomag AG" },
   { 1158,   "ARC Informatique" },
   { 1159,   "Hesmor GmbH" },
   { 1160,   "Kobe Steel, Ltd." },
   { 1161,   "FLIR Systems" },
   { 1162,   "Xcelgo A/S" },
   { 1163,   "STRATON AUTOMATION" },
   { 1164,   "Zypcom, Inc." },
   { 1165,   "Swagelok" },
   { 1166,   "Elspec" },
   { 1167,   "ITT Water & Wastewater AB" },
   { 1168,   "Kunbus GmbH Industrial Communication" },
   { 1169,   "Reserved" },
   { 1170,   "Performance Controls, Inc." },
   { 1171,   "ACS Motion Control, Ltd." },
   { 1172,   "Reserved" },
   { 1173,   "IStar Technology Limited" },
   { 1174,   "Alicat Scientific, Inc." },
   { 1175,   "Reserved" },
   { 1176,   "ADFweb.com SRL" },
   { 1177,   "Tata Consultancy Services Limited" },
   { 1178,   "CXR Ltd." },
   { 1179,   "Vishay Nobel AB" },
   { 1180,   "Reserved" },
   { 1181,   "Emerson - SolaHD" },
   { 1182,   "Endress+Hauser" },
   { 1183,   "Bartec GmbH" },
   { 1184,   "Reserved" },
   { 1185,   "AccuSentry, Inc." },
   { 1186,   "Curtiss Wright - Exlar Actuator Solutions" },
   { 1187,   "ILS Technology" },
   { 1188,   "Control Concepts, Inc." },
   { 1189,   "Reserved" },
   { 1190,   "Procon Engineering A Division of National Oilwell Varco UK Ltd" },
   { 1191,   "Hermary" },
   { 1192,   "Q-Lambda" },
   { 1193,   "Reserved" },
   { 1194,   "VAMP Ltd" },
   { 1195,   "FlexLink" },
   { 1196,   "Office FA.com Co., Ltd." },
   { 1197,   "SPMC (Changzhou) Co. Ltd." },
   { 1198,   "Anton Paar GmbH" },
   { 1199,   "Zhuzhou CSR Times Electric Co., Ltd." },
   { 1200,   "DeStaCo" },
   { 1201,   "Synrad, Inc" },
   { 1202,   "Bonfiglioli Vectron GmbH" },
   { 1203,   "Pivotal Systems" },
   { 1204,   "TKSCT" },
   { 1205,   "Randy Nuernberger" },
   { 1206,   "CENTRALP" },
   { 1207,   "Tengen Group" },
   { 1208,   "OES, Inc." },
   { 1209,   "Actel Corporation" },
   { 1210,   "Monaghan Engineering, Inc." },
   { 1211,   "wenglor sensoric gmbh" },
   { 1212,   "HSA Systems" },
   { 1213,   "MKP Co., Ltd." },
   { 1214,   "Tappan Wire and Cable" },
   { 1215,   "Heinzmann GmbH & Co. KG" },
   { 1216,   "Process Automation International Ltd." },
   { 1217,   "Secure Crossing" },
   { 1218,   "SMA Railway Technology GmbH" },
   { 1219,   "FMS Force Measuring Systems AG" },
   { 1220,   "ABT Endustri Enerji Sistemleri Sanayi Tic. Ltd. Sti." },
   { 1221,   "MagneMotion Inc." },
   { 1222,   "STS Co., Ltd." },
   { 1223,   "Knorr-Bremse Espana, S.A. - Merak Division" },
   { 1224,   "ABOUNDI, Inc." },
   { 1225,   "Rosemount Inc." },
   { 1226,   "GEA FES, Inc." },
   { 1227,   "TMG Technologie und Engineering GmbH" },
   { 1228,   "embeX GmbH" },
   { 1229,   "GH Electrotermia, S.A." },
   { 1230,   "Tolomatic" },
   { 1231,   "Dukane" },
   { 1232,   "Elco (Tian Jin) Electronics Co., Ltd." },
   { 1233,   "Jacobs Automation" },
   { 1234,   "Noda Radio Frequency Technologies Co., Ltd." },
   { 1235,   "MSC Tuttlingen GmbH" },
   { 1236,   "Hitachi Cable Manchester" },
   { 1237,   "ACOREL SAS" },
   { 1238,   "Global Engineering Solutions Co., Ltd." },
   { 1239,   "ALTE Transportation, S.L." },
   { 1240,   "Penko Engineering B.V." },
   { 1241,   "Z-Tec Automation Systems Inc." },
   { 1242,   "ENTRON Controls LLC" },
   { 1243,   "Johannes Huebner Fabrik Elektrischer Maschinen GmbH" },
   { 1244,   "RF IDeas, Inc." },
   { 1245,   "Pentronic AB" },
   { 1246,   "Atlas Copco IAS GmbH" },
   { 1247,   "TDK-Lambda Corporation" },
   { 1248,   "Reserved" },
   { 1249,   "Reserved" },
   { 1250,   "Altronic LLC" },
   { 1251,   "Siemens AG" },
   { 1252,   "Liebherr Transportation Systems GmbH & Co KG" },
   { 1253,   "Reserved" },
   { 1254,   "Reserved" },
   { 1255,   "Reserved" },
   { 1256,   "LMI Technologies" },
   { 1257,   "Reserved" },
   { 1258,   "Reserved" },
   { 1259,   "Reserved" },
   { 1260,   "Reserved" },
   { 1261,   "CEPHALOS Automatisierung mbH" },
   { 1262,   "Reserved" },
   { 1263,   "Reserved" },
   { 1264,   "Reserved" },
   { 1265,   "Quabbin Wire & Cable Co., Inc." },
   { 1266,   "Reserved" },
   { 1267,   "Reserved" },
   { 1268,   "HORIBA Precision Instruments (Beijing) Co.,Ltd." },
   { 1269,   "Reserved" },
   { 1270,   "Rovema GmbH" },
   { 1271,   "Reserved" },
   { 1272,   "IEP GmbH" },
   { 1273,   "Reserved" },
   { 1274,   "Reserved" },
   { 1275,   "Reserved" },
   { 1276,   "Reserved" },
   { 1277,   "Control Chief Corporation" },
   { 1278,   "Reserved" },
   { 1279,   "Reserved" },
   { 1280,   "Reserved" },
   { 1281,   "Reserved" },
   { 1282,   "PRIMES GmbH" },
   { 1283,   "Branson Ultrasonics" },
   { 1284,   "DEIF A/S" },
   { 1285,   "CODESYS GmbH" },
   { 1286,   "Reserved" },
   { 1287,   "Smarteye Corporation" },
   { 1288,   "Shibaura Machine" },
   { 1289,   "HMS/BU Ewon" },
   { 1290,   "OFS" },
   { 1291,   "KROHNE" },
   { 1292,   "Reserved" },
   { 1293,   "Reserved" },
   { 1294,   "Reserved" },
   { 1295,   "Kistler Instrumente AG" },
   { 1296,   "Reserved" },
   { 1297,   "Reserved" },
   { 1298,   "Reserved" },
   { 1299,   "Reserved" },
   { 1300,   "Reserved" },
   { 1301,   "Xylem Analytics Germany GmbH" },
   { 1302,   "Lenord, Bauer & Co. GmbH" },
   { 1303,   "Carlo Gavazzi Controls" },
   { 1304,   "Faiveley Transport" },
   { 1305,   "Reserved" },
   { 1306,   "Sensia LLC" },
   { 1307,   "Kepware Technologies" },
   { 1308,   "duagon AG" },
   { 1309,   "Reserved" },
   { 1310,   "Xylem Water Solutions" },
   { 1311,   "Automation Professionals, LLC" },
   { 1312,   "Reserved" },
   { 1313,   "CEIA SpA" },
   { 1314,   "Reserved" },
   { 1315,   "Alphagate Automatisierungstechnik GmbH" },
   { 1316,   "Mecco Partners, LLC" },
   { 1317,   "LAP GmbH Laser Applikationen" },
   { 1318,   "ABB S.p.A. - SACE Division" },
   { 1319,   "Reserved" },
   { 1320,   "Reserved" },
   { 1321,   "C.E. Electronics, Inc." },
   { 1322,   "Thermo Ramsey Inc., a part of Thermo Fisher Scientific" },
   { 1323,   "Helmholz GmbH & Co. KG" },
   { 1324,   "EUCHNER GmbH + Co. KG" },
   { 1325,   "AMKmotion" },
   { 1326,   "Badger Meter" },
   { 1327,   "Reserved" },
   { 1328,   "Fisher-Rosemount Systems, Inc. doing business as Process Systems & Solutions" },
   { 1329,   "Conductix-Wampfler Automation GmbH" },
   { 1330,   "Fairbanks Scales, Inc." },
   { 1331,   "Imperx, Inc." },
   { 1332,   "FRONIUS International GmbH" },
   { 1333,   "Hoffman Enclosures" },
   { 1334,   "Elecsys Corporation" },
   { 1335,   "Reserved" },
   { 1336,   "RACO Manufacturing and Engineering" },
   { 1337,   "Hein Lanz Industrial Tech." },
   { 1338,   "Codenomicon" },
   { 1339,   "SABO Elektronik GmbH" },
   { 1340,   "Reserved" },
   { 1341,   "Sensirion AG" },
   { 1342,   "SIKO GmbH" },
   { 1343,   "Reserved" },
   { 1344,   "GRUNDFOS" },
   { 1345,   "Reserved" },
   { 1346,   "Beijer Electronics Products AB" },
   { 1347,   "Reserved" },
   { 1348,   "AIMCO" },
   { 1349,   "Reserved" },
   { 1350,   "Coval" },
   { 1351,   "Powell Industries" },
   { 1352,   "Reserved" },
   { 1353,   "IPDisplays" },
   { 1354,   "SCAIME SAS" },
   { 1355,   "Metal Work SpA" },
   { 1356,   "Telsonic AG" },
   { 1357,   "Reserved" },
   { 1358,   "Hauch & Bach ApS" },
   { 1359,   "Pago AG" },
   { 1360,   "ULTIMATE Europe Transportation Equipment GmbH" },
   { 1361,   "Reserved" },
   { 1362,   "FW Murphy Production Controls, LLC" },
   { 1363,   "Lake Cable LLC" },
   { 1364,   "Reserved" },
   { 1365,   "Reserved" },
   { 1366,   "Reserved" },
   { 1367,   "Reserved" },
   { 1368,   "Nanotec Electronic GmbH & Co. KG" },
   { 1369,   "SAMWON ACT Co., Ltd." },
   { 1370,   "Aparian Inc." },
   { 1371,   "Cosys Inc." },
   { 1372,   "Insight Automation Inc." },
   { 1373,   "Reserved" },
   { 1374,   "FASTECH" },
   { 1375,   "K.A. Schmersal GmbH & Co. KG" },
   { 1376,   "Reserved" },
   { 1377,   "Reserved" },
   { 1378,   "SEIDENSHA ELECTRONICS CO., LTD" },
   { 1379,   "Reserved" },
   { 1380,   "Don Electronics Ltd" },
   { 1381,   "burster gmbh & co kg" },
   { 1382,   "Unitronics (1989) (RG) LTD" },
   { 1383,   "OEM Technology Solutions" },
   { 1384,   "Allied Motion" },
   { 1385,   "Reserved" },
   { 1386,   "DENGENSHA TOA CO., LTD" },
   { 1387,   "Systec Systemtechnik und Industrieautomation GmbH" },
   { 1388,   "Reserved" },
   { 1389,   "Jenny Science AG" },
   { 1390,   "Baumer Optronic GmbH" },
   { 1391,   "Invertek Drives Ltd" },
   { 1392,   "High Grade Controls Corporation" },
   { 1393,   "Reserved" },
   { 1394,   "Reserved" },
   { 1395,   "Reserved" },
   { 1396,   "Actia Systems" },
   { 1397,   "Reserved" },
   { 1398,   "Beijing Tianma Intelligent Control Technology Co., Ltd" },
   { 1399,   "Universal Robots A/S" },
   { 1400,   "Reserved" },
   { 1401,   "Dialight" },
   { 1402,   "E-T-A Elektrotechnische Apparate GmbH" },
   { 1403,   "Kemppi Oy" },
   { 1404,   "Reserved" },
   { 1405,   "ORing Industrial Networking Corp." },
   { 1406,   "Reserved" },
   { 1407,   "Reserved" },
   { 1408,   "ELAP S.R.L." },
   { 1409,   "Applied Mining Technologies" },
   { 1410,   "KITZ SCT Corporation" },
   { 1411,   "VTEX Corporation" },
   { 1412,   "ESYSE GmbH Embedded Systems Engineering" },
   { 1413,   "Automation Controls" },
   { 1414,   "Reserved" },
   { 1415,   "Cincinnati Test Systems" },
   { 1416,   "Reserved" },
   { 1417,   "Zumbach Electronics Corp." },
   { 1418,   "Emerson Automation Solutions" },
   { 1419,   "CCS Inc." },
   { 1420,   "Videojet, Inc." },
   { 1421,   "Zebra Technologies" },
   { 1422,   "ANRITSU CORPORATION" },
   { 1423,   "Dimetix AG" },
   { 1424,   "General Measure (China)" },
   { 1425,   "Fortress Interlocks" },
   { 1426,   "Reserved" },
   { 1427,   "Task Force Tips" },
   { 1428,   "SERVO-ROBOT INC." },
   { 1429,   "Flow Devices and Systems, Inc." },
   { 1430,   "nLIGHT, Inc." },
   { 1431,   "Microchip Technology Inc." },
   { 1432,   "Reserved" },
   { 1433,   "Reserved" },
   { 1434,   "Accutron Instruments Inc." },
   { 1435,   "Kaeser Kompressoren SE" },
   { 1436,   "Reserved" },
   { 1437,   "Coherix, Inc." },
   { 1438,   "FLSmidth A/S" },
   { 1439,   "Reserved" },
   { 1440,   "Cole-Parmer Instrument Company" },
   { 1441,   "Wachendorff Automation GmbH & Co., KG" },
   { 1442,   "SMAC Moving Coil Actuators" },
   { 1444,   "PushCorp, Inc." },
   { 1445,   "Fluke Process Instruments GmbH" },
   { 1446,   "Mini Motor S.p.a" },
   { 1447,   "I-CON Industry Tech." },
   { 1448,   "Grace Technologies" },
   { 1449,   "Zaxis Inc." },
   { 1450,   "Lumasense Technologies" },
   { 1451,   "Domino Printing" },
   { 1452,   "Reserved" },
   { 1453,   "Reserved" },
   { 1454,   "Altus Sistemas de Automação S.A." },
   { 1455,   "Reserved" },
   { 1456,   "InterTech Development Company" },
   { 1457,   "Reserved" },
   { 1458,   "Perle Systems Limited" },
   { 1459,   "Utthunga Technologies Pvt Ltd.," },
   { 1460,   "Reserved" },
   { 1461,   "WIPOTEC GmbH" },
   { 1462,   "Atos spa" },
   { 1463,   "Solartron Metrology LTD" },
   { 1464,   "Reserved" },
   { 1465,   "Analog Devices" },
   { 1466,   "Power Electronics International, Inc." },
   { 1468,   "Campbell Wrapper Corporation" },
   { 1469,   "Herkules-Resotec Elektronik GmbH" },
   { 1470,   "aignep spa" },
   { 1471,   "Reserved" },
   { 1472,   "PMV Automation AB" },
   { 1473,   "Reserved" },
   { 1474,   "ProTec Dynatronix LLC dba Dynatronix" },
   { 1475,   "Reserved" },
   { 1476,   "Bitronics, LLC." },
   { 1477,   "Delta Tau Data Systems" },
   { 1478,   "Reserved" },
   { 1479,   "AUTOSOL" },
   { 1480,   "ADB Safegate" },
   { 1481,   "Reserved" },
   { 1482,   "Reserved" },
   { 1483,   "Artis GmbH" },
   { 1484,   "REJ Co., LTD" },
   { 1485,   "Vanderlande" },
   { 1486,   "Packet Power" },
   { 1487,   "ima-tec gmbh" },
   { 1488,   "Vision Automation A/S" },
   { 1489,   "PROCENTEC BV" },
   { 1490,   "HETRONIK GmbH" },
   { 1491,   "Lanmark Controls Inc." },
   { 1492,   "Reserved" },
   { 1493,   "flexlog GmbH" },
   { 1494,   "YUCHANGTECH" },
   { 1495,   "Dynapower Company" },
   { 1496,   "TAKIKAWA ENGINEERING" },
   { 1497,   "Ingersoll Rand" },
   { 1498,   "ASA-RT s.r.l" },
   { 1499,   "TRUMPF Schweiz AG" },
   { 1500,   "Reserved" },
   { 1501,   "Rinstrum" },
   { 1502,   "Reserved" },
   { 1503,   "Reserved" },
   { 1504,   "BlueBotics SA" },
   { 1505,   "Dynapar Corporation" },
   { 1506,   "Blum-Novotest" },
   { 1507,   "CIMON" },
   { 1508,   "Dalian SeaSky Automation Co., ltd" },
   { 1509,   "Rethink Robotics GmbH" },
   { 1510,   "Ingeteam Power Technology S. A." },
   { 1511,   "TOSEI ENGINEERING CORP." },
   { 1512,   "SAMSON AG" },
   { 1513,   "TGW Mechanics GmbH" },
   { 1514,   "Diatrend Corporation" },
   { 1515,   "Reserved" },
   { 1516,   "VAHLE Automation GmbH" },
   { 1517,   "JSL Technology Co.,Ltd." },
   { 1518,   "NetTechnix E&P GmbH" },
   { 1519,   "Reserved" },
   { 1520,   "Tecweigh" },
   { 1521,   "IVEK Corporation" },
   { 1522,   "Reserved" },
   { 1523,   "AQ M-TECH AB" },
   { 1524,   "Rexnord Industries LLC" },
   { 1525,   "Reserved" },
   { 1526,   "OPTEX FA Co., Ltd" },
   { 1527,   "Volktek Corporation" },
   { 1528,   "INGENIA" },
   { 1529,   "Reserved" },
   { 1530,   "Analytical Technology, Inc." },
   { 1531,   "Columbus McKinnon Corporation" },
   { 1532,   "HBC-radiomatic GmbH" },
   { 1533,   "Leonton Technologies" },
   { 1534,   "Mitsubishi Electric India Pvt. Ltd." },
   { 1535,   "FOBA Laser, ALLTEC GmbH" },
   { 1536,   "Leakmaster Inc" },
   { 1537,   "Buhler AG" },
   { 1538,   "LINAK Denmark A/S" },
   { 1539,   "Reserved" },
   { 1540,   "SIEB & MEYER AG" },
   { 1541,   "Reserved" },
   { 1542,   "Watson-Marlow Ltd" },
   { 1543,   "ABB Switzerland Ltd - Low Voltage Products" },
   { 1544,   "Reserved" },
   { 1545,   "adphos" },
   { 1546,   "Hangzhou Hikrobot Technology Co., Ltd." },
   { 1547,   "TOSS GmbH & Co. KG" },
   { 1548,   "Solar Turbines Incorporated" },
   { 1549,   "Reserved" },
   { 1550,   "Reserved" },
   { 1551,   "Carlo Gavazzi Industri" },
   { 1552,   "Nippon Gear" },
   { 1553,   "OSIsoft, LLC" },
   { 1554,   "Rinco Ultrasonics AG" },
   { 1555,   "Reserved" },
   { 1556,   "Reserved" },
   { 1557,   "Mitutoyo" },
   { 1558,   "swisca" },
   { 1559,   "Micro-Epsilon Messtechnik GmbH & Co. KG" },
   { 1560,   "AMADA MIYACHI AMERICA" },
   { 1561,   "Taihan Electric Wire Co., Ltd." },
   { 1562,   "JANOME Corporation" },
   { 1563,   "ISHIDA" },
   { 1564,   "NAKANISHI INC." },
   { 1565,   "Mecademic Inc." },
   { 1566,   "Reserved" },
   { 1567,   "Sigma (NSW) PTY LTD" },
   { 1568,   "Hammond Power Solutions Inc.-Mesta" },
   { 1569,   "Reserved" },
   { 1570,   "Reserved" },
   { 1571,   "TRIDIMEO" },
   { 1572,   "Motortronics UK Ltd." },
   { 1573,   "Doosan Robotics" },
   { 1574,   "ADVANCED Motion Controls" },
   { 1575,   "OnRobot A/S" },
   { 1576,   "Reserved" },
   { 1577,   "Oetiker" },
   { 1578,   "SICK OPTEX" },
   { 1579,   "Reserved" },
   { 1580,   "Reserved" },
   { 1581,   "Kahler Automation Corporation" },
   { 1582,   "Accuenergy (Canada) Inc." },
   { 1583,   "TCI, LLC - An Allied Motion Company" },
   { 1584,   "Sun Automation" },
   { 1585,   "READY Robotics Corporation" },
   { 1586,   "PEM, Power Eng & Mfg., Inc" },
   { 1587,   "Dürr Somac GmbH" },
   { 1588,   "Reserved" },
   { 1589,   "Reserved" },
   { 1590,   "Reserved" },
   { 1591,   "RICOH Industrial Solutions Inc." },
   { 1592,   "Shanghai Junqian Sensing Technology Co. Ltd." },
   { 1593,   "Knick Elektronische Messgeräte GmbH & Co. KG" },
   { 1594,   "Magnescale. Co., Ltd." },
   { 1595,   "Reserved" },
   { 1596,   "Weintek Labs., Inc" },
   { 1597,   "Sherpa, Inc." },
   { 1598,   "Inspekto A.M.V LTD" },
   { 1599,   "Hydronix Ltd" },
   { 1600,   "AIOI- SYSTEMS CO. LTD." },
   { 1601,   "Ingenieurbüro Mewes & Partner GmbH" },
   { 1602,   "HIGHYAG Lasertechnologie GmbH" },
   { 1603,   "Ningbo Jetron Technology Co. Ltd." },
   { 1604,   "Myostat Motion Control" },
   { 1605,   "A-T Controls, Inc" },
   { 1606,   "M2M craft Co., Ltd." },
   { 1607,   "FUTEK Advanced Sensor Technology, Inc." },
   { 1608,   "Cetek" },
   { 1609,   "Norgren Manufacturing Co., Ltd." },
   { 1610,   "Bernstein AG" },
   { 1611,   "Hitachi Industrial Products, Ltd." },
   { 1612,   "Reserved" },
   { 1613,   "Duplomatic MS spa" },
   { 1614,   "Ambrit Ltd" },
   { 1615,   "Highlight Tech Corp." },
   { 1616,   "New Power Plasma Co. Ltd." },
   { 1617,   "AGCO Corporation" },
   { 1618,   "Techman Robot" },
   { 1619,   "Nabeya Bi-tech Kaisha" },
   { 1620,   "Reserved" },
   { 1621,   "Panasonic Corporation / Electric Works Company" },
   { 1622,   "Cytiva" },
   { 1623,   "Janasi Industries Ltd." },
   { 1624,   "Haffmans BV" },
   { 1625,   "Reserved" },
   { 1626,   "Omniview Pty Ltd" },
   { 1627,   "Reserved" },
   { 1628,   "Dover Flexo Electronics" },
   { 1629,   "Reserved" },
   { 1630,   "IDEM Safety Switches" },
   { 1631,   "Sonotroagel GmbH" },
   { 1632,   "Thermo Gamma-Metrics LLC, a part of Thermo Fisher Scientific" },
   { 1633,   "BBH Products" },
   { 1634,   "RSI Elektrotechnik" },
   { 1635,   "Carlo Gavazzi Ltd" },
   { 1636,   "KOFLOC Corp." },
   { 1637,   "VTScada by Trihedral" },
   { 1638,   "Hach" },
   { 1639,   "Cogniac" },
   { 1640,   "Toshiba Infrastructure Systems & Solutions Corporation" },
   { 1641,   "Cannon-Automata" },
   { 1642,   "Rosenberger" },
   { 1643,   "Blue-White Industries" },
   { 1644,   "Cellumation GmbH" },
   { 1645,   "TEAC Corp." },
   { 1646,   "AEG Identifikationssysteme GmbH" },
   { 1647,   "MARS TOHKEN SOLUTION CO.LTD." },
   { 1648,   "Midas Technology Corp." },
   { 1649,   "Dinkle Enterprise Co., Ltd." },
   { 1650,   "THALES" },
   { 1651,   "Dunkermotoren" },
   { 1652,   "SONOTEC GmbH" },
   { 1653,   "Brinkmann Pumpen" },
   { 1654,   "Rheonics" },
   { 1655,   "Precimeter" },
   { 1656,   "Reserved" },
   { 1657,   "ALGO SYSTEM CO., LTD." },
   { 1658,   "Christ Electronic Systems GmbH" },
   { 1659,   "JFcontrol Co., Ltd." },
   { 1660,   "Shenzhen Inovance Technology Co., Ltd" },
   { 1661,   "Rheonik Coriolis Mass Flow Sensors" },
   { 1662,   "Ichor Systems, Inc." },
   { 1663,   "di-soric GmbH & Co. KG" },
   { 1664,   "Amphenol ICC" },
   { 1665,   "Ningbo AirTAC Automation Industrial Co., Ltd." },
   { 1666,   "RSI" },
   { 1667,   "Soft Robotics Inc." },
   { 1668,   "MUSCLE CORPORATION" },
   { 1669,   "Spotlight Systems LLC" },
   { 1670,   "Afag Holding AG" },
   { 1671,   "TELESIS TECHNOLOGIES INC" },
   { 1672,   "SSI Schaefer Automation GmbH" },
   { 1673,   "Super Systems, Inc." },
   { 1674,   "CoreTigo LTD" },
   { 1675,   "Inxpect SPA" },
   { 1676,   "Kostal Industrie Elektrik GmbH" },
   { 1677,   "JingQi (Tianjin) technology Co.,Ltd" },
   { 1678,   "AGI Suretrack" },
   { 1679,   "JAKA Robotics Co., Ltd." },
   { 1680,   "Polarteknik Oy" },
   { 1681,   "RoboteQ, Inc" },
   { 1682,   "Uson" },
   { 1683,   "Opt Machine Vision Tech Co., Ltd" },
   { 1684,   "Asyril SA" },
   { 1685,   "Georg Fischer Piping Systems" },
   { 1686,   "Aber Instruments Ltd" },
   { 1687,   "CodeWrights GmbH" },
   { 1688,   "Neurala, Inc." },
   { 1689,   "Panasonic Software Development Center Dalian Co.,Ltd." },
   { 1690,   "Perinet GmbH" },
   { 1691,   "MS Ultraschall Technologie GmbH" },
   { 1692,   "PLASUS GmbH" },
   { 1693,   "Nikon Corporation" },
   { 1694,   "Shenzhen Hengzhiyuan Technology Corporation Ltd." },
   { 1695,   "Kowa Optronics Co., Ltd." },
   { 1696,   "Specialist Mechanical Engineers" },
   { 1697,   "CMD Corporation" },
   { 1698,   "Sanwa Engineering Corp." },
   { 1699,   "Intellore Systems Pvt. Ltd" },
   { 1700,   "Toledo e Souza" },
   { 1701,   "PBS Biotech, Inc" },
   { 1702,   "PLANET Technology Corporation" },
   { 1703,   "Robatech AG" },
   { 1704,   "MARKEM-IMAJE" },
   { 1705,   "Novanta IMS" },
   { 1706,   "Bamboo-Dynamics" },
   { 1707,   "FACTS Engineering, LLC" },
   { 1708,   "Digital Dynamics" },
   { 1709,   "Fatek Automation Corporation" },
   { 1710,   "Hanwha" },
   { 1711,   "Fukuda" },
   { 1712,   "Zhejiang Eternal Automation Sci-Tec Co.,Ltd" },
   { 1713,   "KYOWA ELECTRONIC INSTRUMENTS CO.,LTD." },
   { 1714,   "Vaisala Oyj" },
   { 1715,   "Hennecke GmbH" },
   { 1716,   "Encoder Products Company" },
   { 1717,   "Converting Equipment International (dba CEI)" },
   { 1718,   "Reserved" },
   { 1719,   "Kinova" },
   { 1720,   "The Poling Group, Inc." },
   { 1721,   "plating electronic GmbH" },
   { 1722,   "HIWIN MIKROSYSTEM CORP." },
   { 1723,   "Wuxi Xinje Electric Co.,Ltd." },
   { 1724,   "ViSCO Technologies Corporation" },
   { 1725,   "MinebeaMitsumi Inc." },
   { 1726,   "FIAtec GmbH" },
   { 1727,   "eSOL Co.,Ltd" },
   { 1728,   "NTN TECHNICAL SERVICE" },
   { 1729,   "Shanghai Flexem" },
   { 1730,   "Magswitch" },
   { 1731,   "VEGA Grieshaber KG" },
   { 1732,   "H.D.T. S.R.L." },
   { 1733,   "Tool-Temp AG" },
   { 1734,   "Hollysys Technology Group Co., Ltd" },
   { 1735,   "Basler Electric Company" },
   { 1736,   "Shinwa Controls Co.,Ltd" },
   { 1737,   "Nanjing Decowell Automation Co.,Ltd." },
   { 1738,   "Reverity Inc" },
   { 1739,   "TOSHIBA MITSUBISHI-ELECTRIC INDUSTRIAL SYSTEMS CORPORATION" },
   { 1740,   "BizLink Special Cables Germany GmbH" },
   { 1741,   "Electronics Inc." },
   { 1742,   "Inexbot" },
   { 1743,   "Mujin, Inc." },
   { 1744,   "Shanghai AYAN Industry System Co., Ltd" },
   { 1745,   "EKE-Electronics Ltd." },
   { 1746,   "Bizerba SE & Co. KG" },
   { 1747,   "Astrodyne TDI" },
   { 9876,   "ODVA" },

   { 0, NULL }
};

value_string_ext cip_vendor_vals_ext = VALUE_STRING_EXT_INIT(cip_vendor_vals);

/* Translate Device Profile's */
static const value_string cip_devtype_vals[] = {
   { 0x00,        "Generic Device (deprecated)"         },
   { 0x02,        "AC Drive"                            },
   { 0x03,        "Motor Overload"                      },
   { 0x04,        "Limit Switch"                        },
   { 0x05,        "Inductive Proximity Switch"          },
   { 0x06,        "Photoelectric Sensor"                },
   { 0x07,        "General Purpose Discrete I/O"        },
   { 0x09,        "Resolver"                            },
   { 0x0C,        "Communications Adapter"              },
   { 0x0E,        "Programmable Logic Controller"       },
   { 0x10,        "Position Controller",                },
   { 0x13,        "DC Drive"                            },
   { 0x15,        "Contactor",                          },
   { 0x16,        "Motor Starter",                      },
   { 0x17,        "Soft Start",                         },
   { 0x18,        "Human-Machine Interface"             },
   { 0x1A,        "Mass Flow Controller"                },
   { 0x1B,        "Pneumatic Valve"                     },
   { 0x1C,        "Vacuum Pressure Gauge"               },
   { 0x1D,        "Process Control Value"               },
   { 0x1E,        "Residual Gas Analyzer"               },
   { 0x1F,        "DC Power Generator"                  },
   { 0x20,        "RF Power Generator"                  },
   { 0x21,        "Turbomolecular Vacuum Pump"          },
   { 0x22,        "Encoder"                             },
   { 0x23,        "Safety Discrete I/O Device"          },
   { 0x24,        "Fluid Flow Controller"               },
   { 0x25,        "CIP Motion Drive"                    },
   { 0x26,        "CompoNet Repeater"                   },
   { 0x27,        "Mass Flow Controller, Enhanced"      },
   { 0x28,        "CIP Modbus Device"                   },
   { 0x29,        "CIP Modbus Translator"               },
   { 0x2A,        "Safety Analog I/O Device"            },
   { 0x2B,        "Generic Device (keyable)"            },
   { 0x2C,        "Managed Ethernet Switch"             },
   { 0x2D,        "CIP Motion Safety Drive Device"      },
   { 0x2E,        "Safety Drive Device"                 },
   { 0x2F,        "CIP Motion Encoder"                  },
   { 0x30,        "CIP Motion Converter"                },
   { 0x31,        "CIP Motion I/O"                      },
   { 0x32,        "ControlNet Physical Layer Component" },
   { 0x33,        "Circuit Breaker"                     },
   { 0x34,        "HART Device"                         },
   { 0x35,        "CIP-HART Translator"                 },
   { 0xC8,        "Embedded Component"                  },

   { 0, NULL }
};

value_string_ext cip_devtype_vals_ext = VALUE_STRING_EXT_INIT(cip_devtype_vals);

/* Translate class names */
const value_string cip_class_names_vals[] = {
   { 0x01,     "Identity"                       },
   { 0x02,     "Message Router"                 },
   { 0x03,     "DeviceNet"                      },
   { 0x04,     "Assembly"                       },
   { 0x05,     "Connection"                     },
   { 0x06,     "Connection Manager"             },
   { 0x07,     "Register"                       },
   { 0x08,     "Discrete Input Point"           },
   { 0x09,     "Discrete Output Point"          },
   { 0x0A,     "Analog Input Point"             },
   { 0x0B,     "Analog Output Point"            },
   { 0x0E,     "Presence Sensing"               },
   { 0x0F,     "Parameter"                      },
   { 0x10,     "Parameter Group"                },
   { 0x12,     "Group"                          },
   { 0x1D,     "Discrete Input Group"           },
   { 0x1E,     "Discrete Output Group"          },
   { 0x1F,     "Discrete Group"                 },
   { 0x20,     "Analog Input Group"             },
   { 0x21,     "Analog Output Group"            },
   { 0x22,     "Analog Group"                   },
   { 0x23,     "Position Sensor"                },
   { 0x24,     "Position Controller Supervisor" },
   { 0x25,     "Position Controller"            },
   { 0x26,     "Block Sequencer"                },
   { 0x27,     "Command Block"                  },
   { 0x28,     "Motor Data"                     },
   { 0x29,     "Control Supervisor"             },
   { 0x2A,     "AC/DC Drive"                    },
   { 0x2B,     "Acknowledge Handler"            },
   { 0x2C,     "Overload"                       },
   { 0x2D,     "Softstart"                      },
   { 0x2E,     "Selection"                      },
   { 0x30,     "S-Device Supervisor"            },
   { 0x31,     "S-Analog Sensor"                },
   { 0x32,     "S-Analog Actuator"              },
   { 0x33,     "S-Single Stage Controller"      },
   { 0x34,     "S-Gas Calibration"              },
   { 0x35,     "Trip Point"                     },
   { 0x37,     "File"                           },
   { 0x38,     "S-Partial Pressure"             },
   { 0x39,     "Safety Supervisor"              },
   { 0x3A,     "Safety Validator"               },
   { 0x3B,     "Safety Discrete Output Point"   },
   { 0x3C,     "Safety Discrete Output Group"   },
   { 0x3D,     "Safety Discrete Input Point"    },
   { 0x3E,     "Safety Discrete Input Group"    },
   { 0x3F,     "Safety Dual Channel Output"     },
   { 0x40,     "S-Sensor Calibration"           },
   { 0x41,     "Event Log"                      },
   { 0x42,     "Motion Device Axis"             },
   { 0x43,     "Time Sync"                      },
   { 0x44,     "Modbus"                         },
   { 0x45,     "Originator Connection List"     },
   { 0x46,     "Modbus Serial Link"             },
   { 0x47,     "Device Level Ring (DLR)"        },
   { 0x48,     "QoS"                            },
   { 0x49,     "Safety Analog Input Point"      },
   { 0x4A,     "Safety Analog Input Group"      },
   { 0x4B,     "Safety Dual Channel Analog Input"  },
   { 0x4C,     "SERCOS III Link"                },
   { 0x4D,     "Target Connection List"         },
   { 0x4E,     "Base Energy"                    },
   { 0x4F,     "Electrical Energy"              },
   { 0x50,     "Non-Electrical Energy"          },
   { 0x51,     "Base Switch"                    },
   { 0x52,     "SNMP"                           },
   { 0x53,     "Power Management"               },
   { 0x54,     "RSTP Bridge"                    },
   { 0x55,     "RSTP Port"                      },
   { 0x56,     "PRP/HSR Protocol"               },
   { 0x57,     "PRP/HSR Nodes Table"            },
   { 0x58,     "Safety Feedback"                },
   { 0x59,     "Safety Dual Channel Feedback"   },
   { 0x5A,     "Safety Stop Functions"          },
   { 0x5B,     "Safety Limit Functions"         },
   { 0x5C,     "Power Curtailment"              },
   { 0x5D,     "CIP Security"                   },
   { 0x5E,     "EtherNet/IP Security"           },
   { 0x5F,     "Certificate Management"         },
   { 0x60,     "Authority"                      },
   { 0x61,     "Password Authenticator"         },
   { 0x62,     "Certificate Authenticator"      },
   { 0x63,     "Ingress Egress"                 },
   { 0x67,     "PCCC Class"                     },
   { 0xF0,     "ControlNet"                     },
   { 0xF1,     "ControlNet Keeper"              },
   { 0xF2,     "ControlNet Scheduling"          },
   { 0xF3,     "Connection Configuration"       },
   { 0xF4,     "Port"                           },
   { 0xF5,     "TCP/IP Interface"               },
   { 0xF6,     "Ethernet Link"                  },
   { 0xF7,     "CompoNet"                       },
   { 0xF8,     "CompoNet Repeater"              },
   { 0xF9,     "HART Master Port"               },
   { 0xFA,     "I/O Aggregation"                },
   { 0x100,    "Protection Trip"                },
   { 0x101,    "Protection Alarm"               },
   { 0x102,    "Circuit Breaker Supervisor"     },
   { 0x103,    "Circuit Breaker Statistics"     },
   { 0x104,    "Electrical Demand"              },
   { 0x105,    "Electrical Statistics"          },
   { 0x106,    "Machine Base Data"              },
   { 0x107,    "HART Process Device"            },
   { 0x108,    "Process Device Diagnostics"     },
   { 0x109,    "LLDP Management"                },
   { 0x10A,    "LLDP Data Table"                },
   { 0x10B,    "IO-Link Service Parameter"      },
   { 0x10C,    "IO-Link Master PHY"             },
   { 0x10D,    "IO-Link Device PHY"             },
   { 0x10E,    "Pilot Light Supervisor"         },
   { 0x10F,    "Select Line Link"               },
   { 0x110,    "In-Cabinet Actual Topology"     },
   { 0x111,    "In-Cabinet Commissioning"       },

   { 0,        NULL                             }
};

const value_string cip_id_state_vals[] = {
   { 0, "Nonexistent" },
   { 1, "Device Self Testing" },
   { 2, "Standby" },
   { 3, "Operational" },
   { 4, "Major Recoverable Fault" },
   { 5, "Major Unrecoverable Fault" },

   { 0, NULL }
};

static const range_string cip_port_type_vals[] = {
   { 0, 0, "Any - no routing" },
   { 1, 1, "Reserved for legacy use" },
   { 2, 2, "ControlNet" },
   { 3, 3, "ControlNet with redundancy" },
   { 4, 4, "EtherNet/IP" },
   { 5, 5, "DeviceNet" },
   { 6, 99, "Reserved for legacy use" },
   { 100, 199, "Vendor Specific" },
   { 200, 200, "CompoNet" },
   { 201, 201, "Modbus/TCP" },
   { 202, 202, "Modbus/SL" },
   { 203, 203, "SERCOS III" },
   { 204, 65534, "Reserved for future use" },
   { 65535, 65535, "Any - user configurable" },

   { 0, 0, NULL }
};

const value_string cip_port_number_vals[] = {
   { 0, "Reserved" },
   { 1, "Backplane" },

   { 0, NULL }
};

value_string_ext cip_class_names_vals_ext = VALUE_STRING_EXT_INIT(cip_class_names_vals);

/* Translate function to string - Run/Idle */
static const value_string cip_run_idle_vals[] = {
   { 0, "Idle" },
   { 1, "Run" },

   { 0, NULL }
};

void cip_rpi_api_fmt(char *s, uint32_t value)
{
   snprintf(s, ITEM_LABEL_LENGTH, "%.3fms", value / 1000.0);
}

static void add_cip_class_to_info_column(packet_info *pinfo, uint32_t class_id, int display_type)
{
   cip_req_info_t *cip_req_info;

   /* Skip printing the top level class for certain common messages because it gets
      too wordy in the Info column. */
   cip_req_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   if (cip_req_info
       && ((cip_req_info->bService == SC_CM_UNCON_SEND && class_id == CI_CLS_CM)
       || (cip_req_info->bService == SC_MULT_SERV_PACK && class_id == CI_CLS_MR)))
   {
       return;
   }

   // Don't show the Assembly class. It's a generic common class, and there are often multiple entries
   // which clutter the display.
   if (display_type == DISPLAY_CONNECTION_PATH && class_id == 4)
   {
      return;
   }

   if (display_type == DISPLAY_CONNECTION_PATH)
   {
       col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(class_id, cip_class_names_vals, "Class (0x%02x)"));
   }
   else if (display_type == DISPLAY_REQUEST_PATH)
   {
       col_append_fstr(pinfo->cinfo, COL_INFO, "%s - ", val_to_str(class_id, cip_class_names_vals, "Class (0x%02x)"));
   }
}

static void add_cip_symbol_to_info_column(packet_info *pinfo, char *symbol_name, int display_type)
{
   if (symbol_name == NULL)
   {
       return;
   }

   if (display_type == DISPLAY_CONNECTION_PATH)
   {
       col_append_fstr(pinfo->cinfo, COL_INFO, " ('%s')", symbol_name);
   }
   else if (display_type == DISPLAY_REQUEST_PATH)
   {
       col_append_fstr(pinfo->cinfo, COL_INFO, "'%s' - ", symbol_name);
   }
}

void add_cip_service_to_info_column(packet_info *pinfo, uint8_t service, const value_string* service_vals)
{
   col_append_str( pinfo->cinfo, COL_INFO,
      val_to_str(service & CIP_SC_MASK, service_vals, "Service (0x%02x)"));
   col_set_fence(pinfo->cinfo, COL_INFO);
}

static void add_cip_pccc_function_to_info_column(packet_info *pinfo, uint8_t fnc, const value_string* fnc_vals)
{
   col_append_fstr( pinfo->cinfo, COL_INFO,
      " - %s", val_to_str(fnc, fnc_vals, "Function (0x%02x)"));
   col_set_fence(pinfo->cinfo, COL_INFO);
}

static int dissect_id_revision(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_identity_revision);
      return total_len;
   }

   proto_tree_add_item( tree, hf_id_major_rev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_id_minor_rev, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
   return 2;
}

static int dissect_id_status(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   static int * const status[] = {
      &hf_id_status_owned,
      &hf_id_status_conf,
      &hf_id_status_extended1,
      &hf_id_status_minor_fault_rec,
      &hf_id_status_minor_fault_unrec,
      &hf_id_status_major_fault_rec,
      &hf_id_status_major_fault_unrec,
      &hf_id_status_extended2,
      NULL
   };

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_identity_status);
      return total_len;
   }

   proto_tree_add_bitmask(tree, tvb, offset, hf_id_status, ett_id_status, status, ENC_LITTLE_ENDIAN);

   return 2;
}

static int dissect_msg_rout_num_classes(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_classes;

   num_classes = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_msg_rout_num_classes, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (total_len < (2+(num_classes*2)))
   {
      expert_add_info(pinfo, item, &ei_mal_msg_rout_num_classes);
      return total_len;
   }

   for (i = 0; i < num_classes; i++)
      proto_tree_add_item( tree, hf_msg_rout_classes, tvb, offset+2+(i*2), 2, ENC_LITTLE_ENDIAN);

   return (2+(num_classes*2));
}

static int dissect_cm_connection_entry_list(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
    int offset, int total_len _U_)
{
    uint32_t num_conn_entries = 0;
    uint32_t num_conn_entries_bytes;

    proto_tree_add_item_ret_uint(tree, hf_conn_mgr_num_conn_entries, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num_conn_entries);

    num_conn_entries_bytes = (num_conn_entries+7)/8;
    proto_tree_add_uint(tree, hf_conn_mgr_num_conn_entries_bytes, tvb, 0, 0, num_conn_entries_bytes);

    for (uint32_t i = 0; i < num_conn_entries_bytes; i++)
    {
        proto_tree_add_item(tree, hf_conn_mgr_conn_open_bits, tvb, offset + 2 + i, 1, ENC_LITTLE_ENDIAN);
    }

    return 2 + num_conn_entries_bytes;
}

static int dissect_time_sync_grandmaster_clock(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 24)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_gm_clock);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_gm_clock_clock_id, tvb, offset, 8, ENC_NA);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_clock_class, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_time_accuracy, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_offset_scaled_log_variance, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_current_utc_offset, tvb, offset+14, 2, ENC_LITTLE_ENDIAN);

   static int* const bits[] = {
      &hf_time_sync_gm_clock_time_property_flags_leap61,
      &hf_time_sync_gm_clock_time_property_flags_leap59,
      &hf_time_sync_gm_clock_time_property_flags_current_utc_valid,
      &hf_time_sync_gm_clock_time_property_flags_ptp_timescale,
      &hf_time_sync_gm_clock_time_property_flags_time_traceable,
      &hf_time_sync_gm_clock_time_property_flags_freq_traceable,
      NULL
   };
   proto_tree_add_bitmask(tree, tvb, offset + 16, hf_time_sync_gm_clock_time_property_flags, ett_time_sync_gm_clock_flags, bits, ENC_LITTLE_ENDIAN);

   proto_tree_add_item( tree, hf_time_sync_gm_clock_time_source, tvb, offset+18, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_priority1, tvb, offset+20, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_gm_clock_priority2, tvb, offset+22, 2, ENC_LITTLE_ENDIAN);
   return 24;
}

static int dissect_time_sync_parent_clock(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 16)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_parent_clock);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_parent_clock_clock_id, tvb, offset, 8, ENC_NA);
   proto_tree_add_item( tree, hf_time_sync_parent_clock_port_number, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_parent_clock_observed_offset_scaled_log_variance, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_parent_clock_observed_phase_change_rate, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);
   return 16;
}

static int dissect_time_sync_local_clock(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 20)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_local_clock);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_local_clock_clock_id, tvb, offset, 8, ENC_NA);
   proto_tree_add_item( tree, hf_time_sync_local_clock_clock_class, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_local_clock_time_accuracy, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_local_clock_offset_scaled_log_variance, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_local_clock_current_utc_offset, tvb, offset+14, 2, ENC_LITTLE_ENDIAN);

   static int* const bits[] = {
      &hf_time_sync_local_clock_time_property_flags_leap61,
      &hf_time_sync_local_clock_time_property_flags_leap59,
      &hf_time_sync_local_clock_time_property_flags_current_utc_valid,
      &hf_time_sync_local_clock_time_property_flags_ptp_timescale,
      &hf_time_sync_local_clock_time_property_flags_time_traceable,
      &hf_time_sync_local_clock_time_property_flags_freq_traceable,
      NULL
   };
   proto_tree_add_bitmask(tree, tvb, offset + 16, hf_time_sync_local_clock_time_property_flags, ett_time_sync_local_clock_flags, bits, ENC_LITTLE_ENDIAN);

   proto_tree_add_item( tree, hf_time_sync_local_clock_time_source, tvb, offset+18, 2, ENC_LITTLE_ENDIAN);
   return 20;
}

static int dissect_time_sync_port_state_info(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_state_info);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_state_info_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*4 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_state_info_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*4, 4, ett_time_sync_port_state_info, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_state_info_port_num, tvb, offset+2+i*4, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_state_info_port_state, tvb, offset+4+i*4, 2, ENC_LITTLE_ENDIAN);
   }

   return 2+num_ports*4;
}

static int dissect_time_sync_port_enable_cfg(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_enable_cfg);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_enable_cfg_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*4 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_enable_cfg_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*4, 4, ett_time_sync_port_enable_cfg, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_enable_cfg_port_num, tvb, offset+2+i*4, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_enable_cfg_port_enable, tvb, offset+4+i*4, 2, ENC_LITTLE_ENDIAN);
   }

   return 2+num_ports*4;
}

static int dissect_time_sync_port_log_announce(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_log_announce);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_log_announce_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*4 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_log_announce_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*4, 4, ett_time_sync_port_log_announce, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_log_announce_port_num, tvb, offset+2+i*4, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_log_announce_interval, tvb, offset+4+i*4, 2, ENC_LITTLE_ENDIAN);
   }

   return 2+num_ports*4;
}

static int dissect_time_sync_port_log_sync(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_log_sync);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_log_sync_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*4 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_log_sync_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*4, 4, ett_time_sync_port_log_sync, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_log_sync_port_num, tvb, offset+2+i*4, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_log_sync_port_log_sync_interval, tvb, offset+4+i*4, 2, ENC_LITTLE_ENDIAN);
   }

   return 2+num_ports*4;
}

static int dissect_time_sync_clock_type(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_clock_type);
      return total_len;
   }

   static int* const bits[] = {
      &hf_time_sync_clock_type_management,
      &hf_time_sync_clock_type_end_to_end,
      &hf_time_sync_clock_type_boundary,
      &hf_time_sync_clock_type_ordinary,
      &hf_time_sync_clock_type_slave_only,
      NULL
   };
   proto_tree_add_bitmask(tree, tvb, offset, hf_time_sync_clock_type, ett_time_sync_clock_type, bits, ENC_LITTLE_ENDIAN);

   return 2;
}

static int dissect_time_sync_manufacture_id(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 4)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_manufacture_id);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_manufacture_id_oui, tvb, offset, 3, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_time_sync_manufacture_id_reserved, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
   return 4;
}

static int dissect_time_sync_prod_desc(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint32_t size;

   if (total_len < 4)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_prod_desc);
      return total_len;
   }

   proto_tree_add_item_ret_uint( tree, hf_time_sync_prod_desc_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size);

   if (size > 64)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_prod_desc_64);
      return total_len;
   }

   if ((int)(size+4) > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_prod_desc_size);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_prod_desc_str, tvb, offset+4, size, ENC_ASCII);
   return size+4;
}

static int dissect_time_sync_revision_data(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint32_t size;

   if (total_len < 4)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_revision_data);
      return total_len;
   }

   proto_tree_add_item_ret_uint( tree, hf_time_sync_revision_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size);

   if (size > 32)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_revision_data_32);
      return total_len;
   }

   if ((int)(size+4) > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_revision_data_size);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_revision_data_str, tvb, offset+4, size, ENC_ASCII);
   return size+4;
}

static int dissect_time_sync_user_desc(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint32_t size;

   if (total_len < 4)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_user_desc);
      return total_len;
   }

   proto_tree_add_item_ret_uint( tree, hf_time_sync_user_desc_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size);

   if (size > 128)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_user_desc_128);
      return total_len;
   }

   if ((int)(size+4) > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_user_desc_size);
      return total_len;
   }

   proto_tree_add_item( tree, hf_time_sync_user_desc_str, tvb, offset+4, size, ENC_ASCII);
   return size+4;
}

static int dissect_time_sync_port_profile_id_info(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_profile_id_info);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_profile_id_info_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*10 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_profile_id_info_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*10, 10, ett_time_sync_port_profile_id_info, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_profile_id_info_port_num, tvb, offset+2+i*10, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_profile_id_info_profile_id, tvb, offset+4+i*10, 8, ENC_NA);
   }

   return 2+num_ports*10;
}

static int dissect_time_sync_port_phys_addr_info(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_phys_addr_info);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_phys_addr_info_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*36 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_phys_addr_info_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*36, 36, ett_time_sync_port_phys_addr_info, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_phys_addr_info_port_num, tvb, offset+2+i*36, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_phys_addr_info_phys_proto, tvb, offset+4+i*36, 16, ENC_ASCII);

       uint32_t addr_size;
       proto_tree_add_item_ret_uint(port_tree, hf_time_sync_port_phys_addr_info_addr_size, tvb, offset+20+i*36, 2, ENC_LITTLE_ENDIAN, &addr_size);

       // Field is 16 bytes, but only highlight the actual size.
       proto_tree_add_item(port_tree, hf_time_sync_port_phys_addr_info_phys_addr, tvb, offset+22+i*36, addr_size, ENC_NA);
   }

   return 2+num_ports*36;
}

static int dissect_time_sync_port_proto_addr_info(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   uint16_t i, num_ports;
   proto_tree* port_tree;

   if (total_len < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_proto_addr_info);
      return total_len;
   }

   num_ports = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_time_sync_port_proto_addr_info_num_ports, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (2+num_ports*22 > total_len)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_port_proto_addr_info_ports);
      return total_len;
   }

   for (i = 0; i < num_ports; i++)
   {
       port_tree = proto_tree_add_subtree_format(tree, tvb, offset+2+i*22, 22, ett_time_sync_port_proto_addr_info, NULL, "Port #%d", i+1);
       proto_tree_add_item(port_tree, hf_time_sync_port_proto_addr_info_port_num, tvb, offset+2+i*22, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_proto_addr_info_network_proto, tvb, offset+4+i*22, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_proto_addr_info_addr_size, tvb, offset+6+i*22, 2, ENC_LITTLE_ENDIAN);
       proto_tree_add_item(port_tree, hf_time_sync_port_proto_addr_info_port_proto_addr, tvb, offset+8+i*22, 16, ENC_NA);
   }

   return 2+num_ports*22;
}

static int dissect_time_sync_sys_time_and_offset(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 16)
   {
      expert_add_info(pinfo, item, &ei_mal_time_sync_sys_time_and_offset);
      return total_len;
   }

   dissect_cip_utime(tree, tvb, offset, hf_time_sync_sys_time_and_offset_time);
   proto_tree_add_item( tree, hf_time_sync_sys_time_and_offset_offset, tvb, offset+8, 8, ENC_LITTLE_ENDIAN);

   return 16;
}

int dissect_optional_attr_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   uint32_t i;
   uint32_t num_attr = 0;

   proto_tree_add_item_ret_uint(tree, hf_attr_class_opt_attr_num, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num_attr);

   if (total_len < (int)(2 + num_attr * 2))
   {
      expert_add_info(pinfo, item, &ei_mal_opt_attr_list);
      return total_len;
   }

   // Look up the request data to get the CIP Class.
   cip_req_info_t *cip_req_info;
   cip_req_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);

   for (i = 0; i < num_attr; ++i)
   {
      proto_item* attr_item = proto_tree_add_item(tree, hf_attr_class_attr_num, tvb, offset + 2 + 2 * i, 2, ENC_LITTLE_ENDIAN);

      // Display attribute name.
      if (cip_req_info && cip_req_info->ciaData)
      {
          const attribute_info_t* attr;
          attr = cip_get_attribute(cip_req_info->ciaData->iClass, 1, i);
          if (attr)
          {
              proto_item_append_text(attr_item, " (%s)", attr->text);
          }
      }
   }

   return 2 + num_attr * 2;
}

int dissect_optional_service_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   uint32_t i;
   uint32_t num_services = 0;

   proto_tree_add_item_ret_uint(tree, hf_attr_class_opt_service_num, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num_services);

   if (total_len < (int)(2 + num_services * 2))
   {
      expert_add_info(pinfo, item, &ei_mal_opt_service_list);
      return total_len;
   }

   for (i = 0; i < num_services; ++i)
   {
      proto_tree_add_item(tree, hf_attr_class_service_code, tvb, offset + 2 + 2 * i, 2, ENC_LITTLE_ENDIAN);
   }

   return 2 + num_services * 2;
}

static int dissect_port_instance_info(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len)
{
   int i;

   for (i = 0; i < total_len; i += 4)
   {
      proto_tree_add_item(tree, hf_port_type, tvb, offset + i, 2, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(tree, hf_port_number, tvb, offset + i + 2, 2, ENC_LITTLE_ENDIAN);
   }

   return total_len;
}

static int dissect_port_associated_comm_objects(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
    int offset, int total_len _U_)
{
    uint32_t num_entries;
    proto_tree_add_item_ret_uint(tree, hf_port_num_comm_object_entries, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_entries);

    int parsed_len = 1;
    for (uint32_t i = 0; i < num_entries; ++i)
    {
        parsed_len += dissect_padded_epath_len_usint(pinfo, tree, item, tvb, offset + parsed_len,
            tvb_reported_length_remaining(tvb, offset + parsed_len));
    }

    return parsed_len;
}

static int dissect_padded_epath_len(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len, bool one_byte_len)
{
   uint32_t    path_size;
   proto_tree *epath_tree;
   proto_item *path_item;

   uint32_t path_size_len;
   int hf_path_len;
   if (one_byte_len == true)
   {
      path_size_len = 1;
      hf_path_len = hf_path_len_usint;
   }
   else
   {
      path_size_len = 2;
      hf_path_len = hf_path_len_uint;
   }

   path_item = proto_tree_add_item_ret_uint(tree, hf_path_len, tvb, offset, path_size_len, ENC_LITTLE_ENDIAN, &path_size);

   if (total_len < (int)(path_size * 2 + path_size_len))
   {
      expert_add_info(pinfo, item, &ei_mal_padded_epath_size);
      return total_len;
   }

   epath_tree = proto_tree_add_subtree(tree, tvb, offset + path_size_len, path_size * 2, ett_path, &path_item, "Path: ");
   dissect_epath(tvb, pinfo, epath_tree, path_item, offset + path_size_len, path_size * 2, false, false, NULL, NULL, NO_DISPLAY, NULL, false);

   return path_size * 2 + path_size_len;
}

/* Format: USINT (Length of EPATH in 16-bit words) + Padded EPATH */
int dissect_padded_epath_len_usint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   return dissect_padded_epath_len(pinfo, tree, item, tvb, offset, total_len, true);
}

/* Format: UINT (Length of EPATH in 16-bit words) + Padded EPATH */
int dissect_padded_epath_len_uint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   return dissect_padded_epath_len(pinfo, tree, item, tvb, offset, total_len, false);
}

static int dissect_single_segment_packed_attr(packet_info *pinfo, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   proto_tree *subtree;
   proto_item *subitem;
   subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_port_path, &subitem, "Path: ");

   int parsed_len = dissect_cip_segment_single(pinfo, tvb, offset, subtree, subitem, false, true, NULL, NULL, NO_DISPLAY, NULL, false);
   proto_item_set_len(subitem, parsed_len);

   return parsed_len;
}

static int dissect_single_segment_padded_attr(packet_info *pinfo, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   proto_tree *subtree;
   proto_item *subitem;
   subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_port_path, &subitem, "Path: ");

   int parsed_len = dissect_cip_segment_single(pinfo, tvb, offset, subtree, subitem, false, false, NULL, NULL, NO_DISPLAY, NULL, false);
   proto_item_set_len(subitem, parsed_len);

   return parsed_len;
}

static int dissect_port_link_object(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len)
{
   return dissect_padded_epath_len_uint(pinfo, tree, item, tvb, offset, total_len);
}

static int dissect_port_node_range(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
   int offset, int total_len _U_)
{
   proto_tree_add_item(tree, hf_port_min_node_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_port_max_node_num, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);

   return 4;
}


/// Identity - Services
static int dissect_identity_reset(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb, int offset, bool request)
{
   int parsed_len = 0;

   if (request)
   {
      if (tvb_reported_length_remaining(tvb, offset) > 0)
      {
         proto_tree_add_item(tree, hf_cip_sc_reset_param, tvb, offset, 1, ENC_LITTLE_ENDIAN);
         parsed_len = 1;
      }
   }
   else
   {
      parsed_len = 0;
   }

   return parsed_len;
}

static const attribute_info_t cip_attribute_vals[] = {
    /* Identity Object (class attributes) */
   {0x01, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   {0x01, true, 2, 1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
   {0x01, true, 3, -1, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
   {0x01, true, 4, -1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   {0x01, true, 5, -1, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   {0x01, true, 6, 2, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   {0x01, true, 7, 3, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },

    /* Identity Object (instance attributes) */
   {0x01, false, 1, 0, "Vendor ID", cip_uint, &hf_id_vendor_id, NULL},
   {0x01, false, 2, 1, "Device Type", cip_uint, &hf_id_device_type, NULL},
   {0x01, false, 3, 2, "Product Code", cip_uint, &hf_id_product_code, NULL},
   {0x01, false, 4, 3, "Revision", cip_dissector_func, NULL, dissect_id_revision},
   {0x01, false, 5, 4, "Status", cip_dissector_func, NULL, dissect_id_status},
   {0x01, false, 6, 5, "Serial Number", cip_udint, &hf_id_serial_number, NULL},
   {0x01, false, 7, 6, "Product Name", cip_short_string, &hf_id_product_name, NULL},
   {0x01, false, 8, 7, "State", cip_usint, &hf_id_state, NULL},
   {0x01, false, 9, 8, "Configuration Consistency Value", cip_uint, &hf_id_config_value, NULL},
   {0x01, false, 10, 9, "Heartbeat Interval", cip_usint, &hf_id_heartbeat, NULL},

    /* Message Router Object (class attributes) */
   {0x02, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   {0x02, true, 2, -1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
   {0x02, true, 3, -1, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
   {0x02, true, 4, 1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   {0x02, true, 5, 2, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   {0x02, true, 6, 3, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   {0x02, true, 7, 4, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },

    /* Message Router Object (instance attributes) */
   {0x02, false, 1, 0, "Object List", cip_dissector_func, NULL, dissect_msg_rout_num_classes},
   {0x02, false, 2, 1, "Number Available", cip_uint, &hf_msg_rout_num_available, NULL},
   {0x02, false, 3, 2, "Number Active", cip_uint, &hf_msg_rout_num_active, NULL},
   {0x02, false, 4, 3, "Active Connections", cip_uint_array, &hf_msg_rout_active_connections, NULL},

    /* Connection Manager Object (class attributes) */
   {0x06, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   {0x06, true, 2, 1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
   {0x06, true, 3, -1, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
   {0x06, true, 4, -1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   {0x06, true, 5, -1, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   {0x06, true, 6, 2, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   {0x06, true, 7, 3, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },

    /* Connection Manager Object (instance attributes) */
   {0x06, false, 1, 0, "Open Requests", cip_uint, &hf_conn_mgr_open_requests, NULL},
   {0x06, false, 2, 1, "Open Format Rejects", cip_uint, &hf_conn_mgr_open_format_rejects, NULL},
   {0x06, false, 3, 2, "Open Resource Rejects", cip_uint, &hf_conn_mgr_open_resource_rejects, NULL},
   {0x06, false, 4, 3, "Other Open Rejects", cip_uint, &hf_conn_mgr_other_open_rejects, NULL},
   {0x06, false, 5, 4, "Close Requests", cip_uint, &hf_conn_mgr_close_requests, NULL},
   {0x06, false, 6, 5, "Close Format Requests", cip_uint, &hf_conn_close_format_requests, NULL},
   {0x06, false, 7, 6, "Close Other Requests", cip_uint, &hf_conn_mgr_close_other_requests, NULL},
   {0x06, false, 8, 7, "Connection Timeouts", cip_uint, &hf_conn_mgr_conn_timouts, NULL},
   {0x06, false, 9, 8, "Connection Entry List", cip_dissector_func, NULL, dissect_cm_connection_entry_list },
   {0x06, false, 11, 9, "CPU Utilization", cip_uint, &hf_conn_mgr_cpu_utilization, NULL },
   {0x06, false, 12, 10, "Max Buff Size", cip_udint, &hf_conn_mgr_max_buff_size, NULL },
   {0x06, false, 13, 11, "Buff Size Remaining", cip_udint, &hf_conn_mgr_buff_size_remaining, NULL },

    /* File Object (instance attributes) */
   {0x37, false, 4, -1, "File Name", cip_stringi, &hf_file_filename, NULL },

    /* Time Sync Object (class attributes) */
   {0x43, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   {0x43, true, 2, 1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
   {0x43, true, 3, 2, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
   {0x43, true, 4, 3, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   {0x43, true, 5, 4, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   {0x43, true, 6, 5, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   {0x43, true, 7, 6, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },

    /* Time Sync Object (instance attributes) */
   {0x43, false, 1, -1, "PTP Enable", cip_bool, &hf_time_sync_ptp_enable, NULL},
   {0x43, false, 2, -1, "Is Synchronized", cip_bool, &hf_time_sync_is_synchronized, NULL},
   {0x43, false, 3, -1, "System Time (Microseconds)", cip_utime, &hf_time_sync_sys_time_micro, NULL},
   {0x43, false, 4, -1, "System Time (Nanoseconds)", cip_stime, &hf_time_sync_sys_time_nano, NULL},
   {0x43, false, 5, -1, "Offset from Master", cip_ntime, &hf_time_sync_offset_from_master, NULL},
   {0x43, false, 6, -1, "Max Offset from Master", cip_ulint, &hf_time_sync_max_offset_from_master, NULL},
   {0x43, false, 7, -1, "Mean Path Delay To Master", cip_ntime, &hf_time_sync_mean_path_delay_to_master, NULL},
   {0x43, false, 8, -1, "Grand Master Clock Info", cip_dissector_func, NULL, dissect_time_sync_grandmaster_clock},
   {0x43, false, 9, -1, "Parent Clock Info", cip_dissector_func, NULL, dissect_time_sync_parent_clock},
   {0x43, false, 10, -1, "Local Clock Info", cip_dissector_func, NULL, dissect_time_sync_local_clock},
   {0x43, false, 11, -1, "Number of Ports", cip_uint, &hf_time_sync_num_ports, NULL},
   {0x43, false, 12, -1, "Port State Info", cip_dissector_func, NULL, dissect_time_sync_port_state_info},
   {0x43, false, 13, -1, "Port Enable Cfg", cip_dissector_func, NULL, dissect_time_sync_port_enable_cfg},
   {0x43, false, 14, -1, "Port Log Announcement Interval Cfg", cip_dissector_func, NULL, dissect_time_sync_port_log_announce},
   {0x43, false, 15, -1, "Port Log Sync Interval Cfg", cip_dissector_func, NULL, dissect_time_sync_port_log_sync},
   {0x43, false, 16, -1, "Priority1", cip_usint, &hf_time_sync_priority1, NULL},
   {0x43, false, 17, -1, "Priority2", cip_usint, &hf_time_sync_priority2, NULL},
   {0x43, false, 18, -1, "Domain number", cip_usint, &hf_time_sync_domain_number, NULL},
   {0x43, false, 19, -1, "Clock Type", cip_dissector_func, NULL, dissect_time_sync_clock_type},
   {0x43, false, 20, -1, "Manufacture Identity", cip_dissector_func, NULL, dissect_time_sync_manufacture_id},
   {0x43, false, 21, -1, "Product Description", cip_dissector_func, NULL, dissect_time_sync_prod_desc},
   {0x43, false, 22, -1, "Revision Data", cip_dissector_func, NULL, dissect_time_sync_revision_data},
   {0x43, false, 23, -1, "User Description", cip_dissector_func, NULL, dissect_time_sync_user_desc},
   {0x43, false, 24, -1, "Port Profile Identity Info", cip_dissector_func, NULL, dissect_time_sync_port_profile_id_info},
   {0x43, false, 25, -1, "Port Physical Address Info", cip_dissector_func, NULL, dissect_time_sync_port_phys_addr_info},
   {0x43, false, 26, -1, "Port Protocol Address Info", cip_dissector_func, NULL, dissect_time_sync_port_proto_addr_info},
   {0x43, false, 27, -1, "Steps Removed", cip_uint, &hf_time_sync_steps_removed, NULL},
   {0x43, false, 28, -1, "System Time and Offset", cip_dissector_func, NULL, dissect_time_sync_sys_time_and_offset},


   /* Connection Configuration Object (class attributes) */
   /* Data sizes are different than common class attributes for some items. */
   { 0xF3, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   { 0xF3, true, 2, 1, CLASS_ATTRIBUTE_2_NAME, cip_udint, &hf_cip_class_max_inst32, NULL },
   { 0xF3, true, 3, 2, CLASS_ATTRIBUTE_3_NAME, cip_udint, &hf_cip_class_num_inst32, NULL },
   { 0xF3, true, 4, -1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   { 0xF3, true, 5, -1, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   { 0xF3, true, 6, -1, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   { 0xF3, true, 7, -1, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },
   { 0xF3, true, 8, 3, "Format Number", cip_uint, &hf_cip_cco_format_number, NULL },
   { 0xF3, true, 9, 4, "Edit Signature", cip_udint, &hf_cip_cco_edit_signature, NULL },

   /* Port Object (class attributes) */
   { 0xF4, true, 1, 0, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
   { 0xF4, true, 2, 1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
   { 0xF4, true, 3, 2, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
   { 0xF4, true, 4, -1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
   { 0xF4, true, 5, -1, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
   { 0xF4, true, 6, -1, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
   { 0xF4, true, 7, -1, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },
   { 0xF4, true, 8, 3, "Entry Port", cip_uint, &hf_port_entry_port, NULL },
   { 0xF4, true, 9, 4, "Port Instance Info", cip_dissector_func, NULL, dissect_port_instance_info },

   /* Port Object (instance attributes) */
   { 0xF4, false, 1, 0, "Port Type", cip_uint, &hf_port_type, NULL },
   { 0xF4, false, 2, 1, "Port Number", cip_uint, &hf_port_number, NULL },
   { 0xF4, false, 3, 2, "Link Object", cip_dissector_func, NULL, dissect_port_link_object },
   { 0xF4, false, 4, 3, "Port Name", cip_short_string, &hf_port_name, NULL },
   { 0xF4, false, 7, 4, "Port Number and Node Address", cip_dissector_func, NULL, dissect_single_segment_padded_attr },
   { 0xF4, false, 8, -1, "Port Node Range", cip_dissector_func, NULL, dissect_port_node_range },
   { 0xF4, false, 9, -1, "Chassis Identity", cip_dissector_func, NULL, dissect_single_segment_packed_attr },
   { 0xF4, false, 11, -1, "Associated Communication Objects", cip_dissector_func, NULL, dissect_port_associated_comm_objects },
};

// Table of CIP services defined by this dissector.
static cip_service_info_t cip_obj_spec_service_table[] = {
    { 0x1, SC_RESET, "Reset", dissect_identity_reset },
};

// Look up a given CIP service from this dissector.
static cip_service_info_t* cip_get_service_cip(uint32_t class_id, uint8_t service_id)
{
   return cip_get_service_one_table(&cip_obj_spec_service_table[0],
      array_length(cip_obj_spec_service_table),
      class_id,
      service_id);
}

typedef struct attribute_val_array {
   size_t size;
   const attribute_info_t* attrs;
} attribute_val_array_t;

/* Each entry in this table (eg: cip_attribute_vals) is a list of:
    Attribute information (class_id/class_instance/attribute) to attribute property

    Note: If more items are added to the individual tables, it may make sense
      to switch to a more efficient implementation (eg: hash table).
*/

static attribute_val_array_t all_attribute_vals[] = {
   {array_length(cip_attribute_vals), cip_attribute_vals},
   {array_length(enip_attribute_vals), enip_attribute_vals},
   {array_length(cip_safety_attribute_vals), cip_safety_attribute_vals},
   {array_length(cip_motion_attribute_vals), cip_motion_attribute_vals},
};

const attribute_info_t* cip_get_attribute(unsigned class_id, unsigned instance, unsigned attribute)
{
   size_t i, j;
   attribute_val_array_t* att_array;
   const attribute_info_t* pattr;

   static const attribute_info_t class_attribute_vals[] = {
      { 0, true, 1, -1, CLASS_ATTRIBUTE_1_NAME, cip_uint, &hf_attr_class_revision, NULL },
      { 0, true, 2, -1, CLASS_ATTRIBUTE_2_NAME, cip_uint, &hf_attr_class_max_instance, NULL },
      { 0, true, 3, -1, CLASS_ATTRIBUTE_3_NAME, cip_uint, &hf_attr_class_num_instance, NULL },
      { 0, true, 4, -1, CLASS_ATTRIBUTE_4_NAME, cip_dissector_func, NULL, dissect_optional_attr_list },
      { 0, true, 5, -1, CLASS_ATTRIBUTE_5_NAME, cip_dissector_func, NULL, dissect_optional_service_list },
      { 0, true, 6, -1, CLASS_ATTRIBUTE_6_NAME, cip_uint, &hf_attr_class_num_class_attr, NULL },
      { 0, true, 7, -1, CLASS_ATTRIBUTE_7_NAME, cip_uint, &hf_attr_class_num_inst_attr, NULL },
   };

   for (i = 0; i < array_length(all_attribute_vals); i++)
   {
      att_array = &all_attribute_vals[i];
      for (j = 0; j < att_array->size; j++)
      {
         pattr = &att_array->attrs[j];
         if ((pattr->class_id == class_id) &&
             (instance != SEGMENT_VALUE_NOT_SET) &&
             (((instance == 0) && (pattr->class_instance == true)) || ((instance != 0) && (pattr->class_instance == false))) &&
             (pattr->attribute == attribute))
         {
            return pattr;
         }
      }
   }

   /* Check against common class attributes. */
   if (instance == 0)
   {
      for (i = 0; i < array_length(class_attribute_vals); i++)
      {
         pattr = &class_attribute_vals[i];
         if (pattr->attribute == attribute)
         {
            return pattr;
         }
      }
   }

   return NULL;
}

// Look up a given CIP service from a table of cip_service_info_t.
cip_service_info_t* cip_get_service_one_table(cip_service_info_t* services, size_t size, uint32_t class_id, uint8_t service_id)
{
   for (uint32_t i = 0; i < size; i++)
   {
      cip_service_info_t* entry = &services[i];
      if (entry->class_id == class_id && entry->service_id == (service_id & CIP_SC_MASK))
      {
         return entry;
      }
   }

   return NULL;
}

// Look through all CIP Service tables from different dissectors, to find a definition for a given CIP service.
static cip_service_info_t* cip_get_service(packet_info *pinfo, uint8_t service_id)
{
   cip_req_info_t *cip_req_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   if (!cip_req_info || !cip_req_info->ciaData)
   {
      return NULL;
   }

   cip_service_info_t* pService = cip_get_service_cip(cip_req_info->ciaData->iClass, service_id);
   if (pService)
   {
      return pService;
   }

   pService = cip_get_service_enip(cip_req_info->ciaData->iClass, service_id);
   if (pService)
   {
      return pService;
   }

   return NULL;
}

static const char *
segment_name_format(wmem_allocator_t *scope, const char *segment_name, const char *fmt)
    G_GNUC_FORMAT(2);

static const char *
segment_name_format(wmem_allocator_t *scope, const char *segment_name, const char *fmt)
{
   wmem_strbuf_t *strbuf;

   strbuf = wmem_strbuf_new(scope, segment_name);
   wmem_strbuf_append(strbuf, fmt);
   return wmem_strbuf_get_str(strbuf);
}

static int
dissect_cia(tvbuff_t *tvb, int offset, unsigned char segment_type,
            bool generate, bool packed, packet_info *pinfo, proto_item *epath_item,
            proto_tree *path_tree, proto_item *path_item, proto_item ** ret_item,
            const char* segment_name, const value_string* vals, int* value,
            int hf8, int hf16, int hf32)
{
   unsigned char logical_format;
   int segment_len;
   int temp_data;
   int value_offset;
   wmem_strbuf_t *strbuf;
   bool extended_logical = false;
   uint8_t logical_seg_type = segment_type & CI_LOGICAL_SEG_TYPE_MASK;

   /* Extended Logical Format is slightly different than other logical formats. An extra byte is
      inserted after the segment type. */
   if (logical_seg_type == CI_LOGICAL_SEG_EXT_LOGICAL)
   {
      extended_logical = true;

      if (generate)
      {
         temp_data = tvb_get_uint8(tvb, offset + 1);
         *ret_item = proto_tree_add_uint(path_tree, hf_cip_ext_logical_type, tvb, 0, 0, temp_data);
         proto_item_set_generated(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item(path_tree, hf_cip_ext_logical_type, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      }
   }

   logical_format = segment_type & CI_LOGICAL_SEG_FORMAT_MASK;
   switch (logical_format)
   {
   case CI_LOGICAL_SEG_8_BIT:
      value_offset = offset + 1;

      if (extended_logical == true)
      {
         value_offset += 1;
      }

      temp_data = tvb_get_uint8(tvb, value_offset);

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(path_tree, hf8, tvb, 0, 0, temp_data );
         proto_item_set_generated(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item(path_tree, hf8, tvb, value_offset, 1, ENC_LITTLE_ENDIAN);
      }

      if (vals == NULL)
      {
         if (logical_seg_type == CI_LOGICAL_SEG_ATTR_ID)
         {
            proto_item_append_text(epath_item, "%s: %d", segment_name, temp_data);
         }
         else
         {
            proto_item_append_text(epath_item, "%s: 0x%02X", segment_name, temp_data);
         }
      }
      else
      {
         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals, segment_name_format( pinfo->pool, segment_name, ": 0x%02X" ) ) );
      }

      if (value != NULL)
         *value = temp_data;

      segment_len = 2;
      if (extended_logical == true)
      {
         if (packed)
         {
            segment_len += 1;
         }
         else
         {
            segment_len += 2;
         }
      }
      break;
   case CI_LOGICAL_SEG_16_BIT:
      if (packed && extended_logical == false)
      {
         value_offset = offset + 1;
         segment_len = 3;
      }
      else
      {
         value_offset = offset + 2;
         segment_len = 4;
      }

      temp_data = tvb_get_letohs(tvb, value_offset);

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(path_tree, hf16, tvb, 0, 0, temp_data );
         proto_item_set_generated(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item(path_tree, hf16, tvb, value_offset, 2, ENC_LITTLE_ENDIAN);
      }

      if (vals == NULL)
      {
         if (logical_seg_type == CI_LOGICAL_SEG_ATTR_ID)
         {
            proto_item_append_text(epath_item, "%s: %d", segment_name, temp_data);
         }
         else
         {
            proto_item_append_text(epath_item, "%s: 0x%04X", segment_name, temp_data);
         }
      }
      else
      {
         strbuf = wmem_strbuf_new(pinfo->pool, segment_name);
         wmem_strbuf_append(strbuf, ": 0x%04X");

         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals, segment_name_format( pinfo->pool, segment_name, ": 0x%04X" ) ) );
      }

      if (value != NULL)
         *value = temp_data;

      break;
   case CI_LOGICAL_SEG_32_BIT:
      if (packed && extended_logical == false)
      {
         value_offset = offset + 1;
         segment_len = 5;
      }
      else
      {
         value_offset = offset + 2;
         segment_len = 6;
      }
      temp_data = tvb_get_letohl(tvb, value_offset);

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(path_tree, hf32, tvb, 0, 0, temp_data );
         proto_item_set_generated(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item(path_tree, hf32, tvb, value_offset, 4, ENC_LITTLE_ENDIAN);
      }

      if (vals == NULL)
      {
         if (logical_seg_type == CI_LOGICAL_SEG_ATTR_ID)
         {
            proto_item_append_text(epath_item, "%s: %d", segment_name, temp_data);
         }
         else
         {
            proto_item_append_text(epath_item, "%s: 0x%08X", segment_name, temp_data);
         }
      }
      else
      {
         strbuf = wmem_strbuf_new(pinfo->pool, segment_name);
         wmem_strbuf_append(strbuf, ": 0x%08X");

         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals, segment_name_format( pinfo->pool, segment_name, ": 0x%08X" ) ) );
      }

      if (value != NULL)
         *value = temp_data;

      break;
   default:
      expert_add_info(pinfo, epath_item, &ei_proto_log_seg_format);
      return 0;
   }

   if (generate == false)
   {
      proto_item_set_len(path_item, segment_len);
   }

   return segment_len;
}

/* Dissect Device ID structure */
void
dissect_deviceid(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_vendor, int hf_devtype, int hf_prodcode,
                 int hf_compatibility, int hf_comp_bit, int hf_majrev, int hf_minrev,
                 bool generate, unsigned encoding)
{
   proto_item* vendor_id_item = proto_tree_add_item(tree, hf_vendor, tvb, offset, 2, encoding);
   proto_item* device_type_item = proto_tree_add_item(tree, hf_devtype, tvb, offset + 2, 2, encoding);
   proto_item* product_code_item = proto_tree_add_item(tree, hf_prodcode, tvb, offset + 4, 2, encoding);

   /* Major revision/Compatibility */
   uint8_t compatibility = tvb_get_uint8(tvb, offset + 6);

   /* Add Major revision/Compatibility tree */
   proto_item* compatibility_item = proto_tree_add_uint_format_value(tree, hf_compatibility,
      tvb, offset + 6, 1, compatibility, "%s, Major Revision: %d",
      val_to_str_const((compatibility & 0x80) >> 7, cip_com_bit_vals, ""),
      compatibility & 0x7F);
   proto_tree* compatibility_tree = proto_item_add_subtree(compatibility_item, ett_mcsc);

   proto_item* comp_bit_item = proto_tree_add_item(compatibility_tree, hf_comp_bit, tvb, offset + 6, 1, encoding);
   proto_item* major_rev_item = proto_tree_add_item(compatibility_tree, hf_majrev, tvb, offset + 6, 1, encoding);
   proto_item* minor_rev_item = proto_tree_add_item(tree, hf_minrev, tvb, offset + 7, 1, encoding);

   if (generate)
   {
      proto_item_set_generated(vendor_id_item);
      proto_item_set_generated(device_type_item);
      proto_item_set_generated(product_code_item);
      proto_item_set_generated(compatibility_item);
      proto_item_set_generated(comp_bit_item);
      proto_item_set_generated(major_rev_item);
      proto_item_set_generated(minor_rev_item);
   }
}

static void
dissect_net_param16(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_net_param16, int hf_owner, int hf_type,
                 int hf_priority, int hf_fixed_var, int hf_con_size, int ncp_ett, cip_connID_info_t* conn_info)
{
   proto_item *net_param_item;
   proto_tree *net_param_tree;

   net_param_item = proto_tree_add_item(tree, hf_net_param16, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   net_param_tree = proto_item_add_subtree(net_param_item, ncp_ett);

   /* Add the data to the tree */
   proto_tree_add_item(net_param_tree, hf_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item_ret_uint(net_param_tree, hf_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &conn_info->type);
   proto_tree_add_item(net_param_tree, hf_priority, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item_ret_uint(net_param_tree, hf_fixed_var, tvb, offset, 2, ENC_LITTLE_ENDIAN, &conn_info->connection_size_type);
   proto_tree_add_item_ret_uint(net_param_tree, hf_con_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &conn_info->connection_size);
}

static void
dissect_net_param32(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_net_param16, int hf_owner, int hf_type,
                 int hf_priority, int hf_fixed_var, int hf_con_size, int ncp_ett, cip_connID_info_t* conn_info)
{
   proto_item *net_param_item;
   proto_tree *net_param_tree;

   net_param_item = proto_tree_add_item(tree, hf_net_param16, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   net_param_tree = proto_item_add_subtree(net_param_item, ncp_ett);

   /* Add the data to the tree */
   proto_tree_add_item(net_param_tree, hf_owner, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item_ret_uint(net_param_tree, hf_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &conn_info->type);
   proto_tree_add_item(net_param_tree, hf_priority, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item_ret_uint(net_param_tree, hf_fixed_var, tvb, offset, 4, ENC_LITTLE_ENDIAN, &conn_info->connection_size_type);
   proto_tree_add_item_ret_uint(net_param_tree, hf_con_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &conn_info->connection_size);
}

static void
dissect_transport_type_trigger(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_ttt, int hf_direction, int hf_trigger, int hf_class, int ett)
{
   int* const bits[] = {
      &hf_direction,
      &hf_trigger,
      &hf_class,
      NULL
   };

   proto_tree_add_bitmask(tree, tvb, offset, hf_ttt, ett, bits, ENC_LITTLE_ENDIAN);
}

static int dissect_segment_network_extended(packet_info *pinfo, proto_item *epath_item, tvbuff_t *tvb, int offset, bool generate, proto_tree *net_tree)
{
   int data_words;
   data_words = tvb_get_uint8(tvb, offset + 1);

   if (generate)
   {
      proto_item *it;
      uint16_t temp_data;

      it = proto_tree_add_uint(net_tree, hf_cip_seg_network_size, tvb, 0, 0, data_words);
      proto_item_set_generated(it);

      temp_data = tvb_get_letohs(tvb, offset + 2);
      it = proto_tree_add_uint(net_tree, hf_cip_seg_network_subtype, tvb, 0, 0, temp_data);
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(net_tree, hf_cip_seg_network_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(net_tree, hf_cip_seg_network_subtype, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
   }

   // Extended Network Subtype is included in the Number of Data words, so we must have at least 1.
   if (data_words < 1)
   {
      expert_add_info(pinfo, epath_item, &ei_proto_ext_network);
      return 0;
   }

   if (generate == false)
   {
      /* The first word of the data is the extended segment subtype, so
         don't include that in the displayed data block. */
      int net_seg_data_offset;
      int net_seg_data_len;
      net_seg_data_offset = offset + 4;
      net_seg_data_len = (data_words - 1) * 2;

      if (tvb_reported_length_remaining(tvb, net_seg_data_offset) < net_seg_data_len)
      {
          expert_add_info(pinfo, epath_item, &ei_proto_ext_network);
          return 0;
      }

      uint16_t net_seg_subtype = tvb_get_letohs(tvb, offset + 2);

      int data_len_parsed = 0;
      switch (net_seg_subtype)
      {
      case CI_CONCURRENT_EXTENDED_NETWORK_SEG:
      {
         data_len_parsed = 4;
         data_len_parsed += dissect_concurrent_connection_network_segment(pinfo, tvb, offset + data_len_parsed, net_tree);
         break;
      }

      default:
      {
         break;
      }
      }

      if (net_seg_data_len - data_len_parsed > 0)
      {
         proto_tree_add_item(net_tree, hf_cip_data, tvb, net_seg_data_offset + data_len_parsed, net_seg_data_len - data_len_parsed, ENC_NA);
      }
   }

   return data_words * 2 + 2;
}

static int dissect_segment_network_production_inhibit_us(tvbuff_t *tvb, int offset, bool generate, proto_tree *net_tree)
{
   int data_words;
   uint32_t inhibit_time;

   data_words = tvb_get_uint8(tvb, offset + 1);
   inhibit_time = tvb_get_letohl(tvb, offset + 2);

   if (generate == true)
   {
      proto_item *it;
      it = proto_tree_add_uint(net_tree, hf_cip_seg_network_size, tvb, 0, 0, data_words);
      proto_item_set_generated(it);

      it = proto_tree_add_uint(net_tree, hf_cip_seg_prod_inhibit_time_us, tvb, 0, 0, inhibit_time);
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(net_tree, hf_cip_seg_network_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(net_tree, hf_cip_seg_prod_inhibit_time_us,
         tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
   }

   return (data_words * 2) + 2;
}

static int dissect_segment_symbolic(tvbuff_t *tvb, proto_tree *path_seg_tree,
   proto_item *path_seg_item, proto_item *epath_item,
   int offset, bool generate)
{
   int seg_size;
   proto_item *it;
   uint8_t symbol_size;

   symbol_size = tvb_get_uint8(tvb, offset) & 0x1F;
   if (generate)
   {
      it = proto_tree_add_uint(path_seg_tree, hf_cip_symbol_size, tvb, 0, 0, symbol_size);
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(path_seg_tree, hf_cip_symbol_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   }

   if (symbol_size != 0)
   {
      char *symbol_name;
      symbol_name = tvb_format_text(wmem_packet_scope(), tvb, offset + 1, symbol_size);

      proto_item_append_text(path_seg_item, " (Symbolic Segment)");

      if (generate)
      {
         it = proto_tree_add_string(path_seg_tree, hf_cip_symbol_ascii, tvb, 0, 0, symbol_name);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_symbol_ascii, tvb, offset + 1, symbol_size, ENC_ASCII | ENC_NA);
      }

      proto_item_append_text(epath_item, "%s", symbol_name);

      seg_size = symbol_size + 1;
   }
   else
   {
      /* Extended String */
      uint8_t string_format;
      uint8_t string_size;
      int data_size = 0;

      proto_item_append_text(path_seg_item, " (Extended String Symbolic Segment)");

      string_format = tvb_get_uint8(tvb, offset + 1) & CI_SYMBOL_SEG_FORMAT_MASK;
      string_size = tvb_get_uint8(tvb, offset + 1) & CI_SYMBOL_SEG_SIZE_MASK;

      if (generate)
      {
         it = proto_tree_add_uint(path_seg_tree, hf_cip_symbol_extended_format, tvb, 0, 0, string_format);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_symbol_extended_format, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      }

      switch (string_format)
      {
      case CI_SYMBOL_SEG_DOUBLE:
         data_size = string_size * 2;

         if (generate)
         {
            it = proto_tree_add_uint(path_seg_tree, hf_cip_symbol_double_size, tvb, 0, 0, string_size);
            proto_item_set_generated(it);
         }
         else
         {
            proto_tree_add_item(path_seg_tree, hf_cip_symbol_double_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(path_seg_tree, hf_cip_data, tvb, offset + 2, data_size, ENC_NA);
         }

         proto_item_append_text(epath_item, "[Data]");

         break;
      case CI_SYMBOL_SEG_TRIPLE:
         data_size = string_size * 3;

         if (generate)
         {
            it = proto_tree_add_uint(path_seg_tree, hf_cip_symbol_triple_size, tvb, 0, 0, string_size);
            proto_item_set_generated(it);
         }
         else
         {
            proto_tree_add_item(path_seg_tree, hf_cip_symbol_triple_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(path_seg_tree, hf_cip_data, tvb, offset + 2, data_size, ENC_NA);
         }

         proto_item_append_text(epath_item, "[Data]");

         break;
      case CI_SYMBOL_SEG_NUMERIC:
      {
         uint32_t numeric_data;

         if (generate)
         {
            it = proto_tree_add_uint(path_seg_tree, hf_cip_symbol_numeric_format, tvb, 0, 0, string_size);
            proto_item_set_generated(it);
         }
         else
         {
            proto_tree_add_item(path_seg_tree, hf_cip_symbol_numeric_format, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
         }

         if (string_size == CI_SYMBOL_NUMERIC_USINT)
         {
            data_size = 1;
            numeric_data = tvb_get_uint8(tvb, offset + 2);

            if (generate)
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_numeric_usint, tvb, 0, 0, numeric_data);
               proto_item_set_generated(it);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_numeric_usint, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
            }
         }
         else if (string_size == CI_SYMBOL_NUMERIC_UINT)
         {
            data_size = 2;
            numeric_data = tvb_get_letohs(tvb, offset + 2);

            if (generate)
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_numeric_uint, tvb, 0, 0, numeric_data);
               proto_item_set_generated(it);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_numeric_uint, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
            }
         }
         else if (string_size == CI_SYMBOL_NUMERIC_UDINT)
         {
            data_size = 4;
            numeric_data = tvb_get_letohl(tvb, offset + 2);

            if (generate)
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_numeric_udint, tvb, 0, 0, numeric_data);
               proto_item_set_generated(it);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_numeric_udint, tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
            }
         }
         else
         {
            /* Unknown Extended String Format. */
            return 0;
         }

         proto_item_append_text(epath_item, "0x%x", numeric_data);

         break;
      }
      default:
         /* Unknown Extended String Format. */
         return 0;
      }

      seg_size = 2 + data_size;
   }

   /* Add padding. */
   seg_size += seg_size % 2;

   return seg_size;
}

static int dissect_segment_port(tvbuff_t* tvb, int offset, bool generate,
   proto_tree* path_seg_tree, proto_item* path_seg_item, proto_item* epath_item)
{
   int segment_len = 0;
   bool extended_port = false;
   int extended_port_offset = 0;
   uint8_t segment_type = tvb_get_uint8(tvb, offset);

   /* Add Extended Link Address flag & Port Identifier*/
   if (generate)
   {
      proto_item* it = proto_tree_add_boolean(path_seg_tree, hf_cip_port_ex_link_addr, tvb, 0, 0, segment_type & CI_PORT_SEG_EX_LINK_ADDRESS);
      proto_item_set_generated(it);
      it = proto_tree_add_uint(path_seg_tree, hf_cip_port, tvb, 0, 0, (segment_type & CI_PORT_SEG_PORT_ID_MASK));
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(path_seg_tree, hf_cip_port_ex_link_addr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(path_seg_tree, hf_cip_port, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   }

   uint8_t port_id = segment_type & CI_PORT_SEG_PORT_ID_MASK;
   if (port_id == 0xF)
   {
      extended_port = true;
   }

   proto_item_append_text(path_seg_item, " (Port Segment)");

   const char *port_name = try_val_to_str(port_id, cip_port_number_vals);
   if (port_name)
   {
      proto_item_append_text(epath_item, "Port: %s", port_name);
   }
   else
   {
      proto_item_append_text(epath_item, "Port: %d", port_id);
   }

   if (segment_type & CI_PORT_SEG_EX_LINK_ADDRESS)
   {
      int offset_link_address = 2;

      if (extended_port == true)
      {
         offset_link_address += 2;
         extended_port_offset = offset + 2;
      }

      uint8_t opt_link_size = tvb_get_uint8(tvb, offset + 1);

      if (generate)
      {
         /* Add size of extended link address */
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_link_address_size, tvb, 0, 0, opt_link_size);
         proto_item_set_generated(it);
         /* Add extended link address */
         it = proto_tree_add_string(path_seg_tree, hf_cip_link_address_string, tvb, 0, 0, tvb_format_text(wmem_packet_scope(), tvb, offset + offset_link_address, opt_link_size));
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_link_address_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(path_seg_tree, hf_cip_link_address_string, tvb, offset + offset_link_address, opt_link_size, ENC_ASCII | ENC_NA);
      }

      proto_item_append_text(epath_item, ", Address: %s", tvb_format_text(wmem_packet_scope(), tvb, offset + offset_link_address, opt_link_size));

      /* Pad byte */
      if (opt_link_size % 2)
      {
         segment_len = 1 + offset_link_address + opt_link_size;
      }
      else
      {
         segment_len = offset_link_address + opt_link_size;
      }
   }
   else
   {
      int offset_link_address = 1;

      segment_len = 2;

      if (extended_port == true)
      {
         segment_len += 2;
         offset_link_address += 2;
         extended_port_offset = offset + 1;
      }

      /* Add Link Address */
      if (generate)
      {
         uint8_t link_address_byte = tvb_get_uint8(tvb, offset + offset_link_address);
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_link_address_byte, tvb, 0, 0, link_address_byte);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_link_address_byte, tvb, offset + offset_link_address, 1, ENC_LITTLE_ENDIAN);
      }

      proto_item_append_text(epath_item, ", Address: %d", tvb_get_uint8(tvb, offset + offset_link_address));
   }

   if (extended_port == true)
   {
      if (generate)
      {
         uint16_t port_extended = tvb_get_letohs(tvb, extended_port_offset);
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_port_extended, tvb, 0, 0, port_extended);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_port_extended, tvb, extended_port_offset, 2, ENC_LITTLE_ENDIAN);
      }
   }

   if (generate == false)
   {
      proto_item_set_len(path_seg_item, segment_len);
   }

   return segment_len;
}

static int dissect_segment_safety(packet_info* pinfo, tvbuff_t* tvb, int offset, bool generate,
   proto_tree* net_tree, cip_safety_epath_info_t* safety, cip_simple_request_info_t* req_data)
{
   uint16_t seg_size = tvb_get_uint8(tvb, offset + 1) * 2;
   int segment_len = seg_size + 2;

   uint32_t safety_format;
   if (generate)
   {
      safety_format = tvb_get_uint8(tvb, offset + 2);

      proto_item* it = proto_tree_add_uint(net_tree, hf_cip_seg_network_size, tvb, 0, 0, seg_size / 2);
      proto_item_set_generated(it);

      it = proto_tree_add_uint(net_tree, hf_cip_seg_safety_format, tvb, 0, 0, safety_format);
      proto_item_set_generated(it);

      /* Skip printing further information in response packets. */
      return segment_len;
   }
   else
   {
      proto_tree_add_item(net_tree, hf_cip_seg_network_size, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item_ret_uint(net_tree, hf_cip_seg_safety_format, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN, &safety_format);
   }

   /* Safety Network Segment Format */
   if (safety_format < 3)
   {
      cip_connID_info_t ignore;
      proto_tree* safety_tree = proto_tree_add_subtree(net_tree, tvb, offset + 3, seg_size - 1,
         ett_network_seg_safety, NULL, val_to_str_const(safety_format, cip_safety_segment_format_type_vals, "Reserved"));

      bool has_scid = false;
      uint32_t ntem_value = 0;
      switch (safety_format)
      {
      case 0:
      {
         has_scid = true;

         /* Target Format - Deprecated*/
         if (safety != NULL)
            safety->format = CIP_SAFETY_BASE_FORMAT;

         proto_tree_add_item(safety_tree, hf_cip_seg_safety_reserved, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_configuration_crc, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
         dissect_cipsafety_snn(safety_tree, tvb, pinfo, offset + 8,
            hf_cip_seg_safety_configuration_timestamp, hf_cip_seg_safety_configuration_date, hf_cip_seg_safety_configuration_time);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_epi, tvb, offset + 14, 4, ENC_LITTLE_ENDIAN);
         dissect_net_param16(tvb, offset + 18, safety_tree,
            hf_cip_seg_safety_time_correction_net_params, hf_cip_seg_safety_time_correction_own,
            hf_cip_seg_safety_time_correction_typ, hf_cip_seg_safety_time_correction_prio,
            hf_cip_seg_safety_time_correction_fixed_var, hf_cip_seg_safety_time_correction_con_size,
            ett_network_seg_safety_time_correction_net_params, &ignore);
         proto_item* it = proto_tree_add_item(safety_tree, hf_cip_seg_safety_tunid, tvb, offset + 20, 10, ENC_NA);
         dissect_unid(tvb, pinfo, offset + 20, it, "Target UNID SNN", hf_cip_seg_safety_tunid_snn_timestamp,
            hf_cip_seg_safety_tunid_snn_date, hf_cip_seg_safety_tunid_snn_time, hf_cip_seg_safety_tunid_nodeid,
            ett_cip_seg_safety_tunid, ett_cip_seg_safety_tunid_snn);
         it = proto_tree_add_item(safety_tree, hf_cip_seg_safety_ounid, tvb, offset + 30, 10, ENC_NA);
         dissect_unid(tvb, pinfo, offset + 30, it, "Originator UNID SNN", hf_cip_seg_safety_ounid_snn_timestamp,
            hf_cip_seg_safety_ounid_snn_date, hf_cip_seg_safety_ounid_snn_time, hf_cip_seg_safety_ounid_nodeid,
            ett_cip_seg_safety_ounid, ett_cip_seg_safety_ounid_snn);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_ping_epi_multiplier, tvb, offset + 40, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_coord_msg_min_multiplier, tvb, offset + 42, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item_ret_uint(safety_tree, hf_cip_seg_safety_network_time_expected_multiplier, tvb, offset + 44, 2, ENC_LITTLE_ENDIAN, &ntem_value);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_timeout_multiplier, tvb, offset + 46, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_max_consumer_number, tvb, offset + 47, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_conn_param_crc, tvb, offset + 48, 4, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_conn_id, tvb, offset + 52, 4, ENC_LITTLE_ENDIAN);
         break;
      }
      case 1:
         /* Router Format */
         if (safety != NULL)
            safety->format = CIP_SAFETY_BASE_FORMAT;

         proto_tree_add_item(safety_tree, hf_cip_seg_safety_reserved, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_conn_id, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_epi, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
         dissect_net_param16(tvb, offset + 12, safety_tree,
            hf_cip_seg_safety_time_correction_net_params, hf_cip_seg_safety_time_correction_own,
            hf_cip_seg_safety_time_correction_typ, hf_cip_seg_safety_time_correction_prio,
            hf_cip_seg_safety_time_correction_fixed_var, hf_cip_seg_safety_time_correction_con_size,
            ett_network_seg_safety_time_correction_net_params, &ignore);
         break;
      case 2:
      {
         has_scid = true;

         /* Extended Format */
         if (safety != NULL)
            safety->format = CIP_SAFETY_EXTENDED_FORMAT;

         proto_tree_add_item(safety_tree, hf_cip_seg_safety_reserved, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_configuration_crc, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
         dissect_cipsafety_snn(safety_tree, tvb, pinfo, offset + 8,
            hf_cip_seg_safety_configuration_timestamp, hf_cip_seg_safety_configuration_date, hf_cip_seg_safety_configuration_time);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_epi, tvb, offset + 14, 4, ENC_LITTLE_ENDIAN);
         dissect_net_param16(tvb, offset + 18, safety_tree,
            hf_cip_seg_safety_time_correction_net_params, hf_cip_seg_safety_time_correction_own,
            hf_cip_seg_safety_time_correction_typ, hf_cip_seg_safety_time_correction_prio,
            hf_cip_seg_safety_time_correction_fixed_var, hf_cip_seg_safety_time_correction_con_size,
            ett_network_seg_safety_time_correction_net_params, &ignore);
         proto_item* it = proto_tree_add_item(safety_tree, hf_cip_seg_safety_tunid, tvb, offset + 20, 10, ENC_NA);
         dissect_unid(tvb, pinfo, offset + 20, it, "Target UNID SNN", hf_cip_seg_safety_tunid_snn_timestamp,
            hf_cip_seg_safety_tunid_snn_date, hf_cip_seg_safety_tunid_snn_time, hf_cip_seg_safety_tunid_nodeid,
            ett_cip_seg_safety_tunid, ett_cip_seg_safety_tunid_snn);
         it = proto_tree_add_item(safety_tree, hf_cip_seg_safety_ounid, tvb, offset + 30, 10, ENC_NA);
         dissect_unid(tvb, pinfo, offset + 30, it, "Originator UNID SNN", hf_cip_seg_safety_ounid_snn_timestamp,
            hf_cip_seg_safety_ounid_snn_date, hf_cip_seg_safety_ounid_snn_time, hf_cip_seg_safety_ounid_nodeid,
            ett_cip_seg_safety_ounid, ett_cip_seg_safety_ounid_snn);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_ping_epi_multiplier, tvb, offset + 40, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_coord_msg_min_multiplier, tvb, offset + 42, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item_ret_uint(safety_tree, hf_cip_seg_safety_network_time_expected_multiplier, tvb, offset + 44, 2, ENC_LITTLE_ENDIAN, &ntem_value);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_timeout_multiplier, tvb, offset + 46, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_max_consumer_number, tvb, offset + 47, 1, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_max_fault_number, tvb, offset + 48, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_conn_param_crc, tvb, offset + 50, 4, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_time_correction_conn_id, tvb, offset + 54, 4, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_init_timestamp, tvb, offset + 58, 2, ENC_LITTLE_ENDIAN);
         proto_tree_add_item(safety_tree, hf_cip_seg_safety_init_rollover, tvb, offset + 60, 2, ENC_LITTLE_ENDIAN);
         break;
      }
      }  // END switch

      if (safety && req_data && has_scid)
      {
         // Check if the SCID (SCCRC + SCTS) is all zeros.
         uint32_t sccrc_value = tvb_get_letohl(tvb, offset + 4);
         uint64_t scts_value = tvb_get_letoh48(tvb, offset + 8);
         bool scid_zero = (sccrc_value == 0) && (scts_value == 0);

         if (req_data->hasSimpleData)
         {
            safety->safety_open_type = CIP_SAFETY_OPEN_TYPE1;
         }
         else if (scid_zero)
         {
            safety->safety_open_type = CIP_SAFETY_OPEN_TYPE2B;
         }
         else
         {
            safety->safety_open_type = CIP_SAFETY_OPEN_TYPE2A;
         }
      }

      if (safety)
      {
         safety->nte_value_ms = ntem_value * 0.128f;
      }
   }
   else
   {
      proto_tree_add_item(net_tree, hf_cip_seg_safety_data, tvb, offset + 3, seg_size - 1, ENC_NA);
   }

   if (safety != NULL)
   {
      safety->safety_seg = true;
   }

   return segment_len;
}

static int dissect_segment_data_simple(packet_info* pinfo, tvbuff_t* tvb, int offset, bool generate,
   proto_tree* path_seg_tree, proto_item* path_seg_item, cip_simple_request_info_t* req_data)
{
   if (req_data)
   {
      req_data->hasSimpleData = true;
   }

   uint16_t seg_size = tvb_get_uint8(tvb, offset + 1) * 2;
   int segment_len = seg_size + 2;

   if (generate)
   {
      proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_data_seg_size_simple, tvb, 0, 0, seg_size / 2);
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(path_seg_tree, hf_cip_data_seg_size_simple, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
   }

   if (generate)
   {
      return segment_len;
   }

   /* Segment data  */
   if (seg_size != 0)
   {
      int parsed_data_len = 0;
      if (req_data && req_data->iClass == CI_CLS_MOTION
         && req_data->iConnPointA != SEGMENT_VALUE_NOT_SET
         && req_data->iConnPoint != SEGMENT_VALUE_NOT_SET)
      {
         parsed_data_len += dissect_motion_configuration_block(tvb, pinfo, path_seg_tree, path_seg_item, offset + 2);
      }

      int remaining_data_len = seg_size - parsed_data_len;
      if (remaining_data_len > 0)
      {
         proto_tree_add_item(path_seg_tree, hf_cip_data_seg_item, tvb, offset + 2 + parsed_data_len, remaining_data_len, ENC_NA);
      }
   }

   proto_item_set_len(path_seg_item, segment_len);

   return segment_len;
}

static int dissect_segment_ansi_extended_symbol(packet_info* pinfo, tvbuff_t* tvb, int offset,
   bool generate, proto_tree* path_seg_tree, proto_item* path_seg_item,
   proto_item* epath_item, int display_type,
   bool is_msp_item, proto_item* msp_item)
{
   /* Segment size */
   uint16_t seg_size = tvb_get_uint8(tvb, offset + 1);
   if (generate)
   {
      proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_data_seg_size_extended, tvb, 0, 0, seg_size);
      proto_item_set_generated(it);
   }
   else
      proto_tree_add_item(path_seg_tree, hf_cip_data_seg_size_extended, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

   /* Segment data  */
   if (seg_size != 0)
   {
      char* symbol_name = tvb_format_text(pinfo->pool, tvb, offset + 2, seg_size);

      if (generate)
      {
         proto_item* it = proto_tree_add_string(path_seg_tree, hf_cip_symbol, tvb, 0, 0, symbol_name);
         proto_item_set_generated(it);
      }
      else
         proto_tree_add_item(path_seg_tree, hf_cip_symbol, tvb, offset + 2, seg_size, ENC_ASCII | ENC_NA);

      proto_item_append_text(epath_item, "%s", symbol_name);

      if (cip_enhanced_info_column == true && is_msp_item == false)
      {
         add_cip_symbol_to_info_column(pinfo, symbol_name, display_type);
      }

      if (msp_item != NULL)
      {
         proto_item_append_text(msp_item, "'%s' - ", symbol_name);
      }
   }

   /* Check for pad byte */
   if (seg_size % 2)
      seg_size++;

   if (!generate)
   {
      proto_item_set_len(path_seg_item, 2 + seg_size);
   }

   return 2 + seg_size;
}

// offset - Starts with the 'Key Data' section of the Electronic Key Segment Format.
int dissect_electronic_key_format(tvbuff_t* tvb, int offset, proto_tree* tree, bool generate, uint8_t key_format, unsigned encoding)
{
   int key_len;
   if (key_format == CI_E_KEY_FORMAT_VAL)
   {
      key_len = 8;
   }
   else  // CI_E_SERIAL_NUMBER_KEY_FORMAT_VAL
   {
      key_len = 12;
   }

   if (generate)
   {
      dissect_deviceid(tvb, offset, tree,
         hf_cip_ekey_vendor, hf_cip_ekey_devtype, hf_cip_ekey_prodcode,
         hf_cip_ekey_compatibility, hf_cip_ekey_comp_bit, hf_cip_ekey_majorrev, hf_cip_ekey_minorrev, true, encoding);
   }
   else
   {
      dissect_deviceid(tvb, offset, tree,
         hf_cip_ekey_vendor, hf_cip_ekey_devtype, hf_cip_ekey_prodcode,
         hf_cip_ekey_compatibility, hf_cip_ekey_comp_bit, hf_cip_ekey_majorrev, hf_cip_ekey_minorrev, false, encoding);

      if (key_format == CI_E_SERIAL_NUMBER_KEY_FORMAT_VAL)
      {
         proto_tree_add_item(tree, hf_cip_ekey_serial_number, tvb, offset + 8, 4, encoding);
      }
   }

   return key_len;
}

static int dissect_segment_logical_special(packet_info* pinfo, tvbuff_t* tvb, int offset,
   bool generate, proto_tree* path_seg_tree,
   proto_item* path_seg_item, proto_item* epath_item)
{
   int segment_len = 0;

   uint8_t segment_type = tvb_get_uint8(tvb, offset);

   /* Logical Special ID, the only logical format specified is electronic key */
   if ((segment_type & CI_LOGICAL_SEG_FORMAT_MASK) == CI_LOGICAL_SEG_E_KEY)
   {
      uint8_t key_format = tvb_get_uint8(tvb, offset + 1);
      if (key_format == CI_E_KEY_FORMAT_VAL || key_format == CI_E_SERIAL_NUMBER_KEY_FORMAT_VAL)
      {
         if (generate)
         {
            proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_ekey_format, tvb, 0, 0, key_format);
            proto_item_set_generated(it);
         }
         else
         {
            proto_tree_add_item(path_seg_tree, hf_cip_ekey_format, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
         }
         segment_len = 2;

         segment_len += dissect_electronic_key_format(tvb, offset + 2, path_seg_tree, generate, key_format, ENC_LITTLE_ENDIAN);

         proto_item_set_len(path_seg_item, segment_len);

         /* Add "summary" information to parent item */
         uint16_t vendor_id = tvb_get_letohs(tvb, offset + 2);
         proto_item_append_text(path_seg_tree, " (VendorID: 0x%04X", vendor_id);

         uint16_t device_type = tvb_get_letohs(tvb, offset + 4);
         proto_item_append_text(path_seg_tree, ", DevTyp: 0x%04X", device_type);

         uint8_t major_rev = tvb_get_uint8(tvb, offset + 8);
         uint8_t minor_rev = tvb_get_uint8(tvb, offset + 9);

         proto_item_append_text(path_seg_tree, ", %d.%d)", (major_rev & 0x7F), minor_rev);
         proto_item_append_text(epath_item, "[Key]");
      }
      else
      {
         expert_add_info(pinfo, epath_item, &ei_proto_electronic_key_format);
      }
   }
   else
   {
      expert_add_info(pinfo, epath_item, &ei_proto_special_segment_format);
   }

   return segment_len;
}

static int dissect_segment_network(packet_info* pinfo, tvbuff_t* tvb, int offset,
   bool generate, proto_tree* path_seg_tree, proto_item* path_seg_item,
   proto_item* epath_item, int display_type, cip_safety_epath_info_t* safety,
   cip_simple_request_info_t* req_data)
{
   int segment_len = 0;

   uint8_t segment_type = tvb_get_uint8(tvb, offset);

   /* Network segment -Determine the segment sub-type */
   if (generate)
   {
      proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_network_seg_type, tvb, 0, 0, segment_type & CI_NETWORK_SEG_TYPE_MASK);
      proto_item_set_generated(it);
   }
   else
   {
      proto_tree_add_item(path_seg_tree, hf_cip_network_seg_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   }

   proto_item_append_text(path_seg_item, " (%s)", val_to_str_const((segment_type & CI_NETWORK_SEG_TYPE_MASK), cip_network_segment_type_vals, "Reserved"));

   switch (segment_type & CI_NETWORK_SEG_TYPE_MASK)
   {
   case CI_NETWORK_SEG_SCHEDULE:
      if (generate)
      {
         uint8_t schedule = tvb_get_uint8(tvb, offset + 1);
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_seg_schedule, tvb, 0, 0, schedule);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_seg_schedule, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      }

      segment_len = 2;
      break;

   case CI_NETWORK_SEG_FIXED_TAG:
      if (generate)
      {
         uint8_t fixed_tag = tvb_get_uint8(tvb, offset + 1);
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_seg_fixed_tag, tvb, 0, 0, fixed_tag);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_seg_fixed_tag, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      }

      segment_len = 2;
      break;

   case CI_NETWORK_SEG_PROD_INHI:
      if (generate)
      {
         uint8_t inhibit_time = tvb_get_uint8(tvb, offset + 1);
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_seg_prod_inhibit_time, tvb, 0, 0, inhibit_time);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_seg_prod_inhibit_time, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      }

      segment_len = 2;
      break;

   case CI_NETWORK_SEG_PROD_INHI_US:
      segment_len = dissect_segment_network_production_inhibit_us(tvb, offset, generate, path_seg_tree);
      break;

   case CI_NETWORK_SEG_EXTENDED:
      segment_len = dissect_segment_network_extended(pinfo, epath_item, tvb, offset, generate, path_seg_tree);
      proto_item_append_text(epath_item, "[Network]");
      break;

   case CI_NETWORK_SEG_SAFETY:
      proto_item_append_text(epath_item, "[Safety]");

      if (display_type == DISPLAY_CONNECTION_PATH)
      {
         col_append_str(pinfo->cinfo, COL_INFO, " [Safety]");
      }

      segment_len = dissect_segment_safety(pinfo, tvb, offset, generate, path_seg_tree, safety, req_data);
      break;

   default:
      expert_add_info(pinfo, epath_item, &ei_proto_log_sub_seg_type);
      segment_len = 0;
      break;
   } /* End of switch sub-type */

   if (generate == false)
   {
      proto_item_set_len(path_seg_item, segment_len);
   }

   return segment_len;
}

static int dissect_segment_logical_service_id(packet_info* pinfo, tvbuff_t* tvb, int offset,
   bool generate, proto_tree* path_seg_tree, proto_item* path_seg_item, proto_item* epath_item)
{
   int segment_len = 0;

   uint8_t segment_type = tvb_get_uint8(tvb, offset);

   /* Logical Service ID - the only logical format specified is 8-bit Service ID */
   if ((segment_type & CI_LOGICAL_SEG_FORMAT_MASK) == CI_LOGICAL_SEG_8_BIT)
   {
      uint8_t service_id = tvb_get_uint8(tvb, offset + 1);

      if (generate)
      {
         proto_item* it = proto_tree_add_uint(path_seg_tree, hf_cip_serviceid8, tvb, 0, 0, service_id);
         proto_item_set_generated(it);
      }
      else
      {
         proto_tree_add_item(path_seg_tree, hf_cip_serviceid8, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);

         proto_item_set_len(path_seg_item, 2);
      }

      proto_item_append_text(epath_item, "Service ID: 0x%x", service_id);

      segment_len = 2;
   }
   else
   {
      expert_add_info(pinfo, epath_item, &ei_proto_log_seg_type);
   }

   return segment_len;
}

int dissect_cip_segment_single(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *path_tree, proto_item *epath_item,
                    bool generate, bool packed, cip_simple_request_info_t* req_data, cip_safety_epath_info_t* safety,
                    int display_type, proto_item *msp_item,
                    bool is_msp_item)
{
   int segment_len = 0;
   unsigned char segment_type;
   proto_tree *path_seg_tree;
   proto_item *it, *cia_ret_item;
   proto_item *path_seg_item;

   {
      if (tvb_reported_length_remaining(tvb, offset) <= 0)
      {
         expert_add_info(pinfo, epath_item, &ei_mal_incomplete_epath);
         return 0;
      }

      /* Get segment type */
      segment_type = tvb_get_uint8( tvb, offset );

      if ( generate )
      {
         path_seg_item = proto_tree_add_uint(path_tree, hf_cip_path_segment, tvb, 0, 0, segment_type );
         proto_item_set_generated(path_seg_item);
         path_seg_tree = proto_item_add_subtree( path_seg_item, ett_path_seg );
         it = proto_tree_add_uint(path_seg_tree, hf_cip_path_segment_type, tvb, 0, 0, segment_type&CI_SEGMENT_TYPE_MASK);
         proto_item_set_generated(it);
      }
      else
      {
         path_seg_item = proto_tree_add_item(path_tree, hf_cip_path_segment, tvb, offset, 1, ENC_LITTLE_ENDIAN);
         path_seg_tree = proto_item_add_subtree( path_seg_item, ett_path_seg );
         proto_tree_add_item(path_seg_tree, hf_cip_path_segment_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      }

      /* Determine the segment type */

      switch( segment_type & CI_SEGMENT_TYPE_MASK )
      {
         case CI_PORT_SEGMENT:
         {
            segment_len = dissect_segment_port(tvb, offset, generate, path_seg_tree, path_seg_item, epath_item);
            break;
         }

         case CI_LOGICAL_SEGMENT:
         {
            uint8_t logical_seg_type;
            logical_seg_type = segment_type & CI_LOGICAL_SEG_TYPE_MASK;

            /* Logical segment, determine the logical type */
            if ( generate )
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_logical_seg_type, tvb, 0, 0, logical_seg_type);
               proto_item_set_generated(it);
               if (logical_seg_type != CI_LOGICAL_SEG_SPECIAL && logical_seg_type != CI_LOGICAL_SEG_SERV_ID)
               {
                  it = proto_tree_add_uint(path_seg_tree, hf_cip_logical_seg_format, tvb, 0, 0, segment_type & CI_LOGICAL_SEG_FORMAT_MASK);
                  proto_item_set_generated(it);
               }
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_logical_seg_type, tvb, offset, 1, ENC_LITTLE_ENDIAN );
               if (logical_seg_type != CI_LOGICAL_SEG_SPECIAL && logical_seg_type != CI_LOGICAL_SEG_SERV_ID)
                  proto_tree_add_item(path_seg_tree, hf_cip_logical_seg_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            }

            proto_item_append_text( path_seg_item, " (%s)", val_to_str_const( ((segment_type & (CI_LOGICAL_SEG_TYPE_MASK|CI_LOGICAL_SEG_FORMAT_MASK))), cip_logical_seg_vals, "Reserved"));

            switch (logical_seg_type)
            {
               case CI_LOGICAL_SEG_CLASS_ID:
               {
                  uint32_t ClassID;
                  segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                       epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                       "Class", cip_class_names_vals, &ClassID,
                       hf_cip_class8, hf_cip_class16, hf_cip_class32);
                  if (segment_len == 0)
                  {
                     return 0;
                  }

                  if (req_data)
                  {
                     req_data->iClass = ClassID;

                     // Save the first ClassID separately.
                     if (req_data->iClassA == SEGMENT_VALUE_NOT_SET)
                     {
                        req_data->iClassA = ClassID;
                     }
                  }

                  if (req_data != NULL)
                  {
                     if (cip_enhanced_info_column == true && is_msp_item == false)
                     {
                        add_cip_class_to_info_column(pinfo, req_data->iClass, display_type);
                     }

                     if (msp_item != NULL)
                     {
                        proto_item_append_text(msp_item, "%s - ", val_to_str(req_data->iClass, cip_class_names_vals, "Class (0x%02x)"));
                     }
                  }

                  break;
               }

               case CI_LOGICAL_SEG_INST_ID:
               {
                  uint32_t InstanceID;
                  segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                       epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                       "Instance", NULL, &InstanceID,
                       hf_cip_instance8, hf_cip_instance16, hf_cip_instance32);
                  if (segment_len == 0)
                  {
                     return 0;
                  }

                  if (req_data)
                  {
                     req_data->iInstance = InstanceID;

                     // Save the first InstanceID separately.
                     if (req_data->iInstanceA == SEGMENT_VALUE_NOT_SET)
                     {
                        req_data->iInstanceA = InstanceID;
                     }
                  }

                  break;
               }

               case CI_LOGICAL_SEG_MBR_ID:
                  segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                       epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                       "Member", NULL, (req_data == NULL) ? NULL : &req_data->iMember,
                       hf_cip_member8, hf_cip_member16, hf_cip_member32);
                  break;

               case CI_LOGICAL_SEG_ATTR_ID:
                  segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                       epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                       "Attribute", NULL, (req_data == NULL) ? NULL : &req_data->iAttribute,
                       hf_cip_attribute8, hf_cip_attribute16, hf_cip_attribute32);
                  if (segment_len == 0)
                  {
                     return 0;
                  }

                  if (req_data != NULL)
                  {
                     const attribute_info_t* att_info = cip_get_attribute(req_data->iClass, req_data->iInstance,
                                                                          req_data->iAttribute);
                     if (att_info != NULL)
                     {
                        proto_item_append_text(cia_ret_item, " (%s)", att_info->text);
                        proto_item_append_text(epath_item, " (%s)", att_info->text);
                     }
                  }
                  break;

               case CI_LOGICAL_SEG_CON_POINT:
               {
                  uint32_t ConnPoint;
                  segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                     epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                     "Connection Point", NULL, &ConnPoint,
                     hf_cip_conpoint8, hf_cip_conpoint16, hf_cip_conpoint32);
                  if (segment_len == 0)
                  {
                     return 0;
                  }

                  if (req_data)
                  {
                     req_data->iConnPoint = ConnPoint;

                     // Save the first ConnPoint separately.
                     if (req_data->iConnPointA == SEGMENT_VALUE_NOT_SET)
                     {
                        req_data->iConnPointA = ConnPoint;
                     }
                  }

                  break;
               }

               case CI_LOGICAL_SEG_SPECIAL:
                   segment_len = dissect_segment_logical_special(pinfo, tvb, offset, generate,
                      path_seg_tree, path_seg_item, epath_item);
                   break;

               case CI_LOGICAL_SEG_SERV_ID:
                   segment_len = dissect_segment_logical_service_id(pinfo, tvb, offset, generate,
                      path_seg_tree, path_seg_item, epath_item);
                   break;

               case CI_LOGICAL_SEG_EXT_LOGICAL:
                   segment_len = dissect_cia(tvb, offset, segment_type, generate, packed, pinfo,
                       epath_item, path_seg_tree, path_seg_item, &cia_ret_item,
                       "Extended Logical", NULL, NULL,
                       hf_cip_ext_logical8, hf_cip_ext_logical16, hf_cip_ext_logical32);
                   break;

               default:
                  expert_add_info(pinfo, epath_item, &ei_proto_log_seg_type);
                  return 0;

            } /* end of switch( logical_seg_type ) */
            break;
         }

         case CI_DATA_SEGMENT:
         {
            /* Data segment, determine the logical type */
            if ( generate )
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_data_seg_type, tvb, 0, 0, segment_type & CI_DATA_SEG_TYPE_MASK);
               proto_item_set_generated(it);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_data_seg_type, tvb, offset, 1, ENC_LITTLE_ENDIAN );
            }

            proto_item_append_text( path_seg_item, " (%s)", val_to_str_const( (segment_type & CI_DATA_SEG_TYPE_MASK), cip_data_segment_type_vals, "Reserved"));

            switch( segment_type & CI_DATA_SEG_TYPE_MASK)
            {
               case CI_DATA_SEG_SIMPLE:
                  segment_len = dissect_segment_data_simple(pinfo, tvb, offset, generate, path_seg_tree, path_seg_item, req_data);
                  proto_item_append_text(epath_item, "[Data]" );
                  break;

               case CI_DATA_SEG_SYMBOL:
                  segment_len = dissect_segment_ansi_extended_symbol(pinfo, tvb, offset, generate,
                     path_seg_tree, path_seg_item, epath_item, display_type, is_msp_item, msp_item);
                  break;

               default:
                  expert_add_info(pinfo, epath_item, &ei_proto_log_sub_seg_type);
                  return 0;

            } /* End of switch sub-type */

            break;
         }

         case CI_NETWORK_SEGMENT:
            segment_len = dissect_segment_network(pinfo, tvb, offset, generate, path_seg_tree, path_seg_item, epath_item, display_type, safety, req_data);
            break;

         case CI_SYMBOLIC_SEGMENT:
         {
             segment_len = dissect_segment_symbolic(tvb, path_seg_tree,
                 path_seg_item, epath_item,
                 offset, generate);

             if (segment_len == 0)
             {
                 expert_add_info(pinfo, epath_item, &ei_proto_ext_string_format);
                 return 0;
             }

             if (generate == false)
             {
                 proto_item_set_len(path_seg_item, segment_len);
             }

             break;
         }

         default:
            expert_add_info(pinfo, epath_item, &ei_proto_seg_type);
            return 0;

      } /* end of switch( segment_type & CI_SEGMENT_TYPE_MASK ) */
   }

   return segment_len;
}

void reset_cip_request_info(cip_simple_request_info_t* req_data)
{
   req_data->iClass = SEGMENT_VALUE_NOT_SET;
   req_data->iClassA = SEGMENT_VALUE_NOT_SET;

   req_data->iInstance = SEGMENT_VALUE_NOT_SET;
   req_data->iInstanceA = SEGMENT_VALUE_NOT_SET;

   req_data->iAttribute = SEGMENT_VALUE_NOT_SET;
   req_data->iMember = SEGMENT_VALUE_NOT_SET;

   req_data->iConnPoint = SEGMENT_VALUE_NOT_SET;
   req_data->iConnPointA = SEGMENT_VALUE_NOT_SET;

   req_data->hasSimpleData = false;
}

void dissect_epath(tvbuff_t *tvb, packet_info *pinfo, proto_tree *path_tree, proto_item *epath_item, int offset, int path_length,
                    bool generate, bool packed, cip_simple_request_info_t* req_data, cip_safety_epath_info_t* safety,
                    int display_type, proto_item *msp_item,
                    bool is_msp_item)
{
   int pathpos = 0;
   proto_item *hidden_item;

   if (req_data != NULL)
   {
      reset_cip_request_info(req_data);
   }

   if (safety != NULL)
      safety->safety_seg = false;

   if ( !generate )
   {
      hidden_item = proto_tree_add_item(path_tree, hf_cip_epath,
                                        tvb, offset, path_length, ENC_NA );
      proto_item_set_hidden(hidden_item);
   }

  while( pathpos < path_length )
  {
      int segment_len;
      segment_len = dissect_cip_segment_single(pinfo, tvb, offset + pathpos, path_tree, epath_item, generate, packed, req_data, safety, display_type, msp_item, is_msp_item);
      if (segment_len == 0)
      {
          break;
      }

      pathpos += segment_len;

      /* Next path segment */
      if( pathpos < path_length )
         proto_item_append_text( epath_item, ", " );

   } /* end of while( pathpos < path_length ) */

} /* end of dissect_epath() */

#define NUM_SECONDS_PER_DAY ((uint64_t)(60 * 60 * 24))

/* Number of seconds between Jan 1, 1970 00:00:00 epoch and CIP's epoch time of Jan 1, 1972 00:00:00 */
#define CIP_TIMEBASE ((uint64_t)(NUM_SECONDS_PER_DAY * 365 * 2))

void dissect_cip_date_and_time(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_datetime)
{
   nstime_t computed_time;
   uint16_t num_days_since_1972;
   uint32_t num_ms_today;

   num_days_since_1972 = tvb_get_letohs(tvb, offset+4);
   num_ms_today = tvb_get_letohl(tvb, offset);

   if ((num_days_since_1972 != 0) || (num_ms_today != 0))
   {
      computed_time.secs = CIP_TIMEBASE + (uint64_t)num_days_since_1972 * NUM_SECONDS_PER_DAY;
      computed_time.secs += num_ms_today/1000;
      computed_time.nsecs = (num_ms_today%1000)*1000000;
   }
   else
   {
      computed_time.secs = 0;
      computed_time.nsecs = 0;
   }

   proto_tree_add_time(tree, hf_datetime, tvb, offset, 6, &computed_time);
}

static int dissect_cip_date(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_date)
{
   char date_str[20];

   uint16_t num_days_since_1972 = tvb_get_letohs(tvb, offset);
   /* Convert to nstime epoch */
   time_t computed_time = CIP_TIMEBASE + (uint64_t)num_days_since_1972 * NUM_SECONDS_PER_DAY;
   struct tm* date = gmtime(&computed_time);

   if (date != NULL)
      strftime(date_str, 20, "%Y-%m-%d", date);
   else
      (void) g_strlcpy(date_str, "Not representable", sizeof date_str);
   proto_tree_add_uint_format_value(tree, hf_date, tvb, offset, 2, num_days_since_1972, "%s", date_str);

   return 2;
}

// CIP Type - STIME (nanoseconds)
static int dissect_cip_stime(proto_tree* tree, tvbuff_t* tvb, int offset, int hf_datetime)
{
   nstime_t ts_nstime = { 0 };
   uint64_t timestamp = tvb_get_letoh64(tvb, offset);
   ts_nstime.secs = timestamp / 1000000000;
   ts_nstime.nsecs = timestamp % 1000000000;

   proto_tree_add_time(tree, hf_datetime, tvb, offset, 8, &ts_nstime);

   return 8;
}

// CIP Type - UTIME (microseconds)
int dissect_cip_utime(proto_tree* tree, tvbuff_t* tvb, int offset, int hf_datetime)
{
   nstime_t ts_nstime = { 0 };
   uint64_t timestamp = tvb_get_letoh64(tvb, offset);
   ts_nstime.secs = timestamp / 1000000;
   ts_nstime.nsecs = (timestamp % 1000000) * 1000;

   proto_tree_add_time(tree, hf_datetime, tvb, offset, 8, &ts_nstime);

   return 8;
}

int dissect_cip_string_type(packet_info *pinfo, proto_tree *tree, proto_item *item,
    tvbuff_t *tvb, int offset, int hf_type, int string_type)
{
    uint32_t string_size_field_len;
    uint32_t string_size;
    unsigned string_encoding;
    int parsed_len;
    int total_len;

    total_len = tvb_reported_length_remaining(tvb, offset);

    switch (string_type)
    {
    case CIP_SHORT_STRING_TYPE:
        string_size = tvb_get_uint8(tvb, offset);
        string_encoding = ENC_ASCII | ENC_NA;
        string_size_field_len = 1;
        break;

    case CIP_STRING_TYPE:
        string_size = tvb_get_letohs(tvb, offset);
        string_encoding = ENC_ASCII | ENC_NA;
        string_size_field_len = 2;
        break;

    case CIP_STRING2_TYPE:
        string_size = tvb_get_letohs(tvb, offset) * 2;
        string_encoding = ENC_UCS_2 | ENC_LITTLE_ENDIAN;
        string_size_field_len = 2;
        break;

    default:
        // Unsupported.
        return total_len;
    }

    if (total_len < (int)(string_size + string_size_field_len))
    {
        expert_add_info(pinfo, item, &ei_mal_missing_string_data);
        parsed_len = total_len;
    }
    else
    {
        proto_tree_add_item(tree, hf_type, tvb, offset + string_size_field_len, string_size, string_encoding);
        parsed_len = string_size + string_size_field_len;
    }

    return parsed_len;
}

static int dissect_cip_stringi(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset)
{
    int parsed_len = 1;
    uint32_t num_char = 0;
    proto_tree_add_item_ret_uint(tree, hf_stringi_number_char, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_char);

    for (uint32_t i = 0; i < num_char; ++i)
    {
        proto_tree_add_item(tree, hf_stringi_language_char, tvb, offset + 1, 3, ENC_ASCII | ENC_NA);

        uint32_t char_string_type = 0;
        proto_tree_add_item_ret_uint(tree, hf_stringi_char_string_struct, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN, &char_string_type);
        proto_tree_add_item(tree, hf_stringi_char_set, tvb, offset + 5, 2, ENC_LITTLE_ENDIAN);
        parsed_len += 6;

        if (char_string_type != CIP_STRING_TYPE
            && char_string_type != CIP_SHORT_STRING_TYPE
            && char_string_type != CIP_STRING2_TYPE)
        {
            // Unsupported type.
            break;
        }

        parsed_len += dissect_cip_string_type(pinfo, tree, item, tvb, offset + parsed_len, hf_stringi_international_string, char_string_type);
    }

    return parsed_len;
}

int dissect_cip_attribute(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                          const attribute_info_t* attr, int offset, int total_len)
{
   int i, temp_data, temp_time, hour, min, sec, ms,
      consumed = 0;

   /* sanity check */
   if (((attr->datatype == cip_dissector_func) && (attr->pdissect == NULL)) ||
       ((attr->datatype != cip_dissector_func) && (attr->phf == NULL)))
   {
      DISSECTOR_ASSERT(0);
      return total_len;
   }

   switch (attr->datatype)
   {
   case cip_bool:
   case cip_usint:
   case cip_sint:
   case cip_byte:
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, 1, ENC_LITTLE_ENDIAN);
      consumed = 1;
      break;
   case cip_uint:
   case cip_int:
   case cip_word:
   case cip_itime:
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, 2, ENC_LITTLE_ENDIAN);
      consumed = 2;
      break;
   case cip_usint_array:
      for (i = 0; i < total_len; i++)
         proto_tree_add_item(tree, *(attr->phf), tvb, offset, total_len, ENC_NA);
      consumed = total_len;
      break;
   case cip_uint_array:
      for (i = 0; i < total_len; i+=2)
         proto_tree_add_item(tree, *(attr->phf), tvb, offset+i, 2, ENC_LITTLE_ENDIAN);
      consumed = i;
      break;
   case cip_udint:
   case cip_dint:
   case cip_dword:
   case cip_real:
   case cip_time:
   case cip_ftime:
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, 4, ENC_LITTLE_ENDIAN);
      consumed = 4;
      break;
   case cip_ulint:
   case cip_lint:
   case cip_lword:
   case cip_lreal:
   case cip_ltime:
   case cip_ntime:
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, 8, ENC_LITTLE_ENDIAN);
      consumed = 8;
      break;
   case cip_short_string:
      consumed = dissect_cip_string_type(pinfo, tree, item, tvb, offset, *(attr->phf), CIP_SHORT_STRING_TYPE);
      break;
   case cip_string:
      consumed = dissect_cip_string_type(pinfo, tree, item, tvb, offset, *(attr->phf), CIP_STRING_TYPE);
      break;
   case cip_dissector_func:
      consumed = attr->pdissect(pinfo, tree, item, tvb, offset, total_len);
      if (consumed == 0)
      {
         consumed = total_len;
      }

      break;
   case cip_date_and_time:
      dissect_cip_date_and_time(tree, tvb, offset, *(attr->phf));
      consumed = 6;
      break;
   case cip_stime:
      consumed = dissect_cip_stime(tree, tvb, offset, *(attr->phf));
      break;
   case cip_utime:
      consumed = dissect_cip_utime(tree, tvb, offset, *(attr->phf));
      break;
   case cip_date:
      consumed = dissect_cip_date(tree, tvb, offset, *(attr->phf));
      break;
   case cip_time_of_day:
      temp_time = temp_data = tvb_get_letohl( tvb, offset);
      hour = temp_time/(60*60*1000);
      temp_time %= (60*60*1000);
      min = temp_time/(60*1000);
      temp_time %= (60*1000);
      sec = temp_time/1000;
      ms = temp_time%1000;
      proto_tree_add_uint_format_value(tree, *(attr->phf), tvb, offset, 4, temp_data, "%02d:%02d:%02d.%03d", hour, min, sec, ms);
      consumed = 4;
      break;
   case cip_string2:
      consumed = dissect_cip_string_type(pinfo, tree, item, tvb, offset, *(attr->phf), CIP_STRING2_TYPE);
      break;
   case cip_stringi:
      consumed = dissect_cip_stringi(pinfo, tree, item, tvb, offset);
      break;
   case cip_stringN:
      /* CURRENTLY NOT SUPPORTED */
      expert_add_info(pinfo, item, &ei_proto_unsupported_datatype);
      consumed = total_len;
      break;
   }

   return consumed;
}

static int dissect_cip_service(packet_info *pinfo, tvbuff_t *tvb, int offset,
   proto_item *ti, proto_tree *item_tree, cip_service_info_t *service_entry, uint8_t service)
{
   int parsed_len = 0;

   if (service_entry != NULL && service_entry->pdissect)
   {
      bool request = !(service & CIP_SC_RESPONSE_MASK);
      parsed_len = service_entry->pdissect(pinfo, item_tree, ti, tvb, offset, request);
   }

   return parsed_len;
}

static int dissect_cip_object_specific_service(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item* msp_item, cip_service_info_t *service_entry)
{
   DISSECTOR_ASSERT(service_entry != NULL);

   int offset = 0;
   uint8_t service = tvb_get_uint8(tvb, offset);
   uint8_t gen_status = 0;

   // Skip over the Request/Response header to get to the actual data.
   if (service & CIP_SC_RESPONSE_MASK)
   {
      gen_status = tvb_get_uint8(tvb, offset + 2);

      uint16_t add_stat_size = tvb_get_uint8(tvb, offset + 3) * 2;
      offset = 4 + add_stat_size;
   }
   else
   {
      uint16_t req_path_size = tvb_get_uint8(tvb, offset + 1) * 2;
      offset = 2 + req_path_size;
   }

   // Display the service name, even if there is no payload data.
   if (service_entry->service_name)
   {
      col_append_str(pinfo->cinfo, COL_INFO, service_entry->service_name);
      col_set_fence(pinfo->cinfo, COL_INFO);

      proto_item_append_text(msp_item, "%s", service_entry->service_name);
   }

   // Only dissect responses with specific response statuses.
   if ((service & CIP_SC_RESPONSE_MASK)
      && (should_dissect_cip_response(tvb, offset, gen_status) == false))
   {
      return 0;
   }

   proto_item *payload_item;
   proto_tree *payload_tree = proto_tree_add_subtree(tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_cmd_data, &payload_item, "");

   // Add the service info to the tree item.
   proto_item_append_text(payload_item, "%s", service_entry->service_name);

   if (service & CIP_SC_RESPONSE_MASK)
   {
      proto_item_append_text(payload_item, " (Response)");
   }
   else
   {
      proto_item_append_text(payload_item, " (Request)");
   }

   // Process any known command-specific data.
   offset += dissect_cip_service(pinfo, tvb, offset, payload_item, payload_tree, service_entry, service);

   // Add any remaining data.
   int len_remain = tvb_reported_length_remaining(tvb, offset);
   if (len_remain > 0)
   {
      proto_tree_add_item(payload_tree, hf_cip_data, tvb, offset, len_remain, ENC_NA);
   }

   return tvb_reported_length(tvb);
}

/************************************************
 *
 * Dissector for generic CIP object
 *
 ************************************************/

static void
dissect_cip_generic_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo, proto_item *ti )
{
   proto_tree *cmd_data_tree;
   int req_path_size;
   unsigned char add_stat_size;
   int cmd_data_len;
   int cmd_data_offset;
   uint8_t service = tvb_get_uint8( tvb, offset );

   if (service & CIP_SC_RESPONSE_MASK)
   {
      /* Response message */
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;
      cmd_data_len = item_length - 4 - add_stat_size;
      cmd_data_offset = offset + 4 + add_stat_size;
   }
   else
   {
      /* Request message */
      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;
      cmd_data_len = item_length - req_path_size - 2;
      cmd_data_offset = offset + 2 + req_path_size;
   }

   /* If there is any command specific data create a sub-tree for it */
   if (cmd_data_len > 0)
   {
      cmd_data_tree = proto_tree_add_subtree(item_tree, tvb, cmd_data_offset, cmd_data_len,
         ett_cmd_data, NULL, "Command Specific Data");
      proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, cmd_data_offset, cmd_data_len, ENC_NA);
   }
   else
   {
      proto_item_set_hidden(ti);
   }

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals);
} /* End of dissect_cip_generic_data() */

static int
dissect_cip_class_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_generic, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_generic );

   dissect_cip_generic_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo, ti );

   return tvb_reported_length(tvb);
}

static int
dissect_cip_set_attribute_single_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int parsed_len = 0;
   const attribute_info_t* attr;

   attr = cip_get_attribute(req_data->iClass, req_data->iInstance, req_data->iAttribute);
   if (attr != NULL)
   {
      parsed_len = dissect_cip_attribute(pinfo, tree, item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
   }

   return parsed_len;
}

int dissect_cip_get_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, att_count, att_value;
   const attribute_info_t* pattribute;
   proto_item *att_list, *att_item;
   proto_tree* att_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_serv_gal);
      return 0;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_get_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
   offset += 2;

   /* Add Attribute List */
   att_tree = proto_tree_add_subtree(tree, tvb, offset, att_count*2, ett_cip_get_attribute_list, &att_list, "Attribute List" );

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_tree, hf_cip_attribute16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      pattribute = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (pattribute != NULL)
         proto_item_append_text(att_item, " (%s)", pattribute->text);

      offset += 2;
      if ((tvb_reported_length_remaining(tvb, offset) < 2) && (i < att_count-1))
      {
         expert_add_info(pinfo, att_list, &ei_mal_serv_gal_count);
         break;
      }
   }

   return 2 + att_count * 2;
}

int
dissect_cip_set_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count,
       att_value, att_size;
   const attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_serv_sal);
      return 0;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_set_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list_tree = proto_tree_add_subtree(tree, tvb, offset+2, att_count*2, ett_cip_set_attribute_list, &att_list, "Attribute List" );
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_attribute16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_set_attribute_list_item);
      offset += 2;

      attr = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (attr != NULL)
      {
         proto_item_append_text(att_item, " (%s)", attr->text);
         /* provide attribute data */
         att_size = dissect_cip_attribute(pinfo, att_tree, att_item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
         offset += att_size;
         proto_item_set_len(att_item, att_size+2);
      }
      else
      {
         /* Can't find the attribute. */
         break;
      }

      if ((tvb_reported_length_remaining(tvb, offset) < 2) && (i < att_count-1))
      {
         expert_add_info(pinfo, att_list, &ei_mal_serv_sal_count);
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );

   return 2 + (offset - start_offset);
}

// NOLINTNEXTLINE(misc-no-recursion)
int dissect_cip_multiple_service_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset, bool request)
{
   proto_tree *mult_serv_tree, *offset_tree;
   int i, num_services, serv_offset, prev_offset = 0;
   int parsed_len;
   cip_req_info_t *cip_req_info, *mr_single_req_info;
   mr_mult_req_info_t *mr_mult_req_info = NULL;

   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_msp_missing_services);
      return 0;
   }

   num_services = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_mult_serv_pack_num_services, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Ensure a rough sanity check */
   if (num_services*2 > tvb_reported_length_remaining(tvb, offset+2))
   {
      expert_add_info(pinfo, item, &ei_mal_msp_services);
   }

   offset_tree = proto_tree_add_subtree(tree, tvb, offset + 2, num_services * 2, ett_cip_msp_offset, NULL, "Offset List");
   for (i = 0; i < num_services; i++)
   {
      proto_tree_add_item(offset_tree, hf_cip_sc_mult_serv_pack_offset, tvb, offset + 2 + i * 2, 2, ENC_LITTLE_ENDIAN);
   }

   cip_req_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0 );
   if ( cip_req_info )
   {
      /* Only allocate memory for requests. */
      if (cip_req_info->pData == NULL && request == true)
      {
         mr_mult_req_info = wmem_new(wmem_file_scope(), mr_mult_req_info_t);
         mr_mult_req_info->service = SC_MULT_SERV_PACK;
         mr_mult_req_info->num_services = num_services;
         mr_mult_req_info->requests = (cip_req_info_t *)wmem_alloc0(wmem_file_scope(), sizeof(cip_req_info_t)*num_services);
         cip_req_info->pData = mr_mult_req_info;
      }

      mr_mult_req_info = (mr_mult_req_info_t*)cip_req_info->pData;

      if (mr_mult_req_info
         && (mr_mult_req_info->service != SC_MULT_SERV_PACK
         || mr_mult_req_info->num_services != num_services))
      {
         mr_mult_req_info = NULL;
      }
   }

   col_append_str(pinfo->cinfo, COL_INFO, ": ");

   parsed_len = 2 + num_services * 2;
   for( i=0; i < num_services; i++ )
   {
      proto_item *mult_serv_item;
      int serv_length;
      tvbuff_t *next_tvb;

      serv_offset = tvb_get_letohs( tvb, offset+2+(i*2) );

      if (tvb_reported_length_remaining(tvb, serv_offset) <= 0)
      {
         expert_add_info(pinfo, item, &ei_mal_msp_inv_offset);
         continue;
      }

      if( i == (num_services-1) )
      {
         /* Last service to add */
         serv_length = tvb_reported_length_remaining(tvb, offset)-serv_offset;
      }
      else
      {
         serv_length = tvb_get_letohs( tvb, offset+2+((i+1)*2) ) - serv_offset;
      }

      mult_serv_tree = proto_tree_add_subtree_format(tree, tvb, offset+serv_offset, serv_length,
                    ett_cip_mult_service_packet, &mult_serv_item, "Service Packet #%d: ", i+1 );
      proto_tree_add_item(mult_serv_tree, hf_cip_sc_mult_serv_pack_offset, tvb, offset+2+(i*2) , 2, ENC_LITTLE_ENDIAN);

      /* Make sure the offset is valid */
      if ((tvb_reported_length_remaining(tvb, serv_offset) <= 0) ||
          (tvb_reported_length_remaining(tvb, serv_offset+serv_length) <= 0) ||
          (serv_length <= 0) ||
          (prev_offset >= serv_offset))
      {
         expert_add_info(pinfo, mult_serv_item, &ei_mal_msp_inv_offset);
         prev_offset = serv_offset;
         continue;
      }
      prev_offset = serv_offset;

      /*
      ** We call ourselves again to dissect embedded packet
      */

      next_tvb = tvb_new_subset_length(tvb, offset+serv_offset, serv_length);

      if ( mr_mult_req_info )
      {
         mr_single_req_info = mr_mult_req_info->requests + i;
         dissect_cip_data(mult_serv_tree, next_tvb, 0, pinfo, mr_single_req_info, mult_serv_item, true);
      }
      else
      {
         dissect_cip_data(mult_serv_tree, next_tvb, 0, pinfo, NULL, mult_serv_item, true);
      }

      /* Add the embedded CIP service to the item. */
      if (mult_serv_item != NULL)
      {
         uint8_t service = tvb_get_uint8(next_tvb, 0);
         proto_item_append_text(mult_serv_item, "%s", val_to_str(service & CIP_SC_MASK, cip_sc_vals, "Service (0x%02x)"));
      }

      if (i != num_services - 1)
      {
          col_append_str(pinfo->cinfo, COL_INFO, ", ");
      }

      parsed_len += serv_length;
   }

   return parsed_len;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_cip_generic_service_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, cip_simple_request_info_t* req_data)
{
   proto_item *cmd_data_item;
   int req_path_size,
       offset = 0;
   proto_tree *cmd_data_tree;
   uint8_t service = tvb_get_uint8( tvb, offset ) & CIP_SC_MASK;

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals);

   req_path_size = tvb_get_uint8(tvb, offset + 1);
   offset += ((req_path_size * 2) + 2);

   /* Create service tree */
   cmd_data_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_cmd_data, &cmd_data_item,
                        val_to_str(service, cip_sc_vals , "Unknown Service (0x%02x)"));
   proto_item_append_text(cmd_data_item, " (Request)");

   int parsed_len = 0;

   switch(service)
   {
   case SC_GET_ATT_LIST:
      parsed_len = dissect_cip_get_attribute_list_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_SET_ATT_LIST:
      parsed_len = dissect_cip_set_attribute_list_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_MULT_SERV_PACK:
      parsed_len = dissect_cip_multiple_service_packet(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, true);
      break;
   case SC_SET_ATT_SINGLE:
      parsed_len = dissect_cip_set_attribute_single_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_FIND_NEXT_OBJ_INST:
      proto_tree_add_item(cmd_data_tree, hf_cip_find_next_object_max_instance, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      parsed_len = 1;
      break;
   default:
      // No specific handling for other services.
      break;
   }

   // Display any remaining unparsed data.
   int remain_len = tvb_reported_length_remaining(tvb, offset + parsed_len);
   if (remain_len > 0)
   {
       proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset + parsed_len, remain_len, ENC_NA);
   }

   proto_item_set_len(cmd_data_item, parsed_len + remain_len);

   return tvb_reported_length(tvb);
}

typedef struct cip_gaa_key {
   uint32_t cip_class;
   bool class_instance;
} cip_gaa_key_t;

typedef struct cip_gaa_val {
   wmem_list_t *attributes;
} cip_gaa_val_t;

static wmem_map_t *cip_gaa_hashtable;

static unsigned
cip_gaa_hash (const void *v)
{
   const cip_gaa_key_t *key = (const cip_gaa_key_t *)v;
   unsigned val;

   val = (unsigned)((key->cip_class << 1) & 0xFFFFFFFE);
   val |= (key->class_instance & 1);

   return val;
}

static int
cip_gaa_equal(const void *v, const void *w)
{
   const cip_gaa_key_t *v1 = (const cip_gaa_key_t *)v;
   const cip_gaa_key_t *v2 = (const cip_gaa_key_t *)w;

   if ((v1->cip_class == v2->cip_class) &&
       (v1->class_instance == v2->class_instance))
       return 1;

   return 0;
}

static void build_get_attr_all_table(void)
{
   size_t i, j;
   attribute_val_array_t* att_array;
   const attribute_info_t* pattr;
   cip_gaa_key_t key;
   cip_gaa_key_t* new_key;
   cip_gaa_val_t *gaa_val;
   int last_attribute_index = -1;

   cip_gaa_hashtable = wmem_map_new(wmem_epan_scope(), cip_gaa_hash, cip_gaa_equal);

   for (i = 0; i < array_length(all_attribute_vals); i++)
   {
      att_array = &all_attribute_vals[i];
      for (j = 0; j < att_array->size; j++)
      {
         pattr = &att_array->attrs[j];
         key.cip_class = pattr->class_id;
         key.class_instance = pattr->class_instance;

         gaa_val = (cip_gaa_val_t *)wmem_map_lookup( cip_gaa_hashtable, &key );
         if (gaa_val == NULL)
         {
            new_key = (cip_gaa_key_t*)wmem_memdup(wmem_epan_scope(), &key, sizeof(cip_gaa_key_t));
            gaa_val = wmem_new0(wmem_epan_scope(), cip_gaa_val_t);
            gaa_val->attributes = wmem_list_new(wmem_epan_scope());

            wmem_map_insert(cip_gaa_hashtable, new_key, gaa_val );
            last_attribute_index = -1;
         }

         if ((pattr->gaa_index >= 0) && (pattr->gaa_index > last_attribute_index))
         {
             wmem_list_append(gaa_val->attributes, (attribute_info_t *)pattr);
             last_attribute_index = pattr->gaa_index;
         }
      }
   }
}

int dissect_cip_get_attribute_all_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, cip_simple_request_info_t* req_data)
{
   int att_size;
   int len_remain;
   const attribute_info_t* attr;
   proto_item *att_item;
   proto_tree *att_tree;
   cip_gaa_key_t key;
   cip_gaa_val_t *gaa_val;
   wmem_list_frame_t* attribute_list;
   int parsed_len = 0;

   key.cip_class = req_data->iClass;
   key.class_instance = (req_data->iInstance == 0);

   gaa_val = (cip_gaa_val_t *)wmem_map_lookup( cip_gaa_hashtable, &key );
   if (gaa_val == NULL)
   {
      return 0;
   }

   for (attribute_list = wmem_list_head(gaa_val->attributes);
       (attribute_list != NULL);
        attribute_list = wmem_list_frame_next(attribute_list))
   {
      attr = (const attribute_info_t *)wmem_list_frame_data(attribute_list);
      len_remain = tvb_reported_length_remaining(tvb, offset);

      /* If there are no more attributes defined or there is no data left. */
      if (attr == NULL || len_remain <= 0)
         break;

      att_item = proto_tree_add_uint_format_value(tree, hf_cip_attribute16, tvb, offset, 0, attr->attribute, "%d (%s)", attr->attribute, attr->text);
      att_tree = proto_item_add_subtree(att_item, ett_cip_get_attributes_all_item);

      att_size = dissect_cip_attribute(pinfo, att_tree, att_item, tvb, attr, offset, len_remain);
      proto_item_set_len(att_item, att_size);

      offset += att_size;
      parsed_len += att_size;
   }

   return parsed_len;
}

static int
dissect_cip_get_attribute_list_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count,
       att_value, att_status;
   unsigned att_size;
   const attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list response */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_serv_gal);
      return 0;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_get_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list_tree = proto_tree_add_subtree(tree, tvb, offset+2, att_count*4, ett_cip_get_attribute_list, &att_list, "Attribute List" );
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_attribute16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_get_attribute_list_item);

      att_status = tvb_get_letohs( tvb, offset+2);
      proto_tree_add_item(att_tree, hf_cip_sc_get_attr_list_attr_status, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);

      attr = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (attr != NULL)
         proto_item_append_text(att_item, " (%s)", attr->text);

      offset += 4;
      if (att_status == 0)
      {
         if (attr != NULL)
         {
            /* provide attribute data */
            att_size = dissect_cip_attribute(pinfo, att_tree, att_item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
            offset += att_size;
            proto_item_set_len(att_item, att_size+4);
         }
         else
         {
            /* Can't find the attribute */
            break;
         }
      }

      if ((tvb_reported_length_remaining(tvb, offset) < 4) && (i < att_count-1))
      {
         expert_add_info(pinfo, att_list, &ei_mal_serv_gal_count);
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );
   return 2 + (offset - start_offset);
}

int
dissect_cip_set_attribute_list_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count, att_value;
   const attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info(pinfo, item, &ei_mal_serv_sal);
      return 0;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_set_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list_tree = proto_tree_add_subtree(tree, tvb, offset+2, att_count*4, ett_cip_get_attribute_list, &att_list, "Attribute List" );
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_attribute16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_set_attribute_list_item);

      proto_tree_add_item(att_tree, hf_cip_sc_set_attr_list_attr_status, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);

      attr = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (attr != NULL)
         proto_item_append_text(att_item, " (%s)", attr->text);

      offset += 4;
      if ((tvb_reported_length_remaining(tvb, offset) < 4) && (i < att_count-1))
      {
         expert_add_info(pinfo, att_list, &ei_mal_serv_sal_count);
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );
   return 2 + (offset - start_offset);
}

static int
dissect_cip_get_attribute_single_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int parsed_len = 0;
   int total_len;
   const attribute_info_t* attr;

   total_len = tvb_reported_length_remaining(tvb, offset);
   attr = cip_get_attribute(req_data->iClass, req_data->iInstance, req_data->iAttribute);
   if (attr != NULL)
   {
      proto_item_append_text(item, " (%s)", attr->text);
      parsed_len = dissect_cip_attribute(pinfo, tree, item, tvb, attr, offset, total_len);
   }

   return parsed_len;
}

static int
dissect_cip_find_next_object_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset)
{
   uint32_t i, num_instances;

   if (tvb_reported_length_remaining(tvb, offset) < 1)
   {
      expert_add_info(pinfo, item, &ei_mal_serv_find_next_object);
      return 0;
   }

   proto_tree_add_item_ret_uint(tree, hf_cip_find_next_object_num_instances, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_instances);
   offset += 1;

   for (i = 0; i < num_instances; i++)
   {
      proto_tree_add_item(tree, hf_cip_find_next_object_instance_item, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;

      if ((tvb_reported_length_remaining(tvb, offset) < 2) && (i < num_instances-1))
      {
         expert_add_info(pinfo, item, &ei_mal_serv_find_next_object_count);
         break;
      }
   }

   return 1 + num_instances * 2;
}

void load_cip_request_data(packet_info *pinfo, cip_simple_request_info_t *req_data)
{
    cip_req_info_t* preq_info;
    preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);

    if ((preq_info != NULL) &&
        (preq_info->ciaData != NULL))
    {
        memcpy(req_data, preq_info->ciaData, sizeof(cip_simple_request_info_t));
    }
    else
    {
        reset_cip_request_info(req_data);
    }
}

bool should_dissect_cip_response(tvbuff_t *tvb, int offset, uint8_t gen_status)
{
    // Only parse the response if there is data left or it has a response status that allows additional data
    //   to be returned.
    if ((tvb_reported_length_remaining(tvb, offset) == 0)
        && gen_status != CI_GRC_SUCCESS
        && gen_status != CI_GRC_ATTR_LIST_ERROR
        && gen_status != CI_GRC_SERVICE_ERROR
        && gen_status != CI_GRC_INVALID_LIST_STATUS)
    {
        return false;
    }

    return true;
}

int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_cip_generic_service_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *cmd_data_item;
   proto_tree *cmd_data_tree;
   cip_simple_request_info_t req_data;
   int offset = 0;
   uint8_t gen_status = tvb_get_uint8(tvb, offset + 2);
   uint8_t service = tvb_get_uint8(tvb, offset) & CIP_SC_MASK;
   uint16_t add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

   offset = 4 + add_stat_size;

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals);

   cmd_data_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
       ett_cmd_data, &cmd_data_item, val_to_str(service, cip_sc_vals, "Unknown Service (0x%02x)"));
   proto_item_append_text(cmd_data_item, " (Response)");

   load_cip_request_data(pinfo, &req_data);

   if (should_dissect_cip_response(tvb, offset, gen_status) == false)
   {
      return 0;
   }

   int parsed_len = 0;

   switch(service)
   {
   case SC_GET_ATT_ALL:
      parsed_len = dissect_cip_get_attribute_all_rsp(tvb, pinfo, cmd_data_tree, offset, &req_data);
      break;
   case SC_GET_ATT_LIST:
      parsed_len = dissect_cip_get_attribute_list_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, &req_data);
      break;
   case SC_SET_ATT_LIST:
      parsed_len = dissect_cip_set_attribute_list_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, &req_data);
      break;
   case SC_CREATE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_create_instance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      parsed_len = 2;
      break;
   case SC_MULT_SERV_PACK:
      parsed_len = dissect_cip_multiple_service_packet(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, false);
      break;
   case SC_GET_ATT_SINGLE:
      parsed_len = dissect_cip_get_attribute_single_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, &req_data);
      break;
   case SC_FIND_NEXT_OBJ_INST:
      parsed_len = dissect_cip_find_next_object_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset);
      break;
   case SC_GROUP_SYNC:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_group_sync_is_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      parsed_len = 1;
      break;
   default:
      // No specific handling for other services.
      break;
   }

   // Display any remaining unparsed data.
   int remain_len = tvb_reported_length_remaining(tvb, offset + parsed_len);
   if (remain_len > 0)
   {
       proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset + parsed_len, remain_len, ENC_NA);
   }

   proto_item_set_len(cmd_data_item, parsed_len + remain_len);

   return tvb_reported_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Manager
 *
 ************************************************/

static void
dissect_cip_cm_timeout(proto_tree *cmd_tree, tvbuff_t *tvb, int offset)
{
   uint8_t tick, timeout_tick;
   int timeout;

   /* Display the priority/tick timer */
   tick = tvb_get_uint8( tvb, offset) & 0x0F;
   proto_tree_add_item( cmd_tree, hf_cip_cm_priority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( cmd_tree, hf_cip_cm_tick_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the time-out ticks */
   timeout_tick = tvb_get_uint8( tvb, offset+1 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_timeout_tick, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);

   /* Display the actual time out */
   timeout = ( 1 << tick ) * timeout_tick;
   proto_tree_add_uint(cmd_tree, hf_cip_cm_timeout, tvb, offset, 2, timeout);
}

static void dissect_connection_triad(tvbuff_t *tvb, int offset, proto_tree *tree,
   int hf_conn_serial, int hf_vendor, int hf_orig_serial,
   cip_connection_triad_t *triad)
{
   uint32_t ConnSerialNumber;
   uint32_t VendorID;
   uint32_t DeviceSerialNumber;

   proto_tree_add_item_ret_uint(tree, hf_conn_serial, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ConnSerialNumber);
   proto_tree_add_item_ret_uint(tree, hf_vendor, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN, &VendorID);
   proto_tree_add_item_ret_uint(tree, hf_orig_serial, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN, &DeviceSerialNumber);

   if (triad)
   {
      triad->ConnSerialNumber = ConnSerialNumber;
      triad->VendorID = VendorID;
      triad->DeviceSerialNumber = DeviceSerialNumber;
   }
}

// Mark this message as belonging to a specific CIP connection index.
static void mark_cip_connection(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree)
{
    cip_conn_info_t* conn_val = (cip_conn_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_enip, ENIP_CONNECTION_INFO);
    if (conn_val)
    {
        proto_item* pi = proto_tree_add_uint(tree, hf_cip_connection, tvb, 0, 0, conn_val->connid);
        proto_item_set_generated(pi);
    }
}

// Save the Route or Connection Path for use in the response packet.
static void save_route_connection_path(packet_info* pinfo, tvbuff_t* tvb, int offset, unsigned path_size_bytes)
{
   if (pinfo->fd->visited)
   {
      return;
   }

   cip_req_info_t* preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   if (preq_info)
   {
      preq_info->pRouteConnectionPath = wmem_alloc(wmem_file_scope(), path_size_bytes);
      preq_info->RouteConnectionPathLen = path_size_bytes / 2;
      tvb_memcpy(tvb, preq_info->pRouteConnectionPath, offset, path_size_bytes);
   }
}

static int get_connection_timeout_multiplier(uint32_t timeout_value)
{
   uint32_t timeout_multiplier;
   switch (timeout_value)
   {
   case 0:
      timeout_multiplier = 4;
      break;
   case 1:
      timeout_multiplier = 8;
      break;
   case 2:
      timeout_multiplier = 16;
      break;
   case 3:
      timeout_multiplier = 32;
      break;
   case 4:
      timeout_multiplier = 64;
      break;
   case 5:
      timeout_multiplier = 128;
      break;
   case 6:
      timeout_multiplier = 256;
      break;
   case 7:
      timeout_multiplier = 512;
      break;
   default:
      // Invalid
      timeout_multiplier = 0;
      break;
   }

   return timeout_multiplier;
}

static void fwd_open_analysis_safety_open(packet_info* pinfo, proto_item* cmd_item, cip_safety_epath_info_t* safety_fwdopen)
{
   if (safety_fwdopen->safety_seg == false)
   {
      return;
   }

   if (safety_fwdopen->safety_open_type == CIP_SAFETY_OPEN_TYPE1)
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_safety_open_type1);
   }
   else if (safety_fwdopen->safety_open_type == CIP_SAFETY_OPEN_TYPE2A)
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_safety_open_type2a);
   }
   else if (safety_fwdopen->safety_open_type == CIP_SAFETY_OPEN_TYPE2B)
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_safety_open_type2b);
   }

   if (safety_fwdopen->originator_type == CIP_SAFETY_ORIGINATOR_PRODUCER)
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_safety_output);
   }
   else if (safety_fwdopen->originator_type == CIP_SAFETY_ORIGINATOR_CONSUMER)
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_safety_input);
   }
}

static void fwd_open_analysis_listen_input_connection(packet_info* pinfo, proto_item* cmd_item, uint8_t TransportClass_trigger, const cip_connID_info_t* O2T_info)
{
   // Listen Only and Input Only connections must be 'Fixed'.
   if (O2T_info->connection_size_type != CIP_CONNECTION_SIZE_TYPE_FIXED)
   {
      return;
   }

   uint8_t transport_class = TransportClass_trigger & CI_TRANSPORT_CLASS_MASK;
   if ((transport_class == 0 && O2T_info->connection_size == 0)
      || (transport_class == 1 && O2T_info->connection_size == 2))
   {
      expert_add_info(pinfo, cmd_item, &ei_cip_listen_input_connection);
   }
}

static void display_previous_route_connection_path(cip_req_info_t* preq_info, proto_tree* item_tree, tvbuff_t* tvb, packet_info* pinfo, int hf_path, int display_type);

// Display all Connection Information and Analysis.
static void display_connection_information_fwd_open_req(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree)
{
   cip_conn_info_t* conn_info = (cip_conn_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_enip, ENIP_CONNECTION_INFO);
   if (!conn_info)
   {
      return;
   }

   proto_item* conn_info_item = NULL;
   proto_tree* conn_info_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_connection_info, &conn_info_item, "Connection Information");
   proto_item_set_generated(conn_info_item);

   mark_cip_connection(pinfo, tvb, conn_info_tree);

   proto_item* pi = proto_tree_add_float(conn_info_tree, hf_cip_cm_ot_timeout, tvb, 0, 0, (conn_info->O2T.rpi / 1000.0f) * conn_info->timeout_multiplier);
   proto_item_set_generated(pi);

   pi = proto_tree_add_float(conn_info_tree, hf_cip_cm_to_timeout, tvb, 0, 0, (conn_info->T2O.rpi / 1000.0f) * conn_info->timeout_multiplier);
   proto_item_set_generated(pi);

   if (conn_info->safety.safety_seg)
   {
      add_safety_data_type_to_info_column(pinfo, ECIDT_O2T, &conn_info->safety);

      pi = proto_tree_add_float(conn_info_tree, hf_cip_safety_nte_ms, tvb, 0, 0, conn_info->safety.nte_value_ms);
      proto_item_set_generated(pi);
   }

   if (conn_info->close_frame != 0)
   {
      pi = proto_tree_add_uint(conn_info_tree, hf_cip_fwd_close_in, tvb, 0, 0, conn_info->close_frame);
      proto_item_set_generated(pi);
   }
   else
   {
      expert_add_info(pinfo, conn_info_item, &ei_cip_no_fwd_close);
   }

   fwd_open_analysis_safety_open(pinfo, conn_info_item, &conn_info->safety);
   fwd_open_analysis_listen_input_connection(pinfo, conn_info_item, conn_info->TransportClass_trigger, &conn_info->O2T);
}

static void display_connection_information_fwd_open_rsp(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree, cip_req_info_t* preq_info)
{
   proto_item* conn_info_item = NULL;
   proto_tree* conn_info_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_connection_info, &conn_info_item, "Connection Information");
   proto_item_set_generated(conn_info_item);

   mark_cip_connection(pinfo, tvb, conn_info_tree);

   display_previous_route_connection_path(preq_info, conn_info_tree, tvb, pinfo, hf_cip_cm_conn_path_size, DISPLAY_CONNECTION_PATH);

   if (preq_info && preq_info->connInfo && preq_info->connInfo->safety.safety_seg)
   {
      add_safety_data_type_to_info_column(pinfo, ECIDT_T2O, &preq_info->connInfo->safety);
   }
}

static void display_connection_information_fwd_close_req(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree)
{
   cip_conn_info_t* conn_info = (cip_conn_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_enip, ENIP_CONNECTION_INFO);
   if (!conn_info)
   {
      return;
   }

   proto_item* conn_info_item = NULL;
   proto_tree* conn_info_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_connection_info, &conn_info_item, "Connection Information");
   proto_item_set_generated(conn_info_item);

   mark_cip_connection(pinfo, tvb, conn_info_tree);

   display_fwd_open_connection_path(conn_info, conn_info_tree, tvb, pinfo);

   proto_item *pi = proto_tree_add_uint(conn_info_tree, hf_cip_fwd_open_in, tvb, 0, 0, conn_info->open_req_frame);
   proto_item_set_generated(pi);

   // Show the API values
   pi = proto_tree_add_uint(conn_info_tree, hf_cip_cm_ot_api, tvb, 0, 0, conn_info->O2T.api);
   proto_item_set_generated(pi);

   pi = proto_tree_add_uint(conn_info_tree, hf_cip_cm_to_api, tvb, 0, 0, conn_info->T2O.api);
   proto_item_set_generated(pi);

   // Connection timeout values
   float ot_timeout_ms = (conn_info->O2T.rpi / 1000.0f) * conn_info->timeout_multiplier;
   float to_timeout_ms = (conn_info->T2O.rpi / 1000.0f) * conn_info->timeout_multiplier;
   proto_item* ot_timeout_item = proto_tree_add_float(conn_info_tree, hf_cip_cm_ot_timeout, tvb, 0, 0, ot_timeout_ms);
   proto_item_set_generated(ot_timeout_item);

   proto_item* to_timeout_item = proto_tree_add_float(conn_info_tree, hf_cip_cm_to_timeout, tvb, 0, 0, to_timeout_ms);
   proto_item_set_generated(to_timeout_item);

   if (conn_info->safety.safety_seg)
   {
      pi = proto_tree_add_float(conn_info_tree, hf_cip_safety_nte_ms, tvb, 0, 0, conn_info->safety.nte_value_ms);
      proto_item_set_generated(pi);
   }

   if (conn_info->safety.safety_seg)
   {
      // Make it obvious that the FwdClose is Safety, to match how the FwdOpen looks.
      col_append_str(pinfo->cinfo, COL_INFO, " [Safety]");
      add_safety_data_type_to_info_column(pinfo, ECIDT_O2T, &conn_info->safety);
   }

}

static void display_connection_information_fwd_close_rsp(packet_info* pinfo, tvbuff_t* tvb, proto_tree* tree)
{
   cip_conn_info_t* conn_val = (cip_conn_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_enip, ENIP_CONNECTION_INFO);
   if (!conn_val)
   {
      return;
   }

   proto_item* conn_info_item = NULL;
   proto_tree* conn_info_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_connection_info, &conn_info_item, "Connection Information");
   proto_item_set_generated(conn_info_item);

   mark_cip_connection(pinfo, tvb, conn_info_tree);

   cip_req_info_t* preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   display_previous_route_connection_path(preq_info, conn_info_tree, tvb, pinfo, hf_cip_cm_conn_path_size, DISPLAY_CONNECTION_PATH);

   if (conn_val->safety.safety_seg)
   {
      // Make it obvious that the FwdClose is Safety, to match how the FwdOpen looks.
      col_append_str(pinfo->cinfo, COL_INFO, " [Safety]");
      add_safety_data_type_to_info_column(pinfo, ECIDT_T2O, &conn_val->safety);
   }
}

//// Concurrent Connections
static int dissect_cip_cc_hop(packet_info* pinfo, tvbuff_t* tvb, int offset, proto_tree* hops_tree, uint8_t hop_number)
{
    int parsed = 0;

    proto_item* item_hop = proto_tree_add_uint(hops_tree, hf_ext_net_seg_hop, tvb, offset, 0, hop_number);

    proto_tree* hop_tree = proto_item_add_subtree(item_hop, ett_cc_hop);
    proto_tree_add_item(hop_tree, hf_ext_net_seg_hop_egress_cip_port, tvb, offset + parsed, 1, ENC_LITTLE_ENDIAN);
    parsed++;

    proto_tree_add_item(hop_tree, hf_ext_net_seg_hop_link_adr_type, tvb, offset + parsed, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hop_tree, hf_ext_net_seg_hop_number_of_linkadr, tvb, offset + parsed, 1, ENC_LITTLE_ENDIAN);
    parsed++;

    uint8_t link_type = tvb_get_uint8(tvb, offset + 1) >> 4;
    uint8_t number_of_links = tvb_get_uint8(tvb, offset + 1) & 0x0F;

    for (uint8_t i = 0; i < number_of_links; i++)
    {
        switch (link_type)
        {
        case 0: // Link addresses
        {
            proto_tree_add_item(hop_tree, hf_ext_net_seg_link_address, tvb, offset + parsed, 1, ENC_LITTLE_ENDIAN);
            parsed++;
            break;
        }

        case 1: // IPv4 addresses encoding
            proto_tree_add_item(hop_tree, hf_ext_net_seg_link_ipv4, tvb, offset + parsed, 4, ENC_LITTLE_ENDIAN);
            parsed += 4;
            break;

        case 2: // Host Name addresses encoding
            parsed += dissect_cip_string_type(pinfo, hop_tree, item_hop, tvb, offset + parsed, hf_ext_net_seg_link_hostname, CIP_STRING_TYPE);

            // Add pad byte when string length is odd
            if (parsed % 2)
            {
                parsed++;
            }

            break;

        default:
            break;
        }
    }

    proto_item_set_len(item_hop, parsed);

    return parsed;
}

#define CC_PACKET_TYPE_MASK (0x001F)
int dissect_concurrent_connection_packet(packet_info* pinfo, tvbuff_t* tvb, int offset, proto_tree* tree)
{
    proto_item* type_item = proto_tree_add_item(tree, proto_cc, tvb, offset, -1, ENC_NA);
    proto_tree* CC_tree = proto_item_add_subtree(type_item, ett_cc_header);

    uint16_t header_type = tvb_get_letohs(tvb, offset) & CC_PACKET_TYPE_MASK;

    int parsed_len = 0;
    if (header_type == 1)
    {
        static int* const options[] = {
           &hf_cip_cc_packet_type,
           &hf_cip_cc_packet_keepalive,
           &hf_cip_cc_packet_keepalive_hop_count,
           &hf_cip_cc_packet_reserved,
           NULL
        };

        proto_tree_add_bitmask(CC_tree, tvb, offset + parsed_len, hf_cip_cc_packet_options, ett_cc_header, options, ENC_LITTLE_ENDIAN);
        parsed_len += 2;

        uint32_t CC_frame_length;
        proto_tree_add_item_ret_uint(CC_tree, hf_cip_cc_packet_length, tvb, offset + parsed_len, 2, ENC_LITTLE_ENDIAN, &CC_frame_length);
        parsed_len += 2;

        uint32_t ccSeq;
        proto_tree_add_item_ret_uint(CC_tree, hf_cip_cc_packet_seq_number, tvb, offset + parsed_len, 4, ENC_LITTLE_ENDIAN, &ccSeq);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CC_SEQ=%010u", ccSeq);
        parsed_len += 4;

        proto_tree_add_item(CC_tree, hf_cip_cc_crc, tvb, offset + CC_frame_length, CC_CRC_LENGTH, ENC_LITTLE_ENDIAN);
        proto_tree_set_appendix(CC_tree, tvb, offset + CC_frame_length, CC_CRC_LENGTH);
    }
    else
    {
        expert_add_info(pinfo, type_item, &ei_cc_invalid_header_type);
    }

    proto_item_set_len(type_item, parsed_len);

    return parsed_len;
}

void proto_register_cc(void)
{
    static hf_register_info hf_cc[] =
    {
        /// Concurrent Connections
        { &hf_cip_cm_cc_version, { "Concurrent Connections Protocol Version", "cip.cm.cc_version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        // Concurrent Connection Packet
        { &hf_cip_cc_packet_length,{ "Packet Length", "cip.cc.packet.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_cip_cc_packet_type,{ "Packet Type", "cip.cc.packet_type", FT_UINT16, BASE_DEC, VALS(cc_packet_type_vals), CC_PACKET_TYPE_MASK, NULL, HFILL } },
        { &hf_cip_cc_packet_options, { "Packet Type and Keep-alive", "cip.cc.packet.type_and_keepalive", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_cip_cc_packet_keepalive,{ "Keep-alive Flag", "cip.cc.packet.keep_alive_flag", FT_UINT16, BASE_HEX, NULL, 0x0020, NULL, HFILL } },
        { &hf_cip_cc_packet_keepalive_hop_count,{ "Keep-alive Hop Count", "cip.cc.packet.keep_alive_count", FT_UINT16, BASE_DEC, NULL, 0x01C0, NULL, HFILL } },
        { &hf_cip_cc_packet_reserved,{ "Reserved", "cip.cc.packet.reserved", FT_UINT16, BASE_HEX, NULL, 0xFE00, NULL, HFILL } },
        { &hf_cip_cc_packet_seq_number,{ "Concurrent Connection Sequence Count", "cip.cc.packet.sequence_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_cip_cc_crc,{ "CRC", "cip.cc.crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },

        // Concurrent Connection Path
        { &hf_ext_net_seg_hops_count,{ "Hops Count", "cip.cc.netsegment.hopsCount", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_ext_net_seg_length,{ "Length of Concurrent Connection Path", "cip.cc.netsegment.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        // Concurrent Connection Hops
        { &hf_ext_net_seg_hop,{ "CC Hop", "cip.cc.netsegment.hop", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_ext_net_seg_hop_egress_cip_port,{ "Egress Port", "cip.cc.netsegment.HopEgreeCipPort", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_ext_net_seg_hop_link_adr_type,{ "Link Address Type", "cip.cc.netsegment.HopLnkAdrType", FT_UINT8, BASE_DEC, VALS(cc_link_adr_type), 0xF0, NULL, HFILL } },
        { &hf_ext_net_seg_hop_number_of_linkadr,{ "Number of link addresses", "cip.cc.netsegment.HopNumberOfLnkAdr", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },
        { &hf_ext_net_seg_link_address,{ "Link address", "cip.cc.netsegment.link", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_ext_net_seg_link_ipv4,{ "IPv4 address", "cip.cc.netsegment.ip", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_ext_net_seg_link_hostname, { "Hostname", "cip.cc.netsegment.hostname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    };

    static ei_register_info ei_cc[] = {
        { &ei_cc_invalid_header_type, { "cip.cc.invalid_packet_type", PI_MALFORMED, PI_ERROR, "Invalid Concurrent Connections Packet Type", EXPFILL }},
    };

    proto_cc = proto_register_protocol("Concurrent Connection Packet",
        "CIPCC",
        "cipcc");

    proto_register_field_array(proto_cc, hf_cc, array_length(hf_cc));
    proto_register_subtree_array(ett_cc, array_length(ett_cc));

    expert_module_t* expert_cc = expert_register_protocol(proto_cc);
    expert_register_field_array(expert_cc, ei_cc, array_length(ei_cc));
}

// Offset - Starts after the Extended Network Segment Subtype
int dissect_concurrent_connection_network_segment(packet_info* pinfo, tvbuff_t* tvb, int offset, proto_tree* tree)
{
    uint32_t hops_count;
    proto_tree_add_item_ret_uint(tree, hf_ext_net_seg_hops_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &hops_count);

    proto_tree_add_item(tree, hf_ext_net_seg_length, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    int parsed_len = 2;

    for (uint32_t i = 0; i < hops_count; i++)
    {
        parsed_len += dissect_cip_cc_hop(pinfo, tvb, offset + parsed_len, tree, i + 1);
    }

    // Add padding when the Network segment length is odd.
    if (parsed_len & 0x0001)
    {
        parsed_len++;
    }

    return parsed_len;
}

static void
dissect_cip_cm_fwd_open_req(cip_req_info_t *preq_info, proto_tree *cmd_tree, proto_item* cmd_item, tvbuff_t *tvb, int offset,
   bool large_fwd_open, packet_info *pinfo, bool concurrent_connection)
{
   proto_item *pi;
   proto_tree *epath_tree;
   int conn_path_size, net_param_offset = 0;
   uint8_t TransportClass_trigger;
   cip_simple_request_info_t connection_path;
   cip_safety_epath_info_t safety_fwdopen = {0};

   cip_connID_info_t O2T_info = {0};
   cip_connID_info_t T2O_info = {0};

   dissect_cip_cm_timeout(cmd_tree, tvb, offset);
   proto_tree_add_item_ret_uint( cmd_tree, hf_cip_cm_ot_connid, tvb, offset+2, 4, ENC_LITTLE_ENDIAN, &O2T_info.connID);
   proto_tree_add_item_ret_uint( cmd_tree, hf_cip_cm_to_connid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN, &T2O_info.connID);

   // Add Connection IDs as hidden items so that it's easy to find all Connection IDs in different fields.
   pi = proto_tree_add_item(cmd_tree, hf_cip_connid, tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
   proto_item_set_hidden(pi);
   pi = proto_tree_add_item(cmd_tree, hf_cip_connid, tvb, offset + 6, 4, ENC_LITTLE_ENDIAN);
   proto_item_set_hidden(pi);

   cip_connection_triad_t conn_triad;
   dissect_connection_triad(tvb, offset + 10, cmd_tree,
      hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
      &conn_triad);

   if (concurrent_connection)
   {
      // For CC there is additional 1 byte containing CC Version and one reserved byte after.
      proto_tree_add_item(cmd_tree, hf_cip_cm_cc_version, tvb, offset + 18, 1, ENC_LITTLE_ENDIAN);
      offset += 2;
   }

   uint32_t timeout_value;
   proto_tree_add_item_ret_uint(cmd_tree, hf_cip_cm_timeout_multiplier, tvb, offset+18, 1, ENC_LITTLE_ENDIAN, &timeout_value);
   uint32_t timeout_multiplier = get_connection_timeout_multiplier(timeout_value);

   proto_tree_add_item(cmd_tree, hf_cip_reserved24, tvb, offset+19, 3, ENC_LITTLE_ENDIAN);

   // O->T parameters
   proto_tree_add_item_ret_uint(cmd_tree, hf_cip_cm_ot_rpi, tvb, offset + 22, 4, ENC_LITTLE_ENDIAN, &O2T_info.rpi);
   if (large_fwd_open)
   {
      dissect_net_param32(tvb, offset+26, cmd_tree,
                 hf_cip_cm_ot_net_params32, hf_cip_cm_lfwo_own, hf_cip_cm_lfwo_typ,
                 hf_cip_cm_lfwo_prio, hf_cip_cm_lfwo_fixed_var, hf_cip_cm_lfwo_con_size, ett_cm_ncp, &O2T_info);
      net_param_offset = 4;
   }
   else
   {
      dissect_net_param16(tvb, offset+26, cmd_tree,
                 hf_cip_cm_ot_net_params16, hf_cip_cm_fwo_own, hf_cip_cm_fwo_typ,
                 hf_cip_cm_fwo_prio, hf_cip_cm_fwo_fixed_var, hf_cip_cm_fwo_con_size, ett_cm_ncp, &O2T_info);
      net_param_offset = 2;
   }

   // T->O parameters
   proto_tree_add_item_ret_uint(cmd_tree, hf_cip_cm_to_rpi, tvb, offset + 26 + net_param_offset, 4, ENC_LITTLE_ENDIAN, &T2O_info.rpi);
   if (large_fwd_open)
   {
      dissect_net_param32(tvb, offset+26+net_param_offset+4, cmd_tree,
                 hf_cip_cm_to_net_params32, hf_cip_cm_lfwo_own, hf_cip_cm_lfwo_typ,
                 hf_cip_cm_lfwo_prio, hf_cip_cm_lfwo_fixed_var, hf_cip_cm_lfwo_con_size, ett_cm_ncp, &T2O_info);
      net_param_offset += 4;
   }
   else
   {
      dissect_net_param16(tvb, offset+26+net_param_offset+4, cmd_tree,
                 hf_cip_cm_to_net_params16, hf_cip_cm_fwo_own, hf_cip_cm_fwo_typ,
                 hf_cip_cm_fwo_prio, hf_cip_cm_fwo_fixed_var, hf_cip_cm_fwo_con_size, ett_cm_ncp, &T2O_info);
      net_param_offset += 2;
   }

   TransportClass_trigger = tvb_get_uint8( tvb, offset+26+net_param_offset+4);
   dissect_transport_type_trigger(tvb, offset+26+net_param_offset+4, cmd_tree, hf_cip_cm_transport_type_trigger,
                                  hf_cip_cm_fwo_dir, hf_cip_cm_fwo_trigg, hf_cip_cm_fwo_class, ett_cm_ttt);

   /* Add path size */
   conn_path_size = tvb_get_uint8( tvb, offset+26+net_param_offset+5 )*2;
   proto_tree_add_item(cmd_tree, hf_cip_cm_conn_path_size, tvb, offset+26+net_param_offset+5, 1, ENC_LITTLE_ENDIAN);

   /* Add the epath */
   epath_tree = proto_tree_add_subtree(cmd_tree, tvb, offset+26+net_param_offset+6, conn_path_size, ett_path, &pi, "Connection Path: ");
   dissect_epath( tvb, pinfo, epath_tree, pi, offset+26+net_param_offset+6, conn_path_size, false, false, &connection_path, &safety_fwdopen, DISPLAY_CONNECTION_PATH, NULL, false);
   save_route_connection_path(pinfo, tvb, offset + 26 + net_param_offset + 6, conn_path_size);

   // Null Forward Opens are a special case, so make it obvious.
   if ((O2T_info.type == CONN_TYPE_NULL) && (T2O_info.type == CONN_TYPE_NULL))
   {
      col_append_str(pinfo->cinfo, COL_INFO, " [Null]");
      expert_add_info(pinfo, cmd_item, &ei_cip_null_fwd_open);
   }

   if (pinfo->fd->visited)
   {
       /* "Connection" is created during ForwardOpen reply (which will be after ForwardOpen request),
          so ForwardOpen request can only be marked after the first pass */
       enip_mark_connection_triad(pinfo, &conn_triad);
   }
   else
   {
      if (preq_info != NULL)
      {
         DISSECTOR_ASSERT(preq_info->connInfo == NULL);
         preq_info->connInfo = wmem_new0(wmem_file_scope(), cip_conn_info_t);

         preq_info->connInfo->triad = conn_triad;
         preq_info->connInfo->open_req_frame = pinfo->num;

         preq_info->connInfo->O2T = O2T_info;
         preq_info->connInfo->T2O = T2O_info;

         preq_info->connInfo->TransportClass_trigger = TransportClass_trigger;
         preq_info->connInfo->IsNullFwdOpen = (O2T_info.type == CONN_TYPE_NULL) && (T2O_info.type == CONN_TYPE_NULL);
         preq_info->connInfo->timeout_multiplier = timeout_multiplier;
         preq_info->connInfo->safety = safety_fwdopen;
         if (preq_info->connInfo->safety.safety_seg)
         {
            bool server_dir = (TransportClass_trigger & CI_PRODUCTION_DIR_MASK) ? true : false;
            if (server_dir)
            {
               preq_info->connInfo->safety.originator_type = CIP_SAFETY_ORIGINATOR_PRODUCER;
            }
            else
            {
               preq_info->connInfo->safety.originator_type = CIP_SAFETY_ORIGINATOR_CONSUMER;
            }
         }

         preq_info->connInfo->connection_path = connection_path;

         preq_info->connInfo->FwdOpenPathLenBytes = conn_path_size;
         preq_info->connInfo->pFwdOpenPathData = wmem_alloc(wmem_file_scope(), conn_path_size);
         tvb_memcpy(tvb, preq_info->connInfo->pFwdOpenPathData, offset + 26 + net_param_offset + 6, conn_path_size);
      }
   }

   display_connection_information_fwd_open_req(pinfo, tvb, cmd_tree);
}

static void display_previous_route_connection_path(cip_req_info_t *preq_info, proto_tree *item_tree, tvbuff_t *tvb, packet_info *pinfo, int hf_path, int display_type)
{
   if (preq_info && preq_info->RouteConnectionPathLen && preq_info->pRouteConnectionPath)
   {
      tvbuff_t* tvbIOI = tvb_new_real_data((const uint8_t *)preq_info->pRouteConnectionPath, preq_info->RouteConnectionPathLen * 2, preq_info->RouteConnectionPathLen * 2);
      if (!tvbIOI)
      {
         return;
      }

      proto_item* pi = proto_tree_add_uint(item_tree, hf_path, tvb, 0, 0, preq_info->RouteConnectionPathLen);
      proto_item_set_generated(pi);

      proto_tree* epath_tree = proto_tree_add_subtree(item_tree, tvb, 0, 0, ett_path, &pi, "Route/Connection Path: ");
      proto_item_set_generated(pi);

      cip_simple_request_info_t route_conn_path;
      dissect_epath(tvbIOI, pinfo, epath_tree, pi, 0, preq_info->RouteConnectionPathLen * 2, true, false, &route_conn_path, NULL, display_type, NULL, false);
      tvb_free(tvbIOI);

      if (preq_info->connInfo && preq_info->connInfo->IsNullFwdOpen)
      {
         col_append_str(pinfo->cinfo, COL_INFO, " [Null]");
         expert_add_info(pinfo, item_tree, &ei_cip_null_fwd_open);
      }
   }
}

typedef struct safety_application_reply_data {
   cip_connection_triad_t target_triad;
   uint16_t init_rollover_value;
   uint16_t init_timestamp_value;
} safety_application_reply_data_t;

static int dissect_fwd_open_rsp_safety_application_reply_data(cip_req_info_t* preq_info, proto_tree* tree, tvbuff_t* tvb, int offset, safety_application_reply_data_t* safety_reply_data)
{
   int reply_parsed_len = 10;

   proto_item* safety_item;
   proto_tree* safety_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_cip_cm_safety, &safety_item, "");

   // Consumer Number and PID/CID are common to all formats.
   proto_tree_add_item(safety_tree, hf_cip_cm_consumer_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   proto_item* pid_item;
   proto_tree* pid_tree = proto_tree_add_subtree(safety_tree, tvb, offset + 2, 8, ett_cip_cm_pid, &pid_item, "");
   bool server_dir = (preq_info->connInfo->TransportClass_trigger & CI_PRODUCTION_DIR_MASK) ? true : false;
   if (server_dir)
   {
      proto_item_set_text(pid_item, "Consumer ID (CID)");
   }
   else
   {
      proto_item_set_text(pid_item, "Producer ID (PID)");
   }

   proto_tree_add_item(pid_tree, hf_cip_cm_targ_vendor_id, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
   safety_reply_data->target_triad.VendorID = tvb_get_letohs(tvb, offset + 2);

   proto_tree_add_item_ret_uint(pid_tree, hf_cip_cm_targ_dev_serial_num, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN, &(safety_reply_data->target_triad.DeviceSerialNumber));

   proto_tree_add_item(pid_tree, hf_cip_cm_targ_conn_serial_num, tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
   safety_reply_data->target_triad.ConnSerialNumber = tvb_get_letohs(tvb, offset + 8);

   if (preq_info->connInfo->safety.format == CIP_SAFETY_EXTENDED_FORMAT)
   {
      proto_tree_add_item(safety_tree, hf_cip_cm_initial_timestamp, tvb, offset + 10, 2, ENC_LITTLE_ENDIAN);
      safety_reply_data->init_timestamp_value = tvb_get_letohs(tvb, offset + 10);

      proto_tree_add_item(safety_tree, hf_cip_cm_initial_rollover, tvb, offset + 12, 2, ENC_LITTLE_ENDIAN);
      safety_reply_data->init_rollover_value = tvb_get_letohs(tvb, offset + 12);

      reply_parsed_len += 4;

      proto_item_set_text(safety_item, "CIP Safety Extended Format Target Application Reply");
   }
   else  // CIP_SAFETY_BASE_FORMAT
   {
      proto_item_set_text(safety_item, "CIP Safety Target Application Reply");
   }

   proto_item_set_len(safety_item, reply_parsed_len);

   return reply_parsed_len;
}

bool cip_connection_triad_match(const cip_connection_triad_t* left, const cip_connection_triad_t* right)
{
   return (left->ConnSerialNumber == right->ConnSerialNumber) &&
      (left->VendorID == right->VendorID) &&
      (left->DeviceSerialNumber == right->DeviceSerialNumber);
}

static int
dissect_cip_cm_fwd_open_rsp_success(cip_req_info_t *preq_info, proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
   int parsed_len = 26;

   /* Display originator to target connection ID */
   uint32_t O2TConnID;
   proto_tree_add_item_ret_uint(tree, hf_cip_cm_ot_connid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &O2TConnID);

   /* Display target to originator connection ID */
   uint32_t T2OConnID;
   proto_tree_add_item_ret_uint(tree, hf_cip_cm_to_connid, tvb, offset+4, 4, ENC_LITTLE_ENDIAN, &T2OConnID);

   // Add Connection IDs as hidden items so that it's easy to find all Connection IDs in different fields.
   proto_item* pi = proto_tree_add_item(tree, hf_cip_connid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
   proto_item_set_hidden(pi);
   pi = proto_tree_add_item(tree, hf_cip_connid, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
   proto_item_set_hidden(pi);

   cip_connection_triad_t conn_triad;
   dissect_connection_triad(tvb, offset + 8, tree,
      hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
      &conn_triad);

   /* Display originator to target actual packet interval */
   uint32_t O2TAPI;
   proto_tree_add_item_ret_uint(tree, hf_cip_cm_ot_api, tvb, offset + 16, 4, ENC_LITTLE_ENDIAN, &O2TAPI);

   /* Display originator to target actual packet interval */
   uint32_t T2OAPI;
   proto_tree_add_item_ret_uint(tree, hf_cip_cm_to_api, tvb, offset + 20, 4, ENC_LITTLE_ENDIAN, &T2OAPI);

   /* Display the application reply size */
   uint16_t app_rep_size = tvb_get_uint8( tvb, offset+24 ) * 2;
   proto_tree_add_item(tree, hf_cip_cm_app_reply_size, tvb, offset+24, 1, ENC_LITTLE_ENDIAN);

   /* Display the Reserved byte */
   proto_tree_add_item(tree, hf_cip_reserved8, tvb, offset+25, 1, ENC_LITTLE_ENDIAN );

   // Handle the Application Reply Data.
   int reply_parsed_len = 0;
   safety_application_reply_data_t safety_reply_data = {0};
   if (preq_info && preq_info->connInfo && preq_info->connInfo->safety.safety_seg == true)
   {
      reply_parsed_len = dissect_fwd_open_rsp_safety_application_reply_data(preq_info, tree, tvb, offset + 26, &safety_reply_data);
   }

   int remaining_reply_len = app_rep_size - reply_parsed_len;
   if (remaining_reply_len > 0)
   {
      proto_tree_add_item(tree, hf_cip_cm_app_reply_data, tvb, offset + 26 + reply_parsed_len, remaining_reply_len, ENC_NA);
   }

   display_connection_information_fwd_open_rsp(pinfo, tvb, tree, preq_info);

   /* See if we've captured the ForwardOpen request.  If so some of the conversation data has already been
      populated and we just need to update it. */
   if (pinfo->fd->visited)
      return parsed_len + app_rep_size;

   if ((preq_info != NULL) && (preq_info->connInfo != NULL))
   {
      /* Ensure the connection triad matches before updating the connection IDs */
      if (cip_connection_triad_match(&(preq_info->connInfo->triad), &conn_triad))
      {
         /* Update the connection IDs as ForwardOpen reply is allowed to update them from
            the ForwardOpen request */
         preq_info->connInfo->O2T.connID = O2TConnID;
         preq_info->connInfo->T2O.connID = T2OConnID;

         preq_info->connInfo->O2T.api = O2TAPI;
         preq_info->connInfo->T2O.api = T2OAPI;
         if (preq_info->connInfo->safety.safety_seg == true)
         {
             preq_info->connInfo->safety.running_rollover_value = safety_reply_data.init_rollover_value;
             preq_info->connInfo->safety.running_timestamp_value = safety_reply_data.init_timestamp_value;
             preq_info->connInfo->safety.target_triad = safety_reply_data.target_triad;
             preq_info->connInfo->safety.seen_non_zero_timestamp = false;
         }
      }
   }

   return parsed_len + app_rep_size;
}

static void dissect_cip_cm_unconnected_send_req(proto_tree* cmd_data_tree, tvbuff_t* tvb, int offset, packet_info* pinfo)
{
   /* Display timeout fields */
   dissect_cip_cm_timeout(cmd_data_tree, tvb, offset);

   /* Message request size */
   uint16_t msg_req_siz = tvb_get_letohs(tvb, offset + 2);
   proto_tree_add_item(cmd_data_tree, hf_cip_cm_msg_req_size, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);

   /* Message Request */
   proto_tree* temp_tree = proto_tree_add_subtree(cmd_data_tree, tvb, offset + 4, msg_req_siz, ett_cm_mes_req, NULL, "CIP Embedded Message Request");

   /*
   ** We call ourselves again to dissect embedded packet
   */

   col_append_str(pinfo->cinfo, COL_INFO, ": ");

   tvbuff_t* next_tvb = tvb_new_subset_length(tvb, offset + 4, msg_req_siz);
   cip_req_info_t* preq_info = (cip_req_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   cip_req_info_t* pembedded_req_info = NULL;
   if (preq_info)
   {
      if (preq_info->pData == NULL)
      {
         pembedded_req_info = wmem_new0(wmem_file_scope(), cip_req_info_t);
         preq_info->pData = pembedded_req_info;
      }
      else
      {
         pembedded_req_info = (cip_req_info_t*)preq_info->pData;
      }
   }

   dissect_cip_data(temp_tree, next_tvb, 0, pinfo, pembedded_req_info, NULL, false);

   if (msg_req_siz % 2)
   {
      /* Pad byte */
      proto_tree_add_item(cmd_data_tree, hf_cip_pad8, tvb, offset + 4 + msg_req_siz, 1, ENC_LITTLE_ENDIAN);
      msg_req_siz++;  /* include the padding */
   }

   /* Route Path Size */
   uint16_t route_path_size = tvb_get_uint8(tvb, offset + 4 + msg_req_siz) * 2;
   proto_tree_add_item(cmd_data_tree, hf_cip_cm_route_path_size, tvb, offset + 4 + msg_req_siz, 1, ENC_LITTLE_ENDIAN);

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset + 5 + msg_req_siz, 1, ENC_LITTLE_ENDIAN);

   /* Route Path */
   proto_item* epath_item;
   proto_tree* epath_tree = proto_tree_add_subtree(cmd_data_tree, tvb, offset + 6 + msg_req_siz, route_path_size, ett_path, &epath_item, "Route Path: ");
   dissect_epath(tvb, pinfo, epath_tree, epath_item, offset + 6 + msg_req_siz, route_path_size, false, false, NULL, NULL, NO_DISPLAY, NULL, false);

   save_route_connection_path(pinfo, tvb, offset + 6 + msg_req_siz, route_path_size);
}

static void dissect_cip_cm_fwd_close_req(proto_tree* cmd_data_tree, tvbuff_t* tvb, int offset, packet_info* pinfo)
{
   cip_simple_request_info_t conn_path;

   dissect_cip_cm_timeout(cmd_data_tree, tvb, offset);

   cip_connection_triad_t conn_triad;
   dissect_connection_triad(tvb, offset + 2, cmd_data_tree,
      hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
      &conn_triad);

   /* Add the path size */
   uint16_t conn_path_size = tvb_get_uint8(tvb, offset + 10) * 2;
   proto_tree_add_item(cmd_data_tree, hf_cip_cm_conn_path_size, tvb, offset + 10, 1, ENC_LITTLE_ENDIAN);

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset + 11, 1, ENC_LITTLE_ENDIAN);

   /* Add the EPATH */
   proto_item *pi;
   proto_tree* epath_tree = proto_tree_add_subtree(cmd_data_tree, tvb, offset + 12, conn_path_size, ett_path, &pi, "Connection Path: ");
   dissect_epath(tvb, pinfo, epath_tree, pi, offset + 12, conn_path_size, false, false, &conn_path, NULL, DISPLAY_CONNECTION_PATH, NULL, false);
   save_route_connection_path(pinfo, tvb, offset + 12, conn_path_size);

   enip_close_cip_connection(pinfo, &conn_triad);
   display_connection_information_fwd_close_req(pinfo, tvb, cmd_data_tree);
}

static int dissect_cip_cm_fwd_close_rsp_success(proto_tree* cmd_data_tree, tvbuff_t* tvb, int offset, packet_info* pinfo, proto_item* cmd_item)
{
   cip_connection_triad_t conn_triad;
   dissect_connection_triad(tvb, offset, cmd_data_tree,
      hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
      &conn_triad);

   /* Display the application reply size */
   uint16_t app_rep_size = tvb_get_uint8(tvb, offset + 8) * 2;
   proto_tree_add_item(cmd_data_tree, hf_cip_cm_app_reply_size, tvb, offset + 8, 1, ENC_LITTLE_ENDIAN);

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset + 9, 1, ENC_LITTLE_ENDIAN);
   if (app_rep_size > 0)
   {
      if (tvb_reported_length_remaining(tvb, offset + 10) < app_rep_size)
      {
         expert_add_info(pinfo, cmd_item, &ei_mal_fwd_close_missing_data);
         return 0;
      }
      proto_tree_add_item(cmd_data_tree, hf_cip_cm_app_reply_data, tvb, offset + 10, app_rep_size, ENC_NA);
   }

   if (!pinfo->fd->visited)
      enip_mark_connection_triad(pinfo, &conn_triad);

   display_connection_information_fwd_close_rsp(pinfo, tvb, cmd_data_tree);

   return 10 + app_rep_size;
}

static void display_previous_request_path(cip_req_info_t *preq_info, proto_tree *item_tree, tvbuff_t *tvb, packet_info *pinfo, proto_item* msp_item, bool is_msp_item)
{
   if (preq_info && preq_info->IOILen && preq_info->pIOI)
   {
      proto_item *pi;
      proto_tree *epath_tree;
      tvbuff_t* tvbIOI;

      tvbIOI = tvb_new_real_data((const uint8_t *)preq_info->pIOI, preq_info->IOILen * 2, preq_info->IOILen * 2);
      if (tvbIOI)
      {
         pi = proto_tree_add_uint(item_tree, hf_cip_request_path_size, tvb, 0, 0, preq_info->IOILen);
         proto_item_set_generated(pi);

         /* Add the epath */
         epath_tree = proto_tree_add_subtree(item_tree, tvb, 0, 0, ett_path, &pi, "Request Path: ");
         proto_item_set_generated(pi);

         if (preq_info->ciaData == NULL)
         {
            preq_info->ciaData = wmem_new(wmem_file_scope(), cip_simple_request_info_t);
         }

         dissect_epath(tvbIOI, pinfo, epath_tree, pi, 0, preq_info->IOILen * 2, true, false, preq_info->ciaData, NULL, DISPLAY_REQUEST_PATH, msp_item, is_msp_item);
         tvb_free(tvbIOI);
      }
   }
}

static void
dissect_cip_cm_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *rrsc_item, *status_item;
   proto_tree *rrsc_tree, *cmd_data_tree;
   int req_path_size;
   unsigned char service, gen_status, add_stat_size;
   unsigned short add_status;
   int i;
   cip_req_info_t *preq_info;

   service = tvb_get_uint8( tvb, offset );

   /* Special handling for Unconnected send response. If successful, embedded service code is sent.
    * If failed, it can be either an Unconnected send response or the embedded service code response. */
   preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0 );
   if (  preq_info != NULL && ( service & CIP_SC_RESPONSE_MASK )
      && preq_info->bService == SC_CM_UNCON_SEND
      )
   {
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;
      if ( add_stat_size == 2 )
         add_status = tvb_get_letohs( tvb, offset + 4 );
      else
         add_status = 0;

      if(   gen_status == CI_GRC_SUCCESS
         || ( ( service & CIP_SC_MASK ) != SC_CM_UNCON_SEND )
         || !(  ( gen_status == CI_GRC_FAILURE && (add_status == CM_ES_UNCONNECTED_REQUEST_TIMED_OUT ||
                                                   add_status == CM_ES_PORT_NOT_AVAILABLE ||
                                                   add_status == CM_ES_LINK_ADDRESS_NOT_VALID ||
                                                   add_status == CM_ES_INVALID_SEGMENT_IN_CONN_PATH ||
                                                   add_status == CM_ES_LINK_ADDRESS_TO_SELF_INVALID))
             || gen_status == CI_GRC_NO_RESOURCE
             || gen_status == CI_GRC_BAD_PATH
             )
         )
      {
         cip_req_info_t* pembedded_req_info = (cip_req_info_t*)preq_info->pData;

         if ( pembedded_req_info )
         {
            tvbuff_t *next_tvb;
            void *p_save_proto_data;
            int service_index;
            heur_dtbl_entry_t *hdtbl_entry;

            p_save_proto_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0 );
            p_remove_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_cip, 0, pembedded_req_info );

            proto_item_set_generated(proto_tree_add_uint_format( item_tree, hf_cip_cm_sc, tvb, 0, 0, SC_CM_UNCON_SEND|CIP_SC_RESPONSE_MASK, "Service: Unconnected Send (Response)" ));
            next_tvb = tvb_new_subset_length(tvb, offset, item_length);

            display_previous_request_path(pembedded_req_info, item_tree, tvb, pinfo, NULL, false);
            display_previous_route_connection_path(preq_info, item_tree, tvb, pinfo, hf_cip_cm_route_path_size, NO_DISPLAY);

            /* Check to see if service is 'generic' */
            try_val_to_str_idx((service & CIP_SC_MASK), cip_sc_vals, &service_index);

            cip_service_info_t* service_entry = cip_get_service(pinfo, service);
            if ( pembedded_req_info && pembedded_req_info->dissector )
            {
               call_dissector(pembedded_req_info->dissector, next_tvb, pinfo, item_tree );
            }
            else if (service_index >= 0 && !service_entry)
            {
               /* See if object dissector wants to override generic service handling */
               if (!dissector_try_heuristic(heur_subdissector_service, tvb, pinfo, item_tree, &hdtbl_entry, NULL))
               {
                   dissect_cip_generic_service_rsp(tvb, pinfo, item_tree);
               }
            }
            else if (service_entry)
            {
               dissect_cip_object_specific_service(tvb, pinfo, item_tree, NULL, service_entry);
            }
            else
            {
               call_dissector( cip_class_generic_handle, next_tvb, pinfo, item_tree );
            }

            p_remove_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_cip, 0, p_save_proto_data);

            /* Return early because the response was only the embedded message response. */
            return;
         }
      }
   }

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CM");

   /* Add Service code & Request/Response tree */
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_cm_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ),
                  cip_sc_vals_cm , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_cm_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   add_cip_service_to_info_column(pinfo, service, cip_sc_vals_cm);

   if( service & CIP_SC_RESPONSE_MASK )
   {
      /* Response message */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

      if (gen_status == CI_GRC_FAILURE)
      {
         /* Dissect object specific error codes */
         proto_tree* status_tree = proto_tree_add_subtree(item_tree, tvb, offset+2, 1, ett_status_item, &status_item, "Status: " );

         /* Add general status */
         proto_tree_add_item(status_tree, hf_cip_cm_genstat, tvb, offset+2, 1, ENC_LITTLE_ENDIAN );
         proto_item_append_text( status_item, "%s", val_to_str_ext( gen_status,
                        &cip_gs_vals_ext , "Unknown Response (%x)")   );

         /* Add additional status size */
         proto_tree_add_item(status_tree, hf_cip_cm_addstat_size, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);

         if( add_stat_size )
         {
            add_status = tvb_get_letohs( tvb, offset + 4 );
            proto_tree_add_item(status_tree, hf_cip_cm_ext_status, tvb, offset+4, 2, ENC_LITTLE_ENDIAN );
            proto_item_append_text(status_item, ", Extended: %s", val_to_str_ext(add_status, &cip_cm_ext_st_vals_ext, "Reserved (0x%04x)"));

            switch(add_status)
            {
            case CM_ES_RPI_NOT_ACCEPTABLE:
               if (add_stat_size < 3)
               {
                  expert_add_info(pinfo, status_item, &ei_mal_rpi_no_data);
               }
               else
               {
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_ot_rpi_type, tvb, offset+6, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_to_rpi_type, tvb, offset+7, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_ot_rpi, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_to_rpi, tvb, offset + 12, 4, ENC_LITTLE_ENDIAN);
               }
               break;
            case CM_ES_INVALID_CONFIGURATION_SIZE:
               proto_tree_add_item(status_tree, hf_cip_cm_ext126_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               break;
            case CM_ES_INVALID_OT_SIZE:
               proto_tree_add_item(status_tree, hf_cip_cm_ext127_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               break;
            case CM_ES_INVALID_TO_SIZE:
               proto_tree_add_item(status_tree, hf_cip_cm_ext128_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               break;
            default:
               /* Add additional status */
               if (add_stat_size > 1)
               {
                  proto_tree* add_status_tree = proto_tree_add_subtree( status_tree, tvb, offset+4, add_stat_size, ett_cm_add_status_item, NULL, "Additional Status" );

                  for( i=0; i < add_stat_size-2; i += 2 )
                     proto_tree_add_item(add_status_tree, hf_cip_cm_add_status, tvb, offset+4+i, 2, ENC_LITTLE_ENDIAN );
               }
            }
         }
      }

      /* If there is any command specific data create a sub-tree for it */
      int data_len = item_length - 4 - add_stat_size;
      if (data_len > 0)
      {
         int parsed_len = 0;
         offset += (4 + add_stat_size);

         proto_item *cmd_item;
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset, data_len,
                                                 ett_cm_cmd_data, &cmd_item, "Command Specific Data" );

         if( gen_status == CI_GRC_SUCCESS )
         {
           /* Success responses */
           switch (service & CIP_SC_MASK)
           {
           case SC_CM_FWD_OPEN:
           case SC_CM_LARGE_FWD_OPEN:
           case SC_CM_CONCURRENT_FWD_OPEN:
              parsed_len = dissect_cip_cm_fwd_open_rsp_success(preq_info, cmd_data_tree, tvb, offset, pinfo);
              break;
           case SC_CM_FWD_CLOSE:
           case SC_CM_CONCURRENT_FWD_CLOSE:
              parsed_len = dissect_cip_cm_fwd_close_rsp_success(cmd_data_tree, tvb, offset, pinfo, cmd_item);
              break;
            case SC_CM_GET_CONN_OWNER:
            {
               /* Get Connection owner response (Success) */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_conn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_coo_conn, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_roo_conn, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_last_action, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);

               dissect_connection_triad(tvb, offset + 4, cmd_data_tree,
                  hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
                  NULL);

               parsed_len = 12;
            }
            break;
            case SC_CM_UNCON_SEND:  // Unconnected send response (Success)
            default:
               parsed_len = 0;
               break;
            }
         }
         else
         {
            /* Error responses */
            switch (service & CIP_SC_MASK)
            {
            case SC_CM_FWD_OPEN:
            case SC_CM_LARGE_FWD_OPEN:
            case SC_CM_FWD_CLOSE:
            case SC_CM_CONCURRENT_FWD_OPEN:
            case SC_CM_CONCURRENT_FWD_CLOSE:
            {
               /* Forward open and forward close error response look the same */
               cip_connection_triad_t conn_triad;
               dissect_connection_triad(tvb, offset, cmd_data_tree,
                  hf_cip_cm_conn_serial_num, hf_cip_cm_vendor, hf_cip_cm_orig_serial_num,
                  &conn_triad);

               // Remaining Path Size is an optional structure.
               if (tvb_reported_length_remaining(tvb, offset + 8) > 0)
               {
                  proto_tree_add_item(cmd_data_tree, hf_cip_cm_remain_path_size, tvb, offset+8, 1, ENC_LITTLE_ENDIAN);
                  proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+9, 1, ENC_LITTLE_ENDIAN);
               }

               /* With an error reply the connection will either never be established or it has since already closed
                  That means the conversation should end too */
               enip_close_cip_connection(pinfo, &conn_triad);
               if (preq_info != NULL)
               {
                  /* Remove any connection information */
                  preq_info->connInfo = NULL;
               }


               display_previous_route_connection_path(preq_info, cmd_data_tree, tvb, pinfo, hf_cip_cm_conn_path_size, DISPLAY_CONNECTION_PATH);

               parsed_len = 10;
               break;
            }
            case SC_CM_UNCON_SEND:
               /* Unconnected send response (Unsuccess) */
               proto_tree_add_item(cmd_data_tree, hf_cip_cm_remain_path_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
               display_previous_route_connection_path(preq_info, item_tree, tvb, pinfo, hf_cip_cm_route_path_size, NO_DISPLAY);
               parsed_len = 2;
               break;
            default:
               parsed_len = 0;
               break;
            }
         } /* end of if-else( CI_CRC_SUCCESS ) */

         int remain_len = tvb_reported_length_remaining(tvb, offset + parsed_len);
         if (remain_len > 0)
         {
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset + parsed_len, remain_len, ENC_NA);
         }
      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         proto_item* cmd_data_item;
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2,
                                                 ett_cm_cmd_data, &cmd_data_item, "Command Specific Data" );

         /* Check what service code that received */
         switch (service)
         {
         case SC_CM_FWD_OPEN:
            /* Forward open Request*/
            dissect_cip_cm_fwd_open_req(preq_info, cmd_data_tree, cmd_data_item, tvb, offset+2+req_path_size, false, pinfo, false);
            break;
         case SC_CM_CONCURRENT_FWD_OPEN:
            dissect_cip_cm_fwd_open_req(preq_info, cmd_data_tree, cmd_data_item, tvb, offset+2+req_path_size, false, pinfo, true);
            break;
         case SC_CM_LARGE_FWD_OPEN:
            /* Large Forward open Request*/
            dissect_cip_cm_fwd_open_req(preq_info, cmd_data_tree, cmd_data_item, tvb, offset+2+req_path_size, true, pinfo, false);
            break;
         case SC_CM_FWD_CLOSE:
         case SC_CM_CONCURRENT_FWD_CLOSE:
            dissect_cip_cm_fwd_close_req(cmd_data_tree, tvb, offset + 2 + req_path_size, pinfo);
            break;
         case SC_CM_UNCON_SEND:
            dissect_cip_cm_unconnected_send_req(cmd_data_tree, tvb, offset + 2 + req_path_size, pinfo);
            break;
         case SC_CM_GET_CONN_OWNER:
         {
            /* Get Connection Owner Request */

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);

            /* Add path size */
            uint16_t conn_path_size = tvb_get_uint8( tvb, offset+2+req_path_size+1 )*2;
            proto_tree_add_item(cmd_data_tree, hf_cip_cm_conn_path_size, tvb, offset+2+req_path_size+1, 1, ENC_LITTLE_ENDIAN);

            /* Add the epath */
            proto_item* pi;
            proto_tree* epath_tree = proto_tree_add_subtree(cmd_data_tree, tvb, offset+2+req_path_size+2, conn_path_size, ett_path, &pi, "Connection Path: ");
            dissect_epath(tvb, pinfo, epath_tree, pi, offset+2+req_path_size+2, conn_path_size, false, false, NULL, NULL, NO_DISPLAY, NULL, false);
            break;
         }
         default:
            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_cm_data() */

static int
dissect_cip_class_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_cm, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_cm );

   dissect_cip_cm_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

/************************************************
 *
 * Dissector for CIP PCCC Object
 *
 ************************************************/
static void
dissect_cip_pccc_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *rrsc_item;
   proto_tree *rrsc_tree, *req_id_tree, *pccc_cmd_tree, *cmd_data_tree;
   int req_path_size;
   unsigned char service;
   int add_status;

   service = tvb_get_uint8( tvb, offset );

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP PCCC");

   /* Add Service code & Request/Response tree */
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_pccc_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ),
                  cip_sc_vals_pccc , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_pccc_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   add_cip_service_to_info_column (pinfo, service, cip_sc_vals_pccc);

   /* There is a minimum of two bytes different between the request and response request path */
   /* Response message */
   if ( service & CIP_SC_RESPONSE_MASK )
   {
       req_path_size = 2 + tvb_get_uint8( tvb, offset+2 )*2;
   }
   /* Request message */
   else
   {
       req_path_size = tvb_get_uint8( tvb, offset+1 )*2;
   }

   int req_id_offset = offset+req_path_size+2;
   int req_id_size = tvb_get_uint8( tvb, req_id_offset );
   int pccc_cmd_offset = req_id_offset+req_id_size;

   /* Add Requestor ID tree */
   req_id_tree = proto_tree_add_subtree( item_tree, tvb, req_id_offset, req_id_size, ett_pccc_req_id, NULL, "Requestor ID" );
   /* Add Length of Requestor ID code */
   proto_tree_add_item(req_id_tree, hf_cip_pccc_req_id_len, tvb, req_id_offset, 1, ENC_LITTLE_ENDIAN );
   /* Add CIP Vendor ID */
   proto_tree_add_item(req_id_tree, hf_cip_pccc_cip_vend_id, tvb, req_id_offset+1, 2, ENC_LITTLE_ENDIAN );
   /* Add CIP Serial Number */
   proto_tree_add_item(req_id_tree, hf_cip_pccc_cip_serial_num, tvb, req_id_offset+3, 4, ENC_LITTLE_ENDIAN );

   if( service & CIP_SC_RESPONSE_MASK )
   {
        /* Add PCCC Response Data tree */
         pccc_cmd_tree = proto_tree_add_subtree( item_tree, tvb, pccc_cmd_offset, item_length-req_path_size-2-req_id_size, ett_pccc_req_id, NULL, "PCCC Response Data" );

         /* Add Command Code */
         proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_resp_code, tvb, pccc_cmd_offset, 1, ENC_LITTLE_ENDIAN );
         /* Add Status Code */
         proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_sts_code, tvb, pccc_cmd_offset+1, 1, ENC_LITTLE_ENDIAN );
         /* Add Transaction Code */
         proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_tns_code, tvb, pccc_cmd_offset+2, 2, ENC_LITTLE_ENDIAN );

         /* Check the status byte for the EXT_STS signifier - 0xF0 */
         add_status = tvb_get_uint8( tvb, pccc_cmd_offset+1 );
         // TODO: still need to test this
         if ( add_status == PCCC_GS_USE_EXTSTS )
         {
             proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_ext_sts_code, tvb, pccc_cmd_offset+4, 1, ENC_LITTLE_ENDIAN );
         }
         // handle cases where data is returned in the response
         else if (item_length-req_path_size-2-req_id_size-4 != 0)
         {
            /* Add the data tree */
            cmd_data_tree = proto_tree_add_subtree( pccc_cmd_tree, tvb, pccc_cmd_offset+4, item_length-req_path_size-2-req_id_size-4, ett_pccc_cmd_data, NULL, "Function Specific Response Data" );
            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_data, tvb, pccc_cmd_offset+4, item_length-req_path_size-2-req_id_size-4, ENC_NA);
         }

   } /* end of if reply */

  /* Request message */
   else
   {
      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         uint32_t cmd_code, fnc_code;

         /* Add PCCC CMD Data tree */
         pccc_cmd_tree = proto_tree_add_subtree( item_tree, tvb, pccc_cmd_offset, item_length-req_path_size-2-req_id_size, ett_pccc_req_id, NULL, "PCCC Command Data" );

         /* Add Command Code */
         proto_tree_add_item_ret_uint(pccc_cmd_tree, hf_cip_pccc_cmd_code, tvb, pccc_cmd_offset, 1, ENC_LITTLE_ENDIAN, &cmd_code);
         /* Add Status Code */
         proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_sts_code, tvb, pccc_cmd_offset+1, 1, ENC_LITTLE_ENDIAN );
         /* Add Transaction Code */
         proto_tree_add_item(pccc_cmd_tree, hf_cip_pccc_tns_code, tvb, pccc_cmd_offset+2, 2, ENC_LITTLE_ENDIAN );
         /* Add Function Code */
         switch(cmd_code)
         {
             case PCCC_CMD_06:
                 proto_tree_add_item_ret_uint(pccc_cmd_tree, hf_cip_pccc_fnc_code_06, tvb, pccc_cmd_offset+4, 1, ENC_LITTLE_ENDIAN, &fnc_code);
                 add_cip_pccc_function_to_info_column(pinfo, fnc_code, cip_pccc_fnc_06_vals);
             break;

             case PCCC_CMD_07:
                 proto_tree_add_item_ret_uint(pccc_cmd_tree, hf_cip_pccc_fnc_code_07, tvb, pccc_cmd_offset+4, 1, ENC_LITTLE_ENDIAN, &fnc_code);
                 add_cip_pccc_function_to_info_column(pinfo, fnc_code, cip_pccc_fnc_07_vals);
             break;

             case PCCC_CMD_0F:
                 proto_tree_add_item_ret_uint(pccc_cmd_tree, hf_cip_pccc_fnc_code_0f, tvb, pccc_cmd_offset+4, 1, ENC_LITTLE_ENDIAN, &fnc_code);
                 add_cip_pccc_function_to_info_column(pinfo, fnc_code, cip_pccc_fnc_0f_vals);
             break;

             default:
                 fnc_code = 0;
             break;
         }

         if (item_length-req_path_size-2-req_id_size-5 != 0 )
         {
                     /* Add the data tree */
            cmd_data_tree = proto_tree_add_subtree( pccc_cmd_tree, tvb, pccc_cmd_offset+5, item_length-req_path_size-req_id_size-7,
                                        ett_pccc_cmd_data, NULL, "Function Specific Data" );

            int running_offset = pccc_cmd_offset+6;
            int num_cmds;
            int sub_fnc_len;
            proto_tree *sub_fnc_tree;

            /* Add in parsing of instructions that contain data beyond the FNC code */
            /* Instructions that end at the FNC codes are already processed */
            switch(cmd_code)
            {
                case PCCC_CMD_0F:
                    switch(fnc_code){
                        /* Change CPU Mode */
                        case PCCC_FNC_0F_80:
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_cpu_mode_80, tvb, pccc_cmd_offset+5, 1, ENC_NA);
                        break;
                        /* Execute Multiple Commands */
                        case PCCC_FNC_0F_88:
                            num_cmds = tvb_get_uint8( tvb, pccc_cmd_offset+5 );
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_execute_multi_count, tvb, pccc_cmd_offset+5, 1, ENC_NA);

                            /* iterate over each of the commands and break them out */
                            for( int i=0; i < num_cmds; i++ ){
                                sub_fnc_len = tvb_get_uint8( tvb, running_offset);
                                sub_fnc_tree = proto_tree_add_subtree_format(cmd_data_tree, tvb, running_offset, sub_fnc_len+1, ett_pccc_req_id, NULL, "Sub Function #%d", i+1);

                                proto_tree_add_item(sub_fnc_tree, hf_cip_pccc_execute_multi_len, tvb, running_offset, 1, ENC_NA);
                                proto_tree_add_item(sub_fnc_tree, hf_cip_pccc_execute_multi_fnc, tvb, running_offset+1, 1, ENC_NA);
                                if( sub_fnc_len > 2 ){
                                    proto_tree_add_item(sub_fnc_tree, hf_cip_pccc_data, tvb, running_offset+2, sub_fnc_len-1, ENC_NA);
                                }
                                running_offset = running_offset+sub_fnc_len+1;
                            }
                        break;
                        /* Protected Typed Logical Read with Three Address Fields */
                        case PCCC_FNC_0F_A2:
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_byte_size, tvb, pccc_cmd_offset+5, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_file_num, tvb, pccc_cmd_offset+6, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_file_type, tvb, pccc_cmd_offset+7, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_element_num, tvb, pccc_cmd_offset+8, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_subelement_num, tvb, pccc_cmd_offset+9, 1, ENC_NA);
                        break;
                        /* Protected Typed Logical Write with Three Address Fields */
                        case PCCC_FNC_0F_AA:
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_byte_size, tvb, pccc_cmd_offset+5, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_file_num, tvb, pccc_cmd_offset+6, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_file_type, tvb, pccc_cmd_offset+7, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_element_num, tvb, pccc_cmd_offset+8, 1, ENC_NA);
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_subelement_num, tvb, pccc_cmd_offset+9, 1, ENC_NA);
                            int byte_size;
                            byte_size = tvb_get_uint8( tvb, pccc_cmd_offset+5 );

                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_data, tvb, pccc_cmd_offset+10, byte_size, ENC_NA);
                        break;
                        default: /* just print the command data if no known command code is passed */
                            proto_tree_add_item(cmd_data_tree, hf_cip_pccc_data, tvb, pccc_cmd_offset+5, item_length-pccc_cmd_offset-5, ENC_NA);
                    }
                break;
                default: /* just print the command data if no known command code is passed */
                    proto_tree_add_item(cmd_data_tree, hf_cip_pccc_data, tvb, pccc_cmd_offset+5, 1, ENC_NA);
            }
        }
       } /* End of if-else( request ) */
    }

} /* End of dissect_cip_pccc_data() */

static int
dissect_cip_class_pccc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_pccc, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_pccc );

   dissect_cip_pccc_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Modbus Object
 *
 ************************************************/
static void
dissect_cip_mb_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *rrsc_item;
   proto_tree *rrsc_tree, *cmd_data_tree;
   tvbuff_t *next_tvb;
   int req_path_size;
   uint8_t gen_status, add_stat_size, service;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP MB");

   /* Add Service code & Request/Response tree */
   service = tvb_get_uint8( tvb, offset );
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_mb_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ),
                  cip_sc_vals_mb , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_mb_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( service & CIP_SC_RESPONSE_MASK )
   {
      /* Response message */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size,
                                                 ett_mb_cmd_data, NULL, "Command Specific Data" );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            /* Success responses */
            switch (service & CIP_SC_MASK)
            {
            case SC_MB_READ_DISCRETE_INPUTS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_discrete_inputs_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
               break;

            case SC_MB_READ_COILS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_coils_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
               break;

            case SC_MB_READ_INPUT_REGISTERS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_input_register_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
               break;

            case SC_MB_READ_HOLDING_REGISTERS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_holding_register_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
               break;

            case SC_MB_WRITE_COILS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_start_addr, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_outputs_forced, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);
               break;

            case SC_MB_WRITE_HOLDING_REGISTERS:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_start_addr, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_outputs_forced, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);
               break;

            case SC_MB_PASSTHROUGH:
               /* Passthrough response (Success) */
               if( tvb_reported_length_remaining(tvb, offset) > 0 )
               {
                  modbus_data_t modbus_data;
                  modbus_data.packet_type = RESPONSE_PACKET;
                  modbus_data.mbtcp_transid = 0;
                  modbus_data.unit_id = 0;

                  /* dissect the Modbus PDU */
                  next_tvb = tvb_new_subset_length( tvb, offset+4+add_stat_size, item_length-4-add_stat_size);

                  /* Call Modbus Dissector */
                  call_dissector_with_data(modbus_handle, next_tvb, pinfo, cmd_data_tree, &modbus_data);

               }
               break;

            default:
               proto_tree_add_item(cmd_data_tree, hf_cip_mb_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
            }
         }
         else
         {
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */
      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2,
                                                ett_mb_cmd_data, NULL, "Command Specific Data" );

         /* Check what service code that received */
         switch (service)
         {
         case SC_MB_READ_DISCRETE_INPUTS:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_discrete_inputs_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_discrete_inputs_num_inputs, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            break;

         case SC_MB_READ_COILS:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_coils_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_coils_num_coils, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            break;

         case SC_MB_READ_INPUT_REGISTERS:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_input_register_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_input_register_num_registers, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            break;

         case SC_MB_READ_HOLDING_REGISTERS:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_holding_register_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_read_holding_register_num_registers, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            break;

         case SC_MB_WRITE_COILS:
            {
            uint16_t NumCoils;

            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            NumCoils = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_num_coils, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_data, tvb, offset+2+req_path_size+4, (NumCoils+7)/8, ENC_NA);
            }
            break;

         case SC_MB_WRITE_HOLDING_REGISTERS:
            {
            uint16_t NumRegisters;

            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            NumRegisters = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_num_registers, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_data, tvb, offset+2+req_path_size+4, NumRegisters*2, ENC_NA);
            }
            break;

         case SC_MB_PASSTHROUGH:
            /* Passthrough Request */
            if( tvb_reported_length_remaining(tvb, offset) > 0 )
            {
               modbus_data_t modbus_data;
               modbus_data.packet_type = QUERY_PACKET;
               modbus_data.mbtcp_transid = 0;
               modbus_data.unit_id = 0;

               /* dissect the Modbus PDU */
               next_tvb = tvb_new_subset_length( tvb, offset+2+req_path_size, item_length-req_path_size-2);

               /* Call Modbus Dissector */
               call_dissector_with_data(modbus_handle, next_tvb, pinfo, cmd_data_tree, &modbus_data);
            }
            break;

         default:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals_mb);
} /* End of dissect_cip_mb_data() */

static int
dissect_cip_class_mb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_mb, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_mb );

   dissect_cip_mb_data( class_tree, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Configuration Object
 *
 ************************************************/
static int
dissect_cip_cco_all_attribute_common( proto_tree *cmd_tree, proto_item *ti,
    tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo)
{
   proto_item *pi;
   proto_tree *tdi_tree, *iomap_tree, *epath_tree;
   proto_tree *ncp_tree;
   int conn_path_size, variable_data_size = 0, config_data_size;
   int iomap_size, ot_rtf, to_rtf;
   int temp_data;

   /* Connection flags */
   temp_data = tvb_get_letohs( tvb, offset);
   ot_rtf = (temp_data >> 1) & 7;
   to_rtf = (temp_data >> 4) & 7;

   static int *const connection_flags[] = {
      &hf_cip_cco_con_type,
      &hf_cip_cco_ot_rtf,
      &hf_cip_cco_to_rtf,
      NULL
   };
   proto_tree_add_bitmask(cmd_tree, tvb, offset, hf_cip_cco_con_flags, ett_cco_con_flag, connection_flags, ENC_LITTLE_ENDIAN);

   /* Target device id */
   tdi_tree = proto_tree_add_subtree( cmd_tree, tvb, offset+2, 10, ett_cco_tdi, NULL, "Target Device ID");

   dissect_deviceid(tvb, offset+2, tdi_tree,
      hf_cip_cco_tdi_vendor, hf_cip_cco_tdi_devtype, hf_cip_cco_tdi_prodcode,
      hf_cip_cco_tdi_compatibility, hf_cip_cco_tdi_comp_bit, hf_cip_cco_tdi_majorrev, hf_cip_cco_tdi_minorrev, false, ENC_LITTLE_ENDIAN);

   /* CS Data Index Number */
   proto_tree_add_item(cmd_tree, hf_cip_cco_cs_data_index, tvb, offset+10, 4, ENC_LITTLE_ENDIAN );

   /* Net Connection Parameters */
   ncp_tree = proto_tree_add_subtree( cmd_tree, tvb, offset+14, 14, ett_cco_ncp, NULL, "Net Connection Parameters");

   /* Timeout multiplier */
   proto_tree_add_item(ncp_tree, hf_cip_cco_timeout_multiplier, tvb, offset+14, 1, ENC_LITTLE_ENDIAN );

   dissect_transport_type_trigger(tvb, offset+15, ncp_tree, hf_cip_cco_transport_type_trigger,
                                  hf_cip_cco_fwo_dir, hf_cip_cco_fwo_trigger, hf_cip_cco_fwo_class, ett_cco_ttt);

   proto_tree_add_item(ncp_tree, hf_cip_cco_ot_rpi, tvb, offset + 16, 4, ENC_LITTLE_ENDIAN);

   /* Display O->T network connection parameters */
   cip_connID_info_t ignore;
   dissect_net_param16(tvb, offset+20, ncp_tree,
              hf_cip_cco_ot_net_param16, hf_cip_cco_fwo_own, hf_cip_cco_fwo_typ,
              hf_cip_cco_fwo_prio, hf_cip_cco_fwo_fixed_var, hf_cip_cco_fwo_con_size, ett_cco_ncp, &ignore);

   proto_tree_add_item(ncp_tree, hf_cip_cco_to_rpi, tvb, offset + 22, 4, ENC_LITTLE_ENDIAN);

   /* Display T->O network connection parameters */
   dissect_net_param16(tvb, offset+26, ncp_tree,
              hf_cip_cco_to_net_param16, hf_cip_cco_fwo_own, hf_cip_cco_fwo_typ,
              hf_cip_cco_fwo_prio, hf_cip_cco_fwo_fixed_var, hf_cip_cco_fwo_con_size, ett_cco_ncp, &ignore);

   /* Connection Path */
   conn_path_size = tvb_get_uint8( tvb, offset+28 )*2;
   proto_tree_add_item(cmd_tree, hf_cip_cco_conn_path_size, tvb, offset+28, 1, ENC_LITTLE_ENDIAN);

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_tree, hf_cip_reserved8, tvb, offset+29, 1, ENC_LITTLE_ENDIAN );

   /* Add the epath */
   epath_tree = proto_tree_add_subtree(cmd_tree, tvb, offset+30, conn_path_size, ett_path, &pi, "Connection Path: ");
   dissect_epath(tvb, pinfo, epath_tree, pi, offset+30, conn_path_size, false, false, NULL, NULL, NO_DISPLAY, NULL, false);

   variable_data_size += (conn_path_size+30);

   /* Config #1 Data */
   config_data_size = tvb_get_letohs( tvb, offset+variable_data_size);
   proto_tree_add_item(cmd_tree, hf_cip_cco_proxy_config_size, tvb, offset+variable_data_size, 2, ENC_LITTLE_ENDIAN );
   if (config_data_size > 0)
      proto_tree_add_item(cmd_tree, hf_cip_cco_proxy_config_data, tvb, offset+variable_data_size+2, config_data_size, ENC_NA);

   variable_data_size += (config_data_size+2);

   /* Config #2 Data */
   config_data_size = tvb_get_letohs( tvb, offset+variable_data_size);
   proto_tree_add_item(cmd_tree, hf_cip_cco_target_config_size, tvb, offset+variable_data_size, 2, ENC_LITTLE_ENDIAN );
   if (config_data_size > 0)
      proto_tree_add_item(cmd_tree, hf_cip_cco_target_config_data, tvb, offset+variable_data_size+2, config_data_size, ENC_NA);

   variable_data_size += (config_data_size+2);

   /* Connection Name */
   variable_data_size += dissect_cip_string_type(pinfo, cmd_tree, ti, tvb, offset + variable_data_size, hf_cip_cco_connection_name, CIP_STRING2_TYPE);

   /* I/O Mapping */
   iomap_size = tvb_get_letohs( tvb, offset+variable_data_size+2);

   iomap_tree = proto_tree_add_subtree( cmd_tree, tvb, offset+variable_data_size, iomap_size+4, ett_cco_iomap, NULL, "I/O Mapping");

   proto_tree_add_item(iomap_tree, hf_cip_cco_iomap_format_number, tvb, offset+variable_data_size, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(iomap_tree, hf_cip_cco_iomap_size, tvb, offset+variable_data_size+2, 2, ENC_LITTLE_ENDIAN);

   /* Attribute data */
   if (iomap_size > 0)
      proto_tree_add_item(iomap_tree, hf_cip_cco_iomap_attribute, tvb, offset+variable_data_size+4, iomap_size, ENC_NA);

   variable_data_size += (iomap_size+4);

   /* Proxy device id */
   tdi_tree = proto_tree_add_subtree( cmd_tree, tvb, offset+variable_data_size, 8, ett_cco_pdi, NULL, "Proxy Device ID");

   dissect_deviceid(tvb, offset+variable_data_size, tdi_tree,
      hf_cip_cco_pdi_vendor, hf_cip_cco_pdi_devtype, hf_cip_cco_pdi_prodcode,
      hf_cip_cco_pdi_compatibility, hf_cip_cco_pdi_comp_bit, hf_cip_cco_pdi_majorrev, hf_cip_cco_pdi_minorrev, false, ENC_LITTLE_ENDIAN);

   /* Add in proxy device id size */
   variable_data_size += 8;

   if ((offset+variable_data_size < item_length) &&
       ((ot_rtf == 5) || (to_rtf == 5)))
   {
      /* Safety parameters */
      proto_tree_add_item(cmd_tree, hf_cip_cco_safety, tvb, offset+variable_data_size, 55, ENC_NA);
      variable_data_size += 55;
   }

   if (offset+variable_data_size < item_length)
   {
      proto_tree_add_item(cmd_tree, hf_cip_cco_connection_disable, tvb, offset+variable_data_size, 1, ENC_LITTLE_ENDIAN );
      variable_data_size++;
   }

   if (offset+variable_data_size < item_length)
   {
      proto_tree_add_item(cmd_tree, hf_cip_cco_net_conn_param_attr, tvb, offset+variable_data_size, 1, ENC_LITTLE_ENDIAN );
      variable_data_size++;
   }

   if (offset+variable_data_size < item_length)
   {
      /* Large Net Connection Parameter */
      ncp_tree = proto_tree_add_subtree( cmd_tree, tvb, offset+variable_data_size, 18, ett_cco_ncp, NULL, "Large Net Connection Parameters");

      proto_tree_add_item(ncp_tree, hf_cip_cco_timeout_multiplier, tvb, offset+variable_data_size, 1, ENC_LITTLE_ENDIAN );
      dissect_transport_type_trigger(tvb, offset+variable_data_size+1, ncp_tree, hf_cip_cco_transport_type_trigger,
                                  hf_cip_cco_fwo_dir, hf_cip_cco_fwo_trigger, hf_cip_cco_fwo_class, ett_cco_ttt);

      proto_tree_add_item(ncp_tree, hf_cip_cco_ot_rpi, tvb, offset + variable_data_size + 2, 4, ENC_LITTLE_ENDIAN);

      /* Display O->T network connection parameters */
      dissect_net_param32(tvb, offset+variable_data_size+6, ncp_tree,
                 hf_cip_cco_ot_net_param32, hf_cip_cco_lfwo_own, hf_cip_cco_lfwo_typ,
                 hf_cip_cco_lfwo_prio, hf_cip_cco_lfwo_fixed_var, hf_cip_cco_lfwo_con_size, ett_cco_ncp, &ignore);

      proto_tree_add_item(ncp_tree, hf_cip_cco_to_rpi, tvb, offset + variable_data_size + 10, 4, ENC_LITTLE_ENDIAN);

      /* Display T->O network connection parameters */
      dissect_net_param32(tvb, offset+variable_data_size+14, ncp_tree,
                 hf_cip_cco_to_net_param32, hf_cip_cco_lfwo_own, hf_cip_cco_lfwo_typ,
                 hf_cip_cco_lfwo_prio, hf_cip_cco_lfwo_fixed_var, hf_cip_cco_lfwo_con_size, ett_cco_ncp, &ignore);

      variable_data_size += 18;
   }

   return variable_data_size;
}

static void
dissect_cip_cco_data( proto_tree *item_tree, proto_item *ti, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *rrsc_item;
   proto_tree *rrsc_tree, *cmd_data_tree, *con_st_tree;
   int req_path_size;
   uint8_t service, gen_status, add_stat_size;
   cip_simple_request_info_t req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CCO");

   /* Add Service code & Request/Response tree */
   service = tvb_get_uint8( tvb, offset );
   rrsc_tree = proto_tree_add_subtree( item_tree, tvb, offset, 1, ett_cco_rrsc, &rrsc_item, "Service: " );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & CIP_SC_MASK ),
                  cip_sc_vals_cco , "Unknown Service (0x%02x)"),
               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_cco_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   load_cip_request_data(pinfo, &req_data);

   if(service & CIP_SC_RESPONSE_MASK )
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      add_stat_size = tvb_get_uint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size,
                                                 ett_cco_cmd_data, NULL, "Command Specific Data" );

         if( gen_status == CI_GRC_SUCCESS )
         {
            /* Success responses */
            if (((service & CIP_SC_MASK) == SC_GET_ATT_ALL) &&
                (req_data.iInstance != SEGMENT_VALUE_NOT_SET))
            {
               if (req_data.iInstance == 0)
               {
                  /* Get Attribute All (class) request */
                  dissect_cip_get_attribute_all_rsp(tvb, pinfo, cmd_data_tree, offset + 4 + add_stat_size, &req_data);
               }
               else
               {
                  /* Get Attribute All (instance) request */

                  /* Connection status */
                  con_st_tree = proto_tree_add_subtree( cmd_data_tree, tvb, offset+4+add_stat_size, 4, ett_cco_con_status, NULL, "Connection Status");

                  proto_tree_add_item(con_st_tree, hf_cip_genstat, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(con_st_tree, hf_cip_pad8, tvb, offset+4+add_stat_size+1, 1, ENC_LITTLE_ENDIAN);

                  /* Extended Status */
                  proto_tree_add_item(con_st_tree, hf_cip_cco_ext_status, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);

                  dissect_cip_cco_all_attribute_common(cmd_data_tree, ti, tvb, offset+4+add_stat_size+4, item_length, pinfo);
               }
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
      req_path_size = tvb_get_uint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         cmd_data_tree = proto_tree_add_subtree( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2,
                                                 ett_cco_cmd_data, NULL, "Command Specific Data" );

         /* Check what service code that received */

         switch (service)
         {
         case SC_CCO_AUDIT_CHANGE:
            proto_tree_add_item(cmd_data_tree, hf_cip_cco_change_type, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN );
            break;
         case SC_CCO_CHANGE_COMPLETE:
            proto_tree_add_item(cmd_data_tree, hf_cip_cco_change_type, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN );
            break;
         case SC_SET_ATT_ALL:
            if ((req_data.iInstance == 0) ||
                (req_data.iInstance == SEGMENT_VALUE_NOT_SET))
            {
               /* Just add raw data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
               break;
            }

            /* Set Attribute All (instance) request */
            dissect_cip_cco_all_attribute_common(cmd_data_tree, ti, tvb, offset+2+req_path_size, item_length, pinfo);
            break;
         default:

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         } /* End of check service code */

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

   add_cip_service_to_info_column(pinfo, service, cip_sc_vals_cco);
} /* End of dissect_cip_cco_data() */

static int
dissect_cip_class_cco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_cco, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_cco );

   dissect_cip_cco_data( class_tree, ti, tvb, 0, tvb_reported_length(tvb), pinfo );

   return tvb_reported_length(tvb);
}

static bool
dissect_class_cco_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   unsigned char service, service_code, ioilen, segment;
   cip_req_info_t* preq_info;
   uint32_t classid = 0;
   int offset = 0;

   service = tvb_get_uint8( tvb, offset );
   service_code = service & CIP_SC_MASK;

   /* Handle GetAttributeAll and SetAttributeAll in CCO class */
   if ((service_code == SC_GET_ATT_ALL) ||
       (service_code == SC_SET_ATT_ALL))
   {
      if (service & CIP_SC_RESPONSE_MASK)
      {
         /* Service response */
         preq_info = (cip_req_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
         if ((preq_info != NULL) &&
             (preq_info->dissector == dissector_get_uint_handle( subdissector_class_table, CI_CLS_CCO)))
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

         if (classid == CI_CLS_CCO)
         {
            call_dissector(cip_class_cco_handle, tvb, pinfo, tree );
            return true;
         }

      }
   }

   return false;
}

/************************************************
 *
 * Dissector for CIP Request/Response
 * - matches requests/responses
 * - calls class specific dissector
 *
 ************************************************/

// NOLINTNEXTLINE(misc-no-recursion)
void dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t* preq_info, proto_item* msp_item, bool is_msp_item )
{
   proto_item *ti;
   proto_tree *cip_tree, *epath_tree;
   proto_item *pi, *rrsc_item, *status_item;
   proto_tree *rrsc_tree, *status_tree, *add_status_tree;
   int req_path_size;
   unsigned char i, gen_status;
   unsigned char service,ioilen,segment;
   void *p_save_proto_data;
   cip_simple_request_info_t path_info;
   dissector_handle_t dissector;
   int service_index;
   heur_dtbl_entry_t *hdtbl_entry;

   p_save_proto_data = p_get_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   p_remove_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   p_add_proto_data(wmem_file_scope(), pinfo, proto_cip, 0, preq_info);

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(item_tree, proto_cip, tvb, 0, -1, ENC_NA);
   cip_tree = proto_item_add_subtree( ti, ett_cip );

   service = tvb_get_uint8( tvb, offset );

   /* Add Service code & Request/Response tree */
   rrsc_item = proto_tree_add_uint_format_value(cip_tree, hf_cip_service,
                               tvb, offset, 1, service, "%s (%s)",
                               val_to_str( ( service & CIP_SC_MASK ), cip_sc_vals , "Unknown Service (0x%02x)"),
                               val_to_str_const( ( service & CIP_SC_RESPONSE_MASK )>>7, cip_sc_rr, ""));

   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_rrsc );

   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(rrsc_tree, hf_cip_service_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   increment_dissection_depth(pinfo);
   if( service & CIP_SC_RESPONSE_MASK )
   {
      /* Response message */
      status_tree = proto_tree_add_subtree( cip_tree, tvb, offset+2, 1, ett_status_item, &status_item, "Status: " );

      /* Add general status */
      gen_status = tvb_get_uint8( tvb, offset+2 );
      proto_tree_add_item(status_tree, hf_cip_genstat, tvb, offset+2, 1, ENC_LITTLE_ENDIAN );
      proto_item_append_text( status_item, "%s: ", val_to_str_ext( gen_status,
                     &cip_gs_vals_ext , "Unknown Response (%x)")   );

      if (is_msp_item == false)
      {
          /* Add reply status to info column */
          col_append_fstr(pinfo->cinfo, COL_INFO, "%s: ",
              val_to_str_ext(gen_status, &cip_gs_vals_ext, "Unknown Response (%x)"));
      }
      else
      {
          proto_item_append_text(msp_item, "%s: ",
              val_to_str_ext(gen_status, &cip_gs_vals_ext, "Unknown Response (%x)"));
      }

      /* Add additional status size */
      uint8_t add_stat_size = tvb_get_uint8( tvb, offset+3 );
      proto_tree_add_item(status_tree, hf_cip_addstat_size, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);

      if( add_stat_size )
      {
         /* Add additional status */
         add_status_tree = proto_tree_add_subtree( status_tree, tvb, offset+4, add_stat_size*2, ett_add_status_item, NULL, "Additional Status" );

         for( i=0; i < add_stat_size; i ++ )
            proto_tree_add_item(add_status_tree, hf_cip_add_stat, tvb, offset+4+(i*2), 2, ENC_LITTLE_ENDIAN );
      }

      proto_item_set_len( status_item, 2 + add_stat_size*2);

      /* The previous packet service must be Unconnected Send, or match the current
         service to be a valid match. If they don't, ignore the previous data.*/
      if(  preq_info
        && !(  preq_info->bService == ( service & CIP_SC_MASK )
            || ( preq_info->bService == SC_CM_UNCON_SEND && preq_info->dissector == cip_class_cm_handle )
            )
        )
         preq_info = NULL;

      display_previous_request_path(preq_info, cip_tree, tvb, pinfo, msp_item, is_msp_item);

      /* Check to see if service is 'generic' */
      try_val_to_str_idx((service & CIP_SC_MASK), cip_sc_vals, &service_index);

      cip_service_info_t* service_entry = cip_get_service(pinfo, service);

      /* If the request set a dissector, then check that first. This ensures
         that Unconnected Send responses are properly parsed based on the
         embedded request. */
      if (preq_info && preq_info->dissector)
      {
         call_dissector(preq_info->dissector, tvb, pinfo, item_tree);
      }
      else if (service_index >= 0 && !service_entry)
      {
         /* See if object dissector wants to override generic service handling */
         if(!dissector_try_heuristic(heur_subdissector_service, tvb, pinfo, item_tree, &hdtbl_entry, NULL))
         {
           dissect_cip_generic_service_rsp(tvb, pinfo, cip_tree);
         }
      }
      else if (service_entry)
      {
         dissect_cip_object_specific_service(tvb, pinfo, cip_tree, msp_item, service_entry);
      }
      else
      {
         call_dissector( cip_class_generic_handle, tvb, pinfo, item_tree );
      }
   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add path size to tree */
      req_path_size = tvb_get_uint8( tvb, offset+1);
      proto_tree_add_item(cip_tree, hf_cip_request_path_size, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);

      /* Add the epath */
      epath_tree = proto_tree_add_subtree(cip_tree, tvb, offset+2, req_path_size*2, ett_path, &pi, "Request Path: ");
      if (preq_info)
      {
         preq_info->ciaData = wmem_new(wmem_file_scope(), cip_simple_request_info_t);
         dissect_epath(tvb, pinfo, epath_tree, pi, offset+2, req_path_size*2, false, false, preq_info->ciaData, NULL, DISPLAY_REQUEST_PATH, msp_item, is_msp_item);
         memcpy(&path_info, preq_info->ciaData, sizeof(cip_simple_request_info_t));
      }
      else
      {
         dissect_epath(tvb, pinfo, epath_tree, pi, offset+2, req_path_size*2, false, false, &path_info, NULL, DISPLAY_REQUEST_PATH, msp_item, is_msp_item);
      }

      ioilen = tvb_get_uint8( tvb, offset + 1 );

      if ( preq_info )
         preq_info->dissector = NULL;
      dissector = NULL;

      /* The class ID should already be extracted if it's available */
      if (path_info.iClass != 0xFFFFFFFF)
      {
         dissector = dissector_get_uint_handle( subdissector_class_table, path_info.iClass);
      }
      else
      {
         if ( ioilen >= 1 )
         {
            segment = tvb_get_uint8( tvb, offset + 2 );
            if ((segment & CI_SEGMENT_TYPE_MASK) == CI_DATA_SEGMENT)
            {
               dissector = dissector_get_uint_handle( subdissector_symbol_table, segment );
            }
         }
      }

      if ( preq_info )
      {
         preq_info->dissector = dissector;

         /* copy IOI for access by response packet */
         preq_info->pIOI = wmem_alloc(wmem_file_scope(), ioilen*2);
         preq_info->IOILen = ioilen;
         tvb_memcpy(tvb, preq_info->pIOI, offset+2, ioilen*2);

         preq_info->bService = service;
      }

      /* Check to see if service is 'generic' */
      try_val_to_str_idx(service, cip_sc_vals, &service_index);

      cip_service_info_t* service_entry = cip_get_service(pinfo, service);
      if (service_index >= 0 && !service_entry)
      {
          /* See if object dissector wants to override generic service handling */
          if(!dissector_try_heuristic(heur_subdissector_service, tvb, pinfo, item_tree, &hdtbl_entry, NULL))
          {
             /* No need to set a custom dissector if this is just a generic service. */
             if (preq_info)
             {
                preq_info->dissector = NULL;
             }

             dissect_cip_generic_service_req(tvb, pinfo, cip_tree, &path_info);
          }
      }
      else if ( dissector )
      {
         call_dissector( dissector, tvb, pinfo, item_tree );
      }
      else if (service_entry)
      {
         dissect_cip_object_specific_service(tvb, pinfo, cip_tree, msp_item, service_entry);
      }
      else
      {
         call_dissector( cip_class_generic_handle, tvb, pinfo, item_tree );
      }
   } /* End of if-else( request ) */

   decrement_dissection_depth(pinfo);

   p_remove_proto_data(wmem_file_scope(), pinfo, proto_cip, 0);
   p_add_proto_data(wmem_file_scope(), pinfo, proto_cip, 0, p_save_proto_data);

} /* End of dissect_cip_data() */

void dissect_cip_run_idle(tvbuff_t* tvb, int offset, proto_tree* item_tree)
{
   static int * const run_idle_header[] = {
      &hf_32bitheader_roo,
      &hf_32bitheader_coo,
      &hf_32bitheader_run_idle,
      NULL
   };

   proto_tree_add_bitmask(item_tree, tvb, offset, hf_32bitheader, ett_32bitheader_tree, run_idle_header, ENC_LITTLE_ENDIAN);
}

static int
dissect_cip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   enip_request_info_t *enip_info;
   cip_req_info_t *preq_info;

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP");

   col_clear(pinfo->cinfo, COL_INFO);
   col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");

   /* Each CIP request received by ENIP gets a unique ID */
   enip_info = (enip_request_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_enip, ENIP_REQUEST_INFO);

   if ( enip_info )
   {
      preq_info = enip_info->cip_info;
      if ( preq_info == NULL )
      {
         preq_info = wmem_new0(wmem_file_scope(), cip_req_info_t);
         enip_info->cip_info = preq_info;
      }
      dissect_cip_data( tree, tvb, 0, pinfo, enip_info->cip_info, NULL, false );
   }
   else
   {
      dissect_cip_data( tree, tvb, 0, pinfo, NULL, NULL, false );
   }

   return tvb_reported_length(tvb);
}

static int
dissect_cip_implicit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
   proto_item *ti;
   proto_tree *cip_tree;

   uint32_t ClassID = GPOINTER_TO_UINT(data);
   int length = tvb_reported_length_remaining(tvb, 0);

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP");
   col_clear(pinfo->cinfo, COL_INFO);

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip, tvb, 0, length, ENC_NA);
   cip_tree = proto_item_add_subtree(ti, ett_cip);

   proto_tree_add_item(cip_tree, hf_cip_data, tvb, 0, length, ENC_NA);

   col_append_fstr(pinfo->cinfo, COL_INFO, "Implicit Data - %s",
        val_to_str(ClassID, cip_class_names_vals, "Class (0x%02x)"));

   return tvb_reported_length(tvb);
}

/*
 * Protocol initialization
 */

void
proto_register_cip(void)
{
   /* Setup list of header fields */
   static hf_register_info hf[] = {
      { &hf_attr_class_revision, { "Revision", "cip.class_revision", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_max_instance, { "Max Instance", "cip.max_instance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_num_instance, { "Number of Instances", "cip.num_instance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_opt_attr_num, { "Number of Attributes", "cip.num_attr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_attr_num, { "Attribute Number", "cip.attr_num", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_opt_service_num, { "Number of Services", "cip.num_service", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_service_code, { "Service Code", "cip.service_code", FT_UINT16, BASE_HEX, VALS(cip_sc_vals), 0, NULL, HFILL } },
      { &hf_attr_class_num_class_attr, { "Maximum ID Number Class Attributes", "cip.num_class_attr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_attr_class_num_inst_attr, { "Maximum ID Number Instance Attributes", "cip.num_inst_attr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

      { &hf_cip_service, { "Service", "cip.service", FT_UINT8, BASE_HEX, NULL, 0, "Service Code + Request/Response", HFILL }},
      { &hf_cip_reqrsp, { "Request/Response", "cip.rr", FT_UINT8, BASE_HEX, VALS(cip_sc_rr), CIP_SC_RESPONSE_MASK, "Request or Response message", HFILL }},
      { &hf_cip_service_code, { "Service", "cip.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals), CIP_SC_MASK, "Service Code", HFILL }},
      { &hf_cip_epath, { "EPath", "cip.epath", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_genstat, { "General Status", "cip.genstat", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_addstat_size, { "Additional Status Size", "cip.addstat_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_add_stat, { "Additional Status", "cip.addstat", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_request_path_size, { "Request Path Size", "cip.request_path_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},

      { &hf_cip_path_segment, { "Path Segment", "cip.path_segment", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_path_segment_type, { "Path Segment Type", "cip.path_segment.type", FT_UINT8, BASE_DEC, VALS(cip_path_seg_vals), CI_SEGMENT_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_port_ex_link_addr, { "Extended Link Address", "cip.ex_linkaddress", FT_BOOLEAN, 8, NULL, CI_PORT_SEG_EX_LINK_ADDRESS, NULL, HFILL }},
      { &hf_cip_port, { "Port", "cip.port", FT_UINT8, BASE_DEC, VALS(cip_port_number_vals), CI_PORT_SEG_PORT_ID_MASK, "Port Identifier", HFILL } },
      { &hf_cip_port_extended,{ "Port Extended", "cip.port", FT_UINT16, BASE_HEX, NULL, 0, "Port Identifier Extended", HFILL } },
      { &hf_cip_link_address_byte, { "Link Address", "cip.linkaddress.byte", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_link_address_size, { "Link Address Size", "cip.linkaddress_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_link_address_string, { "Link Address", "cip.linkaddress.string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_logical_seg_type, { "Logical Segment Type", "cip.logical_segment.type", FT_UINT8, BASE_DEC, VALS(cip_logical_segment_type_vals), CI_LOGICAL_SEG_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_logical_seg_format, { "Logical Segment Format", "cip.logical_segment.format", FT_UINT8, BASE_DEC, VALS(cip_logical_segment_format_vals), CI_LOGICAL_SEG_FORMAT_MASK, NULL, HFILL }},
      { &hf_cip_class8, { "Class", "cip.class", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_class16, { "Class", "cip.class", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_class32, { "Class", "cip.class", FT_UINT32, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_instance8, { "Instance", "cip.instance", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_instance16, { "Instance", "cip.instance", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_instance32, { "Instance", "cip.instance", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_member8, { "Member", "cip.member", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_member16, { "Member", "cip.member", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_member32, { "Member", "cip.member", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_attribute8, { "Attribute", "cip.attribute", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_attribute16, { "Attribute", "cip.attribute", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_attribute32, { "Attribute", "cip.attribute", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint8, { "Connection Point", "cip.connpoint", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint16, { "Connection Point", "cip.connpoint", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint32, { "Connection Point", "cip.connpoint", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_serviceid8,{ "Service ID", "cip.serviceid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_ekey_format, { "Key Format", "cip.ekey.format", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_vendor, { "Vendor ID", "cip.ekey.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_ekey_devtype, { "Device Type", "cip.ekey.devtype", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_ekey_prodcode, { "Product Code", "cip.ekey.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_compatibility, { "Compatibility", "cip.ekey.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_comp_bit, { "Compatibility", "cip.ekey.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, "EKey: Compatibility bit", HFILL }},
      { &hf_cip_ekey_majorrev, { "Major Revision", "cip.ekey.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, "EKey: Major Revision", HFILL }},
      { &hf_cip_ekey_minorrev, { "Minor Revision", "cip.ekey.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_serial_number, { "Serial Number", "cip.ekey.serial_number", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ext_logical8,{ "Extended Logical", "cip.extlogical", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_ext_logical16,{ "Extended Logical", "cip.extlogical", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_ext_logical32,{ "Extended Logical", "cip.extlogical", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_ext_logical_type,{ "Extended Logical Type", "cip.extlogical.type", FT_UINT8, BASE_HEX, VALS(cip_ext_logical_segment_format_vals), 0, NULL, HFILL } },
      { &hf_cip_data_seg_type, { "Data Segment Type", "cip.data_segment.type", FT_UINT8, BASE_DEC, VALS(cip_data_segment_type_vals), CI_DATA_SEG_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_data_seg_size_simple, { "Data Size", "cip.data_segment.size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_data_seg_size_extended, { "Data Size", "cip.data_segment.size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0, NULL, HFILL } },
      { &hf_cip_data_seg_item, { "Data", "cip.data_segment.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_symbol, { "ANSI Symbol", "cip.symbol", FT_STRING, BASE_NONE, NULL, 0, "ANSI Extended Symbol Segment", HFILL }},
      { &hf_cip_symbol_size, { "Symbolic Symbol Size", "cip.symbol.size", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL } },
      { &hf_cip_symbol_ascii, { "ASCII Symbol", "cip.ascii_symbol", FT_STRING, BASE_NONE, NULL, 0, "ASCII Symbol Segment", HFILL } },
      { &hf_cip_symbol_extended_format,{ "Extended String Format", "cip.symbol.format", FT_UINT8, BASE_DEC, VALS(cip_symbolic_format_vals), CI_SYMBOL_SEG_FORMAT_MASK, NULL, HFILL } },
      { &hf_cip_symbol_numeric_format,{ "Extended String Numeric Format", "cip.symbol.numformat", FT_UINT8, BASE_DEC, VALS(cip_symbolic_numeric_format_vals), 0x1F, NULL, HFILL } },
      { &hf_cip_symbol_double_size, { "Double Byte Chars", "cip.symbol.size", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL } },
      { &hf_cip_symbol_triple_size, { "Triple Byte Chars", "cip.symbol.size", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL } },
      { &hf_cip_numeric_usint,{ "Numeric Symbol", "cip.numeric_symbol", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_numeric_uint,{ "Numeric Symbol", "cip.numeric_symbol", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_numeric_udint,{ "Numeric Symbol", "cip.numeric_symbol", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_network_seg_type, { "Network Segment Type", "cip.network_segment.type", FT_UINT8, BASE_DEC, VALS(cip_network_segment_type_vals), CI_NETWORK_SEG_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_seg_schedule, { "Multiplier/Phase", "cip.network_segment.schedule", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_fixed_tag, { "Fixed Tag", "cip.network_segment.fixed_tag", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_prod_inhibit_time, { "Production Inhibit Time (ms)", "cip.network_segment.prod_inhibit", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_prod_inhibit_time_us, { "Production Inhibit Time (us)", "cip.network_segment.prod_inhibit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_cip_seg_network_size, { "Network Segment Length", "cip.network_segment.length", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_seg_network_subtype, { "Extended Segment Subtype", "cip.network_segment.subtype", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_cip_seg_safety_format, { "Safety Format", "cip.safety_segment.format", FT_UINT8, BASE_DEC, VALS(cip_safety_segment_format_type_vals),  0, NULL, HFILL }},
      { &hf_cip_seg_safety_reserved, { "Reserved", "cip.safety_segment.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_configuration_crc, { "Configuration CRC (SCCRC)", "cip.safety_segment.configuration_crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_configuration_timestamp, { "Configuration Timestamp (SCTS)", "cip.safety_segment.configuration_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_configuration_date, { "Configuration (Manual) Date", "cip.safety_segment.configuration_date", FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_configuration_time, { "Configuration (Manual) Time", "cip.safety_segment.configuration_time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_time_correction_epi, { "Time Correction EPI", "cip.safety_segment.time_correction_epi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_time_correction_net_params, { "Time Correction Network Connection Parameters", "cip.safety_segment.time_correction.net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_time_correction_own, { "Redundant Owner", "cip.safety_segment.time_correction.owner", FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000, "Time Correction: Redundant owner bit", HFILL }},
      { &hf_cip_seg_safety_time_correction_typ, { "Connection Type", "cip.safety_segment.time_correction.type", FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000, "Time Correction: Connection type", HFILL }},
      { &hf_cip_seg_safety_time_correction_prio, { "Priority", "cip.safety_segment.time_correction.prio", FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00, "Time Correction: Connection priority", HFILL }},
      { &hf_cip_seg_safety_time_correction_fixed_var, { "Connection Size Type", "cip.safety_segment.time_correction.f_v", FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200, "Time Correction: Fixed or variable connection size", HFILL }},
      { &hf_cip_seg_safety_time_correction_con_size, { "Connection Size", "cip.safety_segment.time_correction.consize", FT_UINT16, BASE_DEC, NULL, 0x01FF, "Time Correction: Connection size", HFILL }},
      { &hf_cip_seg_safety_tunid, { "Target UNID (TUNID)", "cip.safety_segment.tunid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_tunid_snn_timestamp, { "SNN Timestamp", "cip.safety_segment.tunid.snn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_tunid_snn_date, { "SNN (Manual) Date", "cip.safety_segment.tunid.snn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_tunid_snn_time, { "SNN (Manual) Time", "cip.safety_segment.tunid.snn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_tunid_nodeid, { "Node ID", "cip.safety_segment.tunid.nodeid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ounid, { "Originator UNID (OUNID)", "cip.safety_segment.ounid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ounid_snn_timestamp, { "SNN Timestamp", "cip.safety_segment.ounid.snn.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ounid_snn_date, { "SNN (Manual) Date", "cip.safety_segment.ounid.snn.date", FT_UINT16, BASE_HEX, VALS(cipsafety_snn_date_vals), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ounid_snn_time, { "SNN (Manual) Time", "cip.safety_segment.ounid.snn.time", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ounid_nodeid, { "Node ID", "cip.safety_segment.ounid.nodeid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_ping_epi_multiplier, { "Ping Interval EPI Multiplier", "cip.safety_segment.ping_epi_multiplier", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_time_coord_msg_min_multiplier, { "Time Coord Msg Min Multiplier", "cip.safety_segment.time_coord_msg_min_multiplier", FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_network_time_expected_multiplier, { "Network Time Expectation Multiplier", "cip.safety_segment.network_time_expected_multiplier", FT_UINT16, BASE_CUSTOM, CF_FUNC(cip_safety_128us_fmt), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_timeout_multiplier, { "Timeout Multiplier", "cip.safety_segment.timeout_multiplier", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_max_consumer_number, { "Max Consumer Number", "cip.safety_segment.max_consumer_number", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(safety_max_consumer_numbers), 0, NULL, HFILL }},
      { &hf_cip_seg_safety_conn_param_crc, { "Connection Parameters CRC (CPCRC)", "cip.safety_segment.conn_param_crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_time_correction_conn_id, { "Time Correction Connection ID", "cip.safety_segment.time_correction_conn_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_max_fault_number, { "Max Fault Number", "cip.safety_segment.max_fault_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_init_timestamp, { "Initial Timestamp", "cip.safety_segment.init_timestamp", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_init_rollover, { "Initial Rollover Value", "cip.safety_segment.init_rollover", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_safety_data, { "Safety Data", "cip.safety_segment.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_class_max_inst32, { "Max Instance", "cip.class.max_inst", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_class_num_inst32, { "Number of Instances", "cip.class.num_inst", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_reserved8, { "Reserved", "cip.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_reserved24, { "Reserved", "cip.reserved", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pad8, { "Pad Byte", "cip.pad", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

      { &hf_cip_sc_get_attr_list_attr_count, { "Attribute Count", "cip.getlist.attr_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_get_attr_list_attr_status, { "Attribute Status", "cip.getlist.attr_status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_count, { "Attribute Count", "cip.setlist.attr_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_status, { "Attribute Status", "cip.setlist.attr_status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_sc_reset_param, { "Reset type", "cip.reset.type", FT_UINT8, BASE_DEC, VALS(cip_reset_type_vals), 0, NULL, HFILL }},
      { &hf_cip_sc_create_instance, { "Instance", "cip.create.instance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_mult_serv_pack_num_services, { "Number of Services", "cip.msp.num_services", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_mult_serv_pack_offset, { "Offset", "cip.msp.offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_max_instance, { "Maximum ID", "cip.find_next_object.max_instance", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_num_instances, { "Number of Instances", "cip.find_next_object.num_instances", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_instance_item, { "Instance", "cip.find_next_object.instance", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_group_sync_is_sync, { "IsSynchronized", "cip.group_sync.is_sync", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_data, { "Data", "cip.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

      { &hf_id_vendor_id, { "Vendor ID", "cip.id.vendor_id", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL } },
      { &hf_id_device_type, { "Device Type", "cip.id.device_type", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_id_product_code, { "Product Code", "cip.id.product_code", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_major_rev, { "Major Revision", "cip.id.major_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_minor_rev, { "Minor Revision", "cip.id.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_status, { "Status", "cip.id.status", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_id_serial_number, { "Serial Number", "cip.id.serial_number", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_id_product_name, { "Product Name", "cip.id.product_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_id_state, { "State", "cip.id.state", FT_UINT8, BASE_HEX, VALS(cip_id_state_vals), 0, NULL, HFILL } },
      { &hf_id_config_value, { "Configuration Consistency Value", "cip.id.config_value", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_id_heartbeat, { "Heartbeat Interval", "cip.id.heartbeat", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_id_status_owned, { "Owned", "cip.id.owned", FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL } },
      { &hf_id_status_conf, { "Configured", "cip.id.conf", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL } },
      { &hf_id_status_extended1, { "Extended Device Status", "cip.id.ext", FT_UINT16, BASE_HEX, NULL, 0x00F0, NULL, HFILL } },
      { &hf_id_status_minor_fault_rec, { "Minor Recoverable Fault", "cip.id.minor_fault1", FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL } },
      { &hf_id_status_minor_fault_unrec, { "Minor Unrecoverable Fault", "cip.id.minor_fault2", FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL } },
      { &hf_id_status_major_fault_rec, { "Major Recoverable Fault", "cip.id.major_fault1", FT_UINT16, BASE_DEC, NULL, 0x0400, NULL, HFILL } },
      { &hf_id_status_major_fault_unrec, { "Major Unrecoverable Fault", "cip.id.major_fault2", FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL } },
      { &hf_id_status_extended2, { "Extended Device Status 2", "cip.id.ext2", FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL } },

      { &hf_msg_rout_num_classes, { "Number of Classes", "cip.mr.num_classes", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_msg_rout_classes, { "Class", "cip.mr.class", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0, NULL, HFILL }},
      { &hf_msg_rout_num_available, { "Number Available", "cip.mr.num_available", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_msg_rout_num_active, { "Number Active", "cip.mr.num_active", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_msg_rout_active_connections, { "Active Connection", "cip.mr.active_connections", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

      { &hf_conn_mgr_open_requests, { "Open Requests", "cip.cm.open_requests", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_open_format_rejects, { "Open Format Rejects", "cip.cm.open_format_rejects", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_open_resource_rejects, { "Open Resource Rejects", "cip.cm.open_resource_rejects", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_other_open_rejects, { "Other Open Rejects", "cip.cm.other_open_rejects", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_close_requests, { "Close Requests", "cip.cm.close_requests", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_close_format_requests, { "Close Format Requests", "cip.cm.close_format_requests", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_close_other_requests, { "Close Other Requests", "cip.cm.close_other_requests", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_conn_timouts, { "Connection Timeouts", "cip.cm.conn_timouts", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_num_conn_entries, { "Number of Connection Entries (Bits)", "cip.cm.conn_entries", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_num_conn_entries_bytes, { "Number of Connection Entries (Bytes)", "cip.cm.conn_entries_bytes", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_conn_open_bits, { "Connection Open Bits", "cip.cm.conn_open_bits", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_conn_mgr_cpu_utilization, { "CPU Utilization", "cip.cm.cpu_util", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_conn_mgr_max_buff_size, { "Max Buff Size", "cip.cm.max_buff_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_conn_mgr_buff_size_remaining, { "Buff Size Remaining", "cip.cm.buff_remain", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

      { &hf_stringi_number_char, { "Number of Characters", "cip.stringi.num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_stringi_language_char, { "Language Chars", "cip.stringi.language_char", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
      { &hf_stringi_char_string_struct, { "Char String Struct", "cip.stringi.char_string_struct", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_stringi_char_set, { "Char Set", "cip.stringi.char_set", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_stringi_international_string, { "International String", "cip.stringi.int_string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

      { &hf_file_filename, { "File Name", "cip.file.file_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

      { &hf_time_sync_ptp_enable, { "PTP Enable", "cip.time_sync.ptp_enable", FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0, NULL, HFILL }},
      { &hf_time_sync_is_synchronized, { "Is Synchronized", "cip.time_sync.is_synchronized", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_sys_time_micro, { "System Time (Microseconds)", "cip.time_sync.sys_time_micro", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_sys_time_nano, { "System Time (Nanoseconds)", "cip.time_sync.sys_time_nano", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_offset_from_master, { "Offset from Master", "cip.time_sync.offset_from_master", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_max_offset_from_master, { "Max Offset from Master", "cip.time_sync.max_offset_from_master", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_mean_path_delay_to_master, { "Mean Path Delay To Master", "cip.time_sync.mean_path_delay_to_master", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_clock_id, { "Clock Identity", "cip.time_sync.gm_clock.clock_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_clock_class, { "Clock Class", "cip.time_sync.gm_clock.clock_class", FT_UINT16, BASE_DEC, VALS(cip_time_sync_clock_class_vals), 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_accuracy, { "Time Accuracy", "cip.time_sync.gm_clock.time_accuracy", FT_UINT16, BASE_DEC, VALS(cip_time_sync_time_accuracy_vals), 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_offset_scaled_log_variance, { "Offset Scaled Log Variance", "cip.time_sync.gm_clock.offset_scaled_log_variance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_current_utc_offset, { "Current UTC Offset", "cip.time_sync.gm_clock.current_utc_offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags, { "Time Property Flags", "cip.time_sync.gm_clock.time_property_flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_leap61, { "Leap indicator 61", "cip.time_sync.gm_clock.time_property_flags.leap61", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_leap59, { "Leap indicator 59", "cip.time_sync.gm_clock.time_property_flags.leap59", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_current_utc_valid, { "Current UTC Offset Valid", "cip.time_sync.gm_clock.time_property_flags.current_utc_valid", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_ptp_timescale, { "PTP Timescale", "cip.time_sync.gm_clock.time_property_flags.ptp_timescale", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_time_traceable, { "Time traceable", "cip.time_sync.gm_clock.time_property_flags.time_traceable", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_property_flags_freq_traceable, { "Frequency traceable", "cip.time_sync.gm_clock.time_property_flags.freq_traceable", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020, NULL, HFILL }},
      { &hf_time_sync_gm_clock_time_source, { "Time Source", "cip.time_sync.gm_clock.time_source", FT_UINT16, BASE_DEC, VALS(cip_time_sync_time_source_vals), 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_priority1, { "Priority1", "cip.time_sync.gm_clock.priority1", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_gm_clock_priority2, { "Priority2", "cip.time_sync.gm_clock.priority2", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_parent_clock_clock_id, { "Clock Identity", "cip.time_sync.parent_clock.clock_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_parent_clock_port_number, { "Port Number", "cip.time_sync.parent_clock.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_parent_clock_observed_offset_scaled_log_variance, { "Observed Offset Scaled Log Variance", "cip.time_sync.parent_clock.observed_offset_scaled_log_variance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_parent_clock_observed_phase_change_rate, { "Observed Phase Change Rate", "cip.time_sync.parent_clock.observed_phase_change_rate", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_clock_id, { "Clock Identity", "cip.time_sync.local_clock.clock_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_clock_class, { "Clock Class", "cip.time_sync.local_clock.clock_class", FT_UINT16, BASE_DEC, VALS(cip_time_sync_clock_class_vals), 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_accuracy, { "Time Accuracy", "cip.time_sync.local_clock.time_accuracy", FT_UINT16, BASE_DEC, VALS(cip_time_sync_time_accuracy_vals), 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_offset_scaled_log_variance, { "Offset Scaled Log Variance", "cip.time_sync.local_clock.offset_scaled_log_variance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_current_utc_offset, { "Current UTC Offset", "cip.time_sync.local_clock.current_utc_offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags, { "Time Property Flags", "cip.time_sync.local_clock.time_property_flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_leap61, { "Leap indicator 61", "cip.time_sync.local_clock.time_property_flags.leap61", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_leap59, { "Leap indicator 59", "cip.time_sync.local_clock.time_property_flags.leap59", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_current_utc_valid, { "Current UTC Offset Valid", "cip.time_sync.local_clock.time_property_flags.current_utc_valid", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_ptp_timescale, { "PTP Timescale", "cip.time_sync.local_clock.time_property_flags.ptp_timescale", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_time_traceable, { "Time traceable", "cip.time_sync.local_clock.time_property_flags.time_traceable", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_property_flags_freq_traceable, { "Frequency traceable", "cip.time_sync.local_clock.time_property_flags.freq_traceable", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020, NULL, HFILL }},
      { &hf_time_sync_local_clock_time_source, { "Time Source", "cip.time_sync.local_clock.time_source", FT_UINT16, BASE_DEC, VALS(cip_time_sync_time_source_vals), 0, NULL, HFILL }},
      { &hf_time_sync_num_ports, { "Port Number", "cip.time_sync.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_state_info_num_ports, { "Number of Ports", "cip.time_sync.port_state_info.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_state_info_port_num, { "Port Number", "cip.time_sync.port_state_info.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_state_info_port_state, { "Port State", "cip.time_sync.port_state_info.port_state", FT_UINT16, BASE_DEC, VALS(cip_time_sync_port_state_vals), 0, NULL, HFILL }},
      { &hf_time_sync_port_enable_cfg_num_ports, { "Number of Ports", "cip.time_sync.port_enable_cfg.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_enable_cfg_port_num, { "Port Number", "cip.time_sync.port_enable_cfg.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_enable_cfg_port_enable, { "Port Enable", "cip.time_sync.port_enable_cfg.port_enable", FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0, NULL, HFILL }},
      { &hf_time_sync_port_log_announce_num_ports, { "Number of Ports", "cip.time_sync.port_log_announce.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_log_announce_port_num, { "Port Number", "cip.time_sync.port_log_announce.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_log_announce_interval, { "Port Log Announce Interval", "cip.time_sync.port_log_announce.interval", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_log_sync_num_ports, { "Number of Ports", "cip.time_sync.port_log_sync.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_log_sync_port_num, { "Port Number", "cip.time_sync.port_log_sync.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_log_sync_port_log_sync_interval, { "Port Log Sync Interval", "cip.time_sync.port_log_sync.port_log_sync_interval", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_priority1, { "Priority1", "cip.time_sync.priority1", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_priority2, { "Priority2", "cip.time_sync.priority2", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_domain_number, { "Domain number", "cip.time_sync.domain_number", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_clock_type, { "Clock Type", "cip.time_sync.clock_type", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_clock_type_ordinary, { "Ordinary Clock", "cip.time_sync.clock_type.ordinary", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080, NULL, HFILL }},
      { &hf_time_sync_clock_type_boundary, { "Boundary Clock", "cip.time_sync.clock_type.boundary", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040, NULL, HFILL }},
      { &hf_time_sync_clock_type_end_to_end, { "End-to-End Transparent Clock", "cip.time_sync.clock_type.end_to_end", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010, NULL, HFILL }},
      { &hf_time_sync_clock_type_management, { "Management Node", "cip.time_sync.clock_type.management", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008, NULL, HFILL }},
      { &hf_time_sync_clock_type_slave_only, { "Slave Only", "cip.time_sync.clock_type.slave_only", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100, NULL, HFILL }},
      { &hf_time_sync_manufacture_id_oui, { "Manufacture Identity OUI", "cip.time_sync.manufacture_id.oui", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_manufacture_id_reserved, { "Reserved", "cip.time_sync.manufacture_id.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_prod_desc_size, { "Product Description Size", "cip.time_sync.prod_desc_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_prod_desc_str, { "Product Description", "cip.time_sync.prod_desc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_revision_data_size, { "Revision Data Size", "cip.time_sync.revision_data_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_revision_data_str, { "Revision Data", "cip.time_sync.revision_data", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_user_desc_size, { "User Description Size", "cip.time_sync.user_desc_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_user_desc_str, { "User Description", "cip.time_sync.user_desc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_profile_id_info_num_ports, { "Number of Ports", "cip.time_sync.port_profile_id_info.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_profile_id_info_port_num, { "Port Number", "cip.time_sync.port_profile_id_info.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_profile_id_info_profile_id, { "Port Profile Identity", "cip.time_sync.port_profile_id_info.profile_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_phys_addr_info_num_ports, { "Number of Ports", "cip.time_sync.port_phys_addr_info.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_phys_addr_info_port_num, { "Port Number", "cip.time_sync.port_phys_addr_info.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_phys_addr_info_phys_proto, { "Physical Protocol", "cip.time_sync.port_profile_id_info.phys_proto", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_phys_addr_info_addr_size, { "Size of Address", "cip.time_sync.port_phys_addr_info.addr_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_phys_addr_info_phys_addr, { "Port Physical Address", "cip.time_sync.port_profile_id_info.phys_addr", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_proto_addr_info_num_ports, { "Number of Ports", "cip.time_sync.port_proto_addr_info.num_ports", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_proto_addr_info_port_num, { "Port Number", "cip.time_sync.port_proto_addr_info.port_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_proto_addr_info_network_proto, { "Network Protocol", "cip.time_sync.port_proto_addr_info.network_proto", FT_UINT16, BASE_DEC, VALS(cip_time_sync_network_protocol_vals), 0, NULL, HFILL }},
      { &hf_time_sync_port_proto_addr_info_addr_size, { "Size of Address", "cip.time_sync.port_proto_addr_info.addr_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_port_proto_addr_info_port_proto_addr, { "Port Protocol Address", "cip.time_sync.port_profile_id_info.port_proto_addr", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_steps_removed, { "Steps Removed", "cip.time_sync.steps_removed", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_sys_time_and_offset_time, { "System Time (Microseconds)", "cip.time_sync.sys_time_and_offset.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
      { &hf_time_sync_sys_time_and_offset_offset, { "System Offset (Microseconds)", "cip.time_sync.sys_time_and_offset.offset", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_port_entry_port, { "Entry Port", "cip.port.entry_port", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_port_type, { "Port Type", "cip.port.type", FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(cip_port_type_vals), 0, NULL, HFILL } },
      { &hf_port_number, { "Port Number", "cip.port.number", FT_UINT16, BASE_DEC, VALS(cip_port_number_vals), 0, NULL, HFILL } },
      { &hf_port_min_node_num, { "Minimum Node Number", "cip.port.min_node", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_port_max_node_num, { "Maximum Node Number", "cip.port.max_node", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_port_name, { "Port Name", "cip.port.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
      { &hf_port_num_comm_object_entries, { "Number of entries", "cip.port.num_comm_object_entries", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
      { &hf_path_len_usint, { "Path Length", "cip.path_len", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL } },
      { &hf_path_len_uint, { "Path Length", "cip.path_len", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL } },

      { &hf_32bitheader, { "32-bit Header", "cip.32bitheader", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
      { &hf_32bitheader_roo, { "ROO", "cip.32bitheader.roo", FT_UINT32, BASE_HEX, NULL, 0xC, "Ready for Ownership of Outputs", HFILL } },
      { &hf_32bitheader_coo, { "COO", "cip.32bitheader.coo", FT_UINT32, BASE_HEX, NULL, 0x2, "Claim Output Ownership", HFILL } },
      { &hf_32bitheader_run_idle, { "Run/Idle", "cip.32bitheader.run_idle", FT_UINT32, BASE_HEX, VALS(cip_run_idle_vals), 0x1, NULL, HFILL } },

      { &hf_cip_connection, { "CIP Connection Index", "cip.connection", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
      { &hf_cip_fwd_open_in, { "Forward Open Request In", "cip.fwd_open_in", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
      { &hf_cip_fwd_close_in, { "Forward Close Request In", "cip.fwd_close_in", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
   };

   static hf_register_info hf_cm[] = {
      { &hf_cip_cm_sc, { "Service", "cip.cm.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_cm), CIP_SC_MASK, NULL, HFILL }},
      { &hf_cip_cm_genstat, { "General Status", "cip.cm.genstat", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_addstat_size, { "Additional Status Size", "cip.cm.addstat_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cm_ext_status, { "Extended Status", "cip.cm.ext_status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_cm_ext_st_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_add_status, { "Additional Status", "cip.cm.addstat", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_priority, { "Priority", "cip.cm.priority", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
      { &hf_cip_cm_tick_time, { "Tick time", "cip.cm.tick_time", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_cip_cm_timeout_tick, { "Time-out ticks", "cip.cm.timeout_tick", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_timeout, { "Actual Time Out", "cip.cm.timeout", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_connid, { "O->T Network Connection ID", "cip.cm.ot_connid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_connid, { "T->O Network Connection ID", "cip.cm.to_connid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_connid, { "Connection ID", "cip.connid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_conn_serial_num, { "Connection Serial Number", "cip.cm.conn_serial_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_vendor, { "Originator Vendor ID", "cip.cm.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_timeout_multiplier, { "Connection Timeout Multiplier", "cip.cm.timeout_multiplier", FT_UINT8, BASE_DEC, VALS(cip_con_time_mult_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ot_rpi, { "O->T RPI", "cip.cm.otrpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_ot_timeout, { "O->T Timeout Threshold", "cip.cm.ot_timeout", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_net_params32, { "O->T Network Connection Parameters", "cip.cm.ot_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_net_params16, { "O->T Network Connection Parameters", "cip.cm.ot_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_rpi, { "T->O RPI", "cip.cm.torpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_to_timeout, { "T->O Timeout Threshold", "cip.cm.to_timeout", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL }},

      { &hf_cip_safety_nte_ms, { "Network Time Expectation (Produce Timeout)", "cip.safety.nte", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL }},

      { &hf_cip_cm_to_net_params32, { "T->O Network Connection Parameters", "cip.cm.to_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_net_params16, { "T->O Network Connection Parameters", "cip.cm.to_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_transport_type_trigger, { "Transport Type/Trigger", "cip.cm.transport_type_trigger", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_conn_path_size, { "Connection Path Size", "cip.cm.connpath_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_api, { "O->T API", "cip.cm.otapi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_to_api, { "T->O API", "cip.cm.toapi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_app_reply_size, { "Application Reply Size", "cip.cm.app_reply_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cm_app_reply_data , { "Application Reply", "cip.cm.app_reply_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_consumer_number, { "Consumer Number", "cip.cm.consumer_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_targ_vendor_id, { "Target Vendor ID", "cip.cm.targ_vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_targ_dev_serial_num, { "Target Device Serial Number", "cip.cm.targ_dev_serial_num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_targ_conn_serial_num, { "Target Connection Serial Number", "cip.cm.targ_conn_serial_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_initial_timestamp, { "Initial Timestamp", "cip.cm.initial_timestamp", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_initial_rollover, { "Initial Rollover Value", "cip.cm.initial_rollover", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_remain_path_size, { "Remaining Path Size", "cip.cm.remain_path_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cm_msg_req_size, { "Embedded Message Request Size", "cip.cm.msg_req_size", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0, NULL, HFILL }},
      { &hf_cip_cm_route_path_size, { "Route Path Size", "cip.cm.route_path_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cm_orig_serial_num, { "Originator Serial Number", "cip.cm.orig_serial_num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_fwo_con_size, { "Connection Size", "cip.cm.fwo.consize", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x01FF, "Fwd Open: Connection size", HFILL }},
      { &hf_cip_cm_lfwo_con_size, { "Connection Size", "cip.cm.fwo.consize", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0xFFFF, "Large Fwd Open: Connection size", HFILL }},
      { &hf_cip_cm_fwo_fixed_var, { "Connection Size Type", "cip.cm.fwo.f_v", FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200, "Fwd Open: Fixed or variable connection size", HFILL }},
      { &hf_cip_cm_lfwo_fixed_var, { "Connection Size Type", "cip.cm.fwo.f_v", FT_UINT32, BASE_DEC, VALS(cip_con_fw_vals), 0x02000000, "Large Fwd Open: Fixed or variable connection size", HFILL }},
      { &hf_cip_cm_fwo_prio, { "Priority", "cip.cm.fwo.prio", FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00, "Fwd Open: Connection priority", HFILL }},
      { &hf_cip_cm_lfwo_prio, { "Priority", "cip.cm.fwo.prio", FT_UINT32, BASE_DEC, VALS(cip_con_prio_vals), 0x0C000000, "Large Fwd Open: Connection priority", HFILL }},
      { &hf_cip_cm_fwo_typ, { "Connection Type", "cip.cm.fwo.type", FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000, "Fwd Open: Connection type", HFILL }},
      { &hf_cip_cm_lfwo_typ, { "Connection Type", "cip.cm.fwo.type", FT_UINT32, BASE_DEC, VALS(cip_con_type_vals), 0x60000000, "Large Fwd Open: Connection type", HFILL }},
      { &hf_cip_cm_fwo_own, { "Redundant Owner", "cip.cm.fwo.owner", FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000, "Fwd Open: Redundant owner bit", HFILL }},
      { &hf_cip_cm_lfwo_own, { "Redundant Owner", "cip.cm.fwo.owner", FT_UINT32, BASE_DEC, VALS(cip_con_owner_vals), 0x80000000, "Large Fwd Open: Redundant owner bit", HFILL }},
      { &hf_cip_cm_fwo_dir, { "Direction", "cip.cm.fwo.dir", FT_BOOLEAN, 8, TFS(&tfs_server_client), CI_PRODUCTION_DIR_MASK, "Fwd Open: Direction", HFILL }},
      { &hf_cip_cm_fwo_trigg, { "Trigger", "cip.cm.fwo.trigger", FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), CI_PRODUCTION_TRIGGER_MASK, "Fwd Open: Production trigger", HFILL }},
      { &hf_cip_cm_fwo_class, { "Class", "cip.cm.fwo.transport", FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), CI_TRANSPORT_CLASS_MASK, "Fwd Open: Transport Class", HFILL }},
      { &hf_cip_cm_gco_conn, { "Number of Connections", "cip.cm.gco.conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: Number of Connections", HFILL }},
      { &hf_cip_cm_gco_coo_conn, { "COO Connections", "cip.cm.gco.coo_conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: COO Connections", HFILL }},
      { &hf_cip_cm_gco_roo_conn, { "ROO Connections", "cip.cm.gco.roo_conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: ROO Connections", HFILL }},
      { &hf_cip_cm_gco_last_action, { "Last Action", "cip.cm.gco.la", FT_UINT8, BASE_DEC, VALS(cip_con_last_action_vals), 0, "GetConnOwner: Last Action", HFILL }},
      { &hf_cip_cm_ext112_ot_rpi_type, { "Trigger", "cip.cm.ext112otrpi_type", FT_UINT8, BASE_DEC, VALS(cip_cm_rpi_type_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_to_rpi_type, { "Trigger", "cip.cm.ext112torpi_type", FT_UINT8, BASE_DEC, VALS(cip_cm_rpi_type_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_ot_rpi, { "Acceptable O->T RPI", "cip.cm.ext112otrpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_to_rpi, { "Acceptable T->O RPI", "cip.cm.ext112torpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cm_ext126_size, { "Maximum Size", "cip.cm.ext126_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext127_size, { "Maximum Size", "cip.cm.ext127_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext128_size, { "Maximum Size", "cip.cm.ext128_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }}
   };

  static hf_register_info hf_pccc[] = {
      { &hf_cip_pccc_sc, { "Service", "cip.pccc.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_pccc), CIP_SC_MASK, NULL, HFILL }},
      { &hf_cip_pccc_req_id_len, { "Requestor ID Length", "cip.pccc.req.id.len", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_cip_vend_id, { "CIP Vendor ID", "cip.pccc.cip.vend.id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_cip_serial_num, { "CIP Serial Number", "cip.pccc.cip.serial.num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_cmd_code, { "Command Code", "cip.pccc.cmd.code", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_sts_code, { "Status", "cip.pccc.gs.status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_gs_st_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_ext_sts_code, { "Extended Status", "cip.pccc.es.status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_es_st_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_tns_code, { "Transaction Code", "cip.pccc.tns.code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_fnc_code_06, { "Function Code", "cip.pccc.fnc.code_06", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_fnc_06_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_fnc_code_07, { "Function Code", "cip.pccc.fnc.code_07", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_fnc_07_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_fnc_code_0f, { "Function Code", "cip.pccc.fnc.code_0f", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_fnc_0f_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_byte_size, { "Byte Size", "cip.pccc.byte.size", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_file_num, { "File Number", "cip.pccc.file.num", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_file_type, { "File Type", "cip.pccc.file.type", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_file_type_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_element_num, { "Element Number", "cip.pccc.element.num", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_subelement_num, { "Sub-Element Number", "cip.pccc.subelement.num", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
#if 0
      { &hf_cip_pccc_cpu_mode_3a, { "CPU Mode", "cip.pccc.cpu.mode_3a", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_cpu_mode_3a_vals_ext, 0, NULL, HFILL }},
#endif
      { &hf_cip_pccc_cpu_mode_80, { "CPU Mode", "cip.pccc.cpu.mode_80", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_pccc_cpu_mode_80_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_pccc_resp_code, { "Response Code", "cip.pccc.resp.code", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_execute_multi_count, { "Execute Multiple Command - Number of Commands", "cip.pccc.execute.multi.count", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_execute_multi_len, { "Execute Multiple Command - Command Length", "cip.pccc.execute.multi.len", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pccc_execute_multi_fnc, { "Execute Multiple Command - Function Code", "cip.pccc.execute.multi.code", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

      { &hf_cip_pccc_data, { "Data", "cip.pccc.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }}
   };

   static hf_register_info hf_mb[] = {
      { &hf_cip_mb_sc, { "Service", "cip.mb.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_mb), CIP_SC_MASK, NULL, HFILL }},
      { &hf_cip_mb_read_coils_start_addr, { "Starting Address", "cip.mb.read_coils.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_coils_num_coils, { "Quantity of Coils", "cip.mb.read_coils.num_coils", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_coils_data, { "Data", "cip.mb.read_coils.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_discrete_inputs_start_addr, { "Starting Address", "cip.mb.read_discrete_inputs.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_discrete_inputs_num_inputs, { "Quantity of Inputs", "cip.mb.read_discrete_inputs.num_inputs", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_discrete_inputs_data, { "Data", "cip.mb.read_discrete_inputs.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_holding_register_start_addr, { "Starting Address", "cip.mb.read_holding_register.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_holding_register_num_registers, { "Quantity of Holding Registers", "cip.mb.read_holding_register.num_registers", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_holding_register_data, { "Data", "cip.mb.read_holding_register.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_input_register_start_addr, { "Starting Address", "cip.mb.read_input_register.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_input_register_num_registers, { "Quantity of Input Registers", "cip.mb.read_input_register.num_registers", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_read_input_register_data, { "Data", "cip.mb.read_input_register.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_coils_start_addr, { "Starting Address", "cip.mb.write_coils.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_coils_outputs_forced, { "Outputs Forced", "cip.mb.write_coils.outputs_forced", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_coils_num_coils, { "Quantity of Coils", "cip.mb.write_coils.num_coils", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_coils_data, { "Data", "cip.mb.write_coils.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_registers_start_addr, { "Starting Address", "cip.mb.write_registers.start_addr", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_registers_outputs_forced, { "Outputs Forced", "cip.mb.write_registers.outputs_forced", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_registers_num_registers, { "Quantity of Holding Registers", "cip.mb.write_registers.num_registers", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_write_registers_data, { "Data", "cip.mb.write_registers.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_mb_data, { "Data", "cip.mb.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }}
   };

   static hf_register_info hf_cco[] = {
      { &hf_cip_cco_sc, { "Service", "cip.cco.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_cco), CIP_SC_MASK, NULL, HFILL }},
      { &hf_cip_cco_format_number, { "Format Number", "cip.cco.format_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_edit_signature, { "Edit Signature", "cip.cco.edit_signature", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_con_flags, { "Connection Flags", "cip.cco.connflags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_con_type, { "Connection O_T", "cip.cco.con", FT_UINT16, BASE_DEC, VALS(cip_con_vals), 0x0001, NULL, HFILL }},
      { &hf_cip_cco_ot_rtf, { "O->T real time transfer format", "cip.cco.otrtf", FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x000E, NULL, HFILL }},
      { &hf_cip_cco_to_rtf, { "T->O real time transfer format", "cip.cco.tortf", FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x0070, NULL, HFILL }},
      { &hf_cip_cco_tdi_vendor, { "Vendor ID", "cip.cco.tdi.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_devtype, { "Device Type", "cip.cco.tdi.devtype", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_prodcode, { "Product Code", "cip.cco.tdi.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_compatibility, { "Compatibility", "cip.cco.tdi.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_comp_bit, { "Compatibility", "cip.cco.tdi.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, NULL, HFILL }},
      { &hf_cip_cco_tdi_majorrev, { "Major Revision", "cip.cco.tdi.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_cip_cco_tdi_minorrev, { "Minor Revision", "cip.cco.tdi.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_vendor, { "Vendor ID", "cip.cco.pdi.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_devtype, { "Device Type", "cip.cco.pdi.devtype", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_prodcode, { "Product Code", "cip.cco.pdi.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_compatibility, { "Compatibility", "cip.cco.pdi.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_comp_bit, { "Compatibility", "cip.cco.pdi.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, NULL, HFILL }},
      { &hf_cip_cco_pdi_majorrev, { "Major Revision", "cip.cco.pdi.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_cip_cco_pdi_minorrev, { "Minor Revision", "cip.cco.pdi.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_cs_data_index, { "CS Data Index Number", "cip.cco.cs_data_index", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_timeout_multiplier, { "Connection Timeout Multiplier", "cip.cco.timeout_multiplier", FT_UINT8, BASE_DEC, VALS(cip_con_time_mult_vals), 0, NULL, HFILL }},
      { &hf_cip_cco_ot_rpi, { "O->T RPI", "cip.cco.otrpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cco_ot_net_param32, { "O->T Network Connection Parameters", "cip.cco.ot_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_ot_net_param16, { "O->T Network Connection Parameters", "cip.cco.ot_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_to_rpi, { "T->O RPI", "cip.cco.torpi", FT_UINT32, BASE_CUSTOM, CF_FUNC(cip_rpi_api_fmt), 0, NULL, HFILL }},
      { &hf_cip_cco_to_net_param16, { "T->O Network Connection Parameters", "cip.cco.to_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_to_net_param32, { "T->O Network Connection Parameters", "cip.cco.to_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_transport_type_trigger, { "Transport Type/Trigger", "cip.cco.transport_type_trigger", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_fwo_con_size, { "Connection Size", "cip.cco.consize", FT_UINT16, BASE_DEC, NULL, 0x01FF, NULL, HFILL }},
      { &hf_cip_cco_lfwo_con_size, { "Connection Size", "cip.cco.consize", FT_UINT32, BASE_DEC, NULL, 0xFFFF, NULL, HFILL }},
      { &hf_cip_cco_fwo_fixed_var, { "Connection Size Type", "cip.cco.f_v", FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200, NULL, HFILL }},
      { &hf_cip_cco_lfwo_fixed_var, { "Connection Size Type", "cip.cco.f_v", FT_UINT32, BASE_DEC, VALS(cip_con_fw_vals), 0x02000000, NULL, HFILL }},
      { &hf_cip_cco_fwo_prio, { "Priority", "cip.cco.prio", FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00, NULL, HFILL }},
      { &hf_cip_cco_lfwo_prio, { "Priority", "cip.cco.prio", FT_UINT32, BASE_DEC, VALS(cip_con_prio_vals), 0x0C000000, NULL, HFILL }},
      { &hf_cip_cco_fwo_typ, { "Connection Type", "cip.cco.type", FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000, NULL, HFILL }},
      { &hf_cip_cco_lfwo_typ, { "Connection Type", "cip.cco.type", FT_UINT32, BASE_DEC, VALS(cip_con_type_vals), 0x60000000, NULL, HFILL }},
      { &hf_cip_cco_fwo_own, { "Redundant Owner", "cip.cco.owner", FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000, NULL, HFILL }},
      { &hf_cip_cco_lfwo_own, { "Redundant Owner", "cip.cco.owner", FT_UINT32, BASE_DEC, VALS(cip_con_owner_vals), 0x80000000, NULL, HFILL }},
      { &hf_cip_cco_fwo_dir, { "Direction", "cip.cco.dir", FT_BOOLEAN, 8, TFS(&tfs_server_client), CI_PRODUCTION_DIR_MASK, NULL, HFILL }},
      { &hf_cip_cco_fwo_trigger, { "Trigger", "cip.cco.trigger", FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), CI_PRODUCTION_TRIGGER_MASK, NULL, HFILL }},
      { &hf_cip_cco_fwo_class, { "Class", "cip.cco.transport", FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), CI_TRANSPORT_CLASS_MASK, NULL, HFILL }},
      { &hf_cip_cco_conn_path_size, { "Connection Path Size", "cip.cco.connpath_size", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_word_words, 0, NULL, HFILL }},
      { &hf_cip_cco_proxy_config_size, { "Proxy Config Data Size", "cip.cco.proxy_config_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_target_config_size, { "Target Config Data Size", "cip.cco.target_config_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_format_number, { "Format number", "cip.cco.iomap_format_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_size, { "Mapping data size", "cip.cco.iomap_size", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0, NULL, HFILL }},
      { &hf_cip_cco_connection_disable, { "Connection Disable", "cip.cco.connection_disable", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_cip_cco_net_conn_param_attr, { "Net Connection Parameter Attribute Selection", "cip.cco.net_conn_param_attr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_proxy_config_data, { "Proxy Config Data", "cip.cco.proxy_config_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_target_config_data, { "Target Config Data", "cip.cco.target_config_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_attribute, { "Attribute Data", "cip.cco.iomap", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_safety, { "Safety Parameters", "cip.cco.safety", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_change_type, { "Change Type", "cip.cco.change_type", FT_UINT16, BASE_DEC, VALS(cip_cco_change_type_vals), 0, NULL, HFILL }},
      { &hf_cip_cco_connection_name, { "Connection Name", "cip.cco.connection_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_ext_status, { "Extended Status", "cip.cco.ext_status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_cm_ext_st_vals_ext, 0, NULL, HFILL }},
   };

   /* Setup protocol subtree array */
   static int *ett[] = {
      &ett_cip_class_generic,
      &ett_cip,
      &ett_path,
      &ett_path_seg,
      &ett_rrsc,
      &ett_mcsc,
      &ett_cia_path,
      &ett_data_seg,
      &ett_cmd_data,
      &ett_port_path,
      &ett_network_seg,
      &ett_network_seg_safety,
      &ett_network_seg_safety_time_correction_net_params,
      &ett_cip_seg_safety_tunid,
      &ett_cip_seg_safety_tunid_snn,
      &ett_cip_seg_safety_ounid,
      &ett_cip_seg_safety_ounid_snn,
      &ett_status_item,
      &ett_add_status_item,
      &ett_cip_get_attributes_all_item,
      &ett_cip_get_attribute_list,
      &ett_cip_get_attribute_list_item,
      &ett_cip_set_attribute_list,
      &ett_cip_set_attribute_list_item,
      &ett_cip_mult_service_packet,
      &ett_cip_msp_offset,
      &ett_time_sync_gm_clock_flags,
      &ett_time_sync_local_clock_flags,
      &ett_time_sync_port_state_info,
      &ett_time_sync_port_enable_cfg,
      &ett_time_sync_port_log_announce,
      &ett_time_sync_port_log_sync,
      &ett_time_sync_clock_type,
      &ett_time_sync_port_profile_id_info,
      &ett_time_sync_port_phys_addr_info,
      &ett_time_sync_port_proto_addr_info,
      &ett_id_status,
      &ett_32bitheader_tree,
      &ett_connection_info,
   };

   static int *ett_cm[] = {
      &ett_cip_class_cm,
      &ett_cm_rrsc,
      &ett_cm_mes_req,
      &ett_cm_ncp,
      &ett_cm_cmd_data,
      &ett_cm_ttt,
      &ett_cm_add_status_item,
      &ett_cip_cm_pid,
      &ett_cip_cm_safety
   };

   static int *ett_pccc[] = {
      &ett_cip_class_pccc,
      &ett_pccc_rrsc,
      &ett_pccc_req_id,
      &ett_pccc_cmd_data
    };

   static int *ett_mb[] = {
      &ett_cip_class_mb,
      &ett_mb_rrsc,
      &ett_mb_cmd_data
    };

   static int *ett_cco[] = {
      &ett_cip_class_cco,
      &ett_cco_iomap,
      &ett_cco_con_status,
      &ett_cco_con_flag,
      &ett_cco_tdi,
      &ett_cco_pdi,
      &ett_cco_ncp,
      &ett_cco_rrsc,
      &ett_cco_cmd_data,
      &ett_cco_ttt,
    };

   static ei_register_info ei[] = {
      { &ei_mal_identity_revision, { "cip.malformed.id.revision", PI_MALFORMED, PI_ERROR, "Malformed Identity revision", EXPFILL }},
      { &ei_mal_identity_status, { "cip.malformed.id.status", PI_MALFORMED, PI_ERROR, "Malformed Identity status", EXPFILL } },
      { &ei_mal_msg_rout_num_classes, { "cip.malformed.msg_rout.num_classes", PI_MALFORMED, PI_ERROR, "Malformed Message Router Attribute 1", EXPFILL }},
      { &ei_mal_time_sync_gm_clock, { "cip.malformed.time_sync.gm_clock", PI_MALFORMED, PI_ERROR, "Malformed Grandmaster clock info", EXPFILL }},
      { &ei_mal_time_sync_parent_clock, { "cip.malformed.time_sync.parent_clock", PI_MALFORMED, PI_ERROR, "Malformed Parent clock info", EXPFILL }},
      { &ei_mal_time_sync_local_clock, { "cip.malformed.time_sync.local_clock", PI_MALFORMED, PI_ERROR, "Malformed Local clock info", EXPFILL }},
      { &ei_mal_time_sync_port_state_info, { "cip.malformed.time_sync.port_state_info", PI_MALFORMED, PI_ERROR, "Malformed Port State Info", EXPFILL }},
      { &ei_mal_time_sync_port_state_info_ports, { "cip.malformed.time_sync.port_state_info.ports", PI_MALFORMED, PI_ERROR, "Malformed Port State Info - too many ports", EXPFILL }},
      { &ei_mal_time_sync_port_enable_cfg, { "cip.malformed.time_sync.port_enable_cfg", PI_MALFORMED, PI_ERROR, "Malformed Port Enable Cfg", EXPFILL }},
      { &ei_mal_time_sync_port_enable_cfg_ports, { "cip.malformed.time_sync.port_enable_cfg.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Enable Cfg - too many ports", EXPFILL }},
      { &ei_mal_time_sync_port_log_announce, { "cip.malformed.time_sync.port_log_announce", PI_MALFORMED, PI_ERROR, "Malformed Port Log Announcement Interval Cfg", EXPFILL }},
      { &ei_mal_time_sync_port_log_announce_ports, { "cip.malformed.time_sync.port_log_announce.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Log Announcement Interval Cfg - too many ports", EXPFILL }},
      { &ei_mal_time_sync_port_log_sync, { "cip.malformed.time_sync.port_log_sync", PI_MALFORMED, PI_ERROR, "Malformed Port Log Sync Interval Cfg", EXPFILL }},
      { &ei_mal_time_sync_port_log_sync_ports, { "cip.malformed.time_sync.port_log_sync.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Log Sync Interval Cfg - too many ports", EXPFILL }},
      { &ei_mal_time_sync_clock_type, { "cip.malformed.time_sync.clock_type", PI_MALFORMED, PI_ERROR, "Malformed Clock Type", EXPFILL }},
      { &ei_mal_time_sync_manufacture_id, { "cip.malformed.time_sync.manufacture_id", PI_MALFORMED, PI_ERROR, "Malformed Manufacture Identity", EXPFILL }},
      { &ei_mal_time_sync_prod_desc, { "cip.malformed.time_sync.prod_desc", PI_MALFORMED, PI_ERROR, "Malformed Product Description", EXPFILL }},
      { &ei_mal_time_sync_prod_desc_64, { "cip.malformed.time_sync.prod_desc.limit_64", PI_PROTOCOL, PI_WARN, "Product Description limited to 64 characters", EXPFILL }},
      { &ei_mal_time_sync_prod_desc_size, { "cip.malformed.time_sync.prod_desc.size", PI_MALFORMED, PI_ERROR, "Malformed Product Description - invalid size", EXPFILL }},
      { &ei_mal_time_sync_revision_data, { "cip.malformed.time_sync.revision_data", PI_MALFORMED, PI_ERROR, "Malformed Revision Data", EXPFILL }},
      { &ei_mal_time_sync_revision_data_32, { "cip.malformed.time_sync.revision_data.limit_32", PI_PROTOCOL, PI_WARN, "Revision Data limited to 32 characters", EXPFILL }},
      { &ei_mal_time_sync_revision_data_size, { "cip.malformed.time_sync.revision_data.size", PI_MALFORMED, PI_ERROR, "Malformed Revision Data - invalid size", EXPFILL }},
      { &ei_mal_time_sync_user_desc, { "cip.malformed.time_sync.user_desc", PI_MALFORMED, PI_ERROR, "Malformed User Description", EXPFILL }},
      { &ei_mal_time_sync_user_desc_128, { "cip.malformed.time_sync.user_desc.limit_128", PI_PROTOCOL, PI_WARN, "User Description limited to 128 characters", EXPFILL }},
      { &ei_mal_time_sync_user_desc_size, { "cip.malformed.time_sync.user_desc.size", PI_MALFORMED, PI_ERROR, "Malformed User Description - invalid size", EXPFILL }},
      { &ei_mal_time_sync_port_profile_id_info, { "cip.malformed.time_sync.port_profile_id_info", PI_MALFORMED, PI_ERROR, "Malformed Port Profile Identity Info", EXPFILL }},
      { &ei_mal_time_sync_port_profile_id_info_ports, { "cip.malformed.time_sync.port_profile_id_info.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Profile Identity Info - too many ports", EXPFILL }},
      { &ei_mal_time_sync_port_phys_addr_info, { "cip.malformed.time_sync.port_phys_addr_info", PI_MALFORMED, PI_ERROR, "Malformed Port Physical Address Info", EXPFILL }},
      { &ei_mal_time_sync_port_phys_addr_info_ports, { "cip.malformed.time_sync.port_phys_addr_info.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Physical Address Info - too many ports", EXPFILL }},
      { &ei_mal_time_sync_port_proto_addr_info, { "cip.malformed.time_sync.port_proto_addr_info", PI_MALFORMED, PI_ERROR, "Malformed Port Protocol Address Info", EXPFILL }},
      { &ei_mal_time_sync_port_proto_addr_info_ports, { "cip.malformed.time_sync.port_proto_addr_info.ports", PI_MALFORMED, PI_ERROR, "Malformed Port Protocol Address Info - too many ports", EXPFILL }},
      { &ei_mal_time_sync_sys_time_and_offset, { "cip.malformed.time_sync.sys_time_and_offset", PI_MALFORMED, PI_ERROR, "Malformed System Time and Offset", EXPFILL }},
      { &ei_proto_log_seg_format, { "cip.unsupported.log_seg_format", PI_PROTOCOL, PI_WARN, "Unsupported Logical Segment Format", EXPFILL }},
      { &ei_mal_incomplete_epath, { "cip.malformed.incomplete_epath", PI_MALFORMED, PI_ERROR, "Incomplete EPATH", EXPFILL }},
      { &ei_proto_electronic_key_format, { "cip.unsupported.electronic_key_format", PI_PROTOCOL, PI_WARN, "Unsupported Electronic Key Format", EXPFILL }},
      { &ei_proto_special_segment_format, { "cip.unsupported.special_segment_format", PI_PROTOCOL, PI_WARN, "Unsupported Special Segment Format", EXPFILL }},
      { &ei_proto_log_seg_type, { "cip.unsupported.log_seg_type", PI_PROTOCOL, PI_WARN, "Unsupported Logical Segment Type", EXPFILL }},
      { &ei_proto_log_sub_seg_type, { "cip.unsupported.log_sub_seg_type", PI_PROTOCOL, PI_WARN, "Unsupported Sub-Segment Type", EXPFILL }},
      { &ei_proto_ext_string_format, { "cip.unsupported.ext_string_format", PI_PROTOCOL, PI_WARN, "Unsupported Extended String Format", EXPFILL } },
      { &ei_proto_ext_network, { "cip.malformed.ext_network", PI_PROTOCOL, PI_ERROR, "Malformed Extended Network Segment Format", EXPFILL } },
      { &ei_proto_seg_type, { "cip.unsupported.seg_type", PI_PROTOCOL, PI_WARN, "Unsupported Segment Type", EXPFILL }},
      { &ei_proto_unsupported_datatype, { "cip.unsupported.datatype", PI_PROTOCOL, PI_WARN, "Unsupported Datatype", EXPFILL }},
      { &ei_mal_serv_gal, { "cip.malformed.get_attribute_list", PI_MALFORMED, PI_ERROR, "Malformed Get Attribute List service", EXPFILL }},
      { &ei_mal_serv_gal_count, { "cip.malformed.get_attribute_list.count", PI_MALFORMED, PI_ERROR, "Malformed Get Attribute List attribute list count greater than packet size", EXPFILL }},
      { &ei_mal_serv_sal, { "cip.malformed.set_attribute_list", PI_MALFORMED, PI_ERROR, "Malformed Set Attribute List service", EXPFILL }},
      { &ei_mal_serv_sal_count, { "cip.malformed.set_attribute_list.count", PI_MALFORMED, PI_ERROR, "Malformed Set Attribute List attribute list count greater than packet size", EXPFILL }},
      { &ei_mal_msp_services, { "cip.malformed.msp.services", PI_MALFORMED, PI_WARN, "Multiple Service Packet too many services for packet", EXPFILL }},
      { &ei_mal_msp_inv_offset, { "cip.malformed.msp.inv_offset", PI_MALFORMED, PI_WARN, "Multiple Service Packet service invalid offset", EXPFILL }},
      { &ei_mal_msp_missing_services, { "cip.malformed.msp.missing_services", PI_MALFORMED, PI_ERROR, "Multiple Service Packet service missing Number of Services field", EXPFILL }},
      { &ei_mal_serv_find_next_object, { "cip.malformed.find_next_object", PI_MALFORMED, PI_ERROR, "Find Next Object service missing Number of List Members field", EXPFILL }},
      { &ei_mal_serv_find_next_object_count, { "cip.malformed.find_next_object.count", PI_MALFORMED, PI_ERROR, "Find Next Object instance list count greater than packet size", EXPFILL }},
      { &ei_mal_rpi_no_data, { "cip.malformed.rpi_no_data", PI_MALFORMED, PI_WARN, "RPI not acceptable - missing extended data", EXPFILL }},
      { &ei_mal_fwd_close_missing_data, { "cip.malformed.fwd_close_missing_data", PI_MALFORMED, PI_ERROR, "Forward Close response missing application reply data", EXPFILL }},
      { &ei_mal_opt_attr_list, { "cip.malformed.opt_attr_list", PI_MALFORMED, PI_ERROR, "Optional attribute list missing data", EXPFILL }},
      { &ei_mal_opt_service_list, { "cip.malformed.opt_service_list", PI_MALFORMED, PI_ERROR, "Optional service list missing data", EXPFILL }},
      { &ei_mal_padded_epath_size, { "cip.malformed.epath.size", PI_MALFORMED, PI_ERROR, "Malformed EPATH vs Size", EXPFILL } },
      { &ei_mal_missing_string_data, { "cip.malformed.missing_str_data", PI_MALFORMED, PI_ERROR, "Missing string data", EXPFILL } },

      { &ei_cip_null_fwd_open, { "cip.analysis.null_fwd_open", PI_PROTOCOL, PI_NOTE, "Null Forward Open", EXPFILL } },
      { &ei_cip_safety_open_type1, { "cip.analysis.safety_open_type1", PI_PROTOCOL, PI_NOTE, "Type 1 - Safety Open with Data", EXPFILL } },
      { &ei_cip_safety_open_type2a, { "cip.analysis.safety_open_type2a", PI_PROTOCOL, PI_NOTE, "Type 2a - Safety Open with SCID check", EXPFILL } },
      { &ei_cip_safety_open_type2b, { "cip.analysis.safety_open_type2b", PI_PROTOCOL, PI_NOTE, "Type 2b - Safety Open without SCID check", EXPFILL } },
      { &ei_cip_safety_input, { "cip.analysis.safety_input", PI_PROTOCOL, PI_NOTE, "Safety Input Connection", EXPFILL } },
      { &ei_cip_safety_output, { "cip.analysis.safety_output", PI_PROTOCOL, PI_NOTE, "Safety Output Connection", EXPFILL } },
      { &ei_cip_listen_input_connection, { "cip.analysis.listen_input_connection", PI_PROTOCOL, PI_NOTE, "[Likely] Listen Only or Input Only Connection", EXPFILL } },
      { &ei_cip_no_fwd_close, { "cip.analysis.no_fwd_close", PI_PROTOCOL, PI_NOTE, "No Forward Close seen for this CIP Connection", EXPFILL } },
   };

   module_t *cip_module;
   expert_module_t* expert_cip;

   /* Register the protocol name and description */
   proto_cip = proto_register_protocol("Common Industrial Protocol",
       "CIP", "cip");
   cip_handle = register_dissector("cip", dissect_cip, proto_cip);

   register_dissector("cip_implicit", dissect_cip_implicit, proto_cip);

   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array(proto_cip, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   expert_cip = expert_register_protocol(proto_cip);
   expert_register_field_array(expert_cip, ei, array_length(ei));

   cip_module = prefs_register_protocol(proto_cip, NULL);
   prefs_register_bool_preference(cip_module, "enhanced_info_column",
      "Display enhanced Info column data",
      "Whether the CIP dissector should display enhanced/verbose data in the Info column for CIP explicit messages",
      &cip_enhanced_info_column);

   subdissector_class_table = register_dissector_table("cip.class.iface",
      "CIP Class Interface Handle", proto_cip, FT_UINT32, BASE_HEX);
   subdissector_symbol_table = register_dissector_table("cip.data_segment.iface",
      "CIP Data Segment Interface Handle", proto_cip, FT_UINT32, BASE_HEX);

   /* Register the protocol name and description */
   proto_cip_class_generic = proto_register_protocol("CIP Class Generic",
       "CIPCLS", "cipcls");
   cip_class_generic_handle = register_dissector("cipcls",
       dissect_cip_class_generic, proto_cip_class_generic);

   /* Register the protocol name and description */
   proto_cip_class_cm = proto_register_protocol("CIP Connection Manager",
       "CIPCM", "cipcm");
   cip_class_cm_handle = register_dissector("cipcm",
       dissect_cip_class_cm, proto_cip_class_cm);
   proto_register_field_array(proto_cip_class_cm, hf_cm, array_length(hf_cm));
   proto_register_subtree_array(ett_cm, array_length(ett_cm));

   proto_cip_class_pccc = proto_register_protocol("CIP PCCC Object",
       "CIPPCCC", "cippccc");
   cip_class_pccc_handle = register_dissector("cippccc",
       dissect_cip_class_pccc, proto_cip_class_pccc);
   proto_register_field_array(proto_cip_class_pccc, hf_pccc, array_length(hf_pccc));
   proto_register_subtree_array(ett_pccc, array_length(ett_pccc));

   proto_cip_class_mb = proto_register_protocol("CIP Modbus Object",
       "CIPMB", "cipmb");
   cip_class_mb_handle = register_dissector("cipmb",
       dissect_cip_class_mb, proto_cip_class_mb);
   proto_register_field_array(proto_cip_class_mb, hf_mb, array_length(hf_mb));
   proto_register_subtree_array(ett_mb, array_length(ett_mb));

   proto_cip_class_cco = proto_register_protocol("CIP Connection Configuration Object",
       "CIPCCO", "cipcco");
   cip_class_cco_handle = register_dissector("cipcco",
       dissect_cip_class_cco, proto_cip_class_cco);
   proto_register_field_array(proto_cip_class_cco, hf_cco, array_length(hf_cco));
   proto_register_subtree_array(ett_cco, array_length(ett_cco));

   /* Register a heuristic dissector on the service of the message so objects
    * can override the dissector for common services */
   heur_subdissector_service = register_heur_dissector_list_with_description("cip.sc", "CIP Service data", proto_cip);

   build_get_attr_all_table();
} /* end of proto_register_cip() */

void
proto_reg_handoff_cip(void)
{
   /* Register for UCMM CIP data, using EtherNet/IP SendRRData service*/
   dissector_add_uint( "enip.srrd.iface", ENIP_CIP_INTERFACE, cip_handle );

   dissector_add_uint("cip.connection.class", CI_CLS_MR, cip_handle);

   /* Register dissector handle for generic class */
   dissector_add_uint( "cip.class.iface", 0, cip_class_generic_handle );

   /* Register dissector handle for Connection Manager */
   dissector_add_uint( "cip.class.iface", CI_CLS_CM, cip_class_cm_handle );

   /* Register dissector handle for the PCCC class */
   dissector_add_uint( "cip.class.iface", CI_CLS_PCCC, cip_class_pccc_handle );

   /* Register dissector handle for Modbus Object */
   dissector_add_uint( "cip.class.iface", CI_CLS_MB, cip_class_mb_handle );
   modbus_handle = find_dissector_add_dependency("modbus", proto_cip_class_mb);

   /* Register dissector handle for Connection Configuration Object */
   dissector_add_uint( "cip.class.iface", CI_CLS_CCO, cip_class_cco_handle );
   heur_dissector_add("cip.sc", dissect_class_cco_heur, "CIP Connection Configuration Object", "cco_cip", proto_cip_class_cco, HEURISTIC_ENABLE);

   proto_enip = proto_get_id_by_filter_name( "enip" );
   proto_modbus = proto_get_id_by_filter_name( "modbus" );

} /* end of proto_reg_handoff_cip() */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
