/* packet-cip.c
 * Routines for Common Industrial Protocol (CIP) dissection
 * CIP Home: www.odva.org
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-cip.h"
#include "packet-enip.h"
#include "packet-mbtcp.h"

#define  ENIP_CIP_INTERFACE   0

typedef struct mr_mult_req_info {
   guint8 service;
   int num_services;
   cip_req_info_t *requests;
} mr_mult_req_info_t;

static dissector_handle_t cip_handle;
static dissector_handle_t cip_class_generic_handle;
static dissector_handle_t cip_class_cm_handle;
static dissector_handle_t cip_class_mb_handle;
static dissector_handle_t modbus_handle;
static dissector_handle_t cip_class_cco_handle;
static heur_dissector_list_t  heur_subdissector_service;

/* Initialize the protocol and registered fields */
static int proto_cip               = -1;
static int proto_cip_class_generic = -1;
static int proto_cip_class_cm      = -1;
static int proto_cip_class_mb      = -1;
static int proto_cip_class_cco     = -1;
static int proto_enip              = -1;
static int proto_modbus            = -1;

static int hf_cip_data              = -1;
static int hf_cip_service           = -1;
static int hf_cip_service_code      = -1;
static int hf_cip_reqrsp            = -1;
static int hf_cip_epath             = -1;
static int hf_cip_genstat           = -1;
static int hf_cip_addstat_size      = -1;
static int hf_cip_add_stat          = -1;
static int hf_cip_request_path_size = -1;

static int hf_cip_cm_sc                   = -1;
static int hf_cip_cm_genstat              = -1;
static int hf_cip_cm_addstat_size         = -1;
static int hf_cip_cm_add_status           = -1;
static int hf_cip_cm_ext_status           = -1;
static int hf_cip_cm_priority             = -1;
static int hf_cip_cm_tick_time            = -1;
static int hf_cip_cm_timeout_tick         = -1;
static int hf_cip_cm_timeout              = -1;
static int hf_cip_cm_ot_connid            = -1;
static int hf_cip_cm_to_connid            = -1;
static int hf_cip_cm_conn_serial_num      = -1;
static int hf_cip_cm_orig_serial_num      = -1;
static int hf_cip_cm_vendor               = -1;
static int hf_cip_cm_timeout_multiplier   = -1;
static int hf_cip_cm_ot_rpi               = -1;
static int hf_cip_cm_ot_net_params32      = -1;
static int hf_cip_cm_ot_net_params16      = -1;
static int hf_cip_cm_to_rpi               = -1;
static int hf_cip_cm_to_net_params32      = -1;
static int hf_cip_cm_to_net_params16      = -1;
static int hf_cip_cm_transport_type_trigger   = -1;
static int hf_cip_cm_conn_path_size       = -1;
static int hf_cip_cm_ot_api               = -1;
static int hf_cip_cm_to_api               = -1;
static int hf_cip_cm_app_reply_size       = -1;
static int hf_cip_cm_app_reply_data       = -1;
static int hf_cip_cm_remain_path_size     = -1;
static int hf_cip_cm_msg_req_size         = -1;
static int hf_cip_cm_route_path_size      = -1;
static int hf_cip_cm_fwo_con_size         = -1;
static int hf_cip_cm_lfwo_con_size        = -1;
static int hf_cip_cm_fwo_fixed_var        = -1;
static int hf_cip_cm_lfwo_fixed_var       = -1;
static int hf_cip_cm_fwo_prio             = -1;
static int hf_cip_cm_lfwo_prio            = -1;
static int hf_cip_cm_fwo_typ              = -1;
static int hf_cip_cm_lfwo_typ             = -1;
static int hf_cip_cm_fwo_own              = -1;
static int hf_cip_cm_lfwo_own             = -1;
static int hf_cip_cm_fwo_dir              = -1;
static int hf_cip_cm_fwo_trigg            = -1;
static int hf_cip_cm_fwo_class            = -1;
static int hf_cip_cm_gco_conn             = -1;
static int hf_cip_cm_gco_coo_conn         = -1;
static int hf_cip_cm_gco_roo_conn         = -1;
static int hf_cip_cm_gco_last_action      = -1;
static int hf_cip_cm_ext112_ot_rpi_type   = -1;
static int hf_cip_cm_ext112_to_rpi_type   = -1;
static int hf_cip_cm_ext112_ot_rpi        = -1;
static int hf_cip_cm_ext112_to_rpi        = -1;
static int hf_cip_cm_ext126_size          = -1;
static int hf_cip_cm_ext127_size          = -1;
static int hf_cip_cm_ext128_size          = -1;

static int hf_cip_mb_sc                                   = -1;
static int hf_cip_mb_read_coils_start_addr                = -1;
static int hf_cip_mb_read_coils_num_coils                 = -1;
static int hf_cip_mb_read_coils_data                      = -1;
static int hf_cip_mb_read_discrete_inputs_start_addr      = -1;
static int hf_cip_mb_read_discrete_inputs_num_inputs      = -1;
static int hf_cip_mb_read_discrete_inputs_data            = -1;
static int hf_cip_mb_read_holding_register_start_addr     = -1;
static int hf_cip_mb_read_holding_register_num_registers  = -1;
static int hf_cip_mb_read_holding_register_data           = -1; 
static int hf_cip_mb_read_input_register_start_addr       = -1;
static int hf_cip_mb_read_input_register_num_registers    = -1;
static int hf_cip_mb_read_input_register_data             = -1;
static int hf_cip_mb_write_coils_start_addr               = -1;
static int hf_cip_mb_write_coils_outputs_forced           = -1;
static int hf_cip_mb_write_coils_num_coils                = -1;
static int hf_cip_mb_write_coils_data                     = -1;
static int hf_cip_mb_write_registers_start_addr           = -1;
static int hf_cip_mb_write_registers_outputs_forced       = -1;
static int hf_cip_mb_write_registers_num_registers        = -1;
static int hf_cip_mb_write_registers_data                 = -1;
static int hf_cip_mb_data                                 = -1;

static int hf_cip_cco_con_type            = -1;
static int hf_cip_cco_ot_rtf              = -1;
static int hf_cip_cco_to_rtf              = -1;
static int hf_cip_cco_sc                  = -1;
static int hf_cip_cco_format_number       = -1;
static int hf_cip_cco_edit_signature      = -1;
static int hf_cip_cco_con_flags           = -1;
static int hf_cip_cco_tdi_vendor          = -1;
static int hf_cip_cco_tdi_devtype         = -1;
static int hf_cip_cco_tdi_prodcode        = -1;
static int hf_cip_cco_tdi_compatibility   = -1;
static int hf_cip_cco_tdi_comp_bit        = -1;
static int hf_cip_cco_tdi_majorrev        = -1;
static int hf_cip_cco_tdi_minorrev        = -1;
static int hf_cip_cco_pdi_vendor          = -1;
static int hf_cip_cco_pdi_devtype         = -1;
static int hf_cip_cco_pdi_prodcode        = -1;
static int hf_cip_cco_pdi_compatibility   = -1;
static int hf_cip_cco_pdi_comp_bit        = -1;
static int hf_cip_cco_pdi_majorrev        = -1;
static int hf_cip_cco_pdi_minorrev        = -1;
static int hf_cip_cco_cs_data_index       = -1;
static int hf_cip_cco_ot_rpi              = -1;
static int hf_cip_cco_to_rpi              = -1;
static int hf_cip_cco_ot_net_param16      = -1;
static int hf_cip_cco_to_net_param16      = -1;
static int hf_cip_cco_fwo_own             = -1;
static int hf_cip_cco_fwo_typ             = -1;
static int hf_cip_cco_fwo_prio            = -1;
static int hf_cip_cco_fwo_fixed_var       = -1;
static int hf_cip_cco_fwo_con_size        = -1;
static int hf_cip_cco_ot_net_param32      = -1;
static int hf_cip_cco_to_net_param32      = -1;
static int hf_cip_cco_lfwo_own            = -1;
static int hf_cip_cco_lfwo_typ            = -1;
static int hf_cip_cco_lfwo_prio           = -1;
static int hf_cip_cco_lfwo_fixed_var      = -1;
static int hf_cip_cco_lfwo_con_size       = -1;
static int hf_cip_cco_conn_path_size      = -1;
static int hf_cip_cco_proxy_config_size   = -1;
static int hf_cip_cco_target_config_size  = -1;
static int hf_cip_cco_iomap_format_number = -1;
static int hf_cip_cco_iomap_size          = -1;
static int hf_cip_cco_connection_disable  = -1;
static int hf_cip_cco_net_conn_param_attr = -1;
static int hf_cip_cco_timeout_multiplier  = -1;
static int hf_cip_cco_transport_type_trigger = -1;
static int hf_cip_cco_fwo_dir             = -1;
static int hf_cip_cco_fwo_trigger         = -1;
static int hf_cip_cco_fwo_class           = -1;
static int hf_cip_cco_proxy_config_data   = -1;
static int hf_cip_cco_target_config_data  = -1;
static int hf_cip_cco_iomap_attribute     = -1;
static int hf_cip_cco_safety              = -1;
static int hf_cip_cco_change_type         = -1;

static int hf_cip_vendor              = -1;
static int hf_cip_devtype             = -1;
static int hf_cip_path_segment        = -1;
static int hf_cip_path_segment_type   = -1;
static int hf_cip_port_segment        = -1;
static int hf_cip_port_ex_link_addr   = -1;
static int hf_cip_port                = -1;
static int hf_cip_link_address_size   = -1;
static int hf_cip_link_address_byte   = -1;
static int hf_cip_link_address_string = -1;
static int hf_cip_logical_seg_type    = -1;
static int hf_cip_logical_seg_format  = -1;
static int hf_cip_class8              = -1;
static int hf_cip_class16             = -1;
static int hf_cip_class32             = -1;
static int hf_cip_instance8           = -1;
static int hf_cip_instance16          = -1;
static int hf_cip_instance32          = -1;
static int hf_cip_member8             = -1;
static int hf_cip_member16            = -1;
static int hf_cip_member32            = -1;
static int hf_cip_attribute8          = -1;
static int hf_cip_attribute16         = -1;
static int hf_cip_attribute32         = -1;
static int hf_cip_conpoint8           = -1;
static int hf_cip_conpoint16          = -1;
static int hf_cip_conpoint32          = -1;
static int hf_cip_ekey                = -1;
static int hf_cip_ekey_format         = -1;
static int hf_cip_ekey_vendor         = -1;
static int hf_cip_ekey_devtype        = -1;
static int hf_cip_ekey_prodcode       = -1;
static int hf_cip_ekey_compatibility  = -1;
static int hf_cip_ekey_comp_bit       = -1;
static int hf_cip_ekey_majorrev       = -1;
static int hf_cip_ekey_minorrev       = -1;
static int hf_cip_data_seg_type       = -1;
static int hf_cip_data_seg_size       = -1;
static int hf_cip_data_seg_item       = -1;
static int hf_cip_symbol              = -1;
static int hf_cip_network_seg_type    = -1;
static int hf_cip_seg_schedule        = -1;
static int hf_cip_seg_fixed_tag       = -1;
static int hf_cip_seg_prod_inhibit_time   = -1;
static int hf_cip_class_rev           = -1;
static int hf_cip_class_max_inst32    = -1;
static int hf_cip_class_num_inst32    = -1;
static int hf_cip_reserved8           = -1;
static int hf_cip_reserved16          = -1;
static int hf_cip_reserved24          = -1;
static int hf_cip_pad8                = -1;

static int hf_cip_sc_get_attr_list_attr_count      = -1;
static int hf_cip_sc_get_attr_list_attr_item       = -1;
static int hf_cip_sc_get_attr_list_attr_status     = -1;
static int hf_cip_sc_get_attr_list_attr_data       = -1;
static int hf_cip_sc_set_attr_list_attr_count      = -1;
static int hf_cip_sc_set_attr_list_attr_item       = -1;
static int hf_cip_sc_set_attr_list_attr_status     = -1;
static int hf_cip_sc_set_attr_list_attr_data       = -1;
static int hf_cip_sc_reset_param                   = -1;
static int hf_cip_sc_get_attribute_all_data        = -1;
static int hf_cip_sc_set_attribute_all_data        = -1;
static int hf_cip_sc_reset_data                    = -1;
static int hf_cip_sc_start_data                    = -1;
static int hf_cip_sc_stop_data                     = -1;
static int hf_cip_sc_create_instance               = -1;
static int hf_cip_sc_create_data                   = -1;
static int hf_cip_sc_delete_data                   = -1;
static int hf_cip_sc_mult_serv_pack_num_services   = -1;
static int hf_cip_sc_mult_serv_pack_offset         = -1;
static int hf_cip_sc_mult_serv_pack_num_replies    = -1;
static int hf_cip_sc_apply_attributes_data         = -1;
static int hf_cip_sc_set_attr_single_data          = -1;
static int hf_cip_sc_get_attr_single_data          = -1;
static int hf_cip_find_next_object_max_instance    = -1;
static int hf_cip_find_next_object_num_instances   = -1;
static int hf_cip_find_next_object_instance_item   = -1;
static int hf_cip_sc_restore_data                  = -1;
static int hf_cip_sc_save_data                     = -1;
static int hf_cip_sc_noop_data                     = -1;
static int hf_cip_sc_get_member_data               = -1;
static int hf_cip_sc_set_member_data               = -1;
static int hf_cip_sc_insert_member_data            = -1;
static int hf_cip_sc_remove_member_data            = -1;
static int hf_cip_sc_group_sync_is_sync            = -1;
static int hf_cip_sc_group_sync_data               = -1;

/* Parsed Attributes */
static int hf_id_vendor_id                         = -1;
static int hf_id_device_type                       = -1;
static int hf_id_produce_code                      = -1;
static int hf_id_major_rev                         = -1;
static int hf_id_minor_rev                         = -1;
static int hf_id_status                            = -1;
static int hf_id_serial_number                     = -1;
static int hf_id_product_name                      = -1;
static int hf_msg_rout_num_classes                 = -1;
static int hf_msg_rout_classes                     = -1;
static int hf_msg_rout_num_available               = -1;
static int hf_msg_rout_num_active                  = -1;
static int hf_msg_rout_active_connections          = -1;
static int hf_conn_mgr_open_requests               = -1;
static int hf_conn_mgr_open_format_rejects         = -1;
static int hf_conn_mgr_open_resource_rejects       = -1;
static int hf_conn_mgr_other_open_rejects          = -1;
static int hf_conn_mgr_close_requests              = -1;
static int hf_conn_close_format_requests           = -1;
static int hf_conn_mgr_close_other_requests        = -1;
static int hf_conn_mgr_conn_timouts                = -1;

/* Initialize the subtree pointers */
static gint ett_cip               = -1;
static gint ett_cip_class_generic = -1;
static gint ett_cip_class_cm      = -1;
static gint ett_cip_class_mb      = -1;
static gint ett_cip_class_cco     = -1;

static gint ett_path          = -1;
static gint ett_path_seg      = -1;
static gint ett_ekey_path     = -1;
static gint ett_mcsc          = -1;
static gint ett_cia_path      = -1;
static gint ett_data_seg      = -1;
static gint ett_data_seg_data = -1;
static gint ett_port_path     = -1;
static gint ett_network_seg   = -1;

static gint ett_rrsc          = -1;
static gint ett_status_item   = -1;
static gint ett_add_status_item = -1;
static gint ett_cmd_data      = -1;

static gint ett_cip_get_attribute_list      = -1;
static gint ett_cip_get_attribute_list_item = -1;
static gint ett_cip_set_attribute_list      = -1;
static gint ett_cip_set_attribute_list_item = -1;
static gint ett_cip_mult_service_packet     = -1;

static gint ett_cm_rrsc     = -1;
static gint ett_cm_ncp      = -1;
static gint ett_cm_mes_req  = -1;
static gint ett_cm_cmd_data = -1;
static gint ett_cm_ttt      = -1;
static gint ett_cm_add_status_item = -1;

static gint ett_mb_rrsc     = -1;
static gint ett_mb_cmd_data = -1;

static gint ett_cco_iomap    = -1;
static gint ett_cco_con_status = -1;
static gint ett_cco_con_flag = -1;
static gint ett_cco_tdi      = -1;
static gint ett_cco_pdi      = -1;
static gint ett_cco_ncp      = -1;
static gint ett_cco_rrsc     = -1;
static gint ett_cco_cmd_data = -1;
static gint ett_cco_ttt      = -1;

dissector_table_t   subdissector_class_table;
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
   { SC_CM_GET_CONN_OWNER,       "Get Connection Owner" },

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
const value_string cip_sc_rr[3] = {
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

const value_string cip_reset_type_vals[4] = {
   { 0,        "Cycle Power" },
   { 1,        "Factory Default" },
   { 2,        "Keep Communication Parameters" },

   { 0,        NULL          }
};

/* Translate function to string - Connection priority */
static const value_string cip_con_prio_vals[] = {
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
   { 0,        "Exclusive" },
   { 1,        "Redundant" },

   { 0,        NULL        }
};

/* Translate function to string - Connection direction */
static const value_string cip_con_dir_vals[] = {
   { 0,        "Client" },
   { 1,        "Server" },

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
static const value_string cip_con_type_vals[] = {
   { CONN_TYPE_NULL,        "Null"           },
   { CONN_TYPE_MULTICAST,   "Multicast"      },
   { CONN_TYPE_P2P,         "Point to Point" },
   { CONN_TYPE_RESERVED,    "Reserved"       },

   { 0,        NULL             }
};

/* Translate function to string - Timeout Multiplier */
static const value_string cip_con_time_mult_vals[] = {
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
   { ((CI_LOGICAL_SEG_RES_1>>2)&7),         "Reserved" },

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

   {CI_LOGICAL_SEG_SPECIAL, "Electronic Key Segment"},

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
   {CI_NETWORK_SEG_PROD_INHI,    "Production Inhibit Time"},
   {CI_NETWORK_SEG_SAFETY,       "Safety Segment"},
   {CI_NETWORK_SEG_EXTENDED,     "Extended Network Segment"},

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
#define CM_ES_NO_TARGET_APP_DATA_AVAILABLE            0x810
#define CM_ES_NO_ORIG_APP_DATA_AVAILABLE              0x811
#define CM_ES_NODE_ADDRESS_CHANGED_AFTER_SCHEDULED    0x812
#define CM_ES_NOT_CONFIGURED_MULTICAST                0x813
#define CM_ES_INVALID_PROD_CONS_DATA_FORMAT           0x814

/* Translate function to string - CIP General Status codes */
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
   { CM_ES_NOT_CONFIGURED_TO_SEND_SCHEDULED_DATA,  "Not confgured to send scheduled priority data" },
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
   { CM_ES_NO_TARGET_APP_DATA_AVAILABLE,           "No target application data available" },
   { CM_ES_NO_ORIG_APP_DATA_AVAILABLE,             "No originator application data available" },
   { CM_ES_NODE_ADDRESS_CHANGED_AFTER_SCHEDULED,   "Node address has changed since the network was scheduled" },
   { CM_ES_NOT_CONFIGURED_MULTICAST,               "Not configured for off-subnet multicast" },
   { CM_ES_INVALID_PROD_CONS_DATA_FORMAT,          "Invalid produce/consume data format" },

   { 0,                          NULL }
};

value_string_ext cip_cm_ext_st_vals_ext = VALUE_STRING_EXT_INIT(cip_cm_ext_st_vals);

/* Translate Vendor IDs */
static const value_string cip_vendor_vals[] = {
   {    0,   "Reserved" },
   {    1,   "Rockwell Automation/Allen-Bradley" },
   {    2,   "Namco Controls Corp." },
   {    3,   "Honeywell Inc." },
   {    4,   "Parker Hannifin Corp. (Veriflo Division)" },
   {    5,   "Rockwell Automation/Reliance Elec." },
   {    6,   "Reserved" },
   {    7,   "SMC Corporation" },
   {    8,   "Molex Incorporated" },
   {    9,   "Western Reserve Controls Corp." },
   {   10,   "Advanced Micro Controls Inc. (AMCI)" },
   {   11,   "ASCO Pneumatic Controls" },
   {   12,   "Banner Engineering Corp." },
   {   13,   "Belden Wire & Cable Company" },
   {   14,   "Cooper Interconnect" },
   {   15,   "Reserved" },
   {   16,   "Daniel Woodhead Co. (Woodhead Connectivity)" },
   {   17,   "Dearborn Group Inc." },
   {   18,   "Reserved" },
   {   19,   "Helm Instrument Company" },
   {   20,   "Huron Net Works" },
   {   21,   "Lumberg, Inc." },
   {   22,   "Online Development Inc.(Automation Value)" },
   {   23,   "Vorne Industries, Inc." },
   {   24,   "ODVA Special Reserve" },
   {   25,   "Reserved" },
   {   26,   "Festo Corporation" },
   {   27,   "Reserved" },
   {   28,   "Reserved" },
   {   29,   "Reserved" },
   {   30,   "Unico, Inc." },
   {   31,   "Ross Controls" },
   {   32,   "Reserved" },
   {   33,   "Reserved" },
   {   34,   "Hohner Corp." },
   {   35,   "Micro Mo Electronics, Inc." },
   {   36,   "MKS Instruments, Inc." },
   {   37,   "Yaskawa Electric America formerly Magnetek Drives" },
   {   38,   "Reserved" },
   {   39,   "AVG Automation (Uticor)" },
   {   40,   "Wago Corporation" },
   {   41,   "Kinetics (Unit Instruments)" },
   {   42,   "IMI Norgren Limited" },
   {   43,   "BALLUFF, Inc." },
   {   44,   "Yaskawa Electric America, Inc." },
   {   45,   "Eurotherm Controls Inc" },
   {   46,   "ABB Industrial Systems" },
   {   47,   "Omron Corporation" },
   {   48,   "TURCk, Inc." },
   {   49,   "Grayhill Inc." },
   {   50,   "Real Time Automation (C&ID)" },
   {   51,   "Reserved" },
   {   52,   "Numatics, Inc." },
   {   53,   "Lutze, Inc." },
   {   54,   "Reserved" },
   {   55,   "Reserved" },
   {   56,   "Softing GmbH" },
   {   57,   "Pepperl + Fuchs" },
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
   {   71,   "Toshiba International Corp." },
   {   72,   "Control Technology Incorporated" },
   {   73,   "TCS (NZ) Ltd." },
   {   74,   "Hitachi, Ltd." },
   {   75,   "ABB Robotics Products AB" },
   {   76,   "NKE Corporation" },
   {   77,   "Rockwell Software, Inc." },
   {   78,   "Escort Memory Systems (A Datalogic Group Co.)" },
   {   79,   "Reserved" },
   {   80,   "Industrial Devices Corporation" },
   {   81,   "IXXAT Automation GmbH" },
   {   82,   "Mitsubishi Electric Automation, Inc." },
   {   83,   "OPTO-22" },
   {   84,   "Reserved" },
   {   85,   "Reserved" },
   {   86,   "Horner Electric" },
   {   87,   "Burkert Werke GmbH & Co. KG" },
   {   88,   "Reserved" },
   {   89,   "Industrial Indexing Systems, Inc." },
   {   90,   "HMS Industrial Networks AB" },
   {   91,   "Robicon" },
   {   92,   "Helix Technology (Granville-Phillips)" },
   {   93,   "Arlington Laboratory" },
   {   94,   "Advantech Co. Ltd." },
   {   95,   "Square D Company" },
   {   96,   "Digital Electronics Corp." },
   {   97,   "Danfoss" },
   {   98,   "Reserved" },
   {   99,   "Reserved" },
   {  100,   "Bosch Rexroth Corporation, Pneumatics" },
   {  101,   "Applied Materials, Inc." },
   {  102,   "Showa Electric Wire & Cable Co." },
   {  103,   "Pacific Scientific (API Controls Inc.)" },
   {  104,   "Sharp Manufacturing Systems Corp." },
   {  105,   "Olflex Wire & Cable, Inc." },
   {  106,   "Reserved" },
   {  107,   "Unitrode" },
   {  108,   "Beckhoff Automation GmbH" },
   {  109,   "National Instruments" },
   {  110,   "Mykrolis Corporations (Millipore)" },
   {  111,   "International Motion Controls Corp." },
   {  112,   "Reserved" },
   {  113,   "SEG Kempen GmbH" },
   {  114,   "Reserved" },
   {  115,   "Reserved" },
   {  116,   "MTS Systems Corp." },
   {  117,   "Krones, Inc" },
   {  118,   "Reserved" },
   {  119,   "EXOR Electronic R & D" },
   {  120,   "SIEI S.p.A." },
   {  121,   "KUKA Roboter GmbH" },
   {  122,   "Reserved" },
   {  123,   "SEC (Samsung Electronics Co., Ltd)" },
   {  124,   "Binary Electronics Ltd" },
   {  125,   "Flexible Machine Controls" },
   {  126,   "Reserved" },
   {  127,   "ABB Inc. (Entrelec)" },
   {  128,   "MAC Valves, Inc." },
   {  129,   "Auma Actuators Inc" },
   {  130,   "Toyoda Machine Works, Ltd" },
   {  131,   "Reserved" },
   {  132,   "Reserved" },
   {  133,   "Balogh T.A.G., Corporation" },
   {  134,   "TR Systemtechnik GmbH" },
   {  135,   "UNIPULSE Corporation" },
   {  136,   "Reserved" },
   {  137,   "Reserved" },
   {  138,   "Conxall Corporation Inc." },
   {  139,   "Reserved" },
   {  140,   "Reserved" },
   {  141,   "Kuramo Electric Co., Ltd." },
   {  142,   "Creative Micro Designs" },
   {  143,   "GE Industrial Systems" },
   {  144,   "Leybold Vacuum GmbH" },
   {  145,   "Siemens Energy & Automation/Drives" },
   {  146,   "Kodensha Ltd" },
   {  147,   "Motion Engineering, Inc." },
   {  148,   "Honda Engineering Co., Ltd" },
   {  149,   "EIM Valve Controls" },
   {  150,   "Melec Inc." },
   {  151,   "Sony Manufacturing Systems Corporation" },
   {  152,   "North American Mfg." },
   {  153,   "WATLOW" },
   {  154,   "Japan Radio Co., Ltd" },
   {  155,   "NADEX Co., Ltd" },
   {  156,   "Ametek Automation & Process Technologies" },
   {  157,   "Reserved" },
   {  158,   "KVASER AB" },
   {  159,   "IDEC IZUMI Corporation" },
   {  160,   "Mitsubishi Heavy Industries Ltd" },
   {  161,   "Mitsubishi Electric Corporation" },
   {  162,   "Horiba-STEC Inc." },
   {  163,   "esd electronic system design gmbh" },
   {  164,   "DAIHEN Corporation" },
   {  165,   "Tyco Valves & Controls/Keystone" },
   {  166,   "EBARA Corporation" },
   {  167,   "Reserved" },
   {  168,   "Reserved" },
   {  169,   "Hokuyo Electric Co. Ltd" },
   {  170,   "Pyramid Solutions, Inc." },
   {  171,   "Denso Wave Incorporated" },
   {  172,   "HLS Hard-Line Solutions Inc" },
   {  173,   "Caterpillar, Inc." },
   {  174,   "PDL Electronics Ltd." },
   {  175,   "Reserved" },
   {  176,   "Red Lion Controls" },
   {  177,   "ANELVA Corporation" },
   {  178,   "Toyo Denki Seizo KK" },
   {  179,   "Sanyo Denki Co., Ltd" },
   {  180,   "Advanced Energy Japan K.K. (Aera Japan)" },
   {  181,   "Pilz GmbH & Co" },
   {  182,   "Marsh Bellofram-Bellofram PCD Division" },
   {  183,   "Reserved" },
   {  184,   "M-SYSTEM Co. Ltd" },
   {  185,   "Nissin Electric Co., Ltd" },
   {  186,   "Hitachi Metals Ltd." },
   {  187,   "Oriental Motor Company" },
   {  188,   "A&D Co., Ltd" },
   {  189,   "Phasetronics, Inc." },
   {  190,   "Cummins Engine Company" },
   {  191,   "Deltron Inc." },
   {  192,   "Geneer Corporation" },
   {  193,   "Anatol Automation, Inc." },
   {  194,   "Reserved" },
   {  195,   "Reserved" },
   {  196,   "Medar, Inc." },
   {  197,   "Comdel Inc." },
   {  198,   "Advanced Energy Industries, Inc" },
   {  199,   "Reserved" },
   {  200,   "DAIDEN Co., Ltd" },
   {  201,   "CKD Corporation" },
   {  202,   "Toyo Electric Corporation" },
   {  203,   "Reserved" },
   {  204,   "AuCom Electronics Ltd" },
   {  205,   "Shinko Electric Co., Ltd" },
   {  206,   "Vector Informatik GmbH" },
   {  207,   "Reserved" },
   {  208,   "Moog Inc." },
   {  209,   "Contemporary Controls" },
   {  210,   "Tokyo Sokki Kenkyujo Co., Ltd" },
   {  211,   "Schenck-AccuRate, Inc." },
   {  212,   "The Oilgear Company" },
   {  213,   "Reserved" },
   {  214,   "ASM Japan K.K." },
   {  215,   "HIRATA Corp." },
   {  216,   "SUNX Limited" },
   {  217,   "Meidensha Corp." },
   {  218,   "NIDEC SANKYO CORPORATION (Sankyo Seiki Mfg. Co., Ltd)" },
   {  219,   "KAMRO Corp." },
   {  220,   "Nippon System Development Co., Ltd" },
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
   {  243,   "Schneider Automation, Inc." },
   {  244,   "Westlock Controls Corp." },
   {  245,   "Nihon Weidmuller Co., Ltd" },
   {  246,   "Brooks Instrument (Div. of Emerson)" },
   {  247,   "Reserved" },
   {  248,   " Moeller GmbH" },
   {  249,   "Varian Vacuum Products" },
   {  250,   "Yokogawa Electric Corporation" },
   {  251,   "Electrical Design Daiyu Co., Ltd" },
   {  252,   "Omron Software Co., Ltd" },
   {  253,   "BOC Edwards" },
   {  254,   "Control Technology Corporation" },
   {  255,   "Bosch Rexroth" },
   {  256,   "Turck" },
   {  257,   "Control Techniques PLC" },
   {  258,   "Hardy Instruments, Inc." },
   {  259,   "LS Industrial Systems" },
   {  260,   "E.O.A. Systems Inc." },
   {  261,   "Reserved" },
   {  262,   "New Cosmos Electric Co., Ltd." },
   {  263,   "Sense Eletronica LTDA" },
   {  264,   "Xycom, Inc." },
   {  265,   "Baldor Electric" },
   {  266,   "Reserved" },
   {  267,   "Patlite Corporation" },
   {  268,   "Reserved" },
   {  269,   "Mogami Wire & Cable Corporation" },
   {  270,   "Welding Technology Corporation (WTC)" },
   {  271,   "Reserved" },
   {  272,   "Deutschmann Automation GmbH" },
   {  273,   "ICP Panel-Tec Inc." },
   {  274,   "Bray Controls USA" },
   {  275,   "Reserved" },
   {  276,   "Status Technologies" },
   {  277,   "Trio Motion Technology Ltd" },
   {  278,   "Sherrex Systems Ltd" },
   {  279,   "Adept Technology, Inc." },
   {  280,   "Spang Power Electronics" },
   {  281,   "Reserved" },
   {  282,   "Acrosser Technology Co., Ltd" },
   {  283,   "Hilscher GmbH" },
   {  284,   "IMAX Corporation" },
   {  285,   "Electronic Innovation, Inc. (Falter Engineering)" },
   {  286,   "Netlogic Inc." },
   {  287,   "Bosch Rexroth Corporation, Indramat" },
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
   {  309,   "Prosoft Technology" },
   {  310,   "Reserved" },
   {  311,   "Towa Shoko Co., Ltd" },
   {  312,   "Kyopal Co., Ltd" },
   {  313,   "Extron Co." },
   {  314,   "Wieland Electric GmbH" },
   {  315,   "SEW Eurodrive GmbH" },
   {  316,   "Aera Corporation" },
   {  317,   "STA Reutlingen" },
   {  318,   "Reserved" },
   {  319,   "Fuji Electric Co., Ltd." },
   {  320,   "Reserved" },
   {  321,   "Reserved" },
   {  322,   "ifm efector, inc." },
   {  323,   "Reserved" },
   {  324,   "IDEACOD-Hohner Automation S.A." },
   {  325,   "CommScope Inc." },
   {  326,   "GE Fanuc Automation North America, Inc." },
   {  327,   "Matsushita Electric Industrial Co., Ltd" },
   {  328,   "Okaya Electronics Corporation" },
   {  329,   "KASHIYAMA Industries, Ltd" },
   {  330,   "JVC" },
   {  331,   "Interface Corporation" },
   {  332,   "Grape Systems Inc." },
   {  333,   "Reserved" },
   {  344,   "Reserved" },
   {  335,   "Toshiba IT & Control Systems Corporation" },
   {  336,   "Sanyo Machine Works, Ltd." },
   {  337,   "Vansco Electronics Ltd." },
   {  338,   "Dart Container Corp." },
   {  339,   "Livingston & Co., Inc." },
   {  340,   "Alfa Laval LKM as" },
   {  341,   "BF ENTRON Ltd. (British Federal)" },
   {  342,   "Bekaert Engineering NV" },
   {  343,   "Ferran  Scientific Inc." },
   {  344,   "KEBA AG" },
   {  345,   "Endress + Hauser" },
   {  346,   "Reserved" },
   {  347,   "ABB ALSTOM Power UK Ltd. (EGT)" },
   {  348,   "Berger Lahr GmbH" },
   {  349,   "Reserved" },
   {  350,   "Federal Signal Corp." },
   {  351,   "Kawasaki Robotics (USA), Inc." },
   {  352,   "Bently Nevada Corporation" },
   {  353,   "Reserved" },
   {  354,   "FRABA Posital GmbH" },
   {  355,   "Elsag Bailey, Inc." },
   {  356,   "Fanuc Robotics America" },
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
   {  398,   "Reserved" },
   {  399,   "Reserved" },
   {  400,   "LINTEC Co., Ltd." },
   {  401,   "Hitachi Cable Ltd." },
   {  402,   "BUSWARE Direct" },
   {  403,   "Eaton Electric B.V. (former Holec Holland N.V.)" },
   {  404,   "VAT Vakuumventile AG" },
   {  405,   "Scientific Technologies Incorporated" },
   {  406,   "Alfa Instrumentos Eletronicos Ltda" },
   {  407,   "TWK Elektronik GmbH" },
   {  408,   "ABB Welding Systems AB" },
   {  409,   "BYSTRONIC Maschinen AG" },
   {  410,   "Kimura Electric Co., Ltd" },
   {  411,   "Nissei Plastic Industrial Co., Ltd" },
   {  412,   "Reserved" },
   {  413,   "Kistler-Morse Corporation" },
   {  414,   "Proteous Industries Inc." },
   {  415,   "IDC Corporation" },
   {  416,   "Nordson Corporation" },
   {  417,   "Rapistan Systems" },
   {  418,   "LP-Elektronik GmbH" },
   {  419,   "GERBI & FASE S.p.A.(Fase Saldatura)" },
   {  420,   "Phoenix Digital Corporation" },
   {  421,   "Z-World Engineering" },
   {  422,   "Honda R&D Co., Ltd." },
   {  423,   "Bionics Instrument Co., Ltd." },
   {  424,   "Teknic, Inc." },
   {  425,   "R.Stahl, Inc." },
   {  426,   "Reserved" },
   {  427,   "Ryco Graphic Manufacturing Inc." },
   {  428,   "Giddings & Lewis, Inc." },
   {  429,   "Koganei Corporation" },
   {  430,   "Reserved" },
   {  431,   "Nichigoh Communication Electric Wire Co., Ltd." },
   {  432,   "Reserved" },
   {  433,   "Fujikura Ltd." },
   {  434,   "AD Link Technology Inc." },
   {  435,   "StoneL Corporation" },
   {  436,   "Computer Optical Products, Inc." },
   {  437,   "CONOS Inc." },
   {  438,   "Erhardt + Leimer GmbH" },
   {  439,   "UNIQUE Co. Ltd" },
   {  440,   "Roboticsware, Inc." },
   {  441,   "Nachi Fujikoshi Corporation" },
   {  442,   "Hengstler GmbH" },
   {  443,   "Reserved" },
   {  444,   "SUNNY GIKEN Inc." },
   {  445,   "Lenze Drive Systems GmbH" },
   {  446,   "CD Systems B.V." },
   {  447,   "FMT/Aircraft Gate Support Systems AB" },
   {  448,   "Axiomatic Technologies Corp" },
   {  449,   "Embedded System Products, Inc." },
   {  450,   "Reserved" },
   {  451,   "Mencom Corporation" },
   {  452,   "Reserved" },
   {  453,   "Matsushita Welding Systems Co., Ltd." },
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
   {  464,   "Huettinger Elektronik GmbH + Co. KG" },
   {  465,   "OCM Technology Inc." },
   {  466,   "Professional Supply Inc." },
   {  467,   "Control Solutions" },
   {  468,   "Baumer IVO GmbH & Co. KG" },
   {  469,   "Worcester Controls Corporation" },
   {  470,   "Pyramid Technical Consultants, Inc." },
   {  471,   "Reserved" },
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
   {  482,   "Koyo Electronics" },
   {  483,   "Clever Devices" },
   {  484,   "GCD Hardware & Software GmbH" },
   {  485,   "Reserved" },
   {  486,   "Miller Electric Mfg Co." },
   {  487,   "GEA Tuchenhagen GmbH" },
   {  488,   "Riken Keiki Co., LTD" },
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
   {  501,   "VIPA GmbH" },
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
   {  521,   "Fujikin , Inc." },
   {  522,   "Estic Corp." },
   {  523,   "GS Hydraulic Sales" },
   {  524,   "Reserved" },
   {  525,   "MTE Limited" },
   {  526,   "Hyde Park Electronics, Inc." },
   {  527,   "Pfeiffer Vacuum GmbH" },
   {  528,   "Cyberlogic Technologies" },
   {  529,   "OKUMA Corporation FA Systems Division" },
   {  530,   "Reserved" },
   {  531,   "Hitachi Kokusai Electric Co., Ltd." },
   {  532,   "SHINKO TECHNOS Co., Ltd." },
   {  533,   "Itoh Electric Co., Ltd." },
   {  534,   "Colorado Flow Tech Inc." },
   {  535,   "Love Controls Division/Dwyer Inst." },
   {  536,   "Alstom Drives and Controls" },
   {  537,   "The Foxboro Company" },
   {  538,   "Tescom Corporation" },
   {  539,   "Reserved" },
   {  540,   "Atlas Copco Controls UK" },
   {  541,   "Reserved" },
   {  542,   "Autojet Technologies" },
   {  543,   "Prima Electronics S.p.A." },
   {  544,   "PMA GmbH" },
   {  545,   "Shimafuji Electric Co., Ltd" },
   {  546,   "Oki Electric Industry Co., Ltd" },
   {  547,   "Kyushu Matsushita Electric Co., Ltd" },
   {  548,   "Nihon Electric Wire & Cable Co., Ltd" },
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
   {  560,   "Sartorius Mechatronics T&H GmbH" },
   {  561,   "Comau S.p.A. Robotics & Final Assembly Division" },
   {  562,   "Phoenix Contact" },
   {  563,   "Yokogawa MAT Corporation" },
   {  564,   "asahi sangyo co., ltd." },
   {  565,   "Reserved" },
   {  566,   "Akita Myotoku Ltd." },
   {  567,   "OBARA Corp." },
   {  568,   "Suetron Electronic GmbH" },
   {  569,   "Reserved" },
   {  570,   "Serck Controls Limited" },
   {  571,   "Fairchild Industrial Products Company" },
   {  572,   "ARO S.A." },
   {  573,   "M2C GmbH" },
   {  574,   "Shin Caterpillar Mitsubishi Ltd." },
   {  575,   "Santest Co., Ltd." },
   {  576,   "Cosmotechs Co., Ltd." },
   {  577,   "Hitachi Electric Systems" },
   {  578,   "Smartscan Ltd" },
   {  579,   "Woodhead Software & Electronics France" },
   {  580,   "Athena Controls, Inc." },
   {  581,   "Syron Engineering & Manufacturing, Inc." },
   {  582,   "Asahi Optical Co., Ltd." },
   {  583,   "Sansha Electric Mfg. Co., Ltd." },
   {  584,   "Nikki Denso Co., Ltd." },
   {  585,   "Star Micronics, Co., Ltd." },
   {  586,   "Ecotecnia Socirtat Corp." },
   {  587,   "AC Technology Corp." },
   {  588,   "West Instruments Limited" },
   {  589,   "NTI Limited" },
   {  590,   "Delta Computer Systems, Inc." },
   {  591,   "FANUC Ltd." },
   {  592,   "Hearn-Gu Lee" },
   {  593,   "ABB Automation Products" },
   {  594,   "Orion Machinery Co., Ltd." },
   {  595,   "Reserved" },
   {  596,   "Wire-Pro, Inc." },
   {  597,   "Beijing Huakong Technology Co. Ltd." },
   {  598,   "Yokoyama Shokai Co., Ltd." },
   {  599,   "Toyogiken Co., Ltd." },
   {  600,   "Coester Equipamentos Eletronicos Ltda." },
   {  601,   "Reserved" },
   {  602,   "Electroplating Engineers of Japan Ltd." },
   {  603,   "ROBOX S.p.A." },
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
   {  625,   "Rockwell Automation-Sprecher+Schuh" },
   {  626,   "Matsushita Electric Industrial Co., Ltd/Motor Co." },
   {  627,   "Rolls-Royce Energy Systems, Inc." },
   {  628,   "JEONGIL INTERCOM CO., LTD" },
   {  629,   "Interroll Corp." },
   {  630,   "Hubbell Wiring Device-Kellems (Delaware)" },
   {  631,   "Intelligent Motion Systems" },
   {  632,   "Reserved" },
   {  633,   "INFICON AG" },
   {  634,   "Hirschmann, Inc." },
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
   {  645,   "Bihl & Wiedemann GmbH" },
   {  646,   "Harmonic Drive Systems Inc." },
   {  647,   "Rikei Corporation" },
   {  648,   "BL Autotec, Ltd." },
   {  649,   "Hana Information & Technology Co., Ltd." },
   {  650,   "Seoil Electric Co., Ltd." },
   {  651,   "Fife Corporation" },
   {  652,   "Shanghai Electrical Apparatus Research Institute" },
   {  653,   "Reserved" },
   {  654,   "Parasense Development Centre" },
   {  655,   "Reserved" },
   {  656,   "Reserved" },
   {  657,   "Six Tau S.p.A." },
   {  658,   "Aucos GmbH" },
   {  659,   "Rotork Controls" },
   {  660,   "Automationdirect.com" },
   {  661,   "Thermo BLH" },
   {  662,   "System Controls, Ltd." },
   {  663,   "Univer S.p.A." },
   {  664,   "MKS-Tenta Technology" },
   {  665,   "Lika Electronic SNC" },
   {  666,   "Mettler-Toledo, Inc." },
   {  667,   "DXL USA Inc." },
   {  668,   "Rockwell Automation/Entek IRD Intl." },
   {  669,   "Nippon Otis Elevator Company" },
   {  670,   "Sinano Electric, Co., Ltd." },
   {  671,   "Sony Manufacturing Systems" },
   {  672,   "Reserved" },
   {  673,   "Contec Co., Ltd." },
   {  674,   "Automated Solutions" },
   {  675,   "Controlweigh" },
   {  676,   "Reserved" },
   {  677,   "Fincor Electronics" },
   {  678,   "Cognex Corporation" },
   {  679,   "Qualiflow" },
   {  680,   "Weidmuller, Inc." },
   {  681,   "Morinaga Milk Industry Co., Ltd." },
   {  682,   "Takagi Industrial Co., Ltd." },
   {  683,   "Wittenstein AG" },
   {  684,   "Sena Technologies, Inc." },
   {  685,   "Reserved" },
   {  686,   "APV Products Unna" },
   {  687,   "Creator Teknisk Utvedkling AB" },
   {  688,   "Reserved" },
   {  689,   "Mibu Denki Industrial Co., Ltd." },
   {  690,   "Takamastsu Machineer Section" },
   {  691,   "Startco Engineering Ltd." },
   {  692,   "Reserved" },
   {  693,   "Holjeron" },
   {  694,   "ALCATEL High Vacuum Technology" },
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
   {  717,   "Trumpf Laser GmbH + Co. KG" },
   {  718,   "Niigata Electronic Instruments Co., Ltd." },
   {  719,   "Yokogawa Digital Computer Corporation" },
   {  720,   "O.N. Electronic Co., Ltd." },
   {  721,   "Industrial Control  Communication, Inc." },
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
   {  740,   "Camozzi S.P. A." },
   {  741,   "Crevis Co., LTD" },
   {  742,   "Rice Lake Weighing Systems" },
   {  743,   "Linux Network Services" },
   {  744,   "KEB Antriebstechnik GmbH" },
   {  745,   "Hagiwara Electric Co., Ltd." },
   {  746,   "Glass Inc. International" },
   {  747,   "Reserved" },
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
   {  778,   "Harting, Inc. NA" },
   {  779,   "Kubler GmbH" },
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
   {  793,   "Metronix Messgerate u. Elektronik GmbH" },
   {  794,   "Reserved" },
   {  795,   "Vaccon Company, Inc." },
   {  796,   "Siemens Energy & Automation, Inc." },
   {  797,   "Ten X Technology, Inc." },
   {  798,   "Tyco Electronics" },
   {  799,   "Delta Power Electronics Center" },
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
   {  824,   "The Montalvo Corporation" },
   {  825,   "Reserved" },
   {  826,   "LEONI Special Cables GmbH" },
   {  827,   "Reserved" },
   {  828,   "ONO SOKKI CO.,LTD." },
   {  829,   "Rockwell Samsung Automation" },
   {  830,   "SHINDENGEN ELECTRIC MFG. CO. LTD" },
   {  831,   "Origin Electric Co. Ltd." },
   {  832,   "Quest Technical Solutions, Inc." },
   {  833,   "LS Cable, Ltd." },
   {  834,   "Enercon-Nord Electronic GmbH" },
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
   {  847,   "REO Elektronik AG" },
   {  848,   "Fusion UV Systems, Inc." },
   {  849,   "ASI Advanced Semiconductor Instruments GmbH" },
   {  850,   "Datalogic, Inc." },
   {  851,   "SoftPLC Corporation" },
   {  852,   "Dynisco Instruments LLC" },
   {  853,   "WEG Industrias SA" },
   {  854,   "Frontline Test Equipment, Inc." },
   {  855,   "Tamagawa Seiki Co., Ltd." },
   {  856,   "Multi Computing Co., Ltd." },
   {  857,   "RVSI" },
   {  858,   "Commercial Timesharing Inc." },
   {  859,   "Tennessee Rand Automation LLC" },
   {  860,   "Wacogiken Co., Ltd" },
   {  861,   "Reflex Integration Inc." },
   {  862,   "Siemens AG, A&D PI Flow Instruments" },
   {  863,   "G. Bachmann Electronic GmbH" },
   {  864,   "NT International" },
   {  865,   "Schweitzer Engineering Laboratories" },
   {  866,   "ATR Industrie-Elektronik GmbH Co." },
   {  867,   "PLASMATECH Co., Ltd" },
   {  868,   "Reserved" },
   {  869,   "GEMU GmbH & Co. KG" },
   {  870,   "Alcorn McBride Inc." },
   {  871,   "MORI SEIKI CO., LTD" },
   {  872,   "NodeTech Systems Ltd" },
   {  873,   "Emhart Teknologies" },
   {  874,   "Cervis, Inc." },
   {  875,   "FieldServer Technologies (Div Sierra Monitor Corp)" },
   {  876,   "NEDAP Power Supplies" },
   {  877,   "Nippon Sanso Corporation" },
   {  878,   "Mitomi Giken Co., Ltd." },
   {  879,   "PULS GmbH" },
   {  880,   "Reserved" },
   {  881,   "Japan Control Engineering Ltd" },
   {  882,   "Embedded Systems Korea (Former Zues Emtek Co Ltd.)" },
   {  883,   "Automa SRL" },
   {  884,   "Harms+Wende GmbH & Co KG" },
   {  885,   "SAE-STAHL GmbH" },
   {  886,   "Microwave Data Systems" },
   {  887,   "Bernecker + Rainer Industrie-Elektronik GmbH" },
   {  888,   "Hiprom Technologies" },
   {  889,   "Reserved" },
   {  890,   "Nitta Corporation" },
   {  891,   "Kontron Modular Computers GmbH" },
   {  892,   "Marlin Controls" },
   {  893,   "ELCIS s.r.l." },
   {  894,   "Acromag, Inc." },
   {  895,   "Avery Weigh-Tronix" },
   {  896,   "Reserved" },
   {  897,   "Reserved" },
   {  898,   "Reserved" },
   {  899,   "Practicon Ltd" },
   {  900,   "Schunk GmbH & Co. KG" },
   {  901,   "MYNAH Technologies" },
   {  902,   "Defontaine Groupe" },
   {  903,   "Emerson Process Management Power & Water Solutions" },
   {  904,   "F.A. Elec" },
   {  905,   "Hottinger Baldwin Messtechnik GmbH" },
   {  906,   "Coreco Imaging, Inc." },
   {  907,   "London Electronics Ltd." },
   {  908,   "HSD SpA" },
   {  909,   "Comtrol Corporation" },
   {  910,   "TEAM, S.A. (Tecnica Electronica de Automatismo Y Medida)" },
   {  911,   "MAN B&W Diesel Ltd. Regulateurs Europa" },
   {  912,   "Reserved" },
   {  913,   "Reserved" },
   {  914,   "Micro Motion, Inc." },
   {  915,   "Eckelmann AG" },
   {  916,   "Hanyoung Nux" },
   {  917,   "Ransburg Industrial Finishing KK" },
   {  918,   "Kun Hung Electric Co. Ltd." },
   {  919,   "Brimos wegbebakening b.v." },
   {  920,   "Nitto Seiki Co., Ltd" },
   {  921,   "PPT Vision, Inc." },
   {  922,   "Yamazaki Machinery Works" },
   {  923,   "SCHMIDT Technology GmbH" },
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
   {  936,   "JVL Industrie Elektronik A/S" },
   {  937,   "NovaTech Process Solutions LLC" },
   {  938,   "Reserved" },
   {  939,   "Cisco Systems" },
   {  940,   "Grid Connect" },
   {  941,   "ITW Automotive Finishing" },
   {  942,   "HanYang System" },
   {  943,   "ABB K.K. Technical Center" },
   {  944,   "Taiyo Electric Wire & Cable Co., Ltd." },
   {  945,   "Reserved" },
   {  946,   "SEREN IPS INC" },
   {  947,   "Belden CDT Electronics Division" },
   {  948,   "ControlNet International" },
   {  949,   "Gefran S.P.A." },
   {  950,   "Jokab Safety AB" },
   {  951,   "SUMITA OPTICAL GLASS, INC." },
   {  952,   "Biffi Italia srl" },
   {  953,   "Beck IPC GmbH" },
   {  954,   "Copley Controls Corporation" },
   {  955,   "Fagor Automation S. Coop." },
   {  956,   "DARCOM" },
   {  957,   "Frick Controls (div. of York International)" },
   {  958,   "SymCom, Inc." },
   {  959,   "Infranor" },
   {  960,   "Kyosan Cable, Ltd." },
   {  961,   "Varian Vacuum Technologies" },
   {  962,   "Messung Systems" },
   {  963,   "Xantrex Technology, Inc." },
   {  964,   "StarThis Inc." },
   {  965,   "Chiyoda Co., Ltd." },
   {  966,   "Flowserve Corporation" },
   {  967,   "Spyder Controls Corp." },
   {  968,   "IBA AG" },
   {  969,   "SHIMOHIRA ELECTRIC MFG.CO.,LTD" },
   {  970,   "Reserved" },
   {  971,   "Siemens L&A" },
   {  972,   "Micro Innovations AG" },
   {  973,   "Switchgear & Instrumentation" },
   {  974,   "PRE-TECH CO., LTD." },
   {  975,   "National Semiconductor" },
   {  976,   "Invensys Process Systems" },
   {  977,   "Ametek HDR Power Systems" },
   {  978,   "Reserved" },
   {  979,   "TETRA-K Corporation" },
   {  980,   "C & M Corporation" },
   {  981,   "Siempelkamp Maschinen" },
   {  982,   "Reserved" },
   {  983,   "Daifuku America Corporation" },
   {  984,   "Electro-Matic Products Inc." },
   {  985,   "BUSSAN MICROELECTRONICS CORP." },
   {  986,   "ELAU AG" },
   {  987,   "Hetronic USA" },
   {  988,   "NIIGATA POWER SYSTEMS Co., Ltd." },
   {  989,   "Software Horizons Inc." },
   {  990,   "B3 Systems, Inc." },
   {  991,   "Moxa Networking Co., Ltd." },
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
   { 1006,   "N-Tron" },
   { 1007,   "Nippon Pneumatics/Fludics System CO.,LTD." },
   { 1008,   "DDK Ltd." },
   { 1009,   "Seiko Epson Corporation" },
   { 1010,   "Halstrup-Walcher GmbH" },
   { 1011,   "ITT" },
   { 1012,   "Ground Fault Systems bv" },
   { 1013,   "Scolari Engineering S.p.A." },
   { 1014,   "Vialis Traffic bv" },
   { 1015,   "Weidmueller Interface GmbH & Co. KG" },
   { 1016,   "Shanghai Sibotech Automation Co. Ltd" },
   { 1017,   "AEG Power Supply Systems GmbH" },
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
   { 1041,   "BTR NETCOM via RIA Connect, Inc." },
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
   { 1060,   "Innovasic Semiconductor" },
   { 1061,   "SoftDEL Systems Limited" },
   { 1062,   "FiberFin, Inc." },
   { 1063,   "Nicollet Technologies Corp." },
   { 1064,   "B.F. Systems" },
   { 1065,   "Empire Wire and Supply LLC" },
   { 1066,   "Reserved" },
   { 1067,   "Elmo Motion Control LTD" },
   { 1068,   "Reserved" },
   { 1069,   "Asahi Keiki Co., Ltd." },
   { 1070,   "Joy Mining Machinery" },
   { 1071,   "MPM Engineering Ltd" },
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
   { 1086,   "TPC Mechatronics, Co., Ltd." },
   { 1087,   "Cooper Bussmann" },
   { 1088,   "Trinite Automatisering B.V." },
   { 1089,   "Peek Traffic B.V." },
   { 1090,   "Acrison, Inc" },
   { 1091,   "Applied Robotics, Inc." },
   { 1092,   "FireBus Systems, Inc." },
   { 1093,   "Beijing Sevenstar Huachuang Electronics" },
   { 1094,   "Magnetek" },
   { 1095,   "Microscan" },
   { 1096,   "Air Water Inc." },
   { 1097,   "Sensopart Industriesensorik GmbH" },
   { 1098,   "Tiefenbach Control Systems GmbH" },
   { 1099,   "INOXPA S.A" },
   { 1100,   "Zurich University of Applied Sciences" },
   { 1101,   "Ethernet Direct" },
   { 1102,   "GSI-Micro-E Systems" },
   { 1103,   "S-Net Automation Co., Ltd." },
   { 1104,   "Power Electronics S.L." },
   { 1105,   "Renesas Technology Corp." },
   { 1106,   "NSWCCD-SSES" },
   { 1107,   "Porter Engineering Ltd." },
   { 1108,   "Meggitt Airdynamics, Inc." },
   { 1109,   "Inductive Automation" },
   { 1110,   "Neural ID" },
   { 1111,   "EEPod LLC" },
   { 1112,   "Hitachi Industrial Equipment Systems Co., Ltd." },
   { 1113,   "Salem Automation" },
   { 1114,   "port GmbH" },
   { 1115,   "B & PLUS" },
   { 1116,   "Graco Inc." },
   { 1117,   "Altera Corporation" },
   { 1118,   "Technology Brewing Corporation" },
   { 1121,   "CSE Servelec" },
   { 1124,   "Fluke Networks" },
   { 1125,   "Tetra Pak Packaging Solutions SPA" },
   { 1126,   "Racine Federated, Inc." },
   { 1127,   "Pureron Japan Co., Ltd." },
   { 1130,   "Brother Industries, Ltd." },
   { 1132,   "Leroy Automation" },
   { 1134,   "THK CO., LTD." },
   { 1137,   "TR-Electronic GmbH" },
   { 1138,   "ASCON S.p.A." },
   { 1139,   "Toledo do Brasil Industria de Balancas Ltda." },
   { 1140,   "Bucyrus DBT Europe GmbH" },
   { 1141,   "Emerson Process Management Valve Automation" },
   { 1142,   "Alstom Transport" },
   { 1144,   "Matrox Electronic Systems" },
   { 1145,   "Littelfuse" },
   { 1146,   "PLASMART, Inc." },
   { 1147,   "Miyachi Corporation" },
   { 1150,   "Promess Incorporated" },
   { 1151,   "COPA-DATA GmbH" },
   { 1152,   "Precision Engine Controls Corporation" },
   { 1153,   "Alga Automacao e controle LTDA" },
   { 1154,   "U.I. Lapp GmbH" },
   { 1155,   "ICES" },
   { 1156,   "Philips Lighting bv" },
   { 1157,   "Aseptomag AG" },
   { 1158,   "ARC Informatique" },
   { 1159,   "Hesmor GmbH" },
   { 1160,   "Kobe Steel, Ltd." },
   { 1161,   "FLIR Systems" },
   { 1162,   "Simcon A/S" },
   { 1163,   "COPALP" },
   { 1164,   "Zypcom, Inc." },
   { 1165,   "Swagelok" },
   { 1166,   "Elspec" },
   { 1167,   "ITT Water & Wastewater AB" },
   { 1168,   "Kunbus GmbH Industrial Communication" },
   { 1170,   "Performance Controls, Inc." },
   { 1171,   "ACS Motion Control, Ltd." },
   { 1173,   "IStar Technology Limited" },
   { 1174,   "Alicat Scientific, Inc." },
   { 1176,   "ADFweb.com SRL" },
   { 1177,   "Tata Consultancy Services Limited" },
   { 1178,   "CXR Ltd." },
   { 1179,   "Vishay Nobel AB" },
   { 1181,   "SolaHD" },
   { 1182,   "Endress+Hauser" },
   { 1183,   "Bartec GmbH" },
   { 1185,   "AccuSentry, Inc." },
   { 1186,   "Exlar Corporation" },
   { 1187,   "ILS Technology" },
   { 1188,   "Control Concepts Inc." },
   { 1190,   "Procon Engineering Limited" },
   { 1191,   "Hermary Opto Electronics Inc." },
   { 1192,   "Q-Lambda" },
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
   { 1213,   "MK Precision Co., Ltd." },
   { 1214,   "Tappan Wire and Cable" },
   { 1215,   "Heinzmann GmbH & Co. KG" },
   { 1216,   "Process Automation International Ltd." },
   { 1217,   "Secure Crossing" },
   { 1218,   "SMA Railway Technology GmbH" },
   { 1219,   "FMS Force Measuring Systems AG" },
   { 1220,   "ABT Endustri Enerji Sistemleri Sanayi Tic. Ltd. Sti." },
   { 1221,   "MagneMotion Inc." },
   { 1222,   "STS Co., Ltd." },
   { 1223,   "MERAK SIC, SA" },
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

   { 0, NULL }
};

value_string_ext cip_vendor_vals_ext = VALUE_STRING_EXT_INIT(cip_vendor_vals);

/* Translate Device Profile:s */
static const value_string cip_devtype_vals[] = {
   { DP_GEN_DEV,              "Generic Device"              },
   { DP_AC_DRIVE,             "AC Drive"                    },
   { DP_MOTOR_OVERLOAD,       "Motor Overload"              },
   { DP_LIMIT_SWITCH,         "Limit Switch"                },
   { DP_IND_PROX_SWITCH,      "Inductive Proximity Switch"  },
   { DP_PHOTO_SENSOR,         "Photoelectric Sensor"        },
   { DP_GENP_DISC_IO,         "General Purpose Discrete I/O"},
   { DP_RESOLVER,             "Resolver"                    },
   { DP_COM_ADAPTER,          "Communications Adapter"      },
   { DP_POS_CNT,              "Position Controller",        },
   { DP_DC_DRIVE,             "DC Drive"                    },
   { DP_CONTACTOR,            "Contactor",                  },
   { DP_MOTOR_STARTER,        "Motor Starter",              },
   { DP_SOFT_START,           "Soft Start",                 },
   { DP_HMI,                  "Human-Machine Interface"     },
   { DP_MASS_FLOW_CNT,        "Mass Flow Controller"        },
   { DP_PNEUM_VALVE,          "Pneumatic Valve"             },
   { DP_VACUUM_PRES_GAUGE,    "Vacuum Pressure Gauge"       },

   { 0, NULL }
};

value_string_ext cip_devtype_vals_ext = VALUE_STRING_EXT_INIT(cip_devtype_vals);

/* Translate class names */
static const value_string cip_class_names_vals[] = {
   { 0x01,     "Identity Object"                       },
   { 0x02,     "Message Router"                        },
   { 0x03,     "DeviceNet Object"                      },
   { 0x04,     "Assembly Object"                       },
   { 0x05,     "Connection Object"                     },
   { 0x06,     "Connection Manager"                    },
   { 0x07,     "Register Object"                       },
   { 0x08,     "Discrete Input Point Object"           },
   { 0x09,     "Discrete Output Point Object"          },
   { 0x0A,     "Analog Input Point Object"             },
   { 0x0B,     "Analog Output Point Object"            },
   { 0x0E,     "Presence Sensing Object"               },
   { 0x0F,     "Parameter Object"                      },
   { 0x10,     "Parameter Group Object"                },
   { 0x12,     "Group Object"                          },
   { 0x1D,     "Discrete Input Group Object"           },
   { 0x1E,     "Discrete Output Group Object"          },
   { 0x1F,     "Discrete Group Object"                 },
   { 0x20,     "Analog Input Group Object"             },
   { 0x21,     "Analog Output Group Object"            },
   { 0x22,     "Analog Group Object"                   },
   { 0x23,     "Position Sensor Object"                },
   { 0x24,     "Position Controller Supervisor Object" },
   { 0x25,     "Position Controller Object"            },
   { 0x26,     "Block Sequencer Object"                },
   { 0x27,     "Command Block Object"                  },
   { 0x28,     "Motor Data Object"                     },
   { 0x29,     "Control Supervisor Object"             },
   { 0x2A,     "AC/DC Drive Object"                    },
   { 0x2B,     "Acknowledge Handler Object"            },
   { 0x2C,     "Overload Object"                       },
   { 0x2D,     "Softstart Object"                      },
   { 0x2E,     "Selection Object"                      },
   { 0x30,     "S-Device Supervisor Object"            },
   { 0x31,     "S-Analog Sensor Object"                },
   { 0x32,     "S-Analog Actuator Object"              },
   { 0x33,     "S-Single Stage Controller Object"      },
   { 0x34,     "S-Gas Calibration Object"              },
   { 0x35,     "Trip Point Object"                     },
   { 0x37,     "File Object"                           },
   { 0x38,     "S-Partial Pressure Object"             },
   { 0x39,     "Safety Supervisor Object"              },
   { 0x3A,     "Safety Validator Object"               },
   { 0x3B,     "Safety Discrete Output Point Object"   },
   { 0x3C,     "Safety Discrete Output Group Object"   },
   { 0x3D,     "Safety Discrete Input Point Object"    },
   { 0x3E,     "Safety Discrete Input Group Object"    },
   { 0x3F,     "Safety Dual Channel Output Object"     },
   { 0x40,     "S-Sensor Calibration Object"           },
   { 0x41,     "Event Log Object"                      },
   { 0x42,     "Motion Axis Object"                    },
   { 0x43,     "Time Sync Object"                      },
   { 0x44,     "Modbus Object"                         },
   { 0x45,     "Originator Connection List Object"     },
   { 0x46,     "Modbus Serial Link Object"             },
   { 0x47,     "Device Level Ring (DLR) Object"        },
   { 0x48,     "QoS Object"                            },
   { 0xF0,     "ControlNet Object"                     },
   { 0xF1,     "ControlNet Keeper Object"              },
   { 0xF2,     "ControlNet Scheduling Object"          },
   { 0xF3,     "Connection Configuration Object"       },
   { 0xF4,     "Port Object"                           },
   { 0xF5,     "TCP/IP Interface Object"               },
   { 0xF6,     "EtherNet Link Object"                  },
   { 0xF7,     "CompoNet Object"                       },
   { 0xF8,     "CompoNet Repeater Object"              },

   { 0,        NULL                                    }
};

value_string_ext cip_class_names_vals_ext = VALUE_STRING_EXT_INIT(cip_class_names_vals);


int dissect_id_revision(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len)
{
   if (total_len < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Identity revision");
      return total_len;
   }

   proto_tree_add_item( tree, hf_id_major_rev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( tree, hf_id_minor_rev, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
   return 2;
}

int dissect_msg_rout_num_classes(packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, tvbuff_t *tvb,
                             int offset, int total_len _U_)
{
   guint16 i, num_classes;

   num_classes = tvb_get_letohs( tvb, offset);
   proto_tree_add_item( tree, hf_msg_rout_num_classes, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (total_len < (2+(num_classes*2)))
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Message Router Attribute 1");
      return total_len;
   }

   for (i = 0; i < num_classes; i++)
      proto_tree_add_item( tree, hf_msg_rout_classes, tvb, offset+2+(i*2), 2, ENC_LITTLE_ENDIAN);

   return (2+(num_classes*2));
}

static attribute_info_t cip_attribute_vals[] = {

   {0x01, FALSE, 1, "Vendor ID", cip_uint, &hf_id_vendor_id, NULL},
   {0x01, FALSE, 2, "Device Type", cip_uint, &hf_id_device_type, NULL},
   {0x01, FALSE, 3, "Product Code", cip_uint, &hf_id_produce_code, NULL},
   {0x01, FALSE, 4, "Revision", cip_dissector_func, NULL, dissect_id_revision},
   {0x01, FALSE, 5, "Status", cip_word, &hf_id_status, NULL},
   {0x01, FALSE, 6, "Serial Number", cip_udint, &hf_id_serial_number, NULL},
   {0x01, FALSE, 7, "Product Name", cip_short_string, &hf_id_product_name, NULL},

   {0x02, FALSE, 1, "Object List", cip_dissector_func, NULL, dissect_msg_rout_num_classes},
   {0x02, FALSE, 2, "Number Available", cip_uint, &hf_msg_rout_num_available, NULL},
   {0x02, FALSE, 3, "Number Active", cip_uint, &hf_msg_rout_num_active, NULL},
   {0x02, FALSE, 4, "Active Connections", cip_uint_array, &hf_msg_rout_active_connections, NULL},

   {0x06, FALSE, 1, "Open Requests", cip_uint, &hf_conn_mgr_open_requests, NULL},
   {0x06, FALSE, 2, "Open Format Rejects", cip_uint, &hf_conn_mgr_open_format_rejects, NULL},
   {0x06, FALSE, 3, "Open Resource Rejects", cip_uint, &hf_conn_mgr_open_resource_rejects, NULL},
   {0x06, FALSE, 4, "Other Open Rejects", cip_uint, &hf_conn_mgr_other_open_rejects, NULL},
   {0x06, FALSE, 5, "Close Requests", cip_uint, &hf_conn_mgr_close_requests, NULL},
   {0x06, FALSE, 6, "Close Format Requests", cip_uint, &hf_conn_close_format_requests, NULL},
   {0x06, FALSE, 7, "Close Other Requests", cip_uint, &hf_conn_mgr_close_other_requests, NULL},
   {0x06, FALSE, 8, "Connection Timeouts", cip_uint, &hf_conn_mgr_conn_timouts, NULL},
};

typedef struct attribute_val_array {
   size_t size;
   attribute_info_t* attrs;
} attribute_val_array_t;

static attribute_val_array_t all_attribute_vals[] = {
   {sizeof(cip_attribute_vals)/sizeof(attribute_info_t), cip_attribute_vals},
   {sizeof(enip_attribute_vals)/sizeof(attribute_info_t), enip_attribute_vals}
};

static void
dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t *preq_info );

static attribute_info_t* cip_get_attribute(guint class_id, guint instance, guint attribute)
{
   size_t i, j;
   attribute_val_array_t* att_array;
   attribute_info_t* pattr;

   for (i = 0; i < sizeof(all_attribute_vals)/sizeof(attribute_val_array_t); i++)
   {
      att_array = &all_attribute_vals[i];
      for (j = 0; j < att_array->size; j++)
      {
         pattr = &att_array->attrs[j];
         if ((pattr->class_id == class_id) &&
             (instance != (guint)-1) &&
             (((instance == 0) && (pattr->class_instance == TRUE)) || ((instance != 0) && (pattr->class_instance == FALSE))) &&
             (pattr->attribute == attribute))
         {
            return pattr;
         }
      }
   }

   return NULL;
}

static gboolean
dissect_cia(tvbuff_t *tvb, int offset, int* pathpos, unsigned char segment_type,
            gboolean generate, packet_info *pinfo, proto_item *epath_item,
            proto_item *item, proto_tree *tree, proto_item *path_item, proto_item ** ret_item,
            const char* segment_name, const value_string* vals, int* value,
            int hf8, int hf16, int hf32)
{
   int temp_data;
   emem_strbuf_t *strbuf;

   switch (segment_type)
   {
   case CI_LOGICAL_SEG_8_BIT:
      temp_data = tvb_get_guint8( tvb, offset + *pathpos + 1 );

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(item, hf8, NULL, 0, 0, temp_data );
         PROTO_ITEM_SET_GENERATED(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item(tree, hf8, tvb, offset + *pathpos + 1, 1, ENC_LITTLE_ENDIAN);
      }

      if (vals == NULL)
      {
         proto_item_append_text( epath_item, "%s: 0x%02X", segment_name,  temp_data);
      }
      else
      {
         strbuf = ep_strbuf_new(segment_name);
         ep_strbuf_append(strbuf, ": 0x%02X");

         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals , strbuf->str) );
      }

      if (value != NULL)
         *value = temp_data;

      proto_item_set_len( item, 2);
      proto_item_set_len( path_item, 2);
      (*pathpos) += 2;
      break;
   case CI_LOGICAL_SEG_16_BIT:
      temp_data = tvb_get_letohs( tvb, offset + *pathpos + 2 );

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(tree, hf16, NULL, 0, 0, temp_data );
         PROTO_ITEM_SET_GENERATED(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item( tree, hf16, tvb, offset + *pathpos + 2, 2, ENC_LITTLE_ENDIAN);
      }
      if (vals == NULL)
      {
         proto_item_append_text( epath_item, "%s: 0x%04X", segment_name,  temp_data);
      }
      else
      {
         strbuf = ep_strbuf_new(segment_name);
         ep_strbuf_append(strbuf, ": 0x%04X");

         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals , strbuf->str) );
      }

      if (value != NULL)
         *value = temp_data;

      proto_item_set_len( item, 4);
      proto_item_set_len( path_item, 4);
      (*pathpos) += 4;
      break;
   case CI_LOGICAL_SEG_32_BIT:
      temp_data = tvb_get_letohl( tvb, offset + *pathpos + 2 );

      if ( generate )
      {
         *ret_item = proto_tree_add_uint(tree, hf32, NULL, 0, 0, temp_data );
         PROTO_ITEM_SET_GENERATED(*ret_item);
      }
      else
      {
         *ret_item = proto_tree_add_item( tree, hf32, tvb, offset + *pathpos + 2, 4, ENC_LITTLE_ENDIAN);
      }

      if (vals == NULL)
      {
         proto_item_append_text( epath_item, "%s: 0x%08X", segment_name,  temp_data);
      }
      else
      {
         strbuf = ep_strbuf_new(segment_name);
         ep_strbuf_append(strbuf, ": 0x%08X");

         proto_item_append_text( epath_item, "%s", val_to_str( temp_data, vals , strbuf->str) );
      }

      if (value != NULL)
         *value = temp_data;

      proto_item_set_len( item, 6);
      proto_item_set_len( path_item, 6);
      (*pathpos) += 6;
      break;
   default:
      expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Logical Segment Format");
      return FALSE;
   }

   return TRUE;
}

/* Dissect Device ID structure */
static void
dissect_deviceid(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_vendor, int hf_devtype, int hf_prodcode,
                 int hf_compatibility, int hf_comp_bit, int hf_majrev, int hf_minrev)
{
   guint compatibility;
   proto_item *compatibility_item;
   proto_item *compatibility_tree;

   proto_tree_add_item(tree, hf_vendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_devtype, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(tree, hf_prodcode, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);

   /* Major revision/Compatibility */
   compatibility = tvb_get_guint8( tvb, offset+6);

   /* Add Major revision/Compatibility tree */
   compatibility_item = proto_tree_add_uint_format_value(tree, hf_compatibility,
            tvb, offset+6, 1, compatibility, "%s, Major Revision: %d",
               val_to_str( ( compatibility & 0x80 )>>7, cip_com_bit_vals , "" ),
               compatibility & 0x7F);
   compatibility_tree = proto_item_add_subtree(compatibility_item, ett_mcsc);

   proto_tree_add_item(compatibility_tree, hf_comp_bit, tvb, offset+6, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(compatibility_tree, hf_majrev, tvb, offset+6, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(tree, hf_minrev, tvb, offset+7, 1, ENC_LITTLE_ENDIAN );
}

static void
dissect_net_param16(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_net_param16, int hf_owner, int hf_type,
                 int hf_priority, int hf_fixed_var, int hf_con_size, gint ncp_ett)
{
   proto_item *net_param_item;
   proto_tree *net_param_tree;

   net_param_item = proto_tree_add_item(tree, hf_net_param16, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   net_param_tree = proto_item_add_subtree(net_param_item, ncp_ett);

   /* Add the data to the tree */
   proto_tree_add_item(net_param_tree, hf_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_type, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_priority, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_fixed_var, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_con_size, tvb, offset, 2, ENC_LITTLE_ENDIAN );
}

static void
dissect_net_param32(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_net_param16, int hf_owner, int hf_type,
                 int hf_priority, int hf_fixed_var, int hf_con_size, gint ncp_ett)
{
   proto_item *net_param_item;
   proto_tree *net_param_tree;

   net_param_item = proto_tree_add_item(tree, hf_net_param16, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   net_param_tree = proto_item_add_subtree(net_param_item, ncp_ett);

   /* Add the data to the tree */
   proto_tree_add_item(net_param_tree, hf_owner, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_type, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_priority, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_fixed_var, tvb, offset, 4, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(net_param_tree, hf_con_size, tvb, offset, 4, ENC_LITTLE_ENDIAN );
}

static void
dissect_transport_type_trigger(tvbuff_t *tvb, int offset, proto_tree *tree,
                 int hf_ttt, int hf_direction, int hf_trigger, int hf_class, gint ett)
{
   proto_item *ttt_item;
   proto_tree *ttt_tree;

   ttt_item = proto_tree_add_item(tree, hf_ttt, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   ttt_tree = proto_item_add_subtree(ttt_item, ett);

   proto_tree_add_item(ttt_tree, hf_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(ttt_tree, hf_trigger, tvb, offset, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(ttt_tree, hf_class, tvb, offset, 1, ENC_LITTLE_ENDIAN );
}

/* Dissect EPATH */
void dissect_epath( tvbuff_t *tvb, packet_info *pinfo, proto_item *epath_item, int offset, int path_length, gboolean generate, cip_simple_request_info_t* req_data)
{
   int pathpos, temp_data, temp_data2, seg_size, i;
   unsigned char segment_type, opt_link_size;
   proto_tree *path_tree, *port_tree, *net_tree;
   proto_tree *cia_tree, *ds_tree, *ds_data_tree, *path_seg_tree;
   proto_item *it, *cia_item, *cia_ret_item, *port_item, *ds_item, *ds_data_item;
   proto_item *net_item, *hidden_item, *path_seg_item;

   attribute_info_t* att_info;

   /* Create a sub tree for the epath */
   path_tree = proto_item_add_subtree( epath_item, ett_path );

   /* can't populate req_data unless its there */
   if (req_data != NULL)
   {
      req_data->iClass = (guint32)-1;
      req_data->iInstance = (guint32)-1;
      req_data->iAttribute = (guint32)-1;
      req_data->iMember = (guint32)-1;
   }

   if ( !generate )
   {
      hidden_item = proto_tree_add_item(path_tree, hf_cip_epath,
                                        tvb, offset, path_length, ENC_LITTLE_ENDIAN );
      PROTO_ITEM_SET_HIDDEN(hidden_item);
   }

   pathpos = 0;

   while( pathpos < path_length )
   {
      if (tvb_reported_length_remaining(tvb, offset + pathpos) <= 0)
      {
         expert_add_info_format(pinfo, epath_item, PI_MALFORMED, PI_ERROR, "Incomplete EPATH");
         return;
      }

      /* Get segement type */
      segment_type = tvb_get_guint8( tvb, offset + pathpos );

      if ( generate )
      {
         path_seg_item = proto_tree_add_uint(path_tree, hf_cip_path_segment, NULL, 0, 0, segment_type );
         PROTO_ITEM_SET_GENERATED(path_seg_item);
         path_seg_tree = proto_item_add_subtree( path_seg_item, ett_path_seg );
         it = proto_tree_add_uint(path_seg_tree, hf_cip_path_segment_type, NULL, 0, 0, segment_type&CI_SEGMENT_TYPE_MASK);
         PROTO_ITEM_SET_GENERATED(it);
      }
      else
      {
         path_seg_item = proto_tree_add_item(path_tree, hf_cip_path_segment, tvb, offset + pathpos, 1, ENC_LITTLE_ENDIAN);
         path_seg_tree = proto_item_add_subtree( path_seg_item, ett_path_seg );
         proto_tree_add_item(path_seg_tree, hf_cip_path_segment_type, tvb, offset + pathpos, 1, ENC_LITTLE_ENDIAN);
      }

      /* Determine the segment type */

      switch( segment_type & CI_SEGMENT_TYPE_MASK )
      {
         case CI_PORT_SEGMENT:
            /* Add Extended Link Address flag & Port Identifier*/
            if ( generate )
            {
               it = proto_tree_add_boolean(path_seg_tree, hf_cip_port_ex_link_addr, NULL, 0, 0, segment_type & CI_PORT_SEG_EX_LINK_ADDRESS);
               PROTO_ITEM_SET_GENERATED(it);
               it = proto_tree_add_uint(path_seg_tree, hf_cip_port, NULL, 0, 0, ( segment_type & 0x0F ) );
               PROTO_ITEM_SET_GENERATED(it);
               port_item = proto_tree_add_text(path_seg_tree, NULL, 0, 0, "Port Segment");
               PROTO_ITEM_SET_GENERATED(port_item);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_port_ex_link_addr, tvb, offset+pathpos, 1, ENC_LITTLE_ENDIAN );
               proto_tree_add_item(path_seg_tree, hf_cip_port, tvb, offset + pathpos, 1, ENC_LITTLE_ENDIAN);
               port_item = proto_tree_add_text(path_seg_tree, tvb, offset + pathpos, 1, "Port Segment");
            }

            proto_item_append_text( path_seg_item, " (Port Segment)");
            proto_item_append_text( epath_item, "Port: %d", ( segment_type & CI_PORT_SEG_PORT_ID_MASK ) );
            port_tree = proto_item_add_subtree( port_item, ett_port_path );

            if( segment_type & CI_PORT_SEG_EX_LINK_ADDRESS )
            {
               opt_link_size = tvb_get_guint8( tvb, offset + pathpos + 1 );

               if ( generate )
               {
                  /* Add size of extended link address */
                  it = proto_tree_add_uint(port_tree, hf_cip_link_address_size, NULL, 0, 0, opt_link_size);
                  PROTO_ITEM_SET_GENERATED(it);
                  /* Add extended link address */
                  it = proto_tree_add_string(port_tree, hf_cip_link_address_string, NULL, 0, 0, tvb_format_text(tvb, offset+pathpos+2, opt_link_size) );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
               {
                  proto_tree_add_item( port_tree, hf_cip_link_address_size, tvb, offset+pathpos+1, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item( port_tree, hf_cip_link_address_string, tvb, offset+pathpos+2, opt_link_size, ENC_ASCII|ENC_NA );
               }

               proto_item_append_text( epath_item, ", Address: %s", tvb_format_text(tvb, offset+pathpos+2, opt_link_size) );

               /* Pad byte */
               if( opt_link_size % 2 )
               {
                  proto_item_set_len( port_item, 3 + opt_link_size );
                  proto_item_set_len( path_seg_item, 3 + opt_link_size );
                  pathpos += (3 + opt_link_size);
               }
               else
               {
                  proto_item_set_len( port_item, 2 + opt_link_size );
                  proto_item_set_len( path_seg_item, 2 + opt_link_size );
                  pathpos += (2 + opt_link_size);
               }
            }
            else
            {
               /* Add Link Address */
               if ( generate )
               {
                  it = proto_tree_add_uint(port_tree, hf_cip_link_address_byte, NULL, 0, 0, tvb_get_guint8( tvb, offset + pathpos + 1 ) );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
               {
                  proto_tree_add_item(port_tree, hf_cip_link_address_byte, tvb, offset+pathpos+1, 1, ENC_LITTLE_ENDIAN );
               }

               proto_item_append_text( epath_item, ", Address: %d",tvb_get_guint8( tvb, offset + pathpos + 1 ) );

               proto_item_set_len( port_item, 2 );
               proto_item_set_len( path_seg_item, 2);
               pathpos += 2;
            }

            break;

         case CI_LOGICAL_SEGMENT:

            /* Logical segment, determine the logical type */
            if ( generate )
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_logical_seg_type, NULL, 0, 0, segment_type & CI_LOGICAL_SEG_TYPE_MASK);
               PROTO_ITEM_SET_GENERATED(it);
               if ((segment_type & CI_LOGICAL_SEG_TYPE_MASK) <= CI_LOGICAL_SEG_ATTR_ID)
               {
                  it = proto_tree_add_uint(path_seg_tree, hf_cip_logical_seg_format, NULL, 0, 0, segment_type & CI_LOGICAL_SEG_FORMAT_MASK);
                  PROTO_ITEM_SET_GENERATED(it);
               }
               cia_item = proto_tree_add_text(path_seg_tree, NULL, 0, 0, "%s", val_to_str( ((segment_type & (CI_LOGICAL_SEG_TYPE_MASK|CI_LOGICAL_SEG_FORMAT_MASK))), cip_logical_seg_vals, "Reserved"));
               PROTO_ITEM_SET_GENERATED(cia_item);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_logical_seg_type, tvb, offset+pathpos, 1, ENC_LITTLE_ENDIAN );
               if ((segment_type & CI_LOGICAL_SEG_TYPE_MASK) <= CI_LOGICAL_SEG_ATTR_ID)
                  proto_tree_add_item(path_seg_tree, hf_cip_logical_seg_format, tvb, offset + pathpos, 1, ENC_LITTLE_ENDIAN);
               cia_item = proto_tree_add_text(path_seg_tree, tvb, offset + pathpos, 1, "%s", val_to_str( ((segment_type & (CI_LOGICAL_SEG_TYPE_MASK|CI_LOGICAL_SEG_FORMAT_MASK))), cip_logical_seg_vals, "Reserved"));
            }

            proto_item_append_text( path_seg_item, " (%s)", val_to_str( ((segment_type & (CI_LOGICAL_SEG_TYPE_MASK|CI_LOGICAL_SEG_FORMAT_MASK))), cip_logical_seg_vals, "Reserved"));
            cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

            switch( segment_type & CI_LOGICAL_SEG_TYPE_MASK )
            {
               case CI_LOGICAL_SEG_CLASS_ID:
                  if (dissect_cia(tvb, offset, &pathpos, segment_type & CI_LOGICAL_SEG_FORMAT_MASK, generate, pinfo,
                       epath_item, cia_item, cia_tree, path_seg_item, &cia_ret_item,
                       "Class", cip_class_names_vals, (req_data == NULL) ? NULL : &req_data->iClass,
                       hf_cip_class8, hf_cip_class16, hf_cip_class32) == FALSE)
                       return;
                  break;

               case CI_LOGICAL_SEG_INST_ID:
                  if (dissect_cia(tvb, offset, &pathpos, segment_type & CI_LOGICAL_SEG_FORMAT_MASK, generate, pinfo,
                       epath_item, cia_item, cia_tree, path_seg_item, &cia_ret_item,
                       "Instance", NULL, (req_data == NULL) ? NULL : &req_data->iInstance,
                       hf_cip_instance8, hf_cip_instance16, hf_cip_instance32) == FALSE)
                       return;
                  break;

               case CI_LOGICAL_SEG_MBR_ID:
                  if (dissect_cia(tvb, offset, &pathpos, segment_type & CI_LOGICAL_SEG_FORMAT_MASK, generate, pinfo,
                       epath_item, cia_item, cia_tree, path_seg_item, &cia_ret_item,
                       "Member", NULL, (req_data == NULL) ? NULL : &req_data->iMember,
                       hf_cip_member8, hf_cip_member16, hf_cip_member32) == FALSE)
                       return;
                  break;

               case CI_LOGICAL_SEG_ATTR_ID:
                  if (dissect_cia(tvb, offset, &pathpos, segment_type & CI_LOGICAL_SEG_FORMAT_MASK, generate, pinfo,
                       epath_item, cia_item, cia_tree, path_seg_item, &cia_ret_item,
                       "Attribute", NULL, (req_data == NULL) ? NULL : &req_data->iAttribute,
                       hf_cip_attribute8, hf_cip_attribute16, hf_cip_attribute32) == FALSE)
                       return;

                  if (req_data != NULL)
                  {
                     att_info = cip_get_attribute(req_data->iClass, req_data->iInstance,
                                                  req_data->iAttribute);
                     if (att_info != NULL)
                     {
                        proto_item_append_text(cia_ret_item, " (%s)", att_info->text);
                        proto_item_append_text(epath_item, " (%s)", att_info->text);
                     }
                  }
                  break;

               case CI_LOGICAL_SEG_CON_POINT:
                  if (dissect_cia(tvb, offset, &pathpos, segment_type & CI_LOGICAL_SEG_FORMAT_MASK, generate, pinfo,
                       epath_item, cia_item, cia_tree, path_seg_item, &cia_ret_item,
                       "Connection Point", NULL, NULL,
                       hf_cip_conpoint8, hf_cip_conpoint16, hf_cip_conpoint32) == FALSE)
                       return;
                  break;

               case CI_LOGICAL_SEG_SPECIAL:

                  /* Logical Special ID, the only logical format specified is electronic key */
                  if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_E_KEY )
                  {
                     /* Get the Key Format */
                     temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );

                     if( temp_data == CI_E_KEY_FORMAT_VAL )
                     {
                        proto_item_set_len(path_seg_item, 10);
                        proto_item_set_len(cia_item, 10);
                        proto_tree_add_item( cia_tree, hf_cip_ekey_format, tvb, offset + pathpos+1, 1, ENC_LITTLE_ENDIAN);

                        /* dissect the device ID */
                        dissect_deviceid(tvb, offset + pathpos + 2, cia_tree,
                           hf_cip_ekey_vendor, hf_cip_ekey_devtype, hf_cip_ekey_prodcode,
                           hf_cip_ekey_compatibility, hf_cip_ekey_comp_bit, hf_cip_ekey_majorrev, hf_cip_ekey_minorrev);

                        /* Add "summary" information to parent item */
                        temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                        proto_item_append_text( cia_tree, " (VendorID: 0x%04X", temp_data );
                        temp_data = tvb_get_letohs( tvb, offset + pathpos + 4 );
                        proto_item_append_text( cia_tree, ", DevTyp: 0x%04X", temp_data );
                        temp_data = tvb_get_guint8( tvb, offset + pathpos + 8 );
                        temp_data2 = tvb_get_guint8( tvb, offset + pathpos + 9 );

                        proto_item_append_text(cia_tree, ", %d.%d)", ( temp_data & 0x7F ), temp_data2 );
                        proto_item_append_text(epath_item, "[Key]" );

                        pathpos += 10;
                     }
                     else
                     {
                        expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Electronic Key Format");
                        return;
                     }
                  }
                  else
                  {
                     expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Special Segment Format");
                     return;
                  }
                  break;

               default:
                  expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Logical Segment Type");
                  return;

            } /* end of switch( segment_type & CI_LOGICAL_SEG_TYPE_MASK ) */
            break;

         case CI_DATA_SEGMENT:

            /* Data segment, determine the logical type */
            if ( generate )
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_data_seg_type, NULL, 0, 0, segment_type & CI_DATA_SEG_TYPE_MASK);
               PROTO_ITEM_SET_GENERATED(it);
               ds_item = proto_tree_add_text(path_seg_tree, NULL, 0, 0, "%s", val_to_str( (segment_type & CI_DATA_SEG_TYPE_MASK), cip_data_segment_type_vals, "Reserved"));
               PROTO_ITEM_SET_GENERATED(ds_item);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_data_seg_type, tvb, offset+pathpos, 1, ENC_LITTLE_ENDIAN );
               ds_item = proto_tree_add_text(path_seg_tree, tvb, offset + pathpos, 1, "%s", val_to_str( (segment_type & CI_DATA_SEG_TYPE_MASK), cip_data_segment_type_vals, "Reserved"));
            }

            proto_item_append_text( path_seg_item, " (%s)", val_to_str( (segment_type & CI_DATA_SEG_TYPE_MASK), cip_data_segment_type_vals, "Reserved"));
            ds_tree = proto_item_add_subtree( ds_item, ett_data_seg  );

            switch( segment_type & CI_DATA_SEG_TYPE_MASK)
            {
               case CI_DATA_SEG_SIMPLE:
                  /* Segment size */
                  seg_size = tvb_get_guint8( tvb, offset + pathpos+1 )*2;

                  proto_tree_add_uint_format_value(ds_tree, hf_cip_data_seg_size,
                     tvb, offset + pathpos+1, 1, seg_size, "%d (words)", seg_size/2);

                  /* Segment data  */
                  if( seg_size != 0 )
                  {
                     ds_data_item = proto_tree_add_text( ds_tree, tvb, offset + pathpos+2, 0, "Data" );
                     ds_data_tree = proto_item_add_subtree( ds_data_item, ett_data_seg_data );

                     for( i=0; i < seg_size/2; i ++ )
                        proto_tree_add_item(ds_data_tree, hf_cip_data_seg_item, tvb, offset + pathpos+2+(i*2), 2, ENC_LITTLE_ENDIAN );

                     proto_item_set_len(ds_data_item, seg_size);
                  }

                  proto_item_set_len( ds_item, 2 + seg_size );
                  proto_item_set_len( path_seg_item, 2 + seg_size );
                  pathpos += (2 + seg_size);

                  proto_item_append_text(epath_item, "[Data]" );
                  break;

               case CI_DATA_SEG_SYMBOL:

                  /* ANSI extended symbol segment */

                  /* Segment size */
                  seg_size = tvb_get_guint8( tvb, offset + pathpos+1 );
                  if ( generate )
                  {
                     it = proto_tree_add_uint(ds_tree, hf_cip_data_seg_type, NULL, 0, 0, seg_size);
                     PROTO_ITEM_SET_GENERATED(it);
                  }
                  else
                     proto_tree_add_item(ds_tree, hf_cip_data_seg_size, tvb, offset + pathpos+1, 1, ENC_LITTLE_ENDIAN );

                  /* Segment data  */
                  if( seg_size != 0 )
                  {
                     if ( generate )
                     {
                        it = proto_tree_add_string(ds_tree, hf_cip_symbol, NULL, 0, 0, tvb_format_text(tvb, offset + pathpos + 2, seg_size));
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( ds_tree, hf_cip_symbol, tvb, offset + pathpos + 2, seg_size, ENC_ASCII|ENC_NA );

                     proto_item_append_text(epath_item, "%s", tvb_format_text(tvb, offset + pathpos + 2, seg_size));
                  }

                  /* Check for pad byte */
                  if( seg_size %2 )
                     seg_size++;

                  if ( !generate )
                  {
                     proto_item_set_len( ds_item, 2 + seg_size );
                     proto_item_set_len( path_seg_item, 2 + seg_size );
                  }
                  pathpos += (2 + seg_size);

                  break;

               default:
                  expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Sub-Segment Type");
                  return;

            } /* End of switch sub-type */

            break;

         case CI_NETWORK_SEGMENT:

            /* Network segment -Determine the segment sub-type */
            if ( generate )
            {
               it = proto_tree_add_uint(path_seg_tree, hf_cip_network_seg_type, NULL, 0, 0, segment_type & CI_NETWORK_SEG_TYPE_MASK);
               PROTO_ITEM_SET_GENERATED(it);
               net_item = proto_tree_add_text(path_seg_tree, NULL, 0, 0, "%s", val_to_str( (segment_type & CI_NETWORK_SEG_TYPE_MASK), cip_network_segment_type_vals, "Reserved"));
               PROTO_ITEM_SET_GENERATED(net_item);
            }
            else
            {
               proto_tree_add_item(path_seg_tree, hf_cip_network_seg_type, tvb, offset+pathpos, 1, ENC_LITTLE_ENDIAN );
               net_item = proto_tree_add_text(path_seg_tree, tvb, offset + pathpos, 1, "%s", val_to_str( (segment_type & CI_NETWORK_SEG_TYPE_MASK), cip_network_segment_type_vals, "Reserved"));
            }

            proto_item_append_text( path_seg_item, " (%s)", val_to_str( (segment_type & CI_NETWORK_SEG_TYPE_MASK), cip_network_segment_type_vals, "Reserved"));
            net_tree = proto_item_add_subtree( net_item, ett_network_seg  );

            switch( segment_type & CI_NETWORK_SEG_TYPE_MASK )
            {
               case CI_NETWORK_SEG_SCHEDULE:
                  proto_tree_add_item(net_tree, hf_cip_seg_schedule, tvb, offset+pathpos+1, 1, ENC_LITTLE_ENDIAN );

                  proto_item_set_len( net_item, 2);
                  proto_item_set_len( path_seg_item, 2);
                  pathpos += 2;
                  break;

               case CI_NETWORK_SEG_FIXED_TAG:
                  proto_tree_add_item(net_tree, hf_cip_seg_fixed_tag, tvb, offset+pathpos+1, 1, ENC_LITTLE_ENDIAN );

                  proto_item_set_len( net_item, 2);
                  proto_item_set_len( path_seg_item, 2);
                  pathpos += 2;
                  break;

               case CI_NETWORK_SEG_PROD_INHI:

                  temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
                  proto_tree_add_uint_format_value(net_tree, hf_cip_seg_prod_inhibit_time,
                     tvb, offset + pathpos+1, 1, temp_data, "%dms", temp_data);

                  proto_item_set_len( net_item, 2);
                  proto_item_set_len( path_seg_item, 2);
                  pathpos += 2;
                  break;

               default:
                  expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Sub-Segment Type");
                  return;

            } /* End of switch sub-type */

            break;

         default:
            expert_add_info_format(pinfo, epath_item, PI_PROTOCOL, PI_ERROR, "Unsupported Segment Type");
            return;

      } /* end of switch( segment_type & CI_SEGMENT_TYPE_MASK ) */

      /* Next path segment */
      if( pathpos < path_length )
         proto_item_append_text( epath_item, ", " );

   } /* end of while( pathpos < path_length ) */

} /* end of dissect_epath() */

static int
dissect_cip_attribute(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                         attribute_info_t* attr, int offset, int total_len)
{
	int i, temp_data,
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
   case cip_byte_array:
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, total_len, ENC_NA);
      consumed = total_len;
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
      proto_tree_add_item(tree, *(attr->phf), tvb, offset, 8, ENC_LITTLE_ENDIAN);
      consumed = 8;
      break;
   case cip_short_string:
      temp_data = tvb_get_guint8( tvb, offset );
      proto_tree_add_item(tree, *(attr->phf), tvb, offset+1, temp_data, ENC_ASCII|ENC_NA);
      consumed = 1+temp_data;
      break;
   case cip_string:
      temp_data = tvb_get_letohs( tvb, offset );
      proto_tree_add_item(tree, *(attr->phf), tvb, offset+2, temp_data, ENC_ASCII|ENC_NA);
      consumed = 2+temp_data;
      break;
   case cip_dissector_func:
      consumed = attr->pdissect(pinfo, tree, item, tvb, offset, total_len);
      break;
   case cip_date:
   case cip_time_of_day:
   case cip_date_and_time:
   case cip_string2:
   case cip_stringN:
   case cip_stringi:
      /* CURRENTLY NOT SUPPORTED */
      expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "Unsupported Datatype");
      break;
   }

   return consumed;
}

/************************************************
 *
 * Dissector for generic CIP object
 *
 ************************************************/

static void
dissect_cip_generic_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo, proto_item *ti )
{
   proto_item *pi;
   proto_tree *cmd_data_tree;
   int req_path_size;
   unsigned char add_stat_size;

   if( tvb_get_guint8( tvb, offset ) & 0x80 )
   {
      /* Response message */
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

         /* Add data */
         proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
      }
      else
      {
         PROTO_ITEM_SET_HIDDEN( ti );
      }

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  cip_sc_vals , "Unknown Service (0x%02x)") );

      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

         proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
      }
      else
      {
         PROTO_ITEM_SET_HIDDEN( ti );
      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_generic_data() */

static int
dissect_cip_class_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_generic, tvb, 0, -1, ENC_NA);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_generic );

      dissect_cip_generic_data( class_tree, tvb, 0, tvb_length(tvb), pinfo, ti );
   }

   return tvb_length(tvb);
}

static void
dissect_cip_set_attribute_single_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   attribute_info_t* attr;

   attr = cip_get_attribute(req_data->iClass, req_data->iInstance, req_data->iAttribute);
   if (attr != NULL)
   {
      dissect_cip_attribute(pinfo, tree, item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
   }
   else
   {
      proto_tree_add_item(tree, hf_cip_sc_set_attr_single_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
   }
}

static void
dissect_cip_get_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, att_count, att_value;
   attribute_info_t* pattribute;
   proto_item *att_list, *att_item;
   proto_tree* att_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Get Attribute List service");
      return;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_get_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list = proto_tree_add_text(tree, tvb, offset+2, att_count*2, "Attribute List" );
   att_tree = proto_item_add_subtree( att_list, ett_cip_get_attribute_list);

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset+2);
      att_item = proto_tree_add_item(att_tree, hf_cip_sc_get_attr_list_attr_item, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
      pattribute = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (pattribute != NULL)
         proto_item_append_text(att_item, " (%s)", pattribute->text);

      offset += 2;
      if ((tvb_reported_length_remaining(tvb, offset+2) < 2) && (i < att_count-1))
      {
         expert_add_info_format(pinfo, att_list, PI_MALFORMED, PI_ERROR, "Get Attribute List attribute list count greater than packet size");
         break;
      }
   }
}

static void
dissect_cip_set_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count,
       att_value, att_size;
   attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Set Attribute List service");
      return;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_set_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list = proto_tree_add_text(tree, tvb, offset+2, att_count*4, "Attribute List" );
   att_list_tree = proto_item_add_subtree( att_list, ett_cip_set_attribute_list);
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_sc_set_attr_list_attr_item, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_set_attribute_list_item);
      offset += 2;

      attr = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (attr != NULL)
      {
         proto_item_append_text(att_item, " (%s)", attr->text);
         /* provide attribute data */
         att_size = dissect_cip_attribute(pinfo, att_tree, att_item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
         offset += att_size;
         proto_item_set_len(att_item, att_size+4);
      }
      else
      {
         /* Can't find the attribute, treat the rest of the request as raw data */
         proto_tree_add_item(att_tree, hf_cip_sc_set_attr_list_attr_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      }

      if ((tvb_reported_length_remaining(tvb, offset) < 2) && (i < att_count-1))
      {
         expert_add_info_format(pinfo, att_list, PI_MALFORMED, PI_ERROR, "Set Attribute List attribute list count greater than packet size");
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );
}

static void
dissect_cip_multiple_service_packet_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset)
{
   proto_item *mult_serv_item;
   proto_tree *mult_serv_tree;
   int i, num_services, serv_offset, prev_offset = 0;
   cip_req_info_t *cip_req_info, *mr_single_req_info;
   mr_mult_req_info_t *mr_mult_req_info = NULL;

   /* Add number of services */
   num_services = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_mult_serv_pack_num_services, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add services */
   cip_req_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );
   if ( cip_req_info )
   {
      if ( cip_req_info->pData == NULL )
      {
         mr_mult_req_info = se_alloc(sizeof(mr_mult_req_info_t));
         mr_mult_req_info->service = SC_MULT_SERV_PACK;
         mr_mult_req_info->num_services = num_services;
         mr_mult_req_info->requests = se_alloc(sizeof(cip_req_info_t)*num_services);
         memset(mr_mult_req_info->requests, 0, sizeof(cip_req_info_t)*num_services);
         cip_req_info->pData = mr_mult_req_info;
      }
      else
      {
         mr_mult_req_info = (mr_mult_req_info_t*)cip_req_info->pData;
         if ( mr_mult_req_info && mr_mult_req_info->num_services != num_services )
            mr_mult_req_info = NULL;
      }
   }

   for( i=0; i < num_services; i++ )
   {
      int serv_length;
      tvbuff_t *next_tvb;

      serv_offset = tvb_get_letohs( tvb, offset+2+(i*2) );

      if (tvb_reported_length_remaining(tvb, serv_offset) <= 0)
      {
         expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Multiple Service Packet service invalid offset");
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

      mult_serv_item = proto_tree_add_text(tree, tvb, offset+serv_offset, serv_length, "Service Packet #%d", i+1 );
      mult_serv_tree = proto_item_add_subtree(mult_serv_item, ett_cip_mult_service_packet );
      proto_tree_add_item(mult_serv_tree, hf_cip_sc_mult_serv_pack_offset, tvb, offset+2+(i*2) , 2, ENC_LITTLE_ENDIAN);

      /* Make sure the offset is valid */
      if ((tvb_reported_length_remaining(tvb, serv_offset) <= 0) ||
          (tvb_reported_length_remaining(tvb, serv_offset+serv_length) <= 0) ||
          (serv_length <= 0) ||
          (prev_offset >= serv_offset))
      {
         expert_add_info_format(pinfo, mult_serv_item, PI_MALFORMED, PI_WARN, "Multiple Service Packet service invalid offset");
         prev_offset = serv_offset;
         continue;
      }
      prev_offset = serv_offset;

      /*
      ** We call our selves again to disect embedded packet
      */

      col_append_str( pinfo->cinfo, COL_INFO, ", ");

      next_tvb = tvb_new_subset(tvb, offset+serv_offset, serv_length, serv_length);

      if ( mr_mult_req_info )
      {
         mr_single_req_info = mr_mult_req_info->requests + i;
         dissect_cip_data(mult_serv_tree, next_tvb, 0, pinfo, mr_single_req_info );
      }
      else
      {
         dissect_cip_data(mult_serv_tree, next_tvb, 0, pinfo, NULL );
      }
   }

}

static int
dissect_cip_generic_service_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, cip_simple_request_info_t* req_data)
{
   proto_item *cmd_data_item;
   int req_path_size,
       offset = 0;
   proto_tree *cmd_data_tree;
   guint8 service = tvb_get_guint8( tvb, offset ) & 0x7F;

   /* Add service to info column */
   col_append_str( pinfo->cinfo, COL_INFO,
            val_to_str(service, cip_sc_vals , "Unknown Service (0x%02x)") );

   /* Create service tree */
   cmd_data_item = proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "%s",
                        val_to_str(service, cip_sc_vals , "Unknown Service (0x%02x)"));
   proto_item_append_text(cmd_data_item, " (Request)");
   cmd_data_tree = proto_item_add_subtree( cmd_data_item, ett_cmd_data );

   req_path_size = tvb_get_guint8( tvb, offset+1);
   offset += ((req_path_size*2)+2);
   if (tvb_reported_length_remaining(tvb, offset) <= 0)
      return tvb_reported_length(tvb);

   switch(service)
   {
   case SC_GET_ATT_ALL:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_get_attribute_all_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_SET_ATT_ALL:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_set_attribute_all_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_GET_ATT_LIST:
      dissect_cip_get_attribute_list_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_SET_ATT_LIST:
      dissect_cip_set_attribute_list_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_RESET:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_reset_param, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_reset_data, tvb, offset+1, tvb_reported_length_remaining(tvb, offset+1), ENC_NA);
      break;
   case SC_START:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_start_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_STOP:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_stop_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_CREATE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_create_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_DELETE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_delete_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_MULT_SERV_PACK:
      dissect_cip_multiple_service_packet_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset);
      break;
   case SC_APPLY_ATTRIBUTES:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_apply_attributes_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_GET_ATT_SINGLE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_get_attr_single_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_SET_ATT_SINGLE:
      dissect_cip_set_attribute_single_req(tvb, pinfo, cmd_data_tree, cmd_data_item, offset, req_data);
      break;
   case SC_FIND_NEXT_OBJ_INST:
      proto_tree_add_item(cmd_data_tree, hf_cip_find_next_object_max_instance, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      break;
   case SC_RESTOR:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_restore_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_SAVE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_save_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_NO_OP:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_noop_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_GET_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_get_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_SET_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_set_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_INSERT_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_insert_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_REMOVE_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_remove_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_GROUP_SYNC:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_group_sync_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   }

   return tvb_length(tvb);
}

static void
dissect_cip_get_attribute_list_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count,
       att_value, att_status;
   guint att_size;
   attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Get Attribute List service");
      return;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_get_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list = proto_tree_add_text(tree, tvb, offset+2, att_count*4, "Attribute List" );
   att_list_tree = proto_item_add_subtree( att_list, ett_cip_get_attribute_list);
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_sc_get_attr_list_attr_item, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_get_attribute_list_item);

      att_status = tvb_get_letohs( tvb, offset+2);
      proto_tree_add_item(att_tree, hf_cip_sc_get_attr_list_attr_status, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);

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
            /* Can't find the attribute, treat the rest of the response as raw data */
            proto_tree_add_item(att_tree, hf_cip_sc_get_attr_list_attr_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
            break;
         }
      }

      if ((tvb_reported_length_remaining(tvb, offset) < 4) && (i < att_count-1))
      {
         expert_add_info_format(pinfo, att_list, PI_MALFORMED, PI_ERROR, "Get Attribute List attribute list count greater than packet size");
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );
}

static void
dissect_cip_set_attribute_list_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   int i, start_offset, att_count, att_value;
   attribute_info_t* attr;
   proto_item *att_list, *att_item;
   proto_tree *att_tree, *att_list_tree;

   /* Get attribute list request */
   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Malformed Set Attribute List service");
      return;
   }

   /* Add number of attributes */
   att_count = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_set_attr_list_attr_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   /* Add Attribute List */
   att_list = proto_tree_add_text(tree, tvb, offset+2, att_count*4, "Attribute List" );
   att_list_tree = proto_item_add_subtree( att_list, ett_cip_get_attribute_list);
   offset += 2;
   start_offset = offset;

   for( i=0; i < att_count; i++ )
   {
      att_value = tvb_get_letohs( tvb, offset);
      att_item = proto_tree_add_item(att_list_tree, hf_cip_sc_set_attr_list_attr_item, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      att_tree = proto_item_add_subtree( att_item, ett_cip_set_attribute_list_item);

      proto_tree_add_item(att_tree, hf_cip_sc_set_attr_list_attr_status, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);

      attr = cip_get_attribute(req_data->iClass, req_data->iInstance, att_value);
      if (attr != NULL)
         proto_item_append_text(att_item, " (%s)", attr->text);

      offset += 4;
      if ((tvb_reported_length_remaining(tvb, offset) < 4) && (i < att_count-1))
      {
         expert_add_info_format(pinfo, att_list, PI_MALFORMED, PI_ERROR, "Set Attribute List attribute list count greater than packet size");
         break;
      }
   }

   proto_item_set_len(att_list, offset-start_offset );
}

static void
dissect_cip_get_attribute_single_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
                                  int offset, cip_simple_request_info_t* req_data)
{
   attribute_info_t* attr;

   attr = cip_get_attribute(req_data->iClass, req_data->iInstance, req_data->iAttribute);
   if (attr != NULL)
   {
      proto_item_append_text(item, " (%s)", attr->text);
      dissect_cip_attribute(pinfo, tree, item, tvb, attr, offset, tvb_reported_length_remaining(tvb, offset));
   }
   else
   {
      /* Can't find the attribute, treat the rest of the response as raw data */
      proto_tree_add_item(tree, hf_cip_sc_get_attr_single_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
   }
}

static void
dissect_cip_multiple_service_packet_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset)
{
   proto_item *mult_serv_item;
   proto_tree *mult_serv_tree;
   int i, num_services, serv_offset;
   cip_req_info_t *cip_req_info, *mr_single_req_info;
   mr_mult_req_info_t *mr_mult_req_info = NULL;

   if (tvb_reported_length_remaining(tvb, offset) < 2)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Multiple Service Packet service missing Number of Services field");
      return;
   }

   num_services = tvb_get_letohs( tvb, offset);
   proto_tree_add_item(tree, hf_cip_sc_mult_serv_pack_num_replies, tvb, offset, 2, ENC_LITTLE_ENDIAN);

   if (tvb_reported_length_remaining(tvb, offset+((num_services+1)*2)) <= 0)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Multiple Service Packet service too many response offsets for packet size");
      return;
   }

   cip_req_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );
   if ( cip_req_info )
   {
      mr_mult_req_info = (mr_mult_req_info_t*)cip_req_info->pData;

      if (  mr_mult_req_info
         && (  mr_mult_req_info->service != SC_MULT_SERV_PACK
            || mr_mult_req_info->num_services != num_services
            )
         )
         mr_mult_req_info = NULL;
   }

   /* Add number of replies */
   for( i=0; i < num_services; i++ )
   {
      int serv_length;
      tvbuff_t *next_tvb;

      serv_offset = tvb_get_letohs( tvb, offset+2+(i*2) );

      if (tvb_reported_length_remaining(tvb, serv_offset) <= 0)
      {
         expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Multiple Service Packet service invalid offset");
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

      mult_serv_item = proto_tree_add_text( tree, tvb, offset+serv_offset, serv_length, "Service Reply #%d", i+1 );
      mult_serv_tree = proto_item_add_subtree( mult_serv_item, ett_cip_mult_service_packet );
      proto_tree_add_item(mult_serv_tree, hf_cip_sc_mult_serv_pack_offset, tvb, offset+2+(i*2) , 2, ENC_LITTLE_ENDIAN);

      /*
      ** We call our selves again to disect embedded packet
      */

      col_append_str( pinfo->cinfo, COL_INFO, ", ");

      next_tvb = tvb_new_subset(tvb, offset+serv_offset, serv_length, serv_length);
      if ( mr_mult_req_info )
      {
         mr_single_req_info = mr_mult_req_info->requests + i;
         dissect_cip_data( mult_serv_tree, next_tvb, 0, pinfo, mr_single_req_info );
      }
      else
      {
         dissect_cip_data( mult_serv_tree, next_tvb, 0, pinfo, NULL );
      }
   }

}

static void
dissect_cip_find_next_object_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset)
{
   guint8 i, num_instances;

   if (tvb_reported_length_remaining(tvb, offset) < 1)
   {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Find Next Object service missing Number of List Members field");
      return;
   }

   num_instances = tvb_get_guint8( tvb, offset);
   proto_tree_add_item(tree, hf_cip_find_next_object_num_instances, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   offset += 1;
   for (i = 0; i < num_instances; i++)
   {
      proto_tree_add_item(tree, hf_cip_find_next_object_instance_item, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      if ((tvb_reported_length_remaining(tvb, offset) < 2) && (i < num_instances-1))
      {
         expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Find Next Object instance list count greater than packet size");
         break;
      }
   }
}

static int
dissect_cip_generic_service_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *cmd_data_item;
   proto_tree *cmd_data_tree;
   cip_req_info_t* preq_info;
   cip_simple_request_info_t req_data;
   int offset = 0,
       item_length = tvb_length(tvb);
   guint8 service = tvb_get_guint8( tvb, offset ) & 0x7F,
          add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

   /* If there is any command specific data create a sub-tree for it */
   if( (item_length-4-add_stat_size ) != 0 )
   {
      cmd_data_item = proto_tree_add_text(tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "%s",
                           val_to_str(service, cip_sc_vals , "Unknown Service (0x%02x)"));
      proto_item_append_text(cmd_data_item, " (Response)");
      cmd_data_tree = proto_item_add_subtree( cmd_data_item, ett_cmd_data );
   }
   else
   {
/*      PROTO_ITEM_SET_HIDDEN( ti ); */
      return tvb_length(tvb);
   }

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

   switch(service)
   {
   case SC_GET_ATT_ALL:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_get_attribute_all_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_SET_ATT_ALL:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_set_attribute_all_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_GET_ATT_LIST:
      dissect_cip_get_attribute_list_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset+4+add_stat_size, &req_data);
      break;
   case SC_SET_ATT_LIST:
      dissect_cip_set_attribute_list_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset+4+add_stat_size, &req_data);
      break;
   case SC_RESET:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_reset_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_START:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_start_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_STOP:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_stop_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_CREATE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_create_instance, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_create_data, tvb, offset+4+add_stat_size+2, tvb_reported_length_remaining(tvb, offset+4+add_stat_size+2), ENC_NA);
      break;
   case SC_DELETE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_delete_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_MULT_SERV_PACK:
      dissect_cip_multiple_service_packet_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset+4+add_stat_size);
      break;
   case SC_APPLY_ATTRIBUTES:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_apply_attributes_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_GET_ATT_SINGLE:
      dissect_cip_get_attribute_single_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset+4+add_stat_size, &req_data);
      break;
   case SC_SET_ATT_SINGLE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_set_attr_single_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_FIND_NEXT_OBJ_INST:
      dissect_cip_find_next_object_rsp(tvb, pinfo, cmd_data_tree, cmd_data_item, offset+4+add_stat_size);
      break;
   case SC_RESTOR:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_restore_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_SAVE:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_save_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_NO_OP:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_noop_data, tvb, offset+4+add_stat_size, tvb_reported_length_remaining(tvb, offset+4+add_stat_size), ENC_NA);
      break;
   case SC_GET_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_get_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_SET_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_set_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_INSERT_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_insert_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_REMOVE_MEMBER:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_remove_member_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
      break;
   case SC_GROUP_SYNC:
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_group_sync_is_sync, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(cmd_data_tree, hf_cip_sc_group_sync_data, tvb, offset+4+add_stat_size+1, tvb_reported_length_remaining(tvb, offset+4+add_stat_size+1), ENC_NA);
      break;
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Manager
 *
 ************************************************/

static void
dissect_cip_cm_timeout(proto_tree *cmd_tree, tvbuff_t *tvb, int offset)
{
   guint8 tick, timeout_tick;
   int timeout;

   /* Display the priority/tick timer */
   tick = tvb_get_guint8( tvb, offset) & 0x0F;
   proto_tree_add_item( cmd_tree, hf_cip_cm_priority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( cmd_tree, hf_cip_cm_tick_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   /* Display the time-out ticks */
   timeout_tick = tvb_get_guint8( tvb, offset+1 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_timeout_tick, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);

   /* Display the actual time out */
   timeout = ( 1 << tick ) * timeout_tick;
   proto_tree_add_uint_format_value(cmd_tree, hf_cip_cm_timeout, tvb, offset, 2, timeout, "%dms", timeout);
}

static void
dissect_cip_cm_fwd_open_req(cip_req_info_t *preq_info, proto_tree *cmd_tree, tvbuff_t *tvb, int offset, gboolean large_fwd_open, packet_info *pinfo)
{
   proto_item *pi;
   int conn_path_size, rpi, net_param_offset = 0;
   guint32 O2TConnID, T2OConnID, DeviceSerialNumber;
   guint16 ConnSerialNumber, VendorID;
   guint8 TransportClass, O2TType, T2OType;

   dissect_cip_cm_timeout(cmd_tree, tvb, offset);
   O2TConnID = tvb_get_letohl( tvb, offset+2 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_ot_connid, tvb, offset+2, 4, ENC_LITTLE_ENDIAN);
   T2OConnID = tvb_get_letohl( tvb, offset+6 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_to_connid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN);
   ConnSerialNumber = tvb_get_letohs( tvb, offset+10 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_conn_serial_num, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
   VendorID = tvb_get_letohs( tvb, offset+12 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_vendor, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
   DeviceSerialNumber = tvb_get_letohl( tvb, offset+14 );
   proto_tree_add_item( cmd_tree, hf_cip_cm_orig_serial_num, tvb, offset+14, 4, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( cmd_tree, hf_cip_cm_timeout_multiplier, tvb, offset+18, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item( cmd_tree, hf_cip_reserved24, tvb, offset+19, 3, ENC_LITTLE_ENDIAN);

   /* Display originator to target requested packet interval */
   rpi = tvb_get_letohl( tvb, offset+22 );
   proto_tree_add_uint_format_value(cmd_tree, hf_cip_cm_ot_rpi, tvb, offset+22, 4, rpi, "%dms (0x%08X)", rpi / 1000, rpi);

   /* Display originator to target network connection parameters as a tree */
   if (large_fwd_open)
   {
      dissect_net_param32(tvb, offset+26, cmd_tree,
                 hf_cip_cm_ot_net_params32, hf_cip_cm_lfwo_own, hf_cip_cm_lfwo_typ,
                 hf_cip_cm_lfwo_prio, hf_cip_cm_lfwo_fixed_var, hf_cip_cm_lfwo_con_size, ett_cm_ncp);

      O2TType = (guint8)(((tvb_get_letohl( tvb, offset+26 ) & 0x60000000) >> 29) & 3);
      net_param_offset = 4;
   }
   else
   {
      dissect_net_param16(tvb, offset+26, cmd_tree,
                 hf_cip_cm_ot_net_params16, hf_cip_cm_fwo_own, hf_cip_cm_fwo_typ,
                 hf_cip_cm_fwo_prio, hf_cip_cm_fwo_fixed_var, hf_cip_cm_fwo_con_size, ett_cm_ncp);

      O2TType = (guint8)(((tvb_get_letohs( tvb, offset+26 ) & 0x6000) >> 13) & 3);
      net_param_offset = 2;
   }

   /* Display target to originator requested packet interval */
   rpi = tvb_get_letohl( tvb, offset+26+net_param_offset );
   proto_tree_add_uint_format_value(cmd_tree, hf_cip_cm_to_rpi, tvb, offset+26+net_param_offset, 4, rpi, "%dms (0x%08X)", rpi / 1000, rpi);

   /* Display target to originator network connection parameters as a tree */
   if (large_fwd_open)
   {
      dissect_net_param32(tvb, offset+26+net_param_offset+4, cmd_tree,
                 hf_cip_cm_to_net_params32, hf_cip_cm_lfwo_own, hf_cip_cm_lfwo_typ,
                 hf_cip_cm_lfwo_prio, hf_cip_cm_lfwo_fixed_var, hf_cip_cm_lfwo_con_size, ett_cm_ncp);

      T2OType = (guint8)(((tvb_get_letohl( tvb, offset+26+net_param_offset+4 ) & 0x60000000) >> 29) & 3);
      net_param_offset += 4;
   }
   else
   {
      dissect_net_param16(tvb, offset+26+net_param_offset+4, cmd_tree,
                 hf_cip_cm_to_net_params16, hf_cip_cm_fwo_own, hf_cip_cm_fwo_typ,
                 hf_cip_cm_fwo_prio, hf_cip_cm_fwo_fixed_var, hf_cip_cm_fwo_con_size, ett_cm_ncp);

      T2OType = (guint8)(((tvb_get_letohs( tvb, offset+26+net_param_offset+4 ) & 0x6000) >> 13) & 3);
      net_param_offset += 2;
   }

   TransportClass = tvb_get_guint8( tvb, offset+26+net_param_offset+4) & 0x0F;
   dissect_transport_type_trigger(tvb, offset+26+net_param_offset+4, cmd_tree, hf_cip_cm_transport_type_trigger,
                                  hf_cip_cm_fwo_dir, hf_cip_cm_fwo_trigg, hf_cip_cm_fwo_class, ett_cm_ttt);

   /* Add path size */
   conn_path_size = tvb_get_guint8( tvb, offset+26+net_param_offset+5 )*2;
   proto_tree_add_uint_format_value(cmd_tree, hf_cip_cm_conn_path_size, tvb, offset+26+net_param_offset+5, 1, conn_path_size/2, "%d (words)", conn_path_size/2);

   /* Add the epath */
   pi = proto_tree_add_text(cmd_tree, tvb, offset+26+net_param_offset+6, conn_path_size, "Connection Path: ");
   dissect_epath( tvb, pinfo, pi, offset+26+net_param_offset+6, conn_path_size, FALSE, NULL);

   if (pinfo->fd->flags.visited)
      return;

   if (preq_info != NULL)
   {
      DISSECTOR_ASSERT(preq_info->connInfo == NULL);
      preq_info->connInfo = se_alloc(sizeof(cip_conn_info_t));

      preq_info->connInfo->ConnSerialNumber = ConnSerialNumber;
      preq_info->connInfo->VendorID = VendorID;
      preq_info->connInfo->DeviceSerialNumber = DeviceSerialNumber;
      preq_info->connInfo->O2T.connID = O2TConnID;
      preq_info->connInfo->T2O.connID = T2OConnID;
      preq_info->connInfo->TransportClass = TransportClass;
      preq_info->connInfo->T2O.type = T2OType;
      preq_info->connInfo->O2T.type = O2TType;
      /* To be filled in by Ethernet/IP encap layer */
      preq_info->connInfo->O2T.ipaddress = 0;
      preq_info->connInfo->O2T.port = 0;
      preq_info->connInfo->T2O.ipaddress = 0;
      preq_info->connInfo->T2O.port = 0;
   }
}

static void
dissect_cip_cm_fwd_open_rsp_success(cip_req_info_t *preq_info, proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
   int temp_data;
   unsigned char app_rep_size;
   guint32 O2TConnID, T2OConnID, DeviceSerialNumber;
   guint16 ConnSerialNumber, VendorID;

   /* Display originator to target connection ID */
   O2TConnID = tvb_get_letohl( tvb, offset );
   proto_tree_add_item( tree, hf_cip_cm_ot_connid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

   /* Display target to originator connection ID */
   T2OConnID = tvb_get_letohl( tvb, offset+4 );
   proto_tree_add_item( tree, hf_cip_cm_to_connid, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);

   /* Display connection serial number */
   ConnSerialNumber = tvb_get_letohs( tvb, offset+8 );
   proto_tree_add_item( tree, hf_cip_cm_conn_serial_num, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);

   /* Display the originator vendor id */
   VendorID = tvb_get_letohs( tvb, offset+10 );
   proto_tree_add_item( tree, hf_cip_cm_vendor, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);

   /* Display the originator serial number */
   DeviceSerialNumber = tvb_get_letohl( tvb, offset+12 );
   proto_tree_add_item( tree, hf_cip_cm_orig_serial_num, tvb, offset+12, 4, ENC_LITTLE_ENDIAN);

   /* Display originator to target actual packet interval */
   temp_data = tvb_get_letohl( tvb, offset+16 );
   proto_tree_add_uint_format_value(tree, hf_cip_cm_ot_api, tvb, offset+16, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

   /* Display originator to target actual packet interval */
   temp_data = tvb_get_letohl( tvb, offset+20 );
   proto_tree_add_uint_format_value(tree, hf_cip_cm_to_api, tvb, offset+20, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

   /* Display the application reply size */
   app_rep_size = tvb_get_guint8( tvb, offset+24 ) * 2;
   proto_tree_add_uint_format_value(tree, hf_cip_cm_app_reply_size, tvb, offset+24, 1, app_rep_size / 2, "%d (words)", app_rep_size / 2);

   /* Display the Reserved byte */
   proto_tree_add_item(tree, hf_cip_reserved8, tvb, offset+25, 1, ENC_LITTLE_ENDIAN );
   if (app_rep_size > 0)
      proto_tree_add_item(tree, hf_cip_cm_app_reply_data, tvb, offset+26, app_rep_size, ENC_NA );

   /* See if we've captured the ForwardOpen request.  If so some of the conversation data has already been
      populated and we just need to update it. */
   if (pinfo->fd->flags.visited)
      return;

   if ((preq_info != NULL) && (preq_info->connInfo != NULL))
   {
      /* Ensure the connection triad matches before updating the connection IDs */
      if ((preq_info->connInfo->ConnSerialNumber == ConnSerialNumber) &&
          (preq_info->connInfo->VendorID == VendorID) &&
          (preq_info->connInfo->DeviceSerialNumber == DeviceSerialNumber))
      {
         /* Update the connection IDs as ForwardOpen reply is allows to update them from
            the ForwardOpen request */
         preq_info->connInfo->O2T.connID = O2TConnID;
         preq_info->connInfo->T2O.connID = T2OConnID;
      }
   }
}

static void
dissect_cip_cm_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item, *status_item, *add_status_item, *temp_item;
   proto_tree *rrsc_tree, *cmd_data_tree, *status_tree, *add_status_tree, *temp_tree;
   int req_path_size, conn_path_size, temp_data;
   unsigned char service, gen_status, add_stat_size;
   unsigned short add_status;
   unsigned char app_rep_size, route_path_size;
   int i, msg_req_siz;
   cip_req_info_t *preq_info;
   cip_req_info_t *pembedded_req_info;
   guint16 ConnSerialNumber, VendorID;
   guint32 DeviceSerialNumber;

   service = tvb_get_guint8( tvb, offset );

   /* Special handling for Unconnected send response. If successful, embedded service code is sent.
    * If failed, it can be either an Unconnected send response or the embedded service code response. */
   preq_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );
   if (  preq_info != NULL && ( service & 0x80 )
      && preq_info->bService == SC_CM_UNCON_SEND
      )
   {
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;
      if ( add_stat_size == 2 )
         add_status = tvb_get_letohs( tvb, offset + 4 );
      else
         add_status = 0;
      if(   gen_status == 0   /* success response ) */
         || ( ( service & 0x7F ) != SC_CM_UNCON_SEND )
         || !(  ( gen_status == CI_GRC_FAILURE && (add_status == CM_ES_UNCONNECTED_REQUEST_TIMED_OUT ||
                                                   add_status == CM_ES_PORT_NOT_AVAILABLE ||
                                                   add_status == CM_ES_LINK_ADDRESS_NOT_VALID ||
                                                   add_status == CM_ES_INVALID_SEGMENT_IN_CONN_PATH) )
             || gen_status == CI_GRC_NO_RESOURCE
             || gen_status == CI_GRC_BAD_PATH
             )
         )
      {
         pembedded_req_info = (cip_req_info_t*)preq_info->pData;

         if ( pembedded_req_info )
         {
            tvbuff_t *next_tvb;
            void *p_save_proto_data;

            p_save_proto_data = p_get_proto_data( pinfo->fd, proto_cip );
            p_remove_proto_data(pinfo->fd, proto_cip);
            p_add_proto_data(pinfo->fd, proto_cip, pembedded_req_info );

            proto_tree_add_text( item_tree, NULL, 0, 0, "(Service: Unconnected Send (Response))" );
            next_tvb = tvb_new_subset(tvb, offset, item_length, item_length);
            if ( pembedded_req_info && pembedded_req_info->dissector )
               call_dissector(pembedded_req_info->dissector, next_tvb, pinfo, item_tree );
            else
               call_dissector( cip_class_generic_handle, next_tvb, pinfo, item_tree );

            p_remove_proto_data(pinfo->fd, proto_cip);
            p_add_proto_data(pinfo->fd, proto_cip, p_save_proto_data);
            return;
         }
      }
   }

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CM");

   /* Add Service code & Request/Response tree */
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_cm_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cm , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_cm_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( service & 0x80 )
   {
      /* Response message */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      if (gen_status == CI_GRC_FAILURE)
      {
         /* Dissect object specific error codes */
         status_item = proto_tree_add_text(item_tree, tvb, offset+2, 1, "Status: " );
         status_tree = proto_item_add_subtree( status_item, ett_status_item );

         /* Add general status */
         proto_tree_add_item(status_tree, hf_cip_cm_genstat, tvb, offset+2, 1, ENC_LITTLE_ENDIAN );
         proto_item_append_text( status_item, "%s", val_to_str_ext( gen_status,
                        &cip_gs_vals_ext , "Unknown Response (%x)")   );

         /* Add additional status size */
         proto_tree_add_uint_format_value(status_tree, hf_cip_cm_addstat_size,
            tvb, offset+3, 1, add_stat_size/2, "%d (words)", add_stat_size/2);

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
                  expert_add_info_format(pinfo, status_item, PI_MALFORMED, PI_WARN, "RPI not acceptable - missing extended data");
               }
               else
               {
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_ot_rpi_type, tvb, offset+6, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(status_tree, hf_cip_cm_ext112_to_rpi_type, tvb, offset+7, 1, ENC_LITTLE_ENDIAN );
                  temp_data = tvb_get_letohl( tvb, offset+8);
                  proto_tree_add_uint_format_value(status_tree, hf_cip_cm_ext112_ot_rpi, tvb, offset+8, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);
                  temp_data = tvb_get_letohl( tvb, offset+12);
                  proto_tree_add_uint_format_value(status_tree, hf_cip_cm_ext112_to_rpi, tvb, offset+12, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);
               }
               break;
            case CM_ES_INVALID_CONFIGURATION_SIZE:
               if (add_stat_size < 1)
               {
                  expert_add_info_format(pinfo, status_item, PI_MALFORMED, PI_WARN, "Invalid configuration size - missing size field");
               }
               else
               {
                  proto_tree_add_item(status_tree, hf_cip_cm_ext126_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               }
               break;
            case CM_ES_INVALID_OT_SIZE:
               if (add_stat_size < 1)
               {
                  expert_add_info_format(pinfo, status_item, PI_MALFORMED, PI_WARN, "Invalid O->T size - missing size field");
               }
               else
               {
                  proto_tree_add_item(status_tree, hf_cip_cm_ext127_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               }
               break;
            case CM_ES_INVALID_TO_SIZE:
               if (add_stat_size < 1)
               {
                  expert_add_info_format(pinfo, status_item, PI_MALFORMED, PI_WARN, "Invalid T->O size - missing size field");
               }
               else
               {
                  proto_tree_add_item(status_tree, hf_cip_cm_ext128_size, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );
               }
               break;
            default:
               /* Add additional status */
               if (add_stat_size > 1)
               {
                  add_status_item = proto_tree_add_text( status_tree, tvb, offset+4, add_stat_size, "Additional Status" );
                  add_status_tree = proto_item_add_subtree( add_status_item, ett_cm_add_status_item );

                  for( i=0; i < add_stat_size-2; i += 2 )
                     proto_tree_add_item(add_status_tree, hf_cip_cm_add_status, tvb, offset+4+i, 2, ENC_LITTLE_ENDIAN );
               }
            }
         }
      }

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cm_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
           /* Success responses */
           switch (service & 0x7F)
           {
           case SC_CM_FWD_OPEN:
           case SC_CM_LARGE_FWD_OPEN:
              dissect_cip_cm_fwd_open_rsp_success(preq_info, cmd_data_tree, tvb, offset+4+add_stat_size, pinfo);
              break;
           case SC_CM_FWD_CLOSE:
           {
               /* Forward close response (Success) */

               /* Display connection serial number */
               ConnSerialNumber = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator vendor id */
               VendorID = tvb_get_letohs( tvb, offset+4+add_stat_size+2 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_vendor, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator serial number */
               DeviceSerialNumber = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+4, 4, ENC_LITTLE_ENDIAN);

               /* Display the application reply size */
               app_rep_size = tvb_get_guint8( tvb, offset+4+add_stat_size+8 ) * 2;
               proto_tree_add_uint_format_value(cmd_data_tree, hf_cip_cm_app_reply_size, tvb, offset+4+add_stat_size+8, 1, app_rep_size / 2, "%d (words)", app_rep_size / 2);

               /* Display the Reserved byte */
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+4+add_stat_size+9, 1, ENC_LITTLE_ENDIAN);
               if (app_rep_size > 0)
                  proto_tree_add_item(cmd_data_tree, hf_cip_cm_app_reply_data, tvb, offset+4+add_stat_size+10, app_rep_size, ENC_NA);

               enip_close_cip_connection( pinfo, ConnSerialNumber, VendorID, DeviceSerialNumber );

            } /* End of if forward close response */
            break;
            case SC_CM_UNCON_SEND:
            {
               /* Unconnected send response (Success) */
               /* Display service response data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
            }
            break;
            case SC_CM_GET_CONN_OWNER:
            {
               /* Get Connection owner response (Success) */

               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_conn, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_coo_conn, tvb, offset+4+add_stat_size+1, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_roo_conn, tvb, offset+4+add_stat_size+2, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_last_action, tvb, offset+4+add_stat_size+3, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size+4, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_vendor, tvb, offset+4+add_stat_size+6, 2, ENC_LITTLE_ENDIAN);
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+8, 4, ENC_LITTLE_ENDIAN);
            }
            break;
            default:
               /* Add data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_LITTLE_ENDIAN);
               break;
            }
         }
         else
         {
            /* Error responses */
            switch (service & 0x7F)
            {
            case SC_CM_FWD_OPEN:
            case SC_CM_LARGE_FWD_OPEN:
            case SC_CM_FWD_CLOSE:

               /* Forward open and forward close error response look the same */
               ConnSerialNumber = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);
               VendorID = tvb_get_letohs( tvb, offset+4+add_stat_size+2 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_vendor, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);
               DeviceSerialNumber = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+4, 4, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(cmd_data_tree, hf_cip_cm_remain_path_size, tvb, offset+4+add_stat_size+8, 1, ENC_LITTLE_ENDIAN);
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+4+add_stat_size+9, 1, ENC_LITTLE_ENDIAN);

               /* With an error reply the connection will either never be established or it has since already closed
                  That means the conversation should end too */
               enip_close_cip_connection(pinfo, ConnSerialNumber, VendorID, DeviceSerialNumber);
               if (preq_info != NULL)
               {
                  /* Remove any connection information */
                  preq_info->connInfo = NULL;
               }
               break;
            case SC_CM_UNCON_SEND:
               /* Unconnected send response (Unsuccess) */
               proto_tree_add_item(cmd_data_tree, hf_cip_cm_remain_path_size, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN);
               break;
            default:
               /* Add data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, ENC_NA);
               break;
            }
         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  cip_sc_vals_cm , "Unknown Service (0x%02x)") );

      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cm_cmd_data );

         /* Check what service code that received */
         switch (service)
         {
         case SC_CM_FWD_OPEN:
            /* Forward open Request*/
            dissect_cip_cm_fwd_open_req(preq_info, cmd_data_tree, tvb, offset+2+req_path_size, FALSE, pinfo);
            break;
         case SC_CM_LARGE_FWD_OPEN:
            /* Large Forward open Request*/
            dissect_cip_cm_fwd_open_req(preq_info, cmd_data_tree, tvb, offset+2+req_path_size, TRUE, pinfo);
            break;
         case SC_CM_FWD_CLOSE:
            /* Forward Close Request */

            dissect_cip_cm_timeout( cmd_data_tree, tvb, offset+2+req_path_size);
            proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item( cmd_data_tree, hf_cip_cm_vendor, tvb, offset+2+req_path_size+4, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+2+req_path_size+6, 4, ENC_LITTLE_ENDIAN);

            /* Add the path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+10 )*2;
            proto_tree_add_uint_format_value(cmd_data_tree, hf_cip_cm_conn_path_size, tvb, offset+2+req_path_size+10, 1, conn_path_size/2, "%d (words)", conn_path_size/2);

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size+11, 1, ENC_LITTLE_ENDIAN);

            /* Add the EPATH */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+12, conn_path_size, "Connection Path: ");
            dissect_epath( tvb, pinfo, pi, offset+2+req_path_size+12, conn_path_size, FALSE, NULL );
            break;
         case SC_CM_UNCON_SEND:
         {
            /* Unconnected send */
            tvbuff_t *next_tvb;

            /* Display timeout fields */
            dissect_cip_cm_timeout( cmd_data_tree, tvb, offset+2+req_path_size);

            /* Message request size */
            msg_req_siz = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_item(cmd_data_tree, hf_cip_cm_msg_req_size, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);

            /* Message Request */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4, msg_req_siz, "Message Request" );
            temp_tree = proto_item_add_subtree(temp_item, ett_cm_mes_req );

            /*
            ** We call our selves again to disect embedded packet
            */

            col_append_str( pinfo->cinfo, COL_INFO, ": ");

            next_tvb = tvb_new_subset(tvb, offset+2+req_path_size+4, msg_req_siz, msg_req_siz);
            preq_info = p_get_proto_data( pinfo->fd, proto_cip );
            pembedded_req_info = NULL;
            if ( preq_info )
            {
               if ( preq_info->pData == NULL )
               {
                  pembedded_req_info = (cip_req_info_t*)se_alloc(sizeof(cip_req_info_t));
                  memset(pembedded_req_info, 0, sizeof(cip_req_info_t));
                  preq_info->pData = pembedded_req_info;
               }
               else
               {
                  pembedded_req_info = (cip_req_info_t*)preq_info->pData;
               }
            }
            dissect_cip_data( temp_tree, next_tvb, 0, pinfo, pembedded_req_info );

            if( msg_req_siz % 2 )
            {
              /* Pad byte */
              proto_tree_add_item(cmd_data_tree, hf_cip_pad8, tvb, offset+2+req_path_size+4+msg_req_siz, 1, ENC_LITTLE_ENDIAN);
              msg_req_siz++;  /* include the padding */
            }

            /* Route Path Size */
            route_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+4+msg_req_siz )*2;
            proto_tree_add_uint_format_value(cmd_data_tree, hf_cip_cm_route_path_size, tvb, offset+2+req_path_size+4+msg_req_siz, 1, route_path_size / 2, "%d (words)", route_path_size / 2);

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size+5+msg_req_siz, 1, ENC_LITTLE_ENDIAN);

            /* Route Path */
            temp_item = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+6+msg_req_siz, route_path_size, "Route Path: ");
            dissect_epath( tvb, pinfo, temp_item, offset+2+req_path_size+6+msg_req_siz, route_path_size, FALSE, NULL );
         }
         break;
         case SC_CM_GET_CONN_OWNER:
            /* Get Connection Owner Request */

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN);

            /* Add path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+1 )*2;
            proto_tree_add_uint_format_value(cmd_data_tree, hf_cip_cm_conn_path_size, tvb, offset+2+req_path_size+1, 1, conn_path_size/2, "%d (words)", conn_path_size/2);

            /* Add the epath */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+2, conn_path_size, "Connection Path: ");
            dissect_epath( tvb, pinfo, pi, offset+2+req_path_size+2, conn_path_size, FALSE, NULL );
            break;
         default:
            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_cm_data() */

static int
dissect_cip_class_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(tree, proto_cip_class_cm, tvb, 0, -1, ENC_NA);
   class_tree = proto_item_add_subtree( ti, ett_cip_class_cm );

   dissect_cip_cm_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Modbus Object
 *
 ************************************************/
static void
dissect_cip_mb_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item;
   proto_tree *rrsc_tree, *cmd_data_tree;
   tvbuff_t *next_tvb;
   int req_path_size;
   guint8 gen_status, add_stat_size, service;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP MB");

   /* Add Service code & Request/Response tree */
   service = tvb_get_guint8( tvb, offset );
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_mb_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_mb , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_mb_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( service & 0x80 )
   {
      /* Response message */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_mb_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            /* Success responses */
            switch (service & 0x7F)
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
               if( tvb_length_remaining(tvb, offset) > 0 )
               {
                  /* dissect the Modbus PDU */
                  next_tvb = tvb_new_subset( tvb, offset+4+add_stat_size, item_length-4-add_stat_size, item_length-4-add_stat_size);

                  /* keep packet context */
                  p_add_proto_data(pinfo->fd, proto_modbus, (void*)RESPONSE_PACKET);

                  call_dissector(modbus_handle, next_tvb, pinfo, cmd_data_tree);
                  p_remove_proto_data(pinfo->fd, proto_modbus);
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

      /* Add service to info column */
      if(check_col(pinfo->cinfo, COL_INFO))
      {
         col_append_str( pinfo->cinfo, COL_INFO,
                  val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                     cip_sc_vals_mb , "Unknown Service (0x%02x)") );
      }
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_mb_cmd_data );

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
            guint16 NumCoils;

            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            NumCoils = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_num_coils, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_coils_data, tvb, offset+2+req_path_size+4, (NumCoils+7)/8, ENC_NA);
            }
            break;

         case SC_MB_WRITE_HOLDING_REGISTERS:
            {
            guint16 NumRegisters;

            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_start_addr, tvb, offset+2+req_path_size, 2, ENC_LITTLE_ENDIAN);
            NumRegisters = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_num_registers, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_write_registers_data, tvb, offset+2+req_path_size+4, NumRegisters*2, ENC_NA);
            }
            break;

         case SC_MB_PASSTHROUGH:
            /* Passthrough Request */
            if( tvb_length_remaining(tvb, offset) > 0 )
            {
               /* dissect the Modbus PDU */
               next_tvb = tvb_new_subset( tvb, offset+2+req_path_size, item_length-req_path_size-2, item_length-req_path_size-2);

               /* keep packet context */
               p_add_proto_data(pinfo->fd, proto_modbus, (void*)QUERY_PACKET);

               call_dissector(modbus_handle, next_tvb, pinfo, cmd_data_tree);
               p_remove_proto_data(pinfo->fd, proto_modbus);
            }
            break;

         default:
            proto_tree_add_item(cmd_data_tree, hf_cip_mb_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_mb_data() */

static int
dissect_cip_class_mb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_mb, tvb, 0, -1, FALSE);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_mb );

      dissect_cip_mb_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Configuration Object
 *
 ************************************************/
static void
dissect_cip_cco_all_attribute_common( proto_tree *cmd_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo)
{
   proto_item *pi, *tdii, *ncpi, *iomapi, *confgi;
   proto_tree *tdi_tree, *iomap_tree;
   proto_tree *ncp_tree, *confg_tree;
   int conn_path_size, variable_data_size = 0, config_data_size;
   int connection_name_size, iomap_size, ot_rtf, to_rtf;
   int temp_data;
   char* str_connection_name;

   /* Connection flags */
   temp_data = tvb_get_letohs( tvb, offset);
   ot_rtf = (temp_data >> 1) & 7;
   to_rtf = (temp_data >> 4) & 7;
   confgi = proto_tree_add_item(cmd_tree, hf_cip_cco_con_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   confg_tree = proto_item_add_subtree(confgi, ett_cco_con_flag);

      /* Add the data to the tree */
      proto_tree_add_item(confg_tree, hf_cip_cco_con_type, tvb, offset, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(confg_tree, hf_cip_cco_ot_rtf, tvb, offset, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(confg_tree, hf_cip_cco_to_rtf, tvb, offset, 2, ENC_LITTLE_ENDIAN );

   /* Target device id */
   tdii = proto_tree_add_text( cmd_tree, tvb, offset+2, 10, "Target Device ID");
   tdi_tree = proto_item_add_subtree(tdii, ett_cco_tdi);

   dissect_deviceid(tvb, offset+2, tdi_tree,
      hf_cip_cco_tdi_vendor, hf_cip_cco_tdi_devtype, hf_cip_cco_tdi_prodcode,
      hf_cip_cco_tdi_compatibility, hf_cip_cco_tdi_comp_bit, hf_cip_cco_tdi_majorrev, hf_cip_cco_tdi_minorrev);

   /* CS Data Index Number */
   proto_tree_add_item(cmd_tree, hf_cip_cco_cs_data_index, tvb, offset+10, 4, ENC_LITTLE_ENDIAN );

   /* Net Connection Parameters */
   ncpi = proto_tree_add_text( cmd_tree, tvb, offset+14, 14, "Net Connection Parameters");
   ncp_tree = proto_item_add_subtree(ncpi, ett_cco_ncp);

      /* Timeout multiplier */
      proto_tree_add_item(ncp_tree, hf_cip_cco_timeout_multiplier, tvb, offset+14, 1, ENC_LITTLE_ENDIAN );

      dissect_transport_type_trigger(tvb, offset+15, ncp_tree, hf_cip_cco_transport_type_trigger,
                                  hf_cip_cco_fwo_dir, hf_cip_cco_fwo_trigger, hf_cip_cco_fwo_class, ett_cco_ttt);

      temp_data = tvb_get_letohl( tvb, offset+16);
      proto_tree_add_uint_format_value(ncp_tree, hf_cip_cco_ot_rpi, tvb, offset+16, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

      /* Display O->T network connection parameters */
      dissect_net_param16(tvb, offset+20, ncp_tree,
                 hf_cip_cco_ot_net_param16, hf_cip_cco_fwo_own, hf_cip_cco_fwo_typ,
                 hf_cip_cco_fwo_prio, hf_cip_cco_fwo_fixed_var, hf_cip_cco_fwo_con_size, ett_cco_ncp);

      temp_data = tvb_get_letohl( tvb, offset+22);
      proto_tree_add_uint_format_value(ncp_tree, hf_cip_cco_to_rpi, tvb, offset+16, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

      /* Display T->O network connection parameters */
      dissect_net_param16(tvb, offset+26, ncp_tree,
                 hf_cip_cco_to_net_param16, hf_cip_cco_fwo_own, hf_cip_cco_fwo_typ,
                 hf_cip_cco_fwo_prio, hf_cip_cco_fwo_fixed_var, hf_cip_cco_fwo_con_size, ett_cco_ncp);

   /* Connection Path */
   conn_path_size = tvb_get_guint8( tvb, offset+28 )*2;
   proto_tree_add_uint_format_value(cmd_tree, hf_cip_cco_conn_path_size, tvb, offset+28, 1, conn_path_size/2, "%d (words)", conn_path_size/2);

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_tree, hf_cip_reserved8, tvb, offset+29, 1, ENC_LITTLE_ENDIAN );

   /* Add the epath */
   pi = proto_tree_add_text(cmd_tree, tvb, offset+30, conn_path_size, "Connection Path: ");
   dissect_epath( tvb, pinfo, pi, offset+30, conn_path_size, FALSE, NULL );

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
   connection_name_size = tvb_get_guint8( tvb, offset+variable_data_size);
   str_connection_name = tvb_get_ephemeral_string(tvb, offset+variable_data_size+2, connection_name_size);
   proto_tree_add_text(cmd_tree, tvb, offset+variable_data_size, connection_name_size+2, "Connection Name: %s", str_connection_name);

   variable_data_size += ((connection_name_size*2)+2);

   /* I/O Mapping */
   iomap_size = tvb_get_letohs( tvb, offset+variable_data_size+2);

   iomapi = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, iomap_size+2, "I/O Mapping");
   iomap_tree = proto_item_add_subtree(iomapi, ett_cco_iomap);

      proto_tree_add_item(iomap_tree, hf_cip_cco_iomap_format_number, tvb, offset+variable_data_size, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_uint_format_value(iomap_tree, hf_cip_cco_iomap_size, tvb, offset+variable_data_size+2, 2, iomap_size, "%d (bytes)", iomap_size);

      /* Attribute data */
      if (iomap_size > 0)
         proto_tree_add_item(iomap_tree, hf_cip_cco_iomap_attribute, tvb, offset+variable_data_size+4, iomap_size, ENC_NA);

   variable_data_size += (iomap_size+4);

   /* Proxy device id */
   tdii = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 10, "Proxy Device ID");
   tdi_tree = proto_item_add_subtree(tdii, ett_cco_pdi);

   dissect_deviceid(tvb, offset+variable_data_size, tdi_tree,
      hf_cip_cco_pdi_vendor, hf_cip_cco_pdi_devtype, hf_cip_cco_pdi_prodcode,
      hf_cip_cco_pdi_compatibility, hf_cip_cco_pdi_comp_bit, hf_cip_cco_pdi_majorrev, hf_cip_cco_pdi_minorrev);

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
      ncpi = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 18, "Large Net Connection Parameters");
      ncp_tree = proto_item_add_subtree(ncpi, ett_cco_ncp);

      proto_tree_add_item(ncp_tree, hf_cip_cco_timeout_multiplier, tvb, offset+variable_data_size, 1, ENC_LITTLE_ENDIAN );
      dissect_transport_type_trigger(tvb, offset+variable_data_size+1, ncp_tree, hf_cip_cco_transport_type_trigger,
                                  hf_cip_cco_fwo_dir, hf_cip_cco_fwo_trigger, hf_cip_cco_fwo_class, ett_cco_ttt);

      temp_data = tvb_get_letohl( tvb, offset+variable_data_size+2);
      proto_tree_add_uint_format_value(ncp_tree, hf_cip_cco_ot_rpi, tvb, offset+variable_data_size+2, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

      /* Display O->T network connection parameters */
      dissect_net_param32(tvb, offset+variable_data_size+6, ncp_tree,
                 hf_cip_cco_ot_net_param32, hf_cip_cco_lfwo_own, hf_cip_cco_lfwo_typ,
                 hf_cip_cco_lfwo_prio, hf_cip_cco_lfwo_fixed_var, hf_cip_cco_lfwo_con_size, ett_cco_ncp);

      temp_data = tvb_get_letohl( tvb, offset+variable_data_size+10);
      proto_tree_add_uint_format_value(ncp_tree, hf_cip_cco_to_rpi, tvb, offset+variable_data_size+2, 4, temp_data, "%dms (0x%08X)", temp_data / 1000, temp_data);

      /* Display T->O network connection parameters */
      dissect_net_param32(tvb, offset+variable_data_size+14, ncp_tree,
                 hf_cip_cco_to_net_param32, hf_cip_cco_lfwo_own, hf_cip_cco_lfwo_typ,
                 hf_cip_cco_lfwo_prio, hf_cip_cco_lfwo_fixed_var, hf_cip_cco_lfwo_con_size, ett_cco_ncp);

      variable_data_size += 18;
   }
}

static void
dissect_cip_cco_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item, *con_sti;
   proto_tree *rrsc_tree, *cmd_data_tree, *con_st_tree;
   int req_path_size;
   int temp_data;
   guint8 service, gen_status, add_stat_size;
   cip_req_info_t* preq_info;
   cip_simple_request_info_t req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CCO");

   /* Add Service code & Request/Response tree */
   service = tvb_get_guint8( tvb, offset );
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_cco_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cco , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_cco_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

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
         cmd_data_tree = proto_item_add_subtree( pi, ett_cco_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            /* Success responses */
            if (((service & 0x7F) == SC_GET_ATT_ALL) &&
                (req_data.iInstance != (guint32)-1))
            {
               if (req_data.iInstance == 0)
               {
                  /* Get Attribute All (class) request */

                  proto_tree_add_item(cmd_data_tree, hf_cip_class_rev, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(cmd_data_tree, hf_cip_class_max_inst32, tvb, offset+4+add_stat_size+2, 4, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(cmd_data_tree, hf_cip_class_num_inst32, tvb, offset+4+add_stat_size+6, 4, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(cmd_data_tree, hf_cip_cco_format_number, tvb, offset+4+add_stat_size+10, 2, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(cmd_data_tree, hf_cip_cco_edit_signature, tvb, offset+4+add_stat_size+12, 4, ENC_LITTLE_ENDIAN );
               }
               else
               {
                  /* Get Attribute All (instance) request */

                  /* Connection status */
                  con_sti = proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 4, "Connection Status");
                  con_st_tree = proto_item_add_subtree(con_sti, ett_cco_con_status);

                  proto_tree_add_item(con_st_tree, hf_cip_genstat, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN );
                  proto_tree_add_item(con_st_tree, hf_cip_pad8, tvb, offset+4+add_stat_size+1, 1, ENC_LITTLE_ENDIAN);

                  /* Extended Status */
                  temp_data = tvb_get_letohs( tvb, offset+4+add_stat_size+2);
                  proto_tree_add_text(con_st_tree, tvb, offset+4+add_stat_size+2, 2, "Extended Status: 0x%04X", temp_data );

                  dissect_cip_cco_all_attribute_common( cmd_data_tree, tvb, offset+4+add_stat_size+4, item_length, pinfo);
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

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cco , "Unknown Service (0x%02x)") );
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cco_cmd_data );

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
                (req_data.iInstance == (guint32)-1))
            {
               /* Just add raw data */
               proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
               break;
            }

            /* Set Attribute All (instance) request */
            dissect_cip_cco_all_attribute_common(cmd_data_tree, tvb, offset+2+req_path_size, item_length, pinfo);
            break;
         default:

            /* Add data */
            proto_tree_add_item(cmd_data_tree, hf_cip_data, tvb, offset+2+req_path_size, item_length-req_path_size-2, ENC_NA);
         } /* End of check service code */

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_cco_data() */

static int
dissect_cip_class_cco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_cco, tvb, 0, -1, ENC_NA);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_cco );

      dissect_cip_cco_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

static gboolean
dissect_class_cco_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   unsigned char service, service_code, ioilen, segment;
   cip_req_info_t* preq_info;
   guint32 classid = 0;
   int offset = 0;

   service = tvb_get_guint8( tvb, offset );
   service_code = service & 0x7F;

   /* Handle GetAttributeAll and SetAttributeAll in CCO class */
   if ((service_code == SC_GET_ATT_ALL) ||
       (service_code == SC_SET_ATT_ALL))
   {
      if (service & 0x80)
      {
         /* Service response */
         preq_info = (cip_req_info_t*)p_get_proto_data(pinfo->fd, proto_cip);
         if ((preq_info != NULL) &&
             (preq_info->dissector == dissector_get_uint_handle( subdissector_class_table, CI_CLS_CCO)))
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

         if (classid == CI_CLS_CCO)
         {
            call_dissector(cip_class_cco_handle, tvb, pinfo, tree );
            return TRUE;
         }

      }
   }

   return FALSE;
}

/************************************************
 *
 * Dissector for CIP Request/Response
 * - matches requests/responses
 * - calls class specific dissector
 *
 ************************************************/

static void
dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t* preq_info )
{
   proto_item *ti;
   proto_tree *cip_tree;
   proto_item *pi, *rrsc_item, *status_item, *add_status_item;
   proto_tree *rrsc_tree, *status_tree, *add_status_tree;
   int req_path_size;
   unsigned char i, gen_status, add_stat_size;
   unsigned char service,ioilen,segment;
   void *p_save_proto_data;
   cip_simple_request_info_t path_info;
   dissector_handle_t dissector;
   gint service_index;

   p_save_proto_data = p_get_proto_data(pinfo->fd, proto_cip);
   p_remove_proto_data(pinfo->fd, proto_cip);
   p_add_proto_data(pinfo->fd, proto_cip, preq_info);

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(item_tree, proto_cip, tvb, 0, -1, ENC_NA);
   cip_tree = proto_item_add_subtree( ti, ett_cip );

   service = tvb_get_guint8( tvb, offset );

   /* Add Service code & Request/Response tree */
	rrsc_item = proto_tree_add_uint_format_value(cip_tree, hf_cip_service,
		tvb, offset, 1, service, "%s (%s)",
                               val_to_str( ( service & 0x7F ), cip_sc_vals , "Unknown Service (0x%02x)"),
                               val_to_str( ( service & 0x80 )>>7, cip_sc_rr, ""));

   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_rrsc );

   proto_tree_add_item( rrsc_tree, hf_cip_reqrsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
   proto_tree_add_item(rrsc_tree, hf_cip_service_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);

   if( service & 0x80 )
   {
      /* Response message */
      status_item = proto_tree_add_text( cip_tree, tvb, offset+2, 1, "Status: " );
      status_tree = proto_item_add_subtree( status_item, ett_status_item );

      /* Add general status */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      proto_tree_add_item(status_tree, hf_cip_genstat, tvb, offset+2, 1, ENC_LITTLE_ENDIAN );
      proto_item_append_text( status_item, "%s", val_to_str_ext( gen_status,
                     &cip_gs_vals_ext , "Unknown Response (%x)")   );

      /* Add reply status to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str_ext( gen_status, &cip_gs_vals_ext, "Unknown Response (%x)") );

      /* Add additional status size */
      add_stat_size = tvb_get_guint8( tvb, offset+3 );
      proto_tree_add_uint_format_value(status_tree, hf_cip_addstat_size,
         tvb, offset+3, 1, add_stat_size, "%d (words)", add_stat_size);

      if( add_stat_size )
      {
         /* Add additional status */
         add_status_item = proto_tree_add_text( status_tree, tvb, offset+4, add_stat_size*2, "Additional Status" );
         add_status_tree = proto_item_add_subtree( add_status_item, ett_add_status_item );

         for( i=0; i < add_stat_size; i ++ )
            proto_tree_add_item(add_status_tree, hf_cip_add_stat, tvb, offset+4+(i*2), 2, ENC_LITTLE_ENDIAN );
      }

      proto_item_set_len( status_item, 2 + add_stat_size*2);


      if(  preq_info
        && !(  preq_info->bService == ( service & 0x7F )
            || ( preq_info->bService == SC_CM_UNCON_SEND && preq_info->dissector == cip_class_cm_handle )
            )
        )
         preq_info = NULL;

      if ( preq_info )
      {
         if ( preq_info->IOILen && preq_info->pIOI )
         {
            tvbuff_t* tvbIOI;

            tvbIOI = tvb_new_real_data( preq_info->pIOI, preq_info->IOILen * 2, preq_info->IOILen * 2);
            if ( tvbIOI )
            {
               pi = proto_tree_add_text( cip_tree, NULL, 0, 0, "Request Path Size: %d (words)", preq_info->IOILen );
               PROTO_ITEM_SET_GENERATED(pi);

               /* Add the epath */
               pi = proto_tree_add_text(cip_tree, NULL, 0, 0, "Request Path: ");
               PROTO_ITEM_SET_GENERATED(pi);

               preq_info->ciaData = se_alloc(sizeof(cip_simple_request_info_t));
               dissect_epath( tvbIOI, pinfo, pi, 0, preq_info->IOILen*2, TRUE, preq_info->ciaData);
               tvb_free(tvbIOI);
            }
         }
      }

      /* Check to see if service is 'generic' */
      match_strval_idx((service & 0x7F), cip_sc_vals, &service_index);
      if (service_index >= 0)
      {
          /* See if object dissector wants to override generic service handling */
          if(!dissector_try_heuristic(heur_subdissector_service, tvb, pinfo, item_tree))
          {
            dissect_cip_generic_service_rsp(tvb, pinfo, cip_tree);
          }
      }
      else if ( preq_info && preq_info->dissector )
      {
         call_dissector( preq_info->dissector, tvb, pinfo, item_tree );
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
      req_path_size = tvb_get_guint8( tvb, offset+1);
      proto_tree_add_uint_format_value(cip_tree, hf_cip_request_path_size,
         tvb, offset+1, 1, req_path_size, "%d (words)", req_path_size);

      /* Add the epath */
      pi = proto_tree_add_text(cip_tree, tvb, offset+2, req_path_size*2, "Request Path: ");
      if (preq_info)
      {
         preq_info->ciaData = se_alloc(sizeof(cip_simple_request_info_t));
         dissect_epath( tvb, pinfo, pi, offset+2, req_path_size*2, FALSE, preq_info->ciaData);
         memcpy(&path_info, preq_info->ciaData, sizeof(cip_simple_request_info_t));
      }
      else
      {
         dissect_epath( tvb, pinfo, pi, offset+2, req_path_size*2, FALSE, &path_info);
      }

      ioilen = tvb_get_guint8( tvb, offset + 1 );

      if ( preq_info )
         preq_info->dissector = NULL;
      dissector = NULL;

      /* The class ID should already be extracted if its available */
      if (path_info.iClass != 0xFFFFFFFF)
      {
         dissector = dissector_get_uint_handle( subdissector_class_table, path_info.iClass);
      }
      else
      {
         if ( ioilen >= 1 )
         {
            segment = tvb_get_guint8( tvb, offset + 2 );
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
         preq_info->pIOI = se_alloc( ioilen*2);
         preq_info->IOILen = ioilen;
         tvb_memcpy(tvb, preq_info->pIOI, offset+2, ioilen*2);

         preq_info->bService = service;
      }

      /* Check to see if service is 'generic' */
      match_strval_idx(service, cip_sc_vals, &service_index);
      if (service_index >= 0)
      {
          /* See if object dissector wants to override generic service handling */
          if(!dissector_try_heuristic(heur_subdissector_service, tvb, pinfo, item_tree))
          {
             dissect_cip_generic_service_req(tvb, pinfo, cip_tree, &path_info);
          }
      }
      else if ( dissector )
      {
         call_dissector( dissector, tvb, pinfo, item_tree );
      }
      else
      {
         call_dissector( cip_class_generic_handle, tvb, pinfo, item_tree );
      }
   } /* End of if-else( request ) */

   p_remove_proto_data(pinfo->fd, proto_cip);
   p_add_proto_data(pinfo->fd, proto_cip, p_save_proto_data);

} /* End of dissect_cip_data() */


static int
dissect_cip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   enip_request_info_t *enip_info;
   cip_req_info_t *preq_info;

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP");

   col_clear(pinfo->cinfo, COL_INFO);

   /* Each CIP request received by ENIP gets a unique ID */
   enip_info = (enip_request_info_t*)p_get_proto_data(pinfo->fd, proto_enip);

   if ( enip_info )
   {
      preq_info = enip_info->cip_info;
      if ( preq_info == NULL )
      {
         preq_info = se_alloc( sizeof( cip_req_info_t ) );
         memset(preq_info, 0, sizeof(cip_req_info_t));
         enip_info->cip_info = preq_info;
      }
      dissect_cip_data( tree, tvb, 0, pinfo, enip_info->cip_info );
   }
   else
   {
      dissect_cip_data( tree, tvb, 0, pinfo, NULL );
   }

   return tvb_length(tvb);
}

/*
 * Protocol initialization
 */

static void
cip_init_protocol(void)
{
   proto_enip = proto_get_id_by_filter_name( "enip" );
   proto_modbus = proto_get_id_by_filter_name( "modbus" );
}

void
proto_register_cip(void)
{
   /* Setup list of header fields */
   static hf_register_info hf[] = {

      { &hf_cip_service, { "Service", "cip.service", FT_UINT8, BASE_HEX, NULL, 0, "Service Code + Request/Response", HFILL }},
      { &hf_cip_reqrsp, { "Request/Response", "cip.rr", FT_UINT8, BASE_HEX, VALS(cip_sc_rr), 0x80, "Request or Response message", HFILL }},
      { &hf_cip_service_code, { "Service", "cip.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals), 0x7F, "Service Code", HFILL }},
      { &hf_cip_epath, { "EPath", "cip.epath", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_genstat, { "General Status", "cip.genstat", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_addstat_size, { "Additional Status Size", "cip.addstat_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_add_stat, { "Additional Status", "cip.addstat", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_request_path_size, { "Request Path Size", "cip.request_path_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

      { &hf_cip_path_segment, { "Path Segment", "cip.path_segment", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_path_segment_type, { "Path Segment Type", "cip.path_segment.type", FT_UINT8, BASE_DEC, VALS(cip_path_seg_vals), CI_SEGMENT_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_port_segment, { "Port Segment", "cip.port_segment", FT_UINT8, BASE_HEX, NULL, CI_SEGMENT_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_port_ex_link_addr, { "Extended Link Address", "cip.ex_linkaddress", FT_BOOLEAN, BASE_DEC, TFS(&tfs_true_false), CI_PORT_SEG_EX_LINK_ADDRESS, NULL, HFILL }},
      { &hf_cip_port, { "Port", "cip.port", FT_UINT8, BASE_DEC, NULL, CI_PORT_SEG_PORT_ID_MASK, "Port Identifier", HFILL }},
      { &hf_cip_link_address_byte, { "Link Address", "cip.linkaddress", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_link_address_size, { "Link Address Size", "cip.linkaddress_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_link_address_string, { "Link Address", "cip.linkaddress", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
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
      { &hf_cip_attribute8, { "Attribute", "cip.attribute", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_attribute16, { "Attribute", "cip.attribute", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_attribute32, { "Attribute", "cip.attribute", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint8, { "Connection Point", "cip.connpoint", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint16, { "Connection Point", "cip.connpoint", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_conpoint32, { "Connection Point", "cip.connpoint", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey, { "Electronic Key Segment", "cip.ekey", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_format, { "Key Format", "cip.ekey.format", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_vendor, { "Vendor ID", "cip.ekey.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_ekey_devtype, { "Device Type", "cip.ekey.devtype", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_ekey_prodcode, { "Product Code", "cip.ekey.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_compatibility, { "Compatibility", "cip.ekey.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_ekey_comp_bit, { "Compatibility", "cip.ekey.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, "EKey: Compatibility bit", HFILL }},
      { &hf_cip_ekey_majorrev, { "Major Revision", "cip.ekey.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, "EKey: Major Revision", HFILL }},
      { &hf_cip_ekey_minorrev, { "Minor Revision", "cip.ekey.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_data_seg_type, { "Data Segment Type", "cip.data_segment.type", FT_UINT8, BASE_DEC, VALS(cip_data_segment_type_vals), CI_DATA_SEG_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_data_seg_size, { "Data Size", "cip.data_segment.size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_data_seg_item, { "Data", "cip.cip.data_segment.data", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_symbol, { "Symbol", "cip.symbol", FT_STRING, BASE_NONE, NULL, 0, "ANSI Extended Symbol Segment", HFILL }},
      { &hf_cip_network_seg_type, { "Network Segment Type", "cip.network_segment.type", FT_UINT8, BASE_DEC, VALS(cip_network_segment_type_vals), CI_NETWORK_SEG_TYPE_MASK, NULL, HFILL }},
      { &hf_cip_seg_schedule, { "Multiplier/Phase", "cip.network_segment.schedule", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_fixed_tag, { "Fixed Tag", "cip.network_segment.fixed_tag", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_seg_prod_inhibit_time, { "Production Inhibit Time", "cip.network_segment.prod_inhibit", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

      { &hf_cip_vendor, { "Vendor ID", "cip.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_devtype, { "Device Type", "cip.devtype", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_class_rev, { "Class Revision", "cip.class.rev", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_class_max_inst32, { "Max Instance", "cip.class.max_inst", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_class_num_inst32, { "Number of Instances", "cip.class.num_inst", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_reserved8, { "Reserved", "cip.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_reserved16, { "Reserved", "cip.reserved", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_reserved24, { "Reserved", "cip.reserved", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_pad8, { "Pad Byte", "cip.pad", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

      { &hf_cip_sc_get_attr_list_attr_count, { "Attribute Count", "cip.getlist.attr_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_get_attr_list_attr_item, { "Attribute", "cip.getlist.attr_item", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_get_attr_list_attr_status, { "General Status", "cip.getlist.attr_status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_sc_get_attr_list_attr_data, { "Data", "cip.getlist.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_count, { "Attribute Count", "cip.setlist.attr_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_item, { "Attribute", "cip.setlist.attr_item", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_status, { "General Status", "cip.setlist.attr_status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_list_attr_data, { "Data", "cip.setlist.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

      { &hf_cip_sc_get_attribute_all_data, { "Data", "cip.getall.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attribute_all_data, { "Data", "cip.setall.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_reset_param, { "Reset type", "cip.reset.type", FT_UINT8, BASE_DEC, VALS(cip_reset_type_vals), 0, NULL, HFILL }},
      { &hf_cip_sc_reset_data, { "Data", "cip.reset.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_start_data, { "Data", "cip.start.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_stop_data, { "Data", "cip.stop.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_create_instance, { "Instance", "cip.create.instance", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_create_data, { "Data", "cip.create.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_mult_serv_pack_num_services, { "Number of Services", "cip.msp.num_services", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_mult_serv_pack_offset, { "Offset", "cip.msp.offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_mult_serv_pack_num_replies, { "Number of Replies", "cip.msp.num_replies", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_delete_data, { "Data", "cip.delete.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_apply_attributes_data, { "Data", "cip.apply_attributes.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_get_attr_single_data, { "Data", "cip.getsingle.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_attr_single_data, { "Data", "cip.setsingle.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_max_instance, { "Maximum ID", "cip.find_next_object.max_instance", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_num_instances, { "Number of Instances:", "cip.find_next_object.num_instances", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_find_next_object_instance_item, { "Instance", "cip.find_next_object.instance", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_restore_data, { "Data", "cip.restore.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_save_data, { "Data", "cip.save.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_noop_data, { "Data", "cip.noop.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_get_member_data, { "Data", "cip.getmember.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_set_member_data, { "Data", "cip.setmember.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_insert_member_data, { "Data", "cip.insertmember.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_remove_member_data, { "Data", "cip.removemember.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_group_sync_is_sync, { "IsSynchronized", "cip.group_sync.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_sc_group_sync_data, { "Data", "cip.group_sync.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_data, { "Data", "cip.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

      { &hf_id_vendor_id, { "Vendor ID", "cip.id.vendor_id", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_device_type, { "Device Type", "cip.id.device_type", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_produce_code, { "Product Code", "cip.id.produce_code", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_major_rev, { "Major Revision", "cip.id.major_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_minor_rev, { "Minor Revision", "cip.id.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_id_status, { "Status", "cip.id.status", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_id_serial_number, { "Serial Number", "cip.id.serial_number", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_id_product_name, { "Product Name", "cip.id.product_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

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
   };

   static hf_register_info hf_cm[] = {
      { &hf_cip_cm_sc, { "Service", "cip.cm.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_cm), 0x7F, NULL, HFILL }},
      { &hf_cip_cm_genstat, { "General Status", "cip.cm.genstat", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_gs_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_addstat_size, { "Additional Status Size", "cip.cm.addstat_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext_status, { "Extended Status", "cip.cm.ext_status", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_cm_ext_st_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_add_status, { "Additional Status", "cip.cm.addstat", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_priority, { "Priority", "cip.cm.priority", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
      { &hf_cip_cm_tick_time, { "Tick time", "cip.cm.tick_time", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_cip_cm_timeout_tick, { "Time-out ticks", "cip.cm.timeout_tick", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_timeout, { "Actual Time Out", "cip.cm.timeout", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_connid, { "O->T Network Connection ID", "cip.cm.ot_connid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_connid, { "T->O Network Connection ID", "cip.cm.to_connid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_conn_serial_num, { "Connection Serial Number", "cip.cm.conn_serial_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_vendor, { "Vendor ID", "cip.cm.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cm_timeout_multiplier, { "Connection Timeout Multiplier", "cip.cm.timeout_multiplier", FT_UINT8, BASE_DEC, VALS(cip_con_time_mult_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ot_rpi, { "O->T RPI", "cip.cm.otrpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_net_params32, { "O->T Network Connection Parameters", "cip.cm.ot_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_net_params16, { "O->T Network Connection Parameters", "cip.cm.ot_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_rpi, { "T->O RPI", "cip.cm.torpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_net_params32, { "T->O Network Connection Parameters", "cip.cm.to_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_net_params16, { "T->O Network Connection Parameters", "cip.cm.to_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_transport_type_trigger, { "Transport Type/Trigger", "cip.cm.transport_type_trigger", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_conn_path_size, { "Connection Path Size", "cip.cm.connpath_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ot_api, { "O->T API", "cip.cm.otapi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_to_api, { "T->O API", "cip.cm.toapi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_app_reply_size, { "Application Reply Size", "cip.cm.app_reply_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_app_reply_data , { "Application Reply", "cip.cm.app_reply_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_remain_path_size, { "Remaining Path Size", "cip.cm.remain_path_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_msg_req_size, { "Message Request Size", "cip.cm.msg_req_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_route_path_size, { "Route Path Size", "cip.cm.route_path_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_orig_serial_num, { "Originator Serial Number", "cip.cm.orig_serial_num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_fwo_con_size, { "Connection Size", "cip.cm.fwo.consize", FT_UINT16, BASE_DEC, NULL, 0x01FF, "Fwd Open: Connection size", HFILL }},
      { &hf_cip_cm_lfwo_con_size, { "Connection Size", "cip.cm.fwo.consize", FT_UINT32, BASE_DEC, NULL, 0xFFFF, "Large Fwd Open: Connection size", HFILL }},
      { &hf_cip_cm_fwo_fixed_var, { "Connection Size Type", "cip.cm.fwo.f_v", FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200, "Fwd Open: Fixed or variable connection size", HFILL }},
      { &hf_cip_cm_lfwo_fixed_var, { "Connection Size Type", "cip.cm.fwo.f_v", FT_UINT32, BASE_DEC, VALS(cip_con_fw_vals), 0x02000000, "Large Fwd Open: Fixed or variable connection size", HFILL }},
      { &hf_cip_cm_fwo_prio, { "Priority", "cip.cm.fwo.prio", FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00, "Fwd Open: Connection priority", HFILL }},
      { &hf_cip_cm_lfwo_prio, { "Priority", "cip.cm.fwo.prio", FT_UINT32, BASE_DEC, VALS(cip_con_prio_vals), 0x0C000000, "Large Fwd Open: Connection priority", HFILL }},
      { &hf_cip_cm_fwo_typ, { "Connection Type", "cip.cm.fwo.type", FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000, "Fwd Open: Connection type", HFILL }},
      { &hf_cip_cm_lfwo_typ, { "Connection Type", "cip.cm.fwo.type", FT_UINT32, BASE_DEC, VALS(cip_con_type_vals), 0x60000000, "Large Fwd Open: Connection type", HFILL }},
      { &hf_cip_cm_fwo_own, { "Owner", "cip.cm.fwo.owner", FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000, "Fwd Open: Redundant owner bit", HFILL }},
      { &hf_cip_cm_lfwo_own, { "Owner", "cip.cm.fwo.owner", FT_UINT32, BASE_DEC, VALS(cip_con_owner_vals), 0x80000000, "Large Fwd Open: Redundant owner bit", HFILL }},
      { &hf_cip_cm_fwo_dir, { "Direction", "cip.cm.fwo.dir", FT_UINT8, BASE_DEC, VALS(cip_con_dir_vals), 0x80, "Fwd Open: Direction", HFILL }},
      { &hf_cip_cm_fwo_trigg, { "Trigger", "cip.cm.fwo.trigger", FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), 0x70, "Fwd Open: Production trigger", HFILL }},
      { &hf_cip_cm_fwo_class, { "Class", "cip.cm.fwo.transport", FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), 0x0F, "Fwd Open: Transport Class", HFILL }},
      { &hf_cip_cm_gco_conn, { "Number of Connections", "cip.cm.gco.conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: Number of Connections", HFILL }},
      { &hf_cip_cm_gco_coo_conn, { "COO Connections", "cip.cm.gco.coo_conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: COO Connections", HFILL }},
      { &hf_cip_cm_gco_roo_conn, { "ROO Connections", "cip.cm.gco.roo_conn", FT_UINT8, BASE_DEC, NULL, 0, "GetConnOwner: ROO Connections", HFILL }},
      { &hf_cip_cm_gco_last_action, { "Last Action", "cip.cm.gco.la", FT_UINT8, BASE_DEC, VALS(cip_con_last_action_vals), 0, "GetConnOwner: Last Action", HFILL }},
      { &hf_cip_cm_ext112_ot_rpi_type, { "Trigger", "cip.cm.ext112otrpi_type", FT_UINT8, BASE_DEC, VALS(cip_cm_rpi_type_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_to_rpi_type, { "Trigger", "cip.cm.ext112torpi_type", FT_UINT8, BASE_DEC, VALS(cip_cm_rpi_type_vals), 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_ot_rpi, { "Acceptable O->T RPI", "cip.cm.ext112otrpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext112_to_rpi, { "Acceptable T->O RPI", "cip.cm.ext112torpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext126_size, { "Maximum Size", "cip.cm.ext126_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext127_size, { "Maximum Size", "cip.cm.ext127_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cm_ext128_size, { "Maximum Size", "cip.cm.ext128_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }}
   };

   static hf_register_info hf_mb[] = {
      { &hf_cip_mb_sc, { "Service", "cip.mb.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_mb), 0x7F, NULL, HFILL }},
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
      { &hf_cip_cco_sc, { "Service", "cip.cco.sc", FT_UINT8, BASE_HEX, VALS(cip_sc_vals_cco), 0x7F, NULL, HFILL }},
      { &hf_cip_cco_format_number, { "Format Number", "cip.cco.format_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_edit_signature, { "Edit Signature", "cip.cco.edit_signature", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_con_flags, { "Connection Flags", "cip.cco.connflags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_con_type, { "Connection O_T", "cip.cco.con", FT_UINT16, BASE_DEC, VALS(cip_con_vals), 0x001, NULL, HFILL }},
      { &hf_cip_cco_ot_rtf, { "O->T real time transfer format", "cip.cco.otrtf", FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x000E, NULL, HFILL }},
      { &hf_cip_cco_to_rtf, { "T->O real time transfer format", "cip.cco.tortf", FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x0070, NULL, HFILL }},
      { &hf_cip_cco_tdi_vendor, { "Vendor ID", "cip.cco.tdi.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_devtype, { "Device Type", "cip.cco.tdi.devtype", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_prodcode, { "Product Code", "cip.cco.tdi.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_compatibility, { "Compatibility", "cip.cco.tdi.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_tdi_comp_bit, { "Compatibility", "cip.cco.tdi.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, NULL, HFILL }},
      { &hf_cip_cco_tdi_majorrev, { "Major Revision", "cip.cco.tdi.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_cip_cco_tdi_minorrev, { "Minor Revision", "cip.cco.tdi.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_vendor, { "Vendor ID", "cip.cco.pdi.vendor", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_devtype, { "Device Type", "cip.cco.pdi.devtype", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cip_devtype_vals_ext, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_prodcode, { "Product Code", "cip.cco.pdi.product_code", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_compatibility, { "Compatibility", "cip.cco.pdi.compatibility", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_pdi_comp_bit, { "Compatibility", "cip.cco.pdi.comp_bit", FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80, NULL, HFILL }},
      { &hf_cip_cco_pdi_majorrev, { "Major Revision", "cip.cco.pdi.major_rev", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_cip_cco_pdi_minorrev, { "Minor Revision", "cip.cco.pdi.minor_rev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_cs_data_index, { "CS Data Index Number", "cip.cco.cs_data_index", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_timeout_multiplier, { "Connection Timeout Multiplier", "cip.cco.timeout_multiplier", FT_UINT8, BASE_DEC, VALS(cip_con_time_mult_vals), 0, NULL, HFILL }},
      { &hf_cip_cco_ot_rpi, { "O->T RPI", "cip.cco.otrpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_ot_net_param32, { "O->T Network Connection Parameters", "cip.cco.ot_net_params", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_ot_net_param16, { "O->T Network Connection Parameters", "cip.cco.ot_net_params", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_to_rpi, { "T->O RPI", "cip.cco.torpi", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
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
      { &hf_cip_cco_fwo_own, { "Owner", "cip.cco.owner", FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000, NULL, HFILL }},
      { &hf_cip_cco_lfwo_own, { "Owner", "cip.cco.owner", FT_UINT32, BASE_DEC, VALS(cip_con_owner_vals), 0x80000000, NULL, HFILL }},
      { &hf_cip_cco_fwo_dir, { "Direction", "cip.cco.dir", FT_UINT8, BASE_DEC, VALS(cip_con_dir_vals), 0x80, NULL, HFILL }},
      { &hf_cip_cco_fwo_trigger, { "Trigger", "cip.cco.trigger", FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), 0x70, NULL, HFILL }},
      { &hf_cip_cco_fwo_class, { "Class", "cip.cco.transport", FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), 0x0F, NULL, HFILL }},
      { &hf_cip_cco_conn_path_size, { "Connection Path Size", "cip.cco.connpath_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_proxy_config_size, { "Proxy Config Data Size", "cip.cco.proxy_config_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_target_config_size, { "Target Config Data Size", "cip.cco.proxy_config_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_format_number, { "Format number", "cip.cco.iomap_format_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_size, { "Attribute size", "cip.cco.iomap_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_connection_disable, { "Connection Disable", "cip.cco.connection_disable", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_cip_cco_net_conn_param_attr, { "Net Connection Parameter Attribute Selection", "cip.cco.net_conn_param_attr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_proxy_config_data, { "Proxy Config Data", "cip.cco.proxy_config_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_target_config_data, { "Target Config Data", "cip.cco.target_config_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_iomap_attribute, { "Attribute Data", "cip.cco.iomap", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_safety, { "Safety Parameters", "cip.cco.safety", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_cip_cco_change_type, { "Change Type", "cip.cco.change_type", FT_UINT16, BASE_DEC, cip_cco_change_type_vals, 0, NULL, HFILL }},
   };

   /* Setup protocol subtree array */
   static gint *ett[] = {
      &ett_cip_class_generic,
      &ett_cip,
      &ett_path,
      &ett_path_seg,
      &ett_ekey_path,
      &ett_rrsc,
      &ett_mcsc,
      &ett_cia_path,
      &ett_data_seg,
      &ett_data_seg_data,
      &ett_cmd_data,
      &ett_port_path,
      &ett_network_seg,
      &ett_status_item,
      &ett_add_status_item,
      &ett_cip_get_attribute_list,
      &ett_cip_get_attribute_list_item,
      &ett_cip_set_attribute_list,
      &ett_cip_set_attribute_list_item,
      &ett_cip_mult_service_packet
   };

   static gint *ett_cm[] = {
      &ett_cip_class_cm,
      &ett_cm_rrsc,
      &ett_cm_mes_req,
      &ett_cm_ncp,
      &ett_cm_cmd_data,
      &ett_cm_ttt,
      &ett_cm_add_status_item
   };

   static gint *ett_mb[] = {
      &ett_cip_class_mb,
      &ett_mb_rrsc,
      &ett_mb_cmd_data
    };

   static gint *ett_cco[] = {
      &ett_cip_class_cco,
      &ett_cco_iomap,
      &ett_cco_con_status,
      &ett_cco_con_flag,
      &ett_cco_tdi,
      &ett_cco_pdi,
      &ett_cco_ncp,
      &ett_cco_rrsc,
      &ett_cco_cmd_data,
      &ett_cco_ttt
    };

   /* Register the protocol name and description */
   proto_cip = proto_register_protocol("Common Industrial Protocol",
       "CIP", "cip");

   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array(proto_cip, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   subdissector_class_table = register_dissector_table("cip.class.iface",
      "CIP Class Interface Handle", FT_UINT32, BASE_HEX);
   subdissector_symbol_table = register_dissector_table("cip.data_segment.iface",
      "CIP Data Segment Interface Handle", FT_UINT32, BASE_HEX);

   /* Register the protocol name and description */
   proto_cip_class_generic = proto_register_protocol("CIP Class Generic",
       "CIPCLS", "cipcls");

   /* Register the protocol name and description */
   proto_cip_class_cm = proto_register_protocol("CIP Connection Manager",
       "CIPCM", "cipcm");
   proto_register_field_array(proto_cip_class_cm, hf_cm, array_length(hf_cm));
   proto_register_subtree_array(ett_cm, array_length(ett_cm));

   proto_cip_class_mb = proto_register_protocol("CIP Modbus Object",
       "CIPMB", "cipmb");
   proto_register_field_array(proto_cip_class_mb, hf_mb, array_length(hf_mb));
   proto_register_subtree_array(ett_mb, array_length(ett_mb));

   proto_cip_class_cco = proto_register_protocol("CIP Connection Configuration Object",
       "CIPCCO", "cipcco");
   proto_register_field_array(proto_cip_class_cco, hf_cco, array_length(hf_cco));
   proto_register_subtree_array(ett_cco, array_length(ett_cco));

   register_init_routine(&cip_init_protocol);

   /* Register a heuristic dissector on the service of the message so objects
    * can override the dissector for common services */
   register_heur_dissector_list("cip.sc", &heur_subdissector_service);

} /* end of proto_register_cip() */


void
proto_reg_handoff_cip(void)
{
   /* Create dissector handles */
   /* Register for UCMM CIP data, using EtherNet/IP SendRRData service*/
   /* Register for Connected CIP data, using EtherNet/IP SendUnitData service*/
   cip_handle = new_create_dissector_handle( dissect_cip, proto_cip );
   dissector_add_uint( "enip.srrd.iface", ENIP_CIP_INTERFACE, cip_handle );
   dissector_add_uint( "enip.sud.iface", ENIP_CIP_INTERFACE, cip_handle );

   /* Create and register dissector handle for generic class */
   cip_class_generic_handle = new_create_dissector_handle( dissect_cip_class_generic, proto_cip_class_generic );
   dissector_add_uint( "cip.class.iface", 0, cip_class_generic_handle );

   /* Create and register dissector handle for Connection Manager */
   cip_class_cm_handle = new_create_dissector_handle( dissect_cip_class_cm, proto_cip_class_cm );
   dissector_add_uint( "cip.class.iface", CI_CLS_CM, cip_class_cm_handle );

   /* Create and register dissector handle for Modbus Object */
   cip_class_mb_handle = new_create_dissector_handle( dissect_cip_class_mb, proto_cip_class_mb );
   dissector_add_uint( "cip.class.iface", CI_CLS_MB, cip_class_mb_handle );
   modbus_handle = find_dissector("modbus");

   /* Create and register dissector handle for Connection Configuration Object */
   cip_class_cco_handle = new_create_dissector_handle( dissect_cip_class_cco, proto_cip_class_cco );
   dissector_add_uint( "cip.class.iface", CI_CLS_CCO, cip_class_cco_handle );
   heur_dissector_add("cip.sc", dissect_class_cco_heur, proto_cip_class_cco);

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
