/* packet-omron-fins.c
 * Routines for OMRON FINS UDP dissection
 * Copyright Sourcefire, Inc. 2008-2009, Matthew Watchinski <mwatchinski@sourcefire.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Reference for OMRON-FINS W227_E1_02_FINS_Command_Reference_Manual
 * Hopefully google will find it for you.
 *
 * Special thanks to the guys who wrote the README.developer its great.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define OMRON_FINS_UDP_PORT 9600

static int proto_omron_fins = -1;
static gint ett_omron = -1;
static gint ett_omron_header = -1;
static gint ett_omron_icf_fields = -1;
static gint ett_omron_command_data = -1;
static gint ett_area_data = -1;
static gint ett_cpu_bus = -1;
static gint ett_io_data = -1;
static gint ett_pc_status_fields = -1;
static gint ett_fatal_fields = -1;
static gint ett_non_fatal_fields = -1;
static gint ett_message_fields = -1;
static gint ett_omron_error_log_data = -1;
static gint ett_omron_disk_data = -1;
static gint ett_omron_file_data = -1;
static gint ett_omron_data_type = -1;
static gint ett_omron_block_record = -1;
static gint ett_omron_status_block = -1;
static gint ett_omron_cyclic_fields = -1;
static gint ett_omron_netw_nodes_sts = -1;
static gint ett_omron_netw_node_sts = -1;
static gint ett_omron_netw_nodes_non_fatal_err_sts = -1;
static gint ett_omron_netw_nodes_cyclic_err_ctrs = -1;
static gint ett_omron_data_link_status_tree = -1;

#if 0
static gboolean gPREF_HEX = FALSE;
#endif

/* Omron-FINS Header fields */
static int hf_omron_icf = -1;

static int hf_omron_icf_gwb = -1; /* Gateway usage (0: don't use; 1: use) should be 1 */
static int hf_omron_icf_dtb = -1; /* Data type (0: command 1: response) */
static int hf_omron_icf_rb0 = -1; /* Reserved should be 0 */
static int hf_omron_icf_rb1 = -1; /* Reserved should be 0 */
static int hf_omron_icf_rb2 = -1; /* Reserved should be 0 */
static int hf_omron_icf_rb3 = -1; /* Reserved should be 0 */
static int hf_omron_icf_rb4 = -1; /* Reserved should be 0 */
static int hf_omron_icf_rsb = -1; /* Response setting (0: response required; 1: response not required) */

static int hf_omron_rsv = -1;
static int hf_omron_gct = -1;
static int hf_omron_dna = -1;
static int hf_omron_da1 = -1;
static int hf_omron_da2 = -1;
static int hf_omron_sna = -1;
static int hf_omron_sa1 = -1;
static int hf_omron_sa2 = -1;
static int hf_omron_sid = -1;

static int hf_omron_command                  = -1;
static int hf_omron_command_data             = -1;
static int hf_omron_command_memory_area_code = -1;
static int hf_omron_response_code            = -1;

static int hf_omron_address      = -1;
static int hf_omron_address_bits = -1;
static int hf_omron_num_items    = -1;

static int hf_omron_response_data       = -1;
static int hf_omron_parameter_area_code = -1;

static int hf_omron_beginning_word = -1;
static int hf_omron_num_words = -1;

static int hf_omron_program_number = -1;
static int hf_omron_protect_code   = -1;
static int hf_omron_begin_word     = -1;
static int hf_omron_last_word      = -1;
static int hf_omron_password       = -1;

static int hf_omron_clear_code    = -1;
static int hf_omron_mode_code     = -1;
static int hf_omron_monitor_label = -1;

static int hf_omron_controller_model   = -1;
static int hf_omron_controller_version = -1;
static int hf_omron_for_system_use     = -1;

static int hf_omron_program_area_size    = -1;
static int hf_omron_iom_size             = -1;
static int hf_omron_num_dm_words         = -1;
static int hf_omron_timer_counter_size   = -1;
static int hf_omron_expansion_dm_size    = -1;
static int hf_omron_num_step_transitions = -1;
static int hf_omron_kind_memory_card     = -1;
static int hf_omron_memory_card_size     = -1;

static int hf_omron_cpu_bus_unit_0   = -1;
static int hf_omron_cpu_bus_unit_1   = -1;
static int hf_omron_cpu_bus_unit_2   = -1;
static int hf_omron_cpu_bus_unit_3   = -1;
static int hf_omron_cpu_bus_unit_4   = -1;
static int hf_omron_cpu_bus_unit_5   = -1;
static int hf_omron_cpu_bus_unit_6   = -1;
static int hf_omron_cpu_bus_unit_7   = -1;
static int hf_omron_cpu_bus_unit_8   = -1;
static int hf_omron_cpu_bus_unit_9   = -1;
static int hf_omron_cpu_bus_unit_10  = -1;
static int hf_omron_cpu_bus_unit_11  = -1;
static int hf_omron_cpu_bus_unit_12  = -1;
static int hf_omron_cpu_bus_unit_13  = -1;
static int hf_omron_cpu_bus_unit_14  = -1;
static int hf_omron_cpu_bus_unit_15  = -1;
static int hf_omron_cpu_bus_reserved = -1;

static int hf_omron_io_data_num_sysmac_1 = -1;
static int hf_omron_io_data_num_sysmac_2 = -1;

static int hf_omron_pc_status          = -1;
static int hf_omron_pc_status_pdc      = -1;
static int hf_omron_pc_status_hi       = -1;
static int hf_omron_pc_status_r1       = -1;
static int hf_omron_pc_status_r2       = -1;
static int hf_omron_pc_status_rack_num = -1;

static int hf_omron_unit_address = -1;
static int hf_omron_num_units    = -1;
static int hf_omron_model_number = -1;

static int hf_omron_status                      = -1;
static int hf_omron_fatal_error_data            = -1;
static int hf_omron_fatal_fals_error            = -1;
static int hf_omron_fatal_sfc_error             = -1;
static int hf_omron_fatal_cycle_time_over       = -1;
static int hf_omron_fatal_program_error         = -1;
static int hf_omron_fatal_io_setting_error      = -1;
static int hf_omron_fatal_io_point_overflow     = -1;
static int hf_omron_fatal_cpu_bus_error         = -1;
static int hf_omron_fatal_duplication_error     = -1;
static int hf_omron_fatal_io_bus_error          = -1;
static int hf_omron_fatal_memory_error          = -1;
static int hf_omron_fatal_rv_1                  = -1;
static int hf_omron_fatal_rv_2                  = -1;
static int hf_omron_fatal_rv_3                  = -1;
static int hf_omron_fatal_rv_4                  = -1;
static int hf_omron_fatal_rv_5                  = -1;
static int hf_omron_fatal_watch_dog_timer_error = -1;

static int hf_omron_non_fatal_error_data                 = -1;
static int hf_omron_non_fatal_rv1                        = -1;
static int hf_omron_non_fatal_rv2                        = -1;
static int hf_omron_non_fatal_power_interruption         = -1;
static int hf_omron_non_fatal_cpu_bus_unit_setting_error = -1;
static int hf_omron_non_fatal_battery_error              = -1;
static int hf_omron_non_fatal_sysmac_bus_error           = -1;
static int hf_omron_non_fatal_sysmac_bus2_error          = -1;
static int hf_omron_non_fatal_cpu_bus_unit_error         = -1;
static int hf_omron_non_fatal_rv3                        = -1;
static int hf_omron_non_fatal_io_verification_error      = -1;
static int hf_omron_non_fatal_rv4                        = -1;
static int hf_omron_non_fatal_sfc_error                  = -1;
static int hf_omron_non_fatal_indirect_dm_error          = -1;
static int hf_omron_non_fatal_jmp_error                  = -1;
static int hf_omron_non_fatal_rv5                        = -1;
static int hf_omron_non_fatal_fal_error                  = -1;

static int hf_omron_message = -1;
static int hf_omron_message_no_0 = -1;
static int hf_omron_message_no_1 = -1;
static int hf_omron_message_no_2 = -1;
static int hf_omron_message_no_3 = -1;
static int hf_omron_message_no_4 = -1;
static int hf_omron_message_no_5 = -1;
static int hf_omron_message_no_6 = -1;
static int hf_omron_message_no_7 = -1;
static int hf_omron_message_rv_0 = -1;
static int hf_omron_message_rv_1 = -1;
static int hf_omron_message_rv_2 = -1;
static int hf_omron_message_rv_3 = -1;
static int hf_omron_message_rv_4 = -1;
static int hf_omron_message_rv_5 = -1;
static int hf_omron_message_rv_6 = -1;
static int hf_omron_message_rv_7 = -1;

static int hf_omron_fals          = -1;
static int hf_omron_error_message = -1;

static int hf_omron_parameter      = -1;
static int hf_omron_avg_cycle_time = -1;
static int hf_omron_max_cycle_time = -1;
static int hf_omron_min_cycle_time = -1;

static int hf_omron_year   = -1;
static int hf_omron_month  = -1;
static int hf_omron_date   = -1;
static int hf_omron_hour   = -1;
static int hf_omron_minute = -1;
static int hf_omron_second = -1;
static int hf_omron_day    = -1;

static int hf_omron_read_message = -1;

static int hf_omron_node_number     = -1;
static int hf_omron_network_address = -1;

static int hf_omron_error_reset_fals_no = -1;

static int hf_omron_beginning_record_no      = -1;
static int hf_omron_no_of_records            = -1;
static int hf_omron_max_no_of_stored_records = -1;
static int hf_omron_no_of_stored_records     = -1;

static int hf_omron_disk_no                 = -1;
static int hf_omron_beginning_file_position = -1;
static int hf_omron_no_of_files             = -1;

static int hf_omron_volume_label    = -1;
static int hf_omron_date_year       = -1;
static int hf_omron_date_month      = -1;
static int hf_omron_date_day        = -1;
static int hf_omron_date_hour       = -1;
static int hf_omron_date_minute     = -1;
static int hf_omron_date_second     = -1;
static int hf_omron_total_capacity  = -1;
static int hf_omron_unused_capacity = -1;
static int hf_omron_total_no_files  = -1;
static int hf_omron_no_files        = -1;
static int hf_omron_filename        = -1;
static int hf_omron_file_capacity   = -1;

static int hf_omron_file_position       = -1;
static int hf_omron_data_length         = -1;
static int hf_omron_file_data           = -1;
static int hf_omron_file_parameter_code = -1;

static int hf_omron_volume_parameter_code   = -1;
static int hf_omron_transfer_parameter_code = -1;

static int hf_omron_transfer_beginning_address = -1;
static int hf_omron_number_of_bytes            = -1;

static int hf_omron_number_of_bits_flags    = -1;
static int hf_omron_set_reset_specification = -1;
static int hf_omron_bit_flag                = -1;

static int hf_omron_data = -1;

static int hf_omron_beginning_block_num  = -1;
static int hf_omron_num_blocks           = -1;
static int hf_omron_num_blocks_remaining = -1;
static int hf_omron_total_num_blocks     = -1;
static int hf_omron_type                 = -1;
static int hf_omron_data_type            = -1;
static int hf_omron_data_type_type       = -1;
static int hf_omron_data_type_rv         = -1;
static int hf_omron_data_type_protected  = -1;
static int hf_omron_data_type_end        = -1;
static int hf_omron_control_data         = -1;

static int hf_omron_block_num       = -1;
static int hf_omron_num_unit_uint16 = -1;

static int hf_omron_fixed                           = -1;
static int hf_omron_intelligent_id_no               = -1;
static int hf_omron_first_word                      = -1;
static int hf_omron_read_len                        = -1;
static int hf_omron_no_of_link_nodes                = -1;
static int hf_omron_block_record_node_num_status    = -1;
static int hf_omron_block_record_node_num_num_nodes = -1;
static int hf_omron_block_record_cio_area           = -1;
static int hf_omron_block_record_kind_of_dm         = -1;
static int hf_omron_block_record_dm_area_first_word = -1;
static int hf_omron_block_record_no_of_total_words  = -1;

static int hf_omron_status_flags              = -1;
static int hf_omron_status_flags_slave_master = -1;
static int hf_omron_status_flags_data_link    = -1;
static int hf_omron_master_node_number        = -1;
static int hf_omron_status_node_0             = -1;
static int hf_omron_status_node_1             = -1;
static int hf_omron_status_node_2             = -1;
static int hf_omron_status_node_3             = -1;
static int hf_omron_status_node_4             = -1;
static int hf_omron_status_node_5             = -1;
static int hf_omron_status_node_6             = -1;
static int hf_omron_status_node_7             = -1;
static int hf_omron_status_1_node_0           = -1;
static int hf_omron_status_1_node_1           = -1;
static int hf_omron_status_1_node_2           = -1;
static int hf_omron_status_1_node_3           = -1;
static int hf_omron_status_1_node_4           = -1;
static int hf_omron_status_1_node_5           = -1;
static int hf_omron_status_1_node_6           = -1;
static int hf_omron_status_1_node_7           = -1;
static int hf_omron_status_2_node_0           = -1;
static int hf_omron_status_2_node_1           = -1;
static int hf_omron_status_2_node_2           = -1;
static int hf_omron_status_2_node_3           = -1;
static int hf_omron_status_2_node_4           = -1;
static int hf_omron_status_2_node_5           = -1;
static int hf_omron_status_2_node_6           = -1;
static int hf_omron_status_2_node_7           = -1;

static int hf_omron_name_data = -1;

static int hf_omron_num_receptions = -1;

static int hf_omron_netw_node_sts_low_0   = -1;
static int hf_omron_netw_node_sts_low_1   = -1;
static int hf_omron_netw_node_sts_low_2   = -1;
static int hf_omron_netw_node_sts_low_3   = -1;
static int hf_omron_netw_node_sts_high_0  = -1;
static int hf_omron_netw_node_sts_high_1  = -1;
static int hf_omron_netw_node_sts_high_2  = -1;
static int hf_omron_netw_node_sts_high_3  = -1;
static int hf_omron_com_cycle_time        = -1;
static int hf_omron_polling_unit_node_num = -1;
static int hf_omron_cyclic_operation      = -1;
static int hf_omron_cyclic_trans_status   = -1;

static int hf_omron_cyclic_label_1   = -1;
static int hf_omron_cyclic_7         = -1;
static int hf_omron_cyclic_6         = -1;
static int hf_omron_cyclic_5         = -1;
static int hf_omron_cyclic_4         = -1;
static int hf_omron_cyclic_3         = -1;
static int hf_omron_cyclic_2         = -1;
static int hf_omron_cyclic_1         = -1;
static int hf_omron_cyclic_label_2   = -1;
static int hf_omron_cyclic_15        = -1;
static int hf_omron_cyclic_14        = -1;
static int hf_omron_cyclic_13        = -1;
static int hf_omron_cyclic_12        = -1;
static int hf_omron_cyclic_11        = -1;
static int hf_omron_cyclic_10        = -1;
static int hf_omron_cyclic_9         = -1;
static int hf_omron_cyclic_8         = -1;
static int hf_omron_cyclic_label_3   = -1;
static int hf_omron_cyclic_23        = -1;
static int hf_omron_cyclic_22        = -1;
static int hf_omron_cyclic_21        = -1;
static int hf_omron_cyclic_20        = -1;
static int hf_omron_cyclic_19        = -1;
static int hf_omron_cyclic_18        = -1;
static int hf_omron_cyclic_17        = -1;
static int hf_omron_cyclic_16        = -1;
static int hf_omron_cyclic_label_4   = -1;
static int hf_omron_cyclic_31        = -1;
static int hf_omron_cyclic_30        = -1;
static int hf_omron_cyclic_29        = -1;
static int hf_omron_cyclic_28        = -1;
static int hf_omron_cyclic_27        = -1;
static int hf_omron_cyclic_26        = -1;
static int hf_omron_cyclic_25        = -1;
static int hf_omron_cyclic_24        = -1;
static int hf_omron_cyclic_label_5   = -1;
static int hf_omron_cyclic_39        = -1;
static int hf_omron_cyclic_38        = -1;
static int hf_omron_cyclic_37        = -1;
static int hf_omron_cyclic_36        = -1;
static int hf_omron_cyclic_35        = -1;
static int hf_omron_cyclic_34        = -1;
static int hf_omron_cyclic_33        = -1;
static int hf_omron_cyclic_32        = -1;
static int hf_omron_cyclic_label_6   = -1;
static int hf_omron_cyclic_47        = -1;
static int hf_omron_cyclic_46        = -1;
static int hf_omron_cyclic_45        = -1;
static int hf_omron_cyclic_44        = -1;
static int hf_omron_cyclic_43        = -1;
static int hf_omron_cyclic_42        = -1;
static int hf_omron_cyclic_41        = -1;
static int hf_omron_cyclic_40        = -1;
static int hf_omron_cyclic_label_7   = -1;
static int hf_omron_cyclic_55        = -1;
static int hf_omron_cyclic_54        = -1;
static int hf_omron_cyclic_53        = -1;
static int hf_omron_cyclic_52        = -1;
static int hf_omron_cyclic_51        = -1;
static int hf_omron_cyclic_50        = -1;
static int hf_omron_cyclic_49        = -1;
static int hf_omron_cyclic_48        = -1;
static int hf_omron_cyclic_label_8   = -1;
static int hf_omron_cyclic_62        = -1;
static int hf_omron_cyclic_61        = -1;
static int hf_omron_cyclic_60        = -1;
static int hf_omron_cyclic_59        = -1;
static int hf_omron_cyclic_58        = -1;
static int hf_omron_cyclic_57        = -1;
static int hf_omron_cyclic_56        = -1;
static int hf_omron_node_error_count = -1;



/* Defines */
#define ICF_GW_MASK  0x80
#define ICF_GW_DUSE  0x00
#define ICF_GW_USE   0x01

#define ICF_DTB_MASK 0x40
#define ICF_DTB_CMD  0x00
#define ICF_DTB_RESP 0x01

#define ICF_RB0_MASK 0x20
#define ICF_RB1_MASK 0x10
#define ICF_RB2_MASK 0x08
#define ICF_RB3_MASK 0x04
#define ICF_RB4_MASK 0x02

#define ICF_RSB_MASK 0x01
#define ICF_RSB_DUSE 0x00
#define ICF_RSB_USE  0x01

#define INT_DNA_MIN1 0x00
#define INT_DNA_MAX1 0x00
#define INT_DNA_MIN2 0x01
#define INT_DNA_MAX2 0x7F

#define INT_DA1_MIN1 0x00
#define INT_DA1_MAX1 0x3E
#define INT_DA1_MIN2 0x3F
#define INT_DA1_MAX2 0x7E
#define INT_DA1_MIN3 0xFF
#define INT_DA1_MAX3 0xFF

#define INT_DA2_MIN1 0x00
#define INT_DA2_MAX1 0x00
#define INT_DA2_MIN2 0xFE
#define INT_DA2_MAX2 0xFE
#define INT_DA2_MIN3 0x10
#define INT_DA2_MAX3 0x1F

#define INT_SNA_MIN1 0x00
#define INT_SNA_MAX1 0x00
#define INT_SNA_MIN2 0x01
#define INT_SNA_MAX2 0x7F

#define INT_SA1_MIN1 0x00
#define INT_SA1_MAX1 0x3E
#define INT_SA1_MIN2 0x3F
#define INT_SA1_MAX2 0x7E
#define INT_SA1_MIN3 0xFF
#define INT_SA1_MAX3 0xFF

#define INT_SA2_MIN1 0x00
#define INT_SA2_MAX1 0x00
#define INT_SA2_MIN2 0xFE
#define INT_SA2_MAX2 0xFE
#define INT_SA2_MIN3 0x10
#define INT_SA2_MAX3 0x1F


/* Constants used for display */
static const value_string icf_gw_vals[] = {
    { ICF_GW_DUSE, "Don't use Gateway"   },
    { ICF_GW_USE,  "Use Gateway"         },
    { 0,           NULL                  } };

static const value_string icf_dtb_vals[] = {
    { ICF_DTB_CMD,  "Command"   },
    { ICF_DTB_RESP, "Response"  },
    { 0,            NULL        } };

static const value_string icf_rsb_vals[] = {
    { ICF_RSB_DUSE, "Response Required"     },
    { ICF_RSB_USE,  "Response Not Required" },
    { 0,            NULL                    } };

static const range_string omron_dna_range[] = {
    { INT_DNA_MIN1, INT_DNA_MAX1,   "Local network"  },
    { INT_DNA_MIN2, INT_DNA_MAX2,   "Remote network" },
    { 0,            0,              NULL             } };

static const range_string omron_da1_range[] = {
    { INT_DA1_MIN1, INT_DA1_MAX1,   "SYSMAC NET / LINK" },
    { INT_DA1_MIN2, INT_DA1_MAX2,   "SYSMAC NET"        },
    { INT_DA1_MIN3, INT_DA1_MAX3,   "Broadcast"         },
    { 0,            0,              NULL                } };

static const range_string omron_da2_range[] = {
    { INT_DA2_MIN1, INT_DA2_MAX1,   "PC (CPU)"                                     },
    { INT_DA2_MIN2, INT_DA2_MAX2,   "SYSMAC NET or LINK Unit connected to network" },
    { INT_DA2_MIN3, INT_DA2_MAX3,   "CPU BUS Unit"                                 },
    { 0,            0,              NULL                                           } };

static const range_string omron_sna_range[] = {
    { INT_SNA_MIN1, INT_SNA_MAX1,   "Local network"             },
    { INT_SNA_MIN2, INT_SNA_MAX2,   "Remote network"            },
    { 0,            0,              NULL                        } };

static const range_string omron_sa1_range[] = {
    { INT_SA1_MIN1, INT_SA1_MAX1,   "SYSMAC NET / LINK" },
    { INT_SA1_MIN2, INT_SA1_MAX2,   "SYSMAC NET"        },
    { INT_SA1_MIN3, INT_SA1_MAX3,   "Broadcast"         },
    { 0,            0,              NULL                } };

static const range_string omron_sa2_range[] = {
    { INT_SA2_MIN1, INT_SA2_MAX1,   "PC (CPU)" },
    { INT_SA2_MIN2, INT_SA2_MAX2,   "SYSMAC NET or LINK Unit connected to network" },
    { INT_SA2_MIN3, INT_SA2_MAX3,   "CPU BUS Unit"                                 },
    { 0,            0,              NULL                                           } };

static const range_string omron_error_reset_range[] = {
    { 0xFFFE, 0xFFFE, "Present error cleared" },
    { 0x0002, 0x0002, "Power interruption error" },
    { 0x00A0, 0x00A7, "SYSMAC BUS error" },
    { 0x00B0, 0x00B3, "SYSMAC BUS/2 error" },
    { 0x00E7, 0x00E7, "I/O verification error" },
    { 0x00F4, 0x00F4, "Non-fatal SFC error" },
    { 0x00F7, 0x00F7, "Batter error" },
    { 0x00F8, 0x00F8, "Indirect DM error" },
    { 0x00F9, 0x00F9, "JMP error" },
    { 0x0200, 0x0215, "CPU Bus Unit error" },
    { 0x0400, 0x0415, "CPU Bus Unit setting error" },
    { 0x4101, 0x42FF, "FALL (006) executed in user program" },
    { 0xFFFF, 0xFFFF, "All errors cleared" },
    { 0x809F, 0x809F, "Cycle time too long" },
    { 0x80C0, 0x80C7, "I/O bus error" },
    { 0x80E0, 0x80E0, "I/O setting error" },
    { 0x80E1, 0x80E1, "I/O points overflow" },
    { 0x80E9, 0x80E9, "Duplication error" },
    { 0x80F0, 0x80F0, "Program error" },
    { 0x80F1, 0x80F1, "Memory error" },
    { 0x80F3, 0x80F3, "Fatal SFC error" },
    { 0x80FF, 0x80FF, "System error" },
    { 0x8100, 0x8115, "CPU bus error" },
    { 0xC101, 0xC2FF, "FALS(007) executed" },
    { 0,0, NULL }
};

static const value_string command_code_cv[] = {
    { 0x0101, "Memory Area Read" },
    { 0x0102, "Memory Area Write" },
    { 0x0103, "Memory Area Fill" },
    { 0x0104, "Multiple Memory Area Read" },
    { 0x0105, "Memory Area Transfer" },
    { 0x0201, "Parameter Area Read" },
    { 0x0202, "Parameter Area Write" },
    { 0x0203, "Parameter Area Clear" },
    { 0x0220, "Data Link Table Read" },
    { 0x0221, "Data Link Table Write" },
    { 0x0304, "Program Area Protect" },
    { 0x0305, "Program Area Protect Clear" },
    { 0x0306, "Program Area Read" },
    { 0x0307, "Program Area Write" },
    { 0x0308, "Program Area Clear" },
    { 0x0401, "Run" },
    { 0x0402, "Stop" },
    { 0x0403, "Reset" },
    { 0x0501, "Controller Data Read" },
    { 0x0502, "Connection Data Read" },
    { 0x0601, "Controller Status Read" },
    { 0x0602, "Network Status Read" },
    { 0x0603, "Data Link Status Read" },
    { 0x0620, "Cycle Time Read" },
    { 0x0701, "Clock Read" },
    { 0x0702, "Clock Write" },
    { 0x0801, "LOOP-BACK Test" },
    { 0x0802, "Broadcast Test Results Read" },
    { 0x0803, "Broadcast Test Data Send" },
    { 0x0920, "Message Read | Message Clear | FAL/FALS Read" },
    { 0x0C01, "Access Right Acquire" },
    { 0x0C02, "Access Right Forced Acquire" },
    { 0x0C03, "Access Right Release" },
    { 0x2101, "Error Clear" },
    { 0x2102, "Error Log Read" },
    { 0x2103, "Error Log Clear" },
    { 0x2201, "File Name Read" },
    { 0x2202, "Single File Read" },
    { 0x2203, "Single File Write" },
    { 0x2204, "Memory Card Format" },
    { 0x2205, "File Delete" },
    { 0x2206, "Volume Label Create/Delete" },
    { 0x2207, "File Copy" },
    { 0x2208, "File Name Change" },
    { 0x2209, "File Data Check" },
    { 0x220A, "Memory Area File Transfer" },
    { 0x220B, "Parameter Area File Transfer" },
    { 0x220C, "Program Area File Transfer" },
    { 0x220F, "File Memory Index Read" },
    { 0x2210, "File Memory Read" },
    { 0x2211, "File Memory Write" },
    { 0x2301, "Forced Set/Reset" },
    { 0x2302, "Forced Set/Reset Cancel" },
    { 0x230A, "Multiple Forced Status Read" },
    { 0x2601, "Name Set" },
    { 0x2602, "Name Delete" },
    { 0x2603, "Name Read" },
    { 0,    NULL                } };

static const value_string memory_area_code_cv[] = {
    { 0x00, "CIO, TR, CPU Bus Link, and Auxiliary : Bit status" },
    { 0x40, "CIO, TR, CPU Bus Link, and Auxiliary : Bit status (with forced status)" },
    { 0x80, "CIO, TR, CPU Bus Link, and Auxiliary : Word contents" },
    { 0xC0, "CIO, TR, CPU Bus Link, and Auxiliary : Word contents (with forced status)" },
    { 0x01, "Timer/Counter : Completion Flag status" },
    { 0x41, "Timer/Counter : Completion Flag status (with forced status)" },
    { 0x81, "Timer/Counter : PV" },
    { 0x82, "DM : Word contents" },
    { 0x03, "Transition : Flag status" },
    { 0x43, "Transition : Flag status (with forced status)" },
    { 0x04, "Step : Flag status" },
    { 0x44, "Step : Status" },
    { 0x84, "Step : Step timer PV" },
    { 0x05, "Forced status : Bit status" },
    { 0x85, "Forced status : Word contents" },
    { 0x90, "Expansion DM : Word contents, specified bank" },
    { 0x91, "Expansion DM : Word contents, specified bank" },
    { 0x92, "Expansion DM : Word contents, specified bank" },
    { 0x93, "Expansion DM : Word contents, specified bank" },
    { 0x94, "Expansion DM : Word contents, specified bank" },
    { 0x95, "Expansion DM : Word contents, specified bank" },
    { 0x96, "Expansion DM : Word contents, specified bank" },
    { 0x97, "Expansion DM : Word contents, specified bank" },
    { 0x98, "Expansion DM : Word contents, current bank" },
    { 0x9C, "Register : Register contents / Current bank no. of expansion DM" },
    { 0x1B, "Action : Flag status" },
    { 0xDD, "Interrupt status : Scheduled interrupt interval" },
    { 0,    NULL    } };

static const value_string response_codes[] = {
    { 0x0000, "Normal completion" },
    { 0x0001, "Service was interrupted" },
    { 0x0101, "Local node not part of Network" },
    { 0x0102, "Token time-out, node number to large" },
    { 0x0103, "Number of transmit retries exceeded" },
    { 0x0104, "Maximum number of frames exceeded" },
    { 0x0105, "Node number setting error (range)" },
    { 0x0106, "Node number duplication error" },
    { 0x0201, "Destination node not part of Network" },
    { 0x0202, "No node with the specified node number" },
    { 0x0203, "Third node not part of Network : Broadcasting was specified" },
    { 0x0204, "Busy error, destination node busy" },
    { 0x0205, "Response time-out" },
    { 0x0301, "Error occurred : ERC indicator is lit" },
    { 0x0302, "CPU error occurred in the PC at the destination node" },
    { 0x0303, "A controller error has prevented a normal response" },
    { 0x0304, "Node number setting error" },
    { 0x0401, "An undefined command has been used" },
    { 0x0402, "Cannot process command because the specified unit model or version is wrong" },
    { 0x0501, "Destination node number is not set in the routing table" },
    { 0x0502, "Routing table isn't registered" },
    { 0x0503, "Routing table error" },
    { 0x0504, "Max relay nodes (2) was exceeded" },
    { 0x1001, "The command is longer than the max permissible length" },
    { 0x1002, "The command is shorter than the min permissible length" },
    { 0x1003, "The designated number od data items differs from the actual number" },
    { 0x1004, "An incorrect command format has been used" },
    { 0x1005, "An incorrect header has been used" },
    { 0x1101, "Memory area code invalid or DM is not available" },
    { 0x1102, "Access size is wrong in command" },
    { 0x1103, "First address in inaccessible area" },
    { 0x1104, "The end of specified word range exceeds acceptable range" },
    { 0x1106, "A non-existent program number" },
    { 0x1109, "The size of data items in command block are wrong" },
    { 0x110A, "The IOM break function cannot be executed" },
    { 0x110B, "The response block is longer than the max length" },
    { 0x110C, "An incorrect parameter code has been specified" },
    { 0x2002, "The data is protected" },
    { 0x2003, "Registered table does not exist" },
    { 0x2004, "Search data does not exist" },
    { 0x2005, "Non-existent program number" },
    { 0x2006, "Non-existent file" },
    { 0x2007, "Verification error" },
    { 0x2101, "Specified area is read-only" },
    { 0x2102, "The data is protected" },
    { 0x2103, "Too many files open" },
    { 0x2105, "Non-existent program number" },
    { 0x2106, "Non-existent file" },
    { 0x2107, "File already exists" },
    { 0x2108, "Data cannot be changed" },
    { 0x2201, "The mode is wrong (executing)" },
    { 0x2202, "The mode is wrong (stopped)" },
    { 0x2203, "The PC is in the PROGRAM mode" },
    { 0x2204, "The PC is in the DEBUG mode" },
    { 0x2205, "The PC is in the MONITOR mode" },
    { 0x2206, "The PC is in the RUN mode" },
    { 0x2207, "The specified node is not the control node" },
    { 0x2208, "The mode is wrong and the step cannot be executed" },
    { 0x2301, "The file device does not exist where specified" },
    { 0x2302, "The specified memory does not exist" },
    { 0x2303, "No clock exists" },
    { 0x2401, "Data link table is incorrect" },
    { 0x2502, "Parity / checksum error occurred" },
    { 0x2503, "I/O setting error" },
    { 0x2504, "Too many I/O points" },
    { 0x2505, "CPU bus error" },
    { 0x2506, "I/O duplication error" },
    { 0x2507, "I/O bus error" },
    { 0x2509, "SYSMAC BUS/2 error" },
    { 0x250A, "Special I/O Unit error" },
    { 0x250D, "Duplication in SYSMAC BUS word allocation" },
    { 0x250F, "A memory error has occurred" },
    { 0x2510, "Terminator not connected in SYSMAC BUS system" },
    { 0x2601, "The specified area is not protected" },
    { 0x2602, "An incorrect password has been specified" },
    { 0x2604, "The specified area is protected" },
    { 0x2605, "The service is being executed" },
    { 0x2606, "The service is not being executed" },
    { 0x2607, "Service cannot be execute from local node" },
    { 0x2608, "Service cannot be executed settings are incorrect" },
    { 0x2609, "Service cannot be executed incorrect settings in command data" },
    { 0x260A, "The specified action has already been registered" },
    { 0x260B, "Cannot clear error, error still exists" },
    { 0x3001, "The access right is held by another device" },
    { 0x4001, "Command aborted with ABORT command" },
    { 0,    NULL    } };

static const value_string parameter_area_codes[] = {
    { 0x8010, "PC Setup" },
    { 0x8011, "Peripheral Device settings" },
    { 0x8012, "I/O table" },
    { 0x8013, "Routing tables" },
    { 0x8002, "CPU Bus Unit settings" },
    { 0,      NULL } };

static const value_string mode_codes[] = {
    { 0x00, "PROGRAM mode" },
    { 0x01, "DEBUG mode" },
    { 0x02, "MONITOR mode" },
    { 0x04, "RUN mode" },
    { 0,    NULL } };

static const value_string status_codes[] = {
    { 0x00, "Stop" },
    { 0x01, "Run" },
    { 0x80, "CPU on standby" },
    { 0,    NULL    } };

static const value_string memory_card_codes[] = {
    { 0x00, "No memory card" },
    { 0x01, "SPRAM" },
    { 0x02, "EPROM" },
    { 0x03, "EEPROM" },
    { 0,    NULL } };

static const value_string parameter_codes[] = {
    { 0x00, "Initializes the cycle time." },
    { 0x01, "Read the cycle time" },
    { 0,    NULL } };

static const value_string omron_days[] = {
    { 0x00, "Sun"  },
    { 0x01, "Mon"  },
    { 0x02, "Tues" },
    { 0x03, "Wed"  },
    { 0x04, "Thur" },
    { 0x05, "Fri"  },
    { 0x06, "Sat"  },
    { 0,    NULL   } };

static const value_string omron_file_parameter_codes[] = {
    { 0x0000, "Write new file, do not overwrite" },
    { 0x0001, "Write new file, overwrite" },
    { 0x0002, "Appened to file " },
    { 0x0003, "Overwite file" },
    { 0,      NULL  } };

static const value_string omron_volume_parameter_codes[] = {
    { 0x0000, "Create new volume label, do not overwrite" },
    { 0x0001, "Create new volume label, overwrite" },
    { 0x0002, "Delete existing volume label" },
    { 0,    NULL } };

static const value_string omron_transfer_parameter_codes[] = {
    { 0x0000, "Data transfer from the PC memory area to the file device" },
    { 0x0001, "Data transfer from the file device to the PC emory area" },
    { 0x0002, "Data compared" },
    { 0,         NULL } };

static const value_string omron_set_reset_specifications[] = {
    { 0x0000, "Force-reset (OFF)" },
    { 0x0001, "Force-set (ON)" },
    { 0x8000, "Forced status released and bit turned OFF (0)" },
    { 0x8001, "Forced status released and bit turned ON (1)" },
    { 0xFFFF, "Forced status released" },
    { 0,    NULL } };

static const value_string omron_type_codes[] = {
    { 0x00, "RAM" },
    { 0x01, "First half RAM; second half ROM" },
    { 0,    NULL } };

static const value_string omron_data_type_bits[] = {
    { 0x00, "Empty" },
    { 0x01, "I/O data" },
    { 0x02, "User program" },
    { 0x03, "Comments" },
    { 0,    NULL } };

static const value_string omron_cyclic_ops_codes[] = {
    { 0x00, "Stopped" },
    { 0x01, "Active" },
    { 0,    NULL } };

static const value_string omron_cyclic_trans_codes[] = {
    { 0x00, "No transmission" },
    { 0x01, "Transmission" },
    { 0,    NULL } };

static const int *omron_icf_fields[] = {
    &hf_omron_icf_gwb,
    &hf_omron_icf_dtb,
    &hf_omron_icf_rb0,
    &hf_omron_icf_rb1,
    &hf_omron_icf_rb2,
    &hf_omron_icf_rb3,
    &hf_omron_icf_rb4,
    &hf_omron_icf_rsb,
    NULL
};

static const int *pc_status_fields[] = {
    &hf_omron_pc_status_pdc,
    &hf_omron_pc_status_hi,
    &hf_omron_pc_status_r1,
    &hf_omron_pc_status_r2,
    &hf_omron_pc_status_rack_num,
    NULL
};

static const int *fatal_error_fields[] = {
    &hf_omron_fatal_fals_error,
    &hf_omron_fatal_sfc_error,
    &hf_omron_fatal_cycle_time_over,
    &hf_omron_fatal_program_error,
    &hf_omron_fatal_io_setting_error,
    &hf_omron_fatal_io_point_overflow,
    &hf_omron_fatal_cpu_bus_error,
    &hf_omron_fatal_duplication_error,
    &hf_omron_fatal_io_bus_error,
    &hf_omron_fatal_memory_error,
    &hf_omron_fatal_rv_1,
    &hf_omron_fatal_rv_2,
    &hf_omron_fatal_rv_3,
    &hf_omron_fatal_rv_4,
    &hf_omron_fatal_rv_5,
    &hf_omron_fatal_watch_dog_timer_error,
    NULL
};

static const int *non_fatal_error_fields[] = {
    &hf_omron_non_fatal_rv1,
    &hf_omron_non_fatal_rv2,
    &hf_omron_non_fatal_power_interruption,
    &hf_omron_non_fatal_cpu_bus_unit_setting_error,
    &hf_omron_non_fatal_battery_error,
    &hf_omron_non_fatal_sysmac_bus_error,
    &hf_omron_non_fatal_sysmac_bus2_error,
    &hf_omron_non_fatal_cpu_bus_unit_error,
    &hf_omron_non_fatal_rv3,
    &hf_omron_non_fatal_io_verification_error,
    &hf_omron_non_fatal_rv4,
    &hf_omron_non_fatal_sfc_error,
    &hf_omron_non_fatal_indirect_dm_error,
    &hf_omron_non_fatal_jmp_error,
    &hf_omron_non_fatal_rv5,
    &hf_omron_non_fatal_fal_error,
    NULL
};

static const int *message_fields[] = {
    &hf_omron_message_no_0,
    &hf_omron_message_no_1,
    &hf_omron_message_no_2,
    &hf_omron_message_no_3,
    &hf_omron_message_no_4,
    &hf_omron_message_no_5,
    &hf_omron_message_no_6,
    &hf_omron_message_no_7,
    &hf_omron_message_rv_0,
    &hf_omron_message_rv_1,
    &hf_omron_message_rv_2,
    &hf_omron_message_rv_3,
    &hf_omron_message_rv_4,
    &hf_omron_message_rv_5,
    &hf_omron_message_rv_6,
    &hf_omron_message_rv_7,
    NULL
};

static const int *message_yes_no_fields[] = {
    &hf_omron_message_rv_1,
    &hf_omron_message_rv_2,
    &hf_omron_message_rv_3,
    &hf_omron_message_rv_4,
    &hf_omron_message_rv_5,
    &hf_omron_message_rv_6,
    &hf_omron_message_rv_7,
    NULL
};

static const int *data_type_fields[] = {
    &hf_omron_data_type_type,
    &hf_omron_data_type_rv,
    &hf_omron_data_type_protected,
    &hf_omron_data_type_end,
    NULL
};

static const int *cyclic_non_fatal_1_fields[] = {
    &hf_omron_cyclic_1,
    &hf_omron_cyclic_2,
    &hf_omron_cyclic_3,
    &hf_omron_cyclic_4,
    &hf_omron_cyclic_5,
    &hf_omron_cyclic_6,
    &hf_omron_cyclic_7,
    NULL
};

static const int *cyclic_non_fatal_2_fields[] = {
    &hf_omron_cyclic_8,
    &hf_omron_cyclic_9,
    &hf_omron_cyclic_10,
    &hf_omron_cyclic_11,
    &hf_omron_cyclic_12,
    &hf_omron_cyclic_13,
    &hf_omron_cyclic_14,
    &hf_omron_cyclic_15,
    NULL
};

static const int *cyclic_non_fatal_3_fields[] = {
    &hf_omron_cyclic_16,
    &hf_omron_cyclic_17,
    &hf_omron_cyclic_18,
    &hf_omron_cyclic_19,
    &hf_omron_cyclic_20,
    &hf_omron_cyclic_21,
    &hf_omron_cyclic_22,
    &hf_omron_cyclic_23,
    NULL
};

static const int *cyclic_non_fatal_4_fields[] = {
    &hf_omron_cyclic_24,
    &hf_omron_cyclic_25,
    &hf_omron_cyclic_26,
    &hf_omron_cyclic_27,
    &hf_omron_cyclic_28,
    &hf_omron_cyclic_29,
    &hf_omron_cyclic_30,
    &hf_omron_cyclic_31,
    NULL
};

static const int *cyclic_non_fatal_5_fields[] = {
    &hf_omron_cyclic_32,
    &hf_omron_cyclic_33,
    &hf_omron_cyclic_34,
    &hf_omron_cyclic_35,
    &hf_omron_cyclic_36,
    &hf_omron_cyclic_37,
    &hf_omron_cyclic_38,
    &hf_omron_cyclic_39,
    NULL
};

static const int *cyclic_non_fatal_6_fields[] = {
    &hf_omron_cyclic_40,
    &hf_omron_cyclic_41,
    &hf_omron_cyclic_42,
    &hf_omron_cyclic_43,
    &hf_omron_cyclic_44,
    &hf_omron_cyclic_45,
    &hf_omron_cyclic_46,
    &hf_omron_cyclic_47,
    NULL
};

static const int *cyclic_non_fatal_7_fields[] = {
    &hf_omron_cyclic_48,
    &hf_omron_cyclic_49,
    &hf_omron_cyclic_50,
    &hf_omron_cyclic_51,
    &hf_omron_cyclic_52,
    &hf_omron_cyclic_53,
    &hf_omron_cyclic_54,
    &hf_omron_cyclic_55,
    NULL
};

static const int *cyclic_non_fatal_8_fields[] = {
    &hf_omron_cyclic_56,
    &hf_omron_cyclic_57,
    &hf_omron_cyclic_58,
    &hf_omron_cyclic_59,
    &hf_omron_cyclic_60,
    &hf_omron_cyclic_61,
    &hf_omron_cyclic_62,
    NULL
};

static const true_false_string boolean_data_type_protected = {
    "Protected",
    "Not Protected"
};

static const true_false_string boolean_data_type_end = {
    "Last Block",
    "Not Last Block"
};

static const true_false_string boolean_node_num_status = {
    "Normal",
    "Warning"
};

static const true_false_string boolean_status_flag_status = {
    "Error",
    "Normal"
};

static const true_false_string boolean_status_flags_slave_master = {
    "Master",
    "Slave"
};

static const true_false_string boolean_status_flags_data_link = {
    "Active",
    "Not Active"
};

static const true_false_string boolean_status_block_stop_run = {
    "Run",
    "Stop"
};

static const true_false_string boolean_status_flag_status_2 = {
    "Warning",
    "Normal"
};

static const true_false_string boolean_member_network = {
    "In network",
    "Not in network"
};

static const true_false_string boolean_member_polling = {
    "Unit does not respond to polling",
    "Unit responds to polling"
};


/* CODE */

static int
dissect_omron_fins(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti = NULL;
    proto_tree  *omron_tree = NULL;
    proto_tree  *omron_header_tree, *field_tree, *command_tree, *area_data_tree, *cpu_bus_tree;
    proto_tree  *io_data_tree, *error_log_tree, *omron_disk_data_tree, *omron_file_data_tree;
    proto_tree  *omron_block_record_tree, *omron_status_tree;
    const gchar *cmd_str;
    gint     cmd_str_idx;
    gint     reported_length_remaining;
    int      offset = 0;
    guint8   icf_flags;
    guint8   omron_byte;
    gboolean is_response = FALSE;
    gboolean is_command  = FALSE;
    guint16  command_code;

    /* Make sure we have enough actual data to do the heuristics checks */
    if(tvb_length(tvb) < 12 ) {
        return 0;
    }
    /* Check some bytes to see if it's OMRON */
    omron_byte = tvb_get_guint8(tvb, 1);
    if(omron_byte != 0x00) {
        return 0;
    }
    omron_byte = tvb_get_guint8(tvb, 2);
    if(omron_byte != 0x02) {
        return 0;
    }
    /* get the command code: we need it later */
    command_code = tvb_get_ntohs(tvb,10);

    /* Set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OMRON");


    cmd_str = match_strval_idx(command_code, command_code_cv, &cmd_str_idx);
    if (cmd_str_idx == -1)
        cmd_str = ep_strdup_printf("Unknown (%d)", command_code);

    /* Setup and fill in the INFO column if it's there */
    icf_flags = tvb_get_guint8(tvb, offset);
    if (icf_flags & 0x40) {
        is_response = TRUE;
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Response : %s", cmd_str);
        }
    }
    else
    {
        is_command = TRUE;
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Command  : %s", cmd_str);
        }
    }

    if (tree) { /* we are being asked for details */
        ti = proto_tree_add_item(tree, proto_omron_fins, tvb, 0, -1, ENC_NA);
        omron_tree = proto_item_add_subtree(ti, ett_omron);

        ti = proto_tree_add_text(omron_tree, tvb, 0, 12, "Omron Header");
        omron_header_tree = proto_item_add_subtree(ti, ett_omron_header);

        proto_tree_add_bitmask(omron_header_tree, tvb, offset, hf_omron_icf,
                               ett_omron_icf_fields, omron_icf_fields, ENC_BIG_ENDIAN);

        /* Byte 2 RSV */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 3 GCT */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_gct, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 4 DNA */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_dna, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 5 DA1 */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_da1, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 6 DA2 */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_da2, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 7 SNA */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_sna, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 8 SA1 */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_sa1, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 9 SA2 */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_sa2, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 10 SID */
        offset = offset + 1;
        proto_tree_add_item(omron_header_tree, hf_omron_sid, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Byte 11 and 12 Command Code */
        offset = offset + 1;
        ti = proto_tree_add_item(omron_header_tree, hf_omron_command, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset = offset + 2;

        reported_length_remaining = tvb_reported_length_remaining(tvb, offset);

        if (cmd_str_idx == -1) {
            /* Unknown command-code */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown Command-Code");
            return tvb_length(tvb);
        }

        /* Handle  special cases wherein the data length for a command and/or a response can be 0 */
        switch(command_code) {
        case 0x0402:
        case 0x0601:
        case 0x0602:
        case 0x0603:
        case 0x0701:
        case 0x0802:
        case 0x2103:
        case 0x2302:
        case 0x2602:
        case 0x2603:
            /* command data length > 0 is NG;  response data lengths are > 0  */
            if (is_command) {
                if (reported_length_remaining != 0) {
                    expert_add_info_format(pinfo, omron_tree, PI_MALFORMED, PI_WARN, "Unexpected Length (Should be 0)");
                }
                return tvb_length(tvb);
            }
            break;

        case 0x0403:
            /* command data length should be 0 */
            if (is_command) {
                if(reported_length_remaining != 0) {
                    expert_add_info_format(pinfo, omron_tree, PI_MALFORMED, PI_WARN, "Unexpected Length (Should be 0)");
                }
            }
            /* There's no response */
            if (is_response)
            {
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown Response Command-Code");
            }
            return tvb_length(tvb);
            break;

        case 0x0801:
            /* command data length = 0 or > 0 is OK;  */
            if (is_command) {
                if (reported_length_remaining == 0)
                    return tvb_length(tvb);
            }
            break;

        case 0x0803:
            /* command data length = 0 or > 0 is OK;  */
            if (is_command) {
                if (reported_length_remaining == 0)
                    return tvb_length(tvb);
            }
            /* There's no response */
            if (is_response)
            {
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown Response Command-Code");
                return tvb_length(tvb);
            }
            break;

        default:
            break;
        }

        /* Add command data tree */
        /* Note: A "malformed" will be thrown if data length = 0 at this point */
        ti = proto_tree_add_text(omron_tree, tvb, offset, -1, "Command Data");
        command_tree = proto_item_add_subtree(ti, ett_omron_command_data);

        /* Start parsing individual commands */
        switch(command_code) {

        case 0x0101:
        {
            /* check for enough data */
            if(is_command)
            {
                if(reported_length_remaining == 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address_bits, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    offset = offset + 6;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                                        2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 2)
                    {
                        proto_tree_add_item(command_tree, hf_omron_response_data, tvb,
                                            (offset+2), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x0102:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address_bits, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+4), 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_command_data, tvb, (offset+6), -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                        2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0103:
        {
            if(is_command)
            {
                if(reported_length_remaining == 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address_bits, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+4), 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_command_data, tvb, (offset+6), 2, ENC_NA);
                    offset = offset + 8;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                        2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0104:
        {
            if(is_command)
            {
                while(reported_length_remaining >= 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_transfer_beginning_address, tvb, (offset+1), 3, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                    reported_length_remaining = reported_length_remaining - 4;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 3)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                    reported_length_remaining = reported_length_remaining - 2;

                    while(reported_length_remaining >= 2)
                    {
                        guint8 memory_area_code;
                        guint8 memory_code_len;

                        ti = proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                        memory_area_code  = tvb_get_guint8(tvb, offset);
                        switch(memory_area_code) {
                            case 0x00:
                                memory_code_len = 1;
                                break;
                            case 0x40:
                                memory_code_len = 1;
                                break;
                            case 0x80:
                                memory_code_len = 2;
                                break;
                            case 0xC0:
                                memory_code_len = 4;
                                break;
                            case 0x01:
                                memory_code_len = 1;
                                break;
                            case 0x41:
                                memory_code_len = 1;
                                break;
                            case 0x81:
                                memory_code_len = 2;
                                break;
                            case 0x82:
                                memory_code_len = 2;
                                break;
                            case 0x03:
                                memory_code_len = 1;
                                break;
                            case 0x43:
                                memory_code_len = 1;
                                break;
                            case 0x04:
                                memory_code_len = 1;
                                break;
                            case 0x44:
                                memory_code_len = 1;
                                break;
                            case 0x84:
                                memory_code_len = 2;
                                break;
                            case 0x05:
                                memory_code_len = 1;
                                break;
                            case 0x85:
                                memory_code_len = 2;
                                break;
                            case 0x90:
                                memory_code_len = 2;
                                break;
                            case 0x91:
                                memory_code_len = 2;
                                break;
                            case 0x92:
                                memory_code_len = 2;
                                break;
                            case 0x93:
                                memory_code_len = 2;
                                break;
                            case 0x94:
                                memory_code_len = 2;
                                break;
                            case 0x95:
                                memory_code_len = 2;
                                break;
                            case 0x96:
                                memory_code_len = 2;
                                break;
                            case 0x97:
                                memory_code_len = 2;
                                break;
                            case 0x98:
                                memory_code_len = 2;
                                break;
                            case 0x1B:
                                memory_code_len = 1;
                                break;
                            case 0x9C:
                                memory_code_len = 2;
                                break;
                            case 0xDD:
                                memory_code_len = 4;
                                break;
                            default:
                                memory_code_len = 0;
                        } /* switch */

                        offset = offset + 1;
                        reported_length_remaining = reported_length_remaining - 1;

                        if(memory_code_len == 0) {
                            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN,
                                                   "Unknown Memory-Area-Code (%u)", memory_area_code);
                            return tvb_length(tvb); /* Bail out .... */
                        }
                        proto_tree_add_item(command_tree, hf_omron_data, tvb, offset, memory_code_len, ENC_NA);
                        offset = offset + memory_code_len;
                        reported_length_remaining = reported_length_remaining - memory_code_len;

                    } /* while ( ... >= 2) */
                } /* if(reported_length_remaining >= 3) */
            }
        }
        break;

        case 0x0105:
        {
            if(is_command)
            {
                if(reported_length_remaining == 10)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address_bits, tvb, (offset+3), 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code,
                        tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+5), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address_bits, tvb, (offset+7), 1, ENC_BIG_ENDIAN);

                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+8), 2, ENC_BIG_ENDIAN);
                    offset = offset + 10;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                                        2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0201:
        {

            if(is_command)
            {
                if(reported_length_remaining == 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_parameter_area_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_beginning_word, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    offset = offset + 6;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                        2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_parameter_area_code, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_beginning_word, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 8)
                    {
                        proto_tree_add_item(command_tree, hf_omron_response_data, tvb,
                              (offset+8), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x0202:
        case 0x0203:
        {

            if(is_command)
            {
                if(reported_length_remaining >= 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_parameter_area_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_beginning_word, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+4), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 6)
                    {
                        proto_tree_add_item(command_tree, hf_omron_command_data, tvb,
                              (offset+6), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset,
                        2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0220:
        {
            if(is_command)
            {
                if(reported_length_remaining == 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_fixed, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_intelligent_id_no, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_first_word, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_read_len, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    offset = offset + 8;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 3)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_link_nodes, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

                    offset = offset + 3;
                    reported_length_remaining = reported_length_remaining - 3;

                    /* add block record tree for each record */
                    while(reported_length_remaining >= 8)
                    {
                        ti = proto_tree_add_text(command_tree, tvb, offset, 8, "Block Record");
                        omron_block_record_tree = proto_item_add_subtree(ti, ett_omron_block_record);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_node_num_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_node_num_num_nodes, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_cio_area, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_kind_of_dm, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_dm_area_first_word, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_no_of_total_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                        offset = offset + 8;
                        reported_length_remaining = reported_length_remaining - 8;
                    }
                }
            } /* if (is_response) */
        }
        break;

        case 0x0221:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 9)
                {
                    proto_tree_add_item(command_tree, hf_omron_fixed, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_intelligent_id_no, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_first_word, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_read_len, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_link_nodes, tvb, (offset+8), 1, ENC_BIG_ENDIAN);

                    offset = offset + 9;
                    reported_length_remaining = reported_length_remaining - 9;

                    while(reported_length_remaining >= 8)
                    {
                        ti = proto_tree_add_text(command_tree, tvb, offset, 8, "Block Record");
                        omron_block_record_tree = proto_item_add_subtree(ti, ett_omron_block_record);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_node_num_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_node_num_num_nodes, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_cio_area, tvb, (offset+1), 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_kind_of_dm, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_dm_area_first_word, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_block_record_tree, hf_omron_block_record_no_of_total_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                        offset = offset + 8;
                        reported_length_remaining = reported_length_remaining - 8;
                    }
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0304:
        case 0x0305:
        {
            if(is_command)
            {
                if(reported_length_remaining == 15)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_protect_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+3),4,ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_last_word, tvb, (offset+7),4,ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_password, tvb, (offset+11),4,ENC_ASCII|ENC_NA);
                    offset = offset + 15;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0306:
        {
            if(is_command)
            {
                if(reported_length_remaining == 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+2), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    offset = offset + 8;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 10)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+4), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+8), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 10)
                    {
                        proto_tree_add_item(command_tree, hf_omron_response_data, tvb, (offset+10), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x0307:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+2), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 8)
                    {
                        proto_tree_add_item(command_tree, hf_omron_command_data, tvb, (offset+8), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }
            if(is_response)
            {
                if(reported_length_remaining == 10)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+4), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+8), 2, ENC_BIG_ENDIAN);
                    offset = offset + 10;
                }
            }
        }
        break;

        case 0x0308:
        {
            if(is_command)
            {
                if(reported_length_remaining == 3)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_clear_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    offset = offset + 3;
                }
            }
            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0401:
        {
            if(is_command)
            {
                if(reported_length_remaining == 3)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_mode_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    offset = offset + 3;
                }
                else if (reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_monitor_label, tvb, offset, 0, ENC_NA);
                    offset = offset + 2;
                }
            }
            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0402:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0501:
        {
            if(is_command)
            {
                if(reported_length_remaining == 1)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_data, tvb,
                              offset, -1, ENC_NA);
                    offset = offset + 1;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 94)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_controller_model, tvb, (offset+2), 20, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_controller_version, tvb, (offset+22), 20, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_for_system_use, tvb, (offset+42), 40, ENC_ASCII|ENC_NA);
                    /* add area data sub tree */
                    ti = proto_tree_add_text(command_tree, tvb, (offset+82), 12, "Area Data");
                    area_data_tree = proto_item_add_subtree(ti, ett_area_data);
                    proto_tree_add_item(area_data_tree, hf_omron_program_area_size, tvb, (offset+82), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_iom_size, tvb, (offset+84), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_num_dm_words, tvb, (offset+85), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_timer_counter_size, tvb, (offset+87), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_expansion_dm_size, tvb, (offset+88), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_num_step_transitions, tvb, (offset+89), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_kind_memory_card, tvb, (offset+91), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_memory_card_size, tvb, (offset+92), 2, ENC_BIG_ENDIAN);
                    offset = offset + 94;
                }

                else if(reported_length_remaining == 69)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    ti = proto_tree_add_text(command_tree, tvb, (offset+2), 64, "CPU Bus Unit Conf");
                    cpu_bus_tree = proto_item_add_subtree(ti, ett_cpu_bus);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_0, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_1, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_2, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_3, tvb, (offset+8), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_4, tvb, (offset+10), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_5, tvb, (offset+12), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_6, tvb, (offset+14), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_7, tvb, (offset+16), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_8, tvb, (offset+18), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_9, tvb, (offset+20), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_10, tvb, (offset+22), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_11, tvb, (offset+24), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_12, tvb, (offset+26), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_13, tvb, (offset+28), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_14, tvb, (offset+30), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_15, tvb, (offset+32), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_reserved, tvb, (offset+34), 32, ENC_ASCII|ENC_NA);
                    /* Remote IO Data tree */
                    ti = proto_tree_add_text(command_tree, tvb, (offset+66), 2, "Remote I/O data");
                    io_data_tree = proto_item_add_subtree(ti, ett_io_data);
                    proto_tree_add_item(io_data_tree, hf_omron_io_data_num_sysmac_1, tvb, (offset+66), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(io_data_tree, hf_omron_io_data_num_sysmac_2, tvb, (offset+67), 1, ENC_BIG_ENDIAN);
                    /* PC status */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+68), hf_omron_pc_status,
                        ett_pc_status_fields, pc_status_fields, ENC_BIG_ENDIAN);
                    offset = offset + 69;
                }

                else if(reported_length_remaining == 161)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_controller_model, tvb, (offset+2), 20, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_controller_version, tvb, (offset+22), 20, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_for_system_use, tvb, (offset+42), 40, ENC_ASCII|ENC_NA);
                    /* add area data sub tree */
                    ti = proto_tree_add_text(command_tree, tvb, (offset+82), 12, "Area Data");
                    area_data_tree = proto_item_add_subtree(ti, ett_area_data);
                    proto_tree_add_item(area_data_tree, hf_omron_program_area_size, tvb, (offset+82), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_iom_size, tvb, (offset+84), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_num_dm_words, tvb, (offset+85), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_timer_counter_size, tvb, (offset+87), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_expansion_dm_size, tvb, (offset+88), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_num_step_transitions, tvb, (offset+89), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_kind_memory_card, tvb, (offset+91), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(area_data_tree, hf_omron_memory_card_size, tvb, (offset+92), 2, ENC_BIG_ENDIAN);
                    /* cpu bus unit configuration */
                    ti = proto_tree_add_text(command_tree, tvb, (offset+94), 64, "CPU Bus Unit Conf");
                    cpu_bus_tree = proto_item_add_subtree(ti, ett_cpu_bus);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_0, tvb, (offset+94), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_1, tvb, (offset+96), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_2, tvb, (offset+98), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_3, tvb, (offset+100), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_4, tvb, (offset+102), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_5, tvb, (offset+104), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_6, tvb, (offset+106), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_7, tvb, (offset+108), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_8, tvb, (offset+110), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_9, tvb, (offset+112), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_10, tvb, (offset+114), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_11, tvb, (offset+116), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_12, tvb, (offset+118), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_13, tvb, (offset+120), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_14, tvb, (offset+122), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_unit_15, tvb, (offset+124), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(cpu_bus_tree, hf_omron_cpu_bus_reserved, tvb, (offset+126), 32, ENC_ASCII|ENC_NA);
                    /* Remote IO Data tree */
                    ti = proto_tree_add_text(command_tree, tvb, (offset+158), 2, "Remote I/O data");
                    io_data_tree = proto_item_add_subtree(ti, ett_io_data);
                    proto_tree_add_item(io_data_tree, hf_omron_io_data_num_sysmac_1, tvb, (offset+158), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(io_data_tree, hf_omron_io_data_num_sysmac_2, tvb, (offset+159), 1, ENC_BIG_ENDIAN);
                    /* PC status */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+160), hf_omron_pc_status,
                        ett_pc_status_fields, pc_status_fields, ENC_BIG_ENDIAN);
                    offset = offset + 161;
                }
            }
        }
        break;

        case 0x0502:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 1)
                {
                    proto_tree_add_item(command_tree, hf_omron_unit_address, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (reported_length_remaining == 2)
                    {
                        proto_tree_add_item(command_tree, hf_omron_num_units, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                        offset = offset + 1;
                    }
                    offset = offset + 1;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 24)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_units, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                    offset = offset + 3;
                    reported_length_remaining = reported_length_remaining - 3;

                    while(reported_length_remaining >= 21)
                    {
                        proto_tree_add_item(command_tree, hf_omron_unit_address, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(command_tree, hf_omron_model_number, tvb, offset+1, 20, ENC_ASCII|ENC_NA);
                        offset = offset + 21;
                        reported_length_remaining = reported_length_remaining - 21;
                    }
                }
            }
        }
        break;

        case 0x0601:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 28)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_status, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_mode_code, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    /* Add bitmask for Fatal error data */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+4), hf_omron_fatal_error_data,
                        ett_fatal_fields, fatal_error_fields, ENC_BIG_ENDIAN);
                    /* Add bitmask for non fatal error data */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+6), hf_omron_non_fatal_error_data,
                        ett_non_fatal_fields, non_fatal_error_fields, ENC_BIG_ENDIAN);
                    /* add bitmask for message yes/no data */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+8), hf_omron_message,
                        ett_message_fields, message_fields, ENC_BIG_ENDIAN);
                    /* Add rest of fields */
                    proto_tree_add_item(command_tree, hf_omron_fals, tvb, (offset+10), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_error_message, tvb, (offset+12), 16, ENC_ASCII|ENC_NA);
                    offset = offset + 28;
                }
            }
        }
        break;

        case 0x0602:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 108)
                {
                    proto_item *netw_nodes_sts;
                    proto_tree *netw_nodes_sts_tree;
                    proto_item *netw_nodes_non_fatal_err_sts;
                    proto_tree *netw_nodes_non_fatal_err_sts_tree;
                    proto_item *netw_nodes_cyclic_err_ctrs;
                    proto_tree *netw_nodes_cyclic_err_ctrs_tree;
                    guint8 i;
                    guint8 node_num;

                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;

                    /* parsing 31 bytes of foo */
                    netw_nodes_sts = proto_tree_add_text(command_tree, tvb, offset, 31, "Network Nodes Status");
                    netw_nodes_sts_tree = proto_item_add_subtree(netw_nodes_sts, ett_omron_netw_nodes_sts);
                    node_num = 1;
                    for(i = 0; i < 31; i++)
                    {
                        ti = proto_tree_add_text(netw_nodes_sts_tree, tvb, offset, 1, "Node Number %d", node_num);
                        field_tree = proto_item_add_subtree(ti, ett_omron_netw_node_sts);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_low_3, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_low_2, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_low_1, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_low_0, tvb, offset, 1, ENC_BIG_ENDIAN);
                        node_num = node_num + 1;

                        ti = proto_tree_add_text(netw_nodes_sts_tree, tvb, offset, 1, "Node Number %d", node_num);
                        field_tree = proto_item_add_subtree(ti, ett_omron_netw_node_sts);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_high_3, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_high_2, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_high_1, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(field_tree, hf_omron_netw_node_sts_high_0, tvb, offset, 1, ENC_BIG_ENDIAN);
                        node_num = node_num + 1;

                        offset = offset + 1;
                    }

                    proto_tree_add_item(command_tree, hf_omron_com_cycle_time, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_polling_unit_node_num, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_cyclic_operation, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_cyclic_trans_status, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    offset =offset + 5;

                    netw_nodes_non_fatal_err_sts =
                        proto_tree_add_text(command_tree, tvb, offset, 8, "Network Nodes Non-Fatal Error Status");
                    netw_nodes_non_fatal_err_sts_tree =
                        proto_item_add_subtree(netw_nodes_non_fatal_err_sts, ett_omron_netw_nodes_non_fatal_err_sts);

                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+0), hf_omron_cyclic_label_1,
                        ett_omron_cyclic_fields, cyclic_non_fatal_1_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+1), hf_omron_cyclic_label_2,
                        ett_omron_cyclic_fields, cyclic_non_fatal_2_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+2), hf_omron_cyclic_label_3,
                        ett_omron_cyclic_fields, cyclic_non_fatal_3_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+3), hf_omron_cyclic_label_4,
                        ett_omron_cyclic_fields, cyclic_non_fatal_4_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+4), hf_omron_cyclic_label_5,
                        ett_omron_cyclic_fields, cyclic_non_fatal_5_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+5), hf_omron_cyclic_label_6,
                        ett_omron_cyclic_fields, cyclic_non_fatal_6_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+6), hf_omron_cyclic_label_7,
                        ett_omron_cyclic_fields, cyclic_non_fatal_7_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(netw_nodes_non_fatal_err_sts_tree, tvb, (offset+7), hf_omron_cyclic_label_8,
                        ett_omron_cyclic_fields, cyclic_non_fatal_8_fields, ENC_BIG_ENDIAN);

                    offset = offset + 8;

                    netw_nodes_cyclic_err_ctrs = proto_tree_add_text(command_tree, tvb, offset, 62, "Network Nodes Cyclic Error Counters");
                    netw_nodes_cyclic_err_ctrs_tree = proto_item_add_subtree(netw_nodes_cyclic_err_ctrs, ett_omron_netw_nodes_cyclic_err_ctrs);
                    node_num = 1;
                    for(i = 0; i < 62; i++)
                    {
                        guint8 ctr = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format(netw_nodes_cyclic_err_ctrs_tree, hf_omron_node_error_count,
                                                   tvb, offset, 1, ctr, "Node Number %2d: %3d", node_num, ctr);
                        node_num = node_num + 1;
                        offset = offset + 1;
                    }
                }
            }
        }
        break;

        case 0x0603:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 16)
                {
                    proto_item *status_flags;
                    proto_tree *status_flags_tree;

                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);

                    /* add status flag tree */
                    ti = proto_tree_add_item(command_tree, hf_omron_status_flags, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_flags_slave_master, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_flags_data_link, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

                    /* command_tree for master node */
                    proto_tree_add_item(command_tree, hf_omron_master_node_number, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    offset = offset + 4;

                    /* Status flag blocks */
                    status_flags = proto_tree_add_text(command_tree, tvb, offset, 96, "Status flag blocks");
                    status_flags_tree = proto_item_add_subtree(status_flags, ett_omron_data_link_status_tree);

                    /* Status block 1 */
                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+0), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_0, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_1, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_2, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_3, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_4, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_5, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_6, tvb, (offset+0), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_7, tvb, (offset+0), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+0), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_0, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_1, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_2, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_3, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_4, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_5, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_6, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_7, tvb, (offset+1), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+0), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_0, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_1, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_2, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_3, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_4, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_5, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_6, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_7, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

                    /* status block 2 */
                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+3), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_0, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_1, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_2, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_3, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_4, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_5, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_6, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_7, tvb, (offset+3), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+3), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_0, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_1, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_2, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_3, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_4, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_5, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_6, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_7, tvb, (offset+4), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+3), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_0, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_1, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_2, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_3, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_4, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_5, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_6, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_7, tvb, (offset+5), 1, ENC_BIG_ENDIAN);

                    /* status block 3 */
                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+6), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_0, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_1, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_2, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_3, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_4, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_5, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_6, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_7, tvb, (offset+6), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+6), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_0, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_1, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_2, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_3, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_4, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_5, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_6, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_7, tvb, (offset+7), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+6), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_0, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_1, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_2, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_3, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_4, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_5, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_6, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_7, tvb, (offset+8), 1, ENC_BIG_ENDIAN);

                    /* status block 4 */
                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+9), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_0, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_1, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_2, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_3, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_4, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_5, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_6, tvb, (offset+9), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_node_7, tvb, (offset+9), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+9), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_0, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_1, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_2, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_3, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_4, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_5, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_6, tvb, (offset+10), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_1_node_7, tvb, (offset+10), 1, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_item(status_flags_tree, hf_omron_status_flags, tvb, (offset+9), 3, ENC_BIG_ENDIAN);
                    omron_status_tree = proto_item_add_subtree(ti, ett_omron_status_block);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_0, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_1, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_2, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_3, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_4, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_5, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_6, tvb, (offset+11), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_status_tree, hf_omron_status_2_node_7, tvb, (offset+11), 1, ENC_BIG_ENDIAN);

                    offset = offset + 12;
                }
            }
        }
        break;

        case 0x0620:
        {
            if(is_command)
            {
                if(reported_length_remaining == 1)
                {
                    proto_tree_add_item(command_tree, hf_omron_parameter, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset = offset + 1;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }

                else if(reported_length_remaining == 14)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_avg_cycle_time, tvb, (offset+2), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_max_cycle_time, tvb, (offset+6), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_min_cycle_time, tvb, (offset+10), 4, ENC_BIG_ENDIAN);
                    offset = offset + 14;
                }
            }
        }
        break;

        case 0x0701:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 9)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_year, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_month, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_date, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_hour, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_minute, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_second, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_day, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                    offset = offset + 9;
                }
            }
        }
        break;

        case 0x0702:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 5)
                {
                    proto_tree_add_item(command_tree, hf_omron_year, tvb, (offset), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_month, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_date, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_hour, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_minute, tvb, (offset+4), 1, ENC_BIG_ENDIAN);

                    if(reported_length_remaining == 7)
                    {
                        proto_tree_add_item(command_tree, hf_omron_second, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(command_tree, hf_omron_day, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                        offset = offset + 2;
                    }
                    offset = offset + 5;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x0801:
        {
            if(is_command)
            {
                /* zero-length case handled in previous switch statement */
                if(reported_length_remaining > 0)
                {
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, offset, -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining > 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, (offset+2), -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x0802:
        {
            if(is_response)
            {
                if(reported_length_remaining == 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_receptions, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
               }
            }
        }
        break;

        case 0x0803:
        {
            if(is_command)
            {
                /* zero-length case handled in previous switch statement */
                if(reported_length_remaining > 0)
                {
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, offset, -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x0920:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    if((tvb_get_ntohs(tvb, offset) & 0xC000) == 0x8000)
                    {
                        /* "FAL/FALS READ" */
                        proto_tree_add_item(command_tree, hf_omron_fals, tvb, offset, 2, ENC_BIG_ENDIAN);
                    }
                    else
                    {
                        /* "MESSAGE READ" / "MESSAGE CLEAR" */
                        /* add bitmask for message yes/no data */
                        proto_tree_add_bitmask(command_tree, tvb, offset, hf_omron_message,
                                               ett_message_fields, message_yes_no_fields, ENC_BIG_ENDIAN);
                    }
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
                else if(reported_length_remaining == 20)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_fals, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_error_message, tvb, (offset+4), 16, ENC_ASCII|ENC_NA);
                    offset = offset + 20;
                }
                else if(reported_length_remaining >= 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    /* add bitmask for message yes/no data */
                    proto_tree_add_bitmask(command_tree, tvb, (offset+2), hf_omron_message,
                                           ett_message_fields, message_yes_no_fields, ENC_BIG_ENDIAN);

                    offset = offset + 4;
                    reported_length_remaining = reported_length_remaining - 4;

                    while (reported_length_remaining >= 32)
                    {
                        proto_tree_add_item(command_tree, hf_omron_read_message, tvb, offset, 32, ENC_ASCII|ENC_NA);
                        offset = offset + 32;
                        reported_length_remaining = reported_length_remaining - 32;
                    }
                }
            }
        }
        break;

        case 0x0C01:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
                else if(reported_length_remaining == 5)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_unit_address, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_node_number, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_network_address, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                    offset = offset + 5;
                }

            }
        }
        break;

        case 0x0C02:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

        }
        break;

        case 0x0C03:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

        }
        break;

        case 0x2101:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_error_reset_fals_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

        }
        break;

        case 0x2102:
        {
            if(is_command)
            {
                if(reported_length_remaining == 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_beginning_record_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_records, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_max_no_of_stored_records, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_stored_records, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_records, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    offset = offset + 8;
                    reported_length_remaining = reported_length_remaining - 8;

                    while(reported_length_remaining >= 10)
                    {
                        ti = proto_tree_add_text(command_tree, tvb, offset, 10, "Error log data");
                        error_log_tree = proto_item_add_subtree(ti, ett_omron_error_log_data);

                        proto_tree_add_item(error_log_tree, hf_omron_error_reset_fals_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_error_reset_fals_no, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_minute, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_second, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_day, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_hour, tvb, (offset+7), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_year, tvb, (offset+8), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(error_log_tree, hf_omron_month, tvb, (offset+9), 1, ENC_BIG_ENDIAN);

                        offset = offset + 10;
                        reported_length_remaining = reported_length_remaining - 10;
                    }
                }
            }
        }
        break;

        case 0x2103:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2201:
        {
            if(is_command)
            {
                if(reported_length_remaining == 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_beginning_file_position, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_of_files, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    offset = offset + 6;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 50)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);

                    ti = proto_tree_add_text(command_tree, tvb, (offset+2), 26, "Disk data");
                    omron_disk_data_tree = proto_item_add_subtree(ti, ett_omron_disk_data);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_volume_label, tvb, (offset+2), 12, ENC_ASCII|ENC_NA);

                    omron_byte = tvb_get_guint8(tvb, (offset+14));
                    proto_tree_add_uint_format(omron_disk_data_tree, hf_omron_date_year, tvb, (offset+14), 1, omron_byte,
                        "Year: %d", ((omron_byte>>1)+1980));

                    proto_tree_add_item(omron_disk_data_tree, hf_omron_date_month, tvb, (offset+14), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_date_day, tvb, (offset+14), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_date_hour, tvb, (offset+14), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_date_minute, tvb, (offset+14), 4, ENC_BIG_ENDIAN);

                    omron_byte = tvb_get_guint8(tvb, (offset+17));
                    proto_tree_add_uint_format(omron_disk_data_tree, hf_omron_date_second, tvb, (offset+17), 1, omron_byte,
                        "Second: %d", ((omron_byte&0x1F)*2));

                    proto_tree_add_item(omron_disk_data_tree, hf_omron_total_capacity, tvb, (offset+18), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_unused_capacity, tvb, (offset+22), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_total_no_files, tvb, (offset+26), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(omron_disk_data_tree, hf_omron_no_files, tvb, (offset+28), 2, ENC_BIG_ENDIAN);

                    offset = offset + 30;
                    reported_length_remaining = reported_length_remaining - 30;

                    while(reported_length_remaining >= 20)
                    {
                        ti = proto_tree_add_text(command_tree, tvb, offset, 20, "File data");
                        omron_file_data_tree = proto_item_add_subtree(ti, ett_omron_file_data);

                        proto_tree_add_item(omron_file_data_tree, hf_omron_filename, tvb, offset, 12, ENC_ASCII|ENC_NA);

                        omron_byte = tvb_get_guint8(tvb, (offset+12));
                        proto_tree_add_uint_format(omron_file_data_tree, hf_omron_date_year, tvb, (offset+12), 1, omron_byte,
                                                   "Year: %d", ((omron_byte>>1)+1980));

                        proto_tree_add_item(omron_file_data_tree, hf_omron_date_month, tvb, (offset+12), 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_file_data_tree, hf_omron_date_day, tvb, (offset+12), 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_file_data_tree, hf_omron_date_hour, tvb, (offset+12), 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(omron_file_data_tree, hf_omron_date_minute, tvb, (offset+12), 4, ENC_BIG_ENDIAN);

                        omron_byte = tvb_get_guint8(tvb, (offset+15));
                        proto_tree_add_uint_format(omron_file_data_tree, hf_omron_date_second, tvb, (offset+15), 1, omron_byte,
                                                   "Second: %d", ((omron_byte&0x1F)*2));

                        proto_tree_add_item(omron_file_data_tree, hf_omron_file_capacity, tvb, (offset+16), 4, ENC_BIG_ENDIAN);

                        offset = offset + 20;
                        reported_length_remaining = reported_length_remaining - 20;
                    } /* while */
                } /* if(reported_length_remaining >= 50) */
            }
        }
        break;

        case 0x2202:
        {
            if(is_command)
            {
                if(reported_length_remaining == 20)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+2), 12, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_file_position, tvb, (offset+14), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data_length, tvb, (offset+18), 2, ENC_BIG_ENDIAN);
                    offset = offset + 20;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 12)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_file_capacity, tvb, (offset+2), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_file_position, tvb, (offset+6), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data_length, tvb, (offset+10), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining > 12)
                    {
                        proto_tree_add_item(command_tree, hf_omron_file_data, tvb, (offset+12), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x2203:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 22)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_file_parameter_code, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+4), 12, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_file_position, tvb, (offset+16), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data_length, tvb, (offset+20), 2, ENC_BIG_ENDIAN);
                    if(reported_length_remaining > 22)
                    {
                        proto_tree_add_item(command_tree, hf_omron_file_data, tvb, (offset+22), -1, ENC_NA);
                    }
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2204:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2205:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 16)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_files, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                    reported_length_remaining = reported_length_remaining - 4;

                    while(reported_length_remaining >= 12)
                    {
                        proto_tree_add_item(command_tree, hf_omron_filename, tvb, offset, 12, ENC_ASCII|ENC_NA);
                        offset = offset + 12;
                        reported_length_remaining = reported_length_remaining - 12;
                    }
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_no_files, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                }
            }
        }
        break;

        case 0x2206:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_volume_parameter_code, tvb, (offset+2), 2, ENC_BIG_ENDIAN);

                    if(reported_length_remaining == 16)
                    {
                        proto_tree_add_item(command_tree, hf_omron_volume_label, tvb, (offset+4), 12, ENC_ASCII|ENC_NA);
                        offset = offset + 12;
                    }
                    offset = offset + 4;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2207:
        {
            if(is_command)
            {
                if(reported_length_remaining == 28)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+2), 12, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, (offset+14), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+16), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 28;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2208:
        {
            if(is_command)
            {
                if(reported_length_remaining == 26)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+2), 12, ENC_ASCII|ENC_NA);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+14), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 26;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2209:
        {
            if(is_command)
            {
                if(reported_length_remaining == 14)
                {
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+2), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 14;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x220A:
        {
            if(is_command)
            {
                if(reported_length_remaining == 22)
                {
                    proto_tree_add_item(command_tree, hf_omron_transfer_parameter_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_transfer_beginning_address, tvb, (offset+3), 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, (offset+8), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+10), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 22;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_items, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                }
            }
        }
        break;

        case 0x220B:
        {
            if(is_command)
            {
                if(reported_length_remaining == 22)
                {
                    proto_tree_add_item(command_tree, hf_omron_transfer_parameter_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_parameter_area_code, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_address, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, (offset+8), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+10), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 22;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_words, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    offset = offset + 4;
                }
            }
        }
        break;

        case 0x220C:
        {
            if(is_command)
            {
                if(reported_length_remaining == 26)
                {
                    proto_tree_add_item(command_tree, hf_omron_transfer_parameter_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_program_number, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_begin_word, tvb, (offset+4), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_number_of_bytes, tvb, (offset+8), 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_disk_no, tvb, (offset+12), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_filename, tvb, (offset+14), 12, ENC_ASCII|ENC_NA);
                    offset = offset + 26;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_number_of_bytes, tvb, (offset+2), 4, ENC_BIG_ENDIAN);
                    offset = offset + 6;
                }
            }
        }
        break;

        case 0x220F:
        {
            if(is_command)
            {
                if(reported_length_remaining == 3)
                {
                    proto_tree_add_item(command_tree, hf_omron_beginning_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_blocks, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    offset = offset + 3;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 9)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_blocks_remaining, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_total_num_blocks, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_type, tvb, (offset+6), 1, ENC_BIG_ENDIAN);
                    offset = offset + 7;
                    reported_length_remaining = reported_length_remaining - 7;

                    while(reported_length_remaining >= 2)
                    {
                        proto_tree_add_bitmask(command_tree, tvb, offset, hf_omron_data_type,
                            ett_omron_data_type, data_type_fields, ENC_BIG_ENDIAN);
                        proto_tree_add_item(command_tree, hf_omron_control_data, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                        offset = offset + 2;
                        reported_length_remaining = reported_length_remaining - 2;
                    }
                }
            }
        }
        break;

        case 0x2210:
        {
            if(is_command)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_block_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 4)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_bitmask(command_tree, tvb, (offset+2), hf_omron_data_type,
                        ett_omron_data_type, data_type_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_control_data, tvb, (offset+3), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, (offset+4), -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x2211:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 4)
                {
                    proto_tree_add_bitmask(command_tree, tvb, offset, hf_omron_data_type,
                        ett_omron_data_type, data_type_fields, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_control_data, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_block_num, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, (offset+4), -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }

        break;

        case 0x2301:
        {
            if(is_command)
            {
                if(reported_length_remaining >= 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_number_of_bits_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                    reported_length_remaining = reported_length_remaining - 2;

                    while (reported_length_remaining >= 6)
                    {
                        proto_tree_add_item(command_tree, hf_omron_set_reset_specification, tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(command_tree, hf_omron_bit_flag, tvb, (offset+3), 3, ENC_BIG_ENDIAN);

                        offset = offset + 6;
                        reported_length_remaining = reported_length_remaining - 6;
                    }
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2302:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }

        }
        break;

        case 0x230A:
        {
            if(is_command)
            {
                if(reported_length_remaining == 6)
                {
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_transfer_beginning_address, tvb, (offset+1), 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_unit_uint16, tvb, (offset+4), 2, ENC_BIG_ENDIAN);
                    offset = offset + 6;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining >= 8)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_command_memory_area_code, tvb, (offset+2), 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_transfer_beginning_address, tvb, (offset+3), 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_num_unit_uint16, tvb, (offset+6), 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_data, tvb, (offset+8), -1, ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }
        }
        break;

        case 0x2601:
        {
            if(is_command)
            {
                if((reported_length_remaining > 0) && (reported_length_remaining <= 8))
                {
                    proto_tree_add_item(command_tree, hf_omron_name_data, tvb, offset, -1, ENC_ASCII|ENC_NA);
                    offset = offset + reported_length_remaining;
                }
            }

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2602:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if(reported_length_remaining == 2)
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset = offset + 2;
                }
            }
        }
        break;

        case 0x2603:
        {
            /* command data length is 0 */

            if(is_response)
            {
                if((reported_length_remaining > 2) && (reported_length_remaining <= (2+8)))
                {
                    proto_tree_add_item(command_tree, hf_omron_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(command_tree, hf_omron_name_data, tvb, offset, -1, ENC_ASCII|ENC_NA);
                    offset = offset + reported_length_remaining;
               }
            }
        }
        break;

        default:
        { /* invalid command ?? */
            ;/* ??? dissector_bug ??*/
        }
        break;

        } /* switch(command_code) */

        if ((guint)offset != tvb_reported_length(tvb)) {
            expert_add_info_format(pinfo, omron_tree, PI_MALFORMED, PI_WARN, "Unexpected Length");
        }

    } /* if(tree) */

    return tvb_length(tvb);
}

void
proto_register_omron_fins(void)
{
#if 0
    module_t *omron_fins_module;
#endif

    /* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_omron_icf,
        { "OMRON ICF Field", "omron.icf", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_icf_gwb,
        { "Gateway bit", "omron.icf.gwb", FT_UINT8, BASE_HEX, VALS(icf_gw_vals), ICF_GW_MASK, NULL, HFILL }},

        { &hf_omron_icf_dtb,
        { "Data Type bit", "omron.icf.dtb", FT_UINT8, BASE_HEX, VALS(icf_dtb_vals), ICF_DTB_MASK, NULL, HFILL }},

        { &hf_omron_icf_rb0,
        { "Reserved bit 0", "omron.icf.rb0", FT_UINT8, BASE_HEX, NULL, ICF_RB0_MASK, NULL, HFILL }},

        { &hf_omron_icf_rb1,
        { "Reserved bit 1", "omron.icf.rb1", FT_UINT8, BASE_HEX, NULL, ICF_RB1_MASK, NULL, HFILL }},

        { &hf_omron_icf_rb2,
        { "Reserved bit 2", "omron.icf.rb2", FT_UINT8, BASE_HEX, NULL, ICF_RB2_MASK, NULL, HFILL }},

        { &hf_omron_icf_rb3,
        { "Reserved bit 3", "omron.icf.rb3", FT_UINT8, BASE_HEX, NULL, ICF_RB3_MASK, NULL, HFILL }},

        { &hf_omron_icf_rb4,
        { "Reserved bit 4", "omron.icf.rb4", FT_UINT8, BASE_HEX, NULL, ICF_RB4_MASK, NULL, HFILL }},

        { &hf_omron_icf_rsb,
        { "Response setting bit", "omron.icf.rsb", FT_UINT8, BASE_HEX, VALS(icf_rsb_vals), ICF_RSB_MASK, NULL, HFILL }},

        { &hf_omron_rsv,
        { "Reserved", "omron.rsv", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_gct,
        { "Gateway Count", "omron.gct", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_dna,
        { "Destination network address", "omron.dna", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_dna_range), 0x0, NULL, HFILL }},

        { &hf_omron_da1,
        { "Destination node number", "omron.da1", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_da1_range), 0x0, NULL, HFILL }},

        { &hf_omron_da2,
        { "Destination unit address", "omron.da2", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_da2_range), 0x0, NULL, HFILL }},

        { &hf_omron_sna,
        { "Source network address", "omron.sna", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_sna_range), 0x0, NULL, HFILL }},

        { &hf_omron_sa1,
        { "Source node number", "omron.sa1", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_sa1_range), 0x0, NULL, HFILL }},

        { &hf_omron_sa2,
        { "Source unit address", "omron.sa2", FT_UINT8, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_sa2_range), 0x0, NULL, HFILL }},

        { &hf_omron_sid,
        { "Service ID", "omron.sid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_command,
        { "Command CODE", "omron.command", FT_UINT16, BASE_HEX, VALS(command_code_cv), 0x0, NULL, HFILL }},

        { &hf_omron_command_memory_area_code,
        { "Memory Area Code", "omron.memory.area.read", FT_UINT8, BASE_HEX, VALS(memory_area_code_cv), 0x0, NULL, HFILL }},

        { &hf_omron_response_code,
        { "Response code", "omron.response.code", FT_UINT16, BASE_HEX, VALS(response_codes), 0x0, NULL, HFILL }},

        { &hf_omron_command_data,
        { "Command Data", "omron.command.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_omron_address,
        { "Beginning address", "omron.memory.address", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_omron_address_bits,
        { "Beginning address bits", "omron.memory.address.bits", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

        { &hf_omron_num_items,
        { "Number of items", "omron.memory.numitems", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_omron_response_data,
        { "Response data", "omron.response.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_omron_parameter_area_code,
        { "Parameter area code", "omron.parameter_area_code", FT_UINT16, BASE_HEX, VALS(parameter_area_codes), 0x0, NULL, HFILL }},

        { &hf_omron_beginning_word,
        { "Beginning word", "omron.word", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_num_words,
        { "No. words or Bytes", "omron.numwords", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_program_number,
        { "Program number", "omron.program_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_protect_code,
        { "Protect code", "omron.protect_code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_begin_word,
        { "Beginning word", "omron.word.begin", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_last_word,
        { "Last word", "omron.word.last", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_password,
        { "Password", "omron.password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_clear_code,
        { "Clear Code", "omron.clearcode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_mode_code,
        { "Mode Code", "omron.mode_code", FT_UINT8, BASE_HEX, VALS(mode_codes), 0x0, NULL, HFILL }},

        { &hf_omron_monitor_label,
        { "Mode Code (Default Monitor)", "omron.mode_code_default_monitor", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_controller_model,
        { "Controller model", "omron.controller.model", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_controller_version,
        { "Controller version", "omron.controller.version", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_for_system_use,
        { "For system use", "omron.system.use", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_program_area_size,
        {"Program area size", "omron.area_data.program_area_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_iom_size,
        {"IOM size", "omron.area_data.iom_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_num_dm_words,
        { "No. of DM words", "omron.area_data.dm_words", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_timer_counter_size,
        { "Timer/counter size", "omron.area_data.timer_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_expansion_dm_size,
        { "Expansion DM size", "omron.area_data.dm_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_omron_num_step_transitions,
        { "No. of steps/transitions", "omron.area_data.num_steps", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_kind_memory_card,
        { "Kind of Memory card", "omron.area_data.memory_card", FT_UINT8, BASE_DEC, VALS(memory_card_codes), 0x0, NULL, HFILL }},

        { &hf_omron_memory_card_size,
        { "Memory card size", "omron.area_data.memory_card.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_0,
        { "CPU Bus Unit No. 0", "omron.cpubus_unit.no0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_1,
        { "CPU Bus Unit No. 1", "omron.cpubus_unit.no1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_2,
        { "CPU Bus Unit No. 2", "omron.cpubus_unit.no2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_3,
        { "CPU Bus Unit No. 3", "omron.cpubus_unit.no3", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_4,
        { "CPU Bus Unit No. 4", "omron.cpubus_unit.no4", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_5,
        { "CPU Bus Unit No. 5", "omron.cpubus_unit.no5", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_6,
        { "CPU Bus Unit No. 6", "omron.cpubus_unit.no6", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_7,
        { "CPU Bus Unit No. 7", "omron.cpubus_unit.no7", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_8,
        { "CPU Bus Unit No. 8", "omron.cpubus_unit.no8", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_9,
        { "CPU Bus Unit No. 9", "omron.cpubus_unit.no9", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_10,
        { "CPU Bus Unit No. 10", "omron.cpubus_unit.no10", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_11,
        { "CPU Bus Unit No. 11", "omron.cpubus_unit.no11", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_12,
        { "CPU Bus Unit No. 12", "omron.cpubus_unit.no12", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_13,
        { "CPU Bus Unit No. 13", "omron.cpubus_unit.no13", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_14,
        { "CPU Bus Unit No. 14", "omron.cpubus_unit.no14", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_unit_15,
        { "CPU Bus Unit No. 15", "omron.cpubus_unit.no15", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cpu_bus_reserved,
        { "CPU Bus Unit Reserved", "omron.cpubus_unit.reserved", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_io_data_num_sysmac_1,
        { "No. of SYSMAC BUS/2 Masters mounted", "omron.remote_io_date.sysmac_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_io_data_num_sysmac_2,
        { "No. of SYSMAC BUS Masters mounted", "omron.remote_io_date.sysmac_2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_pc_status,
        { "PC status", "omron.pc_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_pc_status_pdc,
        { "Peripheral Device connected", "omron.pc_status.pdc", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL}},
        { &hf_omron_pc_status_hi,
        { "With built-in host interface", "omron.pc_status.hi", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL}},
        { &hf_omron_pc_status_r1,
        { "Reserved 1", "omron.pc_status.r1", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL}},
        { &hf_omron_pc_status_r2,
        { "Reserved 2", "omron.pc_status.r2", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL}},
        { &hf_omron_pc_status_rack_num,
        { "Rack Number", "omron.pcp_status.rack_num", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},
        { &hf_omron_unit_address,
        { "Unit address", "omron.unit_address", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_num_units,
        { "No. of Units", "omron.unit_nums", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_model_number,
        { "Model Number", "omron.model_number", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_status,
        { "Status", "omron.status", FT_UINT8, BASE_HEX, VALS(status_codes), 0x0, NULL, HFILL}},
        { &hf_omron_fatal_error_data,
        { "Fatal error data", "omron.fatal_error_data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_fatal_fals_error,
        {"FALS error", "omron.fatal.fals_error", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
        { &hf_omron_fatal_sfc_error,
        {"Fatal SFC error", "omron.fatal.sfc_error", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
        { &hf_omron_fatal_cycle_time_over,
        {"Cycle time over", "omron.fatal.cycle_time_over", FT_UINT16, BASE_DEC, NULL, 0x2000, NULL, HFILL }},
        { &hf_omron_fatal_program_error,
        {"Program error", "omron.fatal.program_error", FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL }},
        { &hf_omron_fatal_io_setting_error,
        {"I/O setting error", "omron.fatal.io_setting_error", FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL }},
        { &hf_omron_fatal_io_point_overflow,
        {"I/O point overflow", "omron.fatal.io_point_overflow", FT_UINT16, BASE_DEC, NULL, 0x0400, NULL, HFILL }},
        { &hf_omron_fatal_cpu_bus_error,
        {"CPU bus error", "omron.fatal.cpu_bus_error", FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL }},
        { &hf_omron_fatal_duplication_error,
        {"Duplication error", "omron.fatal.duplication_error", FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL }},
        { &hf_omron_fatal_io_bus_error,
        {"I/O bus error", "omron.fatal.io_bus_error", FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL }},
        { &hf_omron_fatal_memory_error,
        {"Memory error", "omron.fatal.memory_error", FT_UINT16, BASE_DEC, NULL, 0x0040, NULL, HFILL }},
        { &hf_omron_fatal_rv_1,
        {"Reserved", "omron.fatal.rv_1", FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL }},
        { &hf_omron_fatal_rv_2,
        {"Reserved", "omron.fatal.rv_2", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL }},
        { &hf_omron_fatal_rv_3,
        {"Reserved", "omron.fatal.rv_3", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL }},
        { &hf_omron_fatal_rv_4,
        {"Reserved", "omron.fatal.rv_4", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL }},
        { &hf_omron_fatal_rv_5,
        {"Reserved", "omron.fatal.rv_5", FT_UINT16, BASE_DEC, NULL, 0x0002, NULL, HFILL }},
        { &hf_omron_fatal_watch_dog_timer_error,
        {"Watch dog timer error", "omron.fatal.watch_dog_timer_error", FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL }},
        { &hf_omron_non_fatal_error_data,
        { "Non fatal error data", "omron.fatal_error_data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_non_fatal_rv1,
        { "Reserved", "omron.non_fatal.rv1", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
        { &hf_omron_non_fatal_rv2,
        { "Reserved", "omron.non_fatal.rv2", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
        { &hf_omron_non_fatal_power_interruption,
        { "Momentary power interruption", "omron.non_fatal.power_interruption", FT_UINT16, BASE_DEC, NULL, 0x2000, NULL, HFILL }},
        { &hf_omron_non_fatal_cpu_bus_unit_setting_error,
        { "CPU Bus Unit setting error", "omron.non_fatal.cpu_bus_unit_setting_error", FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL }},
        { &hf_omron_non_fatal_battery_error,
        { "Battery error", "omron.non_fatal.batter_error", FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL }},
        { &hf_omron_non_fatal_sysmac_bus_error,
        { "SYSMAC BUS error", "omron.non_fatal.sysmac_bus_error", FT_UINT16, BASE_DEC, NULL, 0x0400, NULL, HFILL }},
        { &hf_omron_non_fatal_sysmac_bus2_error,
        { "SYSMAC BUS/2 error", "omron.non_fatal.sysmac_bus2_error", FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL }},
        { &hf_omron_non_fatal_cpu_bus_unit_error,
        { "CPU Bus Unit error", "omron.non_fatal.cpu_bus_unit_error", FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL }},
        { &hf_omron_non_fatal_rv3,
        { "Reserved", "omron.non_fatal.rv3", FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL }},
        { &hf_omron_non_fatal_io_verification_error,
        { "I/O verification error", "omron.non_fatal.io_verification_error", FT_UINT16, BASE_DEC, NULL, 0x0040, NULL, HFILL }},
        { &hf_omron_non_fatal_rv4,
        { "Reserved", "omron.non_fatal.rv4", FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL }},
        { &hf_omron_non_fatal_sfc_error,
        { "Non-fatal SFC error v", "omron.non_fatal.sfc_error", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL }},
        { &hf_omron_non_fatal_indirect_dm_error,
        { "Indirect DM error", "omron.non_fatal.indirect_dm_error", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL }},
        { &hf_omron_non_fatal_jmp_error,
        { "JMP error", "omron.non_fatal.jmp_error", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL }},
        { &hf_omron_non_fatal_rv5,
        { "Reserved", "omron.non_fatal.rv5", FT_UINT16, BASE_DEC, NULL, 0x0002, NULL, HFILL }},
        { &hf_omron_non_fatal_fal_error,
        { "FAL error", "omron.non_fatal.fal_error", FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL }},
        { &hf_omron_message,
        { "Message", "omron.message", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_message_no_0,
        { "Message no. 0", "omron.message.no_0", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000, NULL, HFILL }},
        { &hf_omron_message_no_1,
        { "Message no. 1", "omron.message.no_1", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000, NULL, HFILL }},
        { &hf_omron_message_no_2,
        { "Message no. 2", "omron.message.no_2", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000, NULL, HFILL }},
        { &hf_omron_message_no_3,
        { "Message no. 3", "omron.message.no_3", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000, NULL, HFILL }},
        { &hf_omron_message_no_4,
        { "Message no. 4", "omron.message.no_4", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800, NULL, HFILL }},
        { &hf_omron_message_no_5,
        { "Message no. 5", "omron.message.no_5", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400, NULL, HFILL }},
        { &hf_omron_message_no_6,
        { "Message no. 6", "omron.message.no_6", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200, NULL, HFILL }},
        { &hf_omron_message_no_7,
        { "Message no. 7", "omron.message.no_7", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100, NULL, HFILL }},
        { &hf_omron_message_rv_0,
        { "Reserved", "omron.message.rv_0", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080, NULL, HFILL }},
        { &hf_omron_message_rv_1,
        { "Reserved", "omron.message.rv_1", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040, NULL, HFILL }},
        { &hf_omron_message_rv_2,
        { "Reserved", "omron.message.rv_2", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020, NULL, HFILL }},
        { &hf_omron_message_rv_3,
        { "Reserved", "omron.message.rv_3", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010, NULL, HFILL }},
        { &hf_omron_message_rv_4,
        { "Reserved", "omron.message.rv_4", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008, NULL, HFILL }},
        { &hf_omron_message_rv_5,
        { "Reserved", "omron.message.rv_5", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004, NULL, HFILL }},
        { &hf_omron_message_rv_6,
        { "Reserved", "omron.message.rv_6", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002, NULL, HFILL }},
        { &hf_omron_message_rv_7,
        { "Reserved", "omron.message.rv_7", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001, NULL, HFILL }},
        { &hf_omron_fals,
        { "FALS / FALS no.", "omron.fals", FT_UINT16, BASE_HEX, NULL, 0x3FFF, NULL, HFILL}},
        { &hf_omron_error_message,
        { "Error message", "omron.error_message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_omron_parameter,
        { "Parameter", "omron.parameter", FT_UINT8, BASE_HEX, VALS(parameter_codes), 0x0, NULL, HFILL }},
        { &hf_omron_avg_cycle_time,
        { "Average cycle time", "omron.avg_cycle_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_max_cycle_time,
        { "Max. cycle time", "omron.max_cycle_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_min_cycle_time,
        { "Min cycle time", "omron.min_cycle_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_year,
        { "Year", "omron.year", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_month,
        { "Month", "omron.month", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_date,
        { "Date", "omron.date", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_hour,
        { "Hour", "omron.hour", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_minute,
        { "Minute", "omron.minute", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_second,
        { "Second", "omron.second", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_day,
        { "Day", "omron.day", FT_UINT8, BASE_DEC, VALS(omron_days), 0x0, NULL, HFILL }},
        { &hf_omron_read_message,
        { "Message", "omron.read_message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_node_number,
        { "Node number", "omron.node_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_network_address,
        { "Network address", "omron.network_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_error_reset_fals_no,
        { "Error reset FAL no.", "omron.error_reset_fals_no", FT_UINT16, BASE_RANGE_STRING|BASE_HEX, RVALS(&omron_error_reset_range), 0x0, NULL, HFILL }},
        { &hf_omron_beginning_record_no,
        { "Beginning record no.", "omron.beginning_record_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_no_of_records,
        { "No. of records", "omron.no_of_records", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_max_no_of_stored_records,
        { "Max. no. of stored records", "omron.max_no_of_stored_records", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_no_of_stored_records,
        { "No. of stored records", "omron.no_stored_records", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_disk_no,
        { "Disk no.", "omron.disk_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_beginning_file_position,
        { "Beginning file position", "omron.beginning_file_position", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_no_of_files,
        { "No. of files", "omron.no_of_files", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_volume_label,
        { "Volume label", "omron.disk_data.volume_label", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_date_year,
        { "Year", "omron.disk_data.year", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_date_month,
        { "Month", "omron.disk_data.month", FT_UINT32, BASE_DEC, NULL, 0x01E00000, NULL, HFILL }},
        { &hf_omron_date_day,
        { "Day", "omron.disk_data.day", FT_UINT32, BASE_DEC, NULL, 0x001F0000, NULL, HFILL }},
        { &hf_omron_date_hour,
        { "Hour", "omron.disk_data.hour", FT_UINT32, BASE_DEC, NULL, 0x0000F800, NULL, HFILL }},
        { &hf_omron_date_minute,
        { "Minute", "omron.disk_data.minute", FT_UINT32, BASE_DEC, NULL, 0x000007E0, NULL, HFILL }},
        { &hf_omron_date_second,
        { "Second", "omron.disk_data.second", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_total_capacity,
        { "Total capacity", "omron.disk_data.total_capacity", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_unused_capacity,
        { "Unused capacity", "omron.disk_data.unused_capacity", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_total_no_files,
        { "Total no. of files", "omron.disk_data.total_no_files", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_no_files,
        { "No. of files", "omron.disk_data.no_files", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_filename,
        { "Filename", "omron.file_data.filename", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_file_capacity,
        { "File capacity", "omron.file_data.file_capacity", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_file_position,
        { "File position", "omron.file_position", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_data_length,
        { "Data length", "omron.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_file_data,
        { "File data", "omron.file_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_file_parameter_code,
        { "Parameter code", "omron.file_parameter_code", FT_UINT16, BASE_HEX, VALS(omron_file_parameter_codes), 0x0, NULL, HFILL }},
        { &hf_omron_volume_parameter_code,
        { "Volume parameter code", "omron.volume_parameter_code", FT_UINT16, BASE_HEX, VALS(omron_volume_parameter_codes), 0x0, NULL, HFILL }},
        { &hf_omron_transfer_parameter_code,
        { "Parameter code", "omron.transfer_parameter_code", FT_UINT16, BASE_HEX, VALS(omron_transfer_parameter_codes), 0x0, NULL, HFILL }},
        { &hf_omron_transfer_beginning_address,
        { "Beginning address", "omron.transfer_beginning_address", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_number_of_bytes,
        { "Number of bytes", "omron.number_of_bytes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_number_of_bits_flags,
        { "No. of bits/flags", "omron.number_of_bits_flags", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_set_reset_specification,
        { "Set/Reset Specification", "omron.set_reset_specification", FT_UINT16, BASE_HEX, VALS(omron_set_reset_specifications), 0x0, NULL, HFILL }},
        { &hf_omron_bit_flag,
        { "Bit/flag", "omron.bit_flag", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_data,
        { "Data", "omron.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_beginning_block_num,
        { "Beginning block number", "omron.beginning_block_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_num_blocks,
        { "Number of blocks", "omron.num_blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_num_blocks_remaining,
        { "Number of blocks remaining", "omron.num_blocks_remaining", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_total_num_blocks,
        { "Total number of blocks", "omron.total_num_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_type,
        { "Type", "omron.type", FT_UINT8, BASE_HEX, VALS(omron_type_codes), 0x0, NULL, HFILL }},
        { &hf_omron_data_type,
        { "Data type", "omron.data_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_data_type_type,
        { "Data type", "omron.data_type_type", FT_UINT8, BASE_HEX, VALS(omron_data_type_bits), 0x07, NULL, HFILL }},
        { &hf_omron_data_type_rv,
        { "Reserved", "omron.data_type_rv", FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL }},
        { &hf_omron_data_type_protected,
        { "Protected", "omron.data_type_protected", FT_BOOLEAN, 8, TFS(&boolean_data_type_protected), 0x40, NULL, HFILL }},
        { &hf_omron_data_type_end,
        { "Block", "omron.data_type_end", FT_BOOLEAN, 8, TFS(&boolean_data_type_end), 0x80, NULL, HFILL }},
        { &hf_omron_control_data,
        { "Control data", "omron.control_data", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_block_num,
        { "Block number", "omron.block_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_num_unit_uint16,
        { "Number of units", "omron.num_unit_uint16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_fixed,
        { "Fixed", "omron.fixed", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_intelligent_id_no,
        { "Intelligent ID no.", "omron.intelligent_id_no", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_first_word,
        { "First word", "omron.first_word", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_read_len,
        { "Read length", "omron.read_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_no_of_link_nodes,
        { "No. of link nodes", "omron.no_of_link_nodes", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
        { &hf_omron_block_record_node_num_status,
        { "Data link status", "omron.block_record.node_num_status", FT_BOOLEAN, 8, TFS(&boolean_node_num_status), 0x80, NULL, HFILL }},
        { &hf_omron_block_record_node_num_num_nodes,
        { "No. of link nodes", "omron.block_record.node_num_num_nodes", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
        { &hf_omron_block_record_cio_area,
        { "CIO Area first word", "omron.block_record.cio_area", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_block_record_kind_of_dm,
        { "Kind of DM", "omron.block_record.kind_of_dm", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_block_record_dm_area_first_word,
        { "DM Area first word", "omron.block_record.dm_area_first_word", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_block_record_no_of_total_words,
        { "No. of total words", "omron.block_record.no_of_total_words", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_status_flags,
        { "Status flags", "omron.status_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_status_flags_slave_master,
        { "Status Type", "omron.status_flags.slave_master", FT_BOOLEAN, 8, TFS(&boolean_status_flags_slave_master), 0x80, NULL, HFILL }},
        { &hf_omron_status_flags_data_link,
        { "Status Data link", "omron.status_flags.data_link", FT_BOOLEAN, 8, TFS(&boolean_status_flags_data_link), 0x01, NULL, HFILL }},
        { &hf_omron_master_node_number,
        { "Master node number", "omron.master_node_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_status_node_0,
        { "Node 0", "omron.status.node.0", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x01, NULL, HFILL }},
        { &hf_omron_status_node_1,
        { "Node 1", "omron.status.node.1", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x02, NULL, HFILL }},
        { &hf_omron_status_node_2,
        { "Node 2", "omron.status.node.2", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x04, NULL, HFILL }},
        { &hf_omron_status_node_3,
        { "Node 3", "omron.status.node.3", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x08, NULL, HFILL }},
        { &hf_omron_status_node_4,
        { "Node 4", "omron.status.node.4", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x10, NULL, HFILL }},
        { &hf_omron_status_node_5,
        { "Node 5", "omron.status.node.5", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x20, NULL, HFILL }},
        { &hf_omron_status_node_6,
        { "Node 6", "omron.status.node.6", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x40, NULL, HFILL }},
        { &hf_omron_status_node_7,
        { "Node 7", "omron.status.node.7", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x80, NULL, HFILL }},
        { &hf_omron_status_1_node_0,
        { "Node 0", "omron.status.node.10", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x01, NULL, HFILL }},
        { &hf_omron_status_1_node_1,
        { "Node 1", "omron.status.node.11", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x02, NULL, HFILL }},
        { &hf_omron_status_1_node_2,
        { "Node 2", "omron.status.node.12", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x04, NULL, HFILL }},
        { &hf_omron_status_1_node_3,
        { "Node 3", "omron.status.node.13", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x08, NULL, HFILL }},
        { &hf_omron_status_1_node_4,
        { "Node 4", "omron.status.node.14", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x10, NULL, HFILL }},
        { &hf_omron_status_1_node_5,
        { "Node 5", "omron.status.node.15", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x20, NULL, HFILL }},
        { &hf_omron_status_1_node_6,
        { "Node 6", "omron.status.node.16", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x40, NULL, HFILL }},
        { &hf_omron_status_1_node_7,
        { "Node 7", "omron.status.node.17", FT_BOOLEAN, 8, TFS(&boolean_status_block_stop_run), 0x80, NULL, HFILL }},
        { &hf_omron_status_2_node_0,
        { "Node 0", "omron.status.node.20", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x01, NULL, HFILL }},
        { &hf_omron_status_2_node_1,
        { "Node 1", "omron.status.node.21", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x02, NULL, HFILL }},
        { &hf_omron_status_2_node_2,
        { "Node 2", "omron.status.node.22", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x04, NULL, HFILL }},
        { &hf_omron_status_2_node_3,
        { "Node 3", "omron.status.node.23", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x08, NULL, HFILL }},
        { &hf_omron_status_2_node_4,
        { "Node 4", "omron.status.node.24", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x10, NULL, HFILL }},
        { &hf_omron_status_2_node_5,
        { "Node 5", "omron.status.node.25", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x20, NULL, HFILL }},
        { &hf_omron_status_2_node_6,
        { "Node 6", "omron.status.node.26", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x40, NULL, HFILL }},
        { &hf_omron_status_2_node_7,
        { "Node 7", "omron.status.node.27", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status_2), 0x80, NULL, HFILL }},
        { &hf_omron_name_data,
        { "Name data", "omron.name_data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_num_receptions,
        { "Number of receptions", "omron.num_receptions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_netw_node_sts_low_0,
        { "Network", "omron.node_number.low.network", FT_BOOLEAN, 8, TFS(&boolean_member_network), 0x01, NULL, HFILL }},
        { &hf_omron_netw_node_sts_low_1,
        { "Exit status", "omron.node_number.low.exit_status", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x02, NULL, HFILL }},
        { &hf_omron_netw_node_sts_low_2,
        { "Reserved", "omron.node_number.low.rv", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_omron_netw_node_sts_low_3,
        { "Polling", "omron.node_number.low.polling_Status", FT_BOOLEAN, 8, TFS(&boolean_member_polling), 0x08, NULL, HFILL }},
        { &hf_omron_netw_node_sts_high_0,
        { "Network", "omron.node_number.high.network", FT_BOOLEAN, 8, TFS(&boolean_member_network), 0x10, NULL, HFILL }},
        { &hf_omron_netw_node_sts_high_1,
        { "Exit status", "omron.node_number.high.exit_status", FT_BOOLEAN, 8, TFS(&boolean_status_flag_status), 0x20, NULL, HFILL }},
        { &hf_omron_netw_node_sts_high_2,
        { "Reserved", "omron.node_number.high.rv", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
        { &hf_omron_netw_node_sts_high_3,
        { "Polling", "omron.node_number.high.polling_Status", FT_BOOLEAN, 8, TFS(&boolean_member_polling), 0x80, NULL, HFILL }},
        { &hf_omron_com_cycle_time,
        { "Communications cycle time (usec)", "omron.com_cycle_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_polling_unit_node_num,
        { "Current polling unit node number", "omron.polling_unit_node_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_operation,
        { "Cyclic operation", "omron.cyclic_operation", FT_UINT8, BASE_HEX, VALS(omron_cyclic_ops_codes), 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_trans_status,
        { "Cyclic transmission status", "omron.cyclic_trans_status", FT_UINT8, BASE_HEX, VALS(omron_cyclic_trans_codes), 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_label_1,
        { "Nodes  1- 7", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_7,
        { "Node  7 error status", "omron.cyclic_error.node.7", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_6,
        { "Node  6 error status", "omron.cyclic_error.node.6", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_5,
        { "Node  5 error status", "omron.cyclic_error.node.5", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_4,
        { "Node  4 error status", "omron.cyclic_error.node.4", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_3,
        { "Node  3 error status", "omron.cyclic_error.node.3", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_2,
        { "Node  2 error status", "omron.cyclic_error.node.2", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_1,
        { "Node  1 error status", "omron.cyclic_error.node.1", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_label_2,
        { "Nodes  8-15", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_15,
        { "Node 15 error status", "omron.cyclic_error.node.15", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_14,
        { "Node 14 error status", "omron.cyclic_error.node.14", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_13,
        { "Node 13 error status", "omron.cyclic_error.node.13", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_12,
        { "Node 12 error status", "omron.cyclic_error.node.12", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_11,
        { "Node 11 error status", "omron.cyclic_error.node.11", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_10,
        { "Node 10 error status", "omron.cyclic_error.node.10", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_9,
        { "Node  9 error status", "omron.cyclic_error.node.9", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_8,
        { "Node  8 error status", "omron.cyclic_error.node.8", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_3,
        { "Nodes 16-23", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_23,
        { "Node 23 error status", "omron.cyclic_error.node.23", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_22,
        { "Node 22 error status", "omron.cyclic_error.node.22", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_21,
        { "Node 21 error status", "omron.cyclic_error.node.21", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_20,
        { "Node 20 error status", "omron.cyclic_error.node.20", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_19,
        { "Node 19 error status", "omron.cyclic_error.node.19", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_18,
        { "Node 18 error status", "omron.cyclic_error.node.18", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_17,
        { "Node 17 error status", "omron.cyclic_error.node.17", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_16,
        { "Node 16 error status", "omron.cyclic_error.node.16", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_4,
        { "Nodes 24-31", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_31,
        { "Node 31 error status", "omron.cyclic_error.node.31", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_30,
        { "Node 30 error status", "omron.cyclic_error.node.30", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_29,
        { "Node 29 error status", "omron.cyclic_error.node.29", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_28,
        { "Node 28 error status", "omron.cyclic_error.node.28", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_27,
        { "Node 27 error status", "omron.cyclic_error.node.27", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_26,
        { "Node 26 error status", "omron.cyclic_error.node.26", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_25,
        { "Node 25 error status", "omron.cyclic_error.node.25", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_24,
        { "Node 24 error status", "omron.cyclic_error.node.24", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_5,
        { "Nodes 32-39", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_39,
        { "Node 39 error status", "omron.cyclic_error.node.39", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_38,
        { "Node 38 error status", "omron.cyclic_error.node.38", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_37,
        { "Node 37 error status", "omron.cyclic_error.node.37", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_36,
        { "Node 36 error status", "omron.cyclic_error.node.36", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_35,
        { "Node 35 error status", "omron.cyclic_error.node.35", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_34,
        { "Node 34 error status", "omron.cyclic_error.node.34", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_33,
        { "Node 33 error status", "omron.cyclic_error.node.33", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_32,
        { "Node 32 error status", "omron.cyclic_error.node.32", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_6,
        { "Nodes 40-47", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_47,
        { "Node 47 error status", "omron.cyclic_error.node.47", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_46,
        { "Node 46 error status", "omron.cyclic_error.node.46", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_45,
        { "Node 45 error status", "omron.cyclic_error.node.45", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_44,
        { "Node 44 error status", "omron.cyclic_error.node.44", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_43,
        { "Node 43 error status", "omron.cyclic_error.node.43", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_42,
        { "Node 42 error status", "omron.cyclic_error.node.42", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_41,
        { "Node 41 error status", "omron.cyclic_error.node.41", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_40,
        { "Node 40 error status", "omron.cyclic_error.node.40", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_7,
        { "Nodes 48-55", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_55,
        { "Node 55 error status", "omron.cyclic_error.node.55", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
        { &hf_omron_cyclic_54,
        { "Node 54 error status", "omron.cyclic_error.node.54", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_53,
        { "Node 53 error status", "omron.cyclic_error.node.53", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_52,
        { "Node 52 error status", "omron.cyclic_error.node.52", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_51,
        { "Node 51 error status", "omron.cyclic_error.node.51", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_50,
        { "Node 50 error status", "omron.cyclic_error.node.50", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_49,
        { "Node 49 error status", "omron.cyclic_error.node.49", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_48,
        { "Node 48 error status", "omron.cyclic_error.node.48", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_cyclic_label_8,
        { "Nodes 56-62", "omron.cyclic_error_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_omron_cyclic_62,
        { "Node 62 error status", "omron.cyclic_error.node.62", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
        { &hf_omron_cyclic_61,
        { "Node 61 error status", "omron.cyclic_error.node.61", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
        { &hf_omron_cyclic_60,
        { "Node 60 error status", "omron.cyclic_error.node.60", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
        { &hf_omron_cyclic_59,
        { "Node 59 error status", "omron.cyclic_error.node.59", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL }},
        { &hf_omron_cyclic_58,
        { "Node 58 error status", "omron.cyclic_error.node.58", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04, NULL, HFILL }},
        { &hf_omron_cyclic_57,
        { "Node 57 error status", "omron.cyclic_error.node.57", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL }},
        { &hf_omron_cyclic_56,
        { "Node 56 error status", "omron.cyclic_error.node.56", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01, NULL, HFILL }},
        { &hf_omron_node_error_count,
        { "Node error count", "omron.node_error_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_omron,
        &ett_omron_header,
        &ett_omron_icf_fields,
        &ett_omron_command_data,
        &ett_area_data,
        &ett_cpu_bus,
        &ett_io_data,
        &ett_pc_status_fields,
        &ett_fatal_fields,
        &ett_non_fatal_fields,
        &ett_message_fields,
        &ett_omron_error_log_data,
        &ett_omron_disk_data,
        &ett_omron_file_data,
        &ett_omron_data_type,
        &ett_omron_block_record,
        &ett_omron_status_block,
        &ett_omron_cyclic_fields,
        &ett_omron_netw_nodes_sts,
        &ett_omron_netw_node_sts,
        &ett_omron_netw_nodes_non_fatal_err_sts,
        &ett_omron_netw_nodes_cyclic_err_ctrs,
        &ett_omron_data_link_status_tree,
    };

    /* Register the protocol name and description */
    proto_omron_fins = proto_register_protocol (
            "OMRON FINS Protocol", /* name       */
            "OMRON-FINS",          /* short name */
            "omron"                /* abbrev     */
            );

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_omron_fins, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

#if 0
    /*Register preferences module (See Section 2.6 for more on preferences) */
    omron_fins_module = prefs_register_protocol(proto_omron_fins, NULL);

    /* Register a sample preference */
    prefs_register_bool_preference(omron_fins_module, "show_hex",
         "Display numbers in Hex",
         "Enable to display numerical values in hexadecimal.",
         &gPREF_HEX);
#endif
}

void
proto_reg_handoff_omron_fins(void)
{
    dissector_handle_t omron_fins_handle;

    omron_fins_handle = new_create_dissector_handle(dissect_omron_fins, proto_omron_fins);
    dissector_add_uint("udp.port", OMRON_FINS_UDP_PORT, omron_fins_handle);
}


