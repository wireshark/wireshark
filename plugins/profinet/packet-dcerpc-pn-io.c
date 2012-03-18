/* packet-dcerpc-pn-io.c
 * Routines for PROFINET IO dissection.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * The PN-IO protocol is a field bus protocol related to decentralized
 * periphery and is developed by the PROFIBUS Nutzerorganisation e.V. (PNO),
 * see: www.profibus.com
 *
 *
 * PN-IO is based on the common DCE-RPC and the "lightweight" PN-RT
 * (ethernet type 0x8892) protocols.
 *
 * The context manager (CM) part is handling context information
 * (like establishing, ...) and is using DCE-RPC as it's underlying
 * protocol.
 *
 * The actual cyclic data transfer and acyclic notification uses the
 * "lightweight" PN-RT protocol.
 *
 * There are some other related PROFINET protocols (e.g. PN-DCP, which is
 * handling addressing topics).
 *
 * Please note: the PROFINET CBA protocol is independant of the PN-IO protocol!
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/expert.h>
#include <epan/dissector_filters.h>

#include "packet-pn.h"



static int proto_pn_io = -1;

static int hf_pn_io_opnum = -1;
static int hf_pn_io_reserved16 = -1;

static int hf_pn_io_array = -1;
static int hf_pn_io_status = -1;
static int hf_pn_io_args_max = -1;
static int hf_pn_io_args_len = -1;
static int hf_pn_io_array_max_count = -1;
static int hf_pn_io_array_offset = -1;
static int hf_pn_io_array_act_count = -1;

static int hf_pn_io_ar_type = -1;
static int hf_pn_io_cminitiator_macadd = -1;
static int hf_pn_io_cminitiator_objectuuid = -1;
static int hf_pn_io_parameter_server_objectuuid = -1;
static int hf_pn_io_ar_data = -1;
static int hf_pn_io_ar_properties = -1;
static int hf_pn_io_ar_properties_state = -1;
static int hf_pn_io_ar_properties_supervisor_takeover_allowed = -1;
static int hf_pn_io_ar_properties_parametrization_server = -1;
/* removed within 2.3
static int hf_pn_io_ar_properties_data_rate = -1;
*/
static int hf_pn_io_ar_properties_reserved_1 = -1;
static int hf_pn_io_ar_properties_device_access = -1;
static int hf_pn_io_ar_properties_companion_ar = -1;
static int hf_pn_io_ar_properties_achnowledge_companion_ar = -1;
static int hf_pn_io_ar_properties_reserved = -1;
static int hf_pn_io_ar_properties_pull_module_alarm_allowed = -1;

static int hf_pn_RedundancyInfo = -1;
static int hf_pn_RedundancyInfo_reserved = -1;
static int hf_pn_io_number_of_ARDATAInfo = -1;

static int hf_pn_io_cminitiator_activitytimeoutfactor = -1;
static int hf_pn_io_cminitiator_udprtport = -1;
static int hf_pn_io_station_name_length = -1;
static int hf_pn_io_cminitiator_station_name = -1;
static int hf_pn_io_responder_station_name = -1;
static int hf_pn_io_arproperties_StartupMode = -1;

static int hf_pn_io_parameter_server_station_name = -1;

static int hf_pn_io_cmresponder_macadd = -1;
static int hf_pn_io_cmresponder_udprtport = -1;

static int hf_pn_io_number_of_iocrs = -1;
static int hf_pn_io_iocr_tree = -1;
static int hf_pn_io_iocr_type = -1;
static int hf_pn_io_iocr_reference = -1;
static int hf_pn_io_iocr_SubframeOffset = -1;
static int hf_pn_io_iocr_SubframeData =-1;
static int hf_pn_io_iocr_txports_port = -1;
static int hf_pn_io_iocr_txports_redundantport = -1;
static int hf_pn_io_sr_properties_Reserved_1 = -1;
static int hf_pn_io_sr_properties_Reserved_2 = -1;
static int hf_pn_io_RedundancyDataHoldFactor = -1;
static int hf_pn_io_sr_properties = -1;
static int hf_pn_io_sr_properties_InputValidOnBackupAR = -1;
static int hf_pn_io_sr_properties_ActivateRedundancyAlarm = -1;

static int hf_pn_io_lt = -1;
static int hf_pn_io_iocr_properties = -1;
static int hf_pn_io_iocr_properties_rtclass = -1;
static int hf_pn_io_iocr_properties_reserved_1 = -1;
static int hf_pn_io_iocr_properties_media_redundancy = -1;
static int hf_pn_io_iocr_properties_reserved_2 = -1;
static int hf_pn_io_iocr_properties_reserved_3 = -1;
static int hf_pn_io_iocr_properties_fast_forwarding_mac_adr = -1;
static int hf_pn_io_iocr_properties_distributed_subframe_watchdog = -1;
static int hf_pn_io_iocr_properties_full_subframe_structure = -1;


static int hf_pn_io_data_length = -1;
static int hf_pn_io_ir_frame_data = -1;
static int hf_pn_io_frame_id = -1;
static int hf_pn_io_send_clock_factor = -1;
static int hf_pn_io_reduction_ratio = -1;
static int hf_pn_io_phase = -1;
static int hf_pn_io_sequence = -1;
static int hf_pn_io_frame_send_offset = -1;
static int hf_pn_io_frame_data_properties = -1;
static int hf_pn_io_watchdog_factor = -1;
static int hf_pn_io_data_hold_factor = -1;
static int hf_pn_io_iocr_tag_header = -1;
static int hf_pn_io_iocr_multicast_mac_add = -1;
static int hf_pn_io_number_of_apis = -1;
static int hf_pn_io_number_of_io_data_objects = -1;
static int hf_pn_io_io_data_object_frame_offset = -1;
static int hf_pn_io_number_of_iocs = -1;
static int hf_pn_io_iocs_frame_offset = -1;

static int hf_pn_io_SFIOCRProperties = -1;
static int hf_pn_io_DistributedWatchDogFactor = -1;
static int hf_pn_io_RestartFactorForDistributedWD = -1;
static int hf_pn_io_SFIOCRProperties_DFPmode = -1;
static int hf_pn_io_SFIOCRProperties_reserved_1 = -1;
static int hf_pn_io_SFIOCRProperties_reserved_2 = -1;
static int hf_pn_io_SFIOCRProperties_DFPRedundantPathLayout = -1;
static int hf_pn_io_SFIOCRProperties_SFCRC16 = -1;

static int hf_pn_io_subframe_data = -1;
static int hf_pn_io_subframe_data_reserved1 = -1;
static int hf_pn_io_subframe_data_reserved2 = -1;

static int hf_pn_io_subframe_data_position = -1;
static int hf_pn_io_subframe_reserved1 = -1;
static int hf_pn_io_subframe_data_length = -1;
static int hf_pn_io_subframe_reserved2 = -1;

static int hf_pn_io_alarmcr_type = -1;
static int hf_pn_io_alarmcr_properties = -1;
static int hf_pn_io_alarmcr_properties_priority = -1;
static int hf_pn_io_alarmcr_properties_transport = -1;
static int hf_pn_io_alarmcr_properties_reserved = -1;

static int hf_pn_io_rta_timeoutfactor = -1;
static int hf_pn_io_rta_retries = -1;
static int hf_pn_io_localalarmref = -1;
static int hf_pn_io_remotealarmref = -1;
static int hf_pn_io_maxalarmdatalength = -1;
static int hf_pn_io_alarmcr_tagheaderhigh = -1;
static int hf_pn_io_alarmcr_tagheaderlow = -1;

static int hf_pn_io_IRData_uuid = -1;
static int hf_pn_io_ar_uuid = -1;
static int hf_pn_io_target_ar_uuid = -1;
static int hf_pn_io_api_tree = -1;
static int hf_pn_io_module_tree = -1;
static int hf_pn_io_submodule_tree = -1;
static int hf_pn_io_io_data_object = -1;
static int hf_pn_io_io_cs = -1;

static int hf_pn_io_substitutionmode = -1;

static int hf_pn_io_api = -1;
static int hf_pn_io_slot_nr = -1;
static int hf_pn_io_subslot_nr = -1;
static int hf_pn_io_index = -1;
static int hf_pn_io_seq_number = -1;
static int hf_pn_io_record_data_length = -1;
static int hf_pn_io_add_val1 = -1;
static int hf_pn_io_add_val2 = -1;

static int hf_pn_io_block = -1;
static int hf_pn_io_block_header = -1;
static int hf_pn_io_block_type = -1;
static int hf_pn_io_block_length = -1;
static int hf_pn_io_block_version_high = -1;
static int hf_pn_io_block_version_low = -1;

static int hf_pn_io_sessionkey = -1;
static int hf_pn_io_control_command = -1;
static int hf_pn_io_control_command_prmend = -1;
static int hf_pn_io_control_command_applready = -1;
static int hf_pn_io_control_command_release = -1;
static int hf_pn_io_control_command_done = -1;
static int hf_pn_io_control_command_ready_for_companion = -1;
static int hf_pn_io_control_command_ready_for_rt_class3 = -1;
static int hf_pn_io_control_command_prmbegin = -1;
static int hf_pn_io_control_command_reserved_7_15 = -1;
static int hf_pn_io_control_block_properties = -1;
static int hf_pn_io_control_block_properties_applready = -1;
static int hf_pn_io_control_block_properties_applready0 = -1;

static int hf_pn_io_AlarmSequenceNumber = -1;
static int hf_pn_io_control_command_reserved = -1;
static int hf_pn_io_SubmoduleListEntries = -1;
static int hf_pn_io_error_code = -1;
static int hf_pn_io_error_decode = -1;
static int hf_pn_io_error_code1 = -1;
static int hf_pn_io_error_code1_pniorw = -1;
static int hf_pn_io_error_code1_pnio = -1;
static int hf_pn_io_error_code2 = -1;
static int hf_pn_io_error_code2_pniorw = -1;
static int hf_pn_io_error_code2_pnio_1 = -1;
static int hf_pn_io_error_code2_pnio_2 = -1;
static int hf_pn_io_error_code2_pnio_3 = -1;
static int hf_pn_io_error_code2_pnio_4 = -1;
static int hf_pn_io_error_code2_pnio_5 = -1;
static int hf_pn_io_error_code2_pnio_6 = -1;
static int hf_pn_io_error_code2_pnio_7 = -1;
static int hf_pn_io_error_code2_pnio_8 = -1;
static int hf_pn_io_error_code2_pnio_20 = -1;
static int hf_pn_io_error_code2_pnio_21 = -1;
static int hf_pn_io_error_code2_pnio_22 = -1;
static int hf_pn_io_error_code2_pnio_23 = -1;
static int hf_pn_io_error_code2_pnio_40 = -1;
static int hf_pn_io_error_code2_pnio_61 = -1;
static int hf_pn_io_error_code2_pnio_62 = -1;
static int hf_pn_io_error_code2_pnio_63 = -1;
static int hf_pn_io_error_code2_pnio_64 = -1;
static int hf_pn_io_error_code2_pnio_65 = -1;
static int hf_pn_io_error_code2_pnio_66 = -1;
static int hf_pn_io_error_code2_pnio_70 = -1;
static int hf_pn_io_error_code2_pnio_71 = -1;
static int hf_pn_io_error_code2_pnio_72 = -1;
static int hf_pn_io_error_code2_pnio_73 = -1;
static int hf_pn_io_error_code2_pnio_74 = -1;
static int hf_pn_io_error_code2_pnio_75 = -1;
static int hf_pn_io_error_code2_pnio_76 = -1;
static int hf_pn_io_error_code2_pnio_77 = -1;
static int hf_pn_io_error_code2_pnio_253 = -1;
static int hf_pn_io_error_code2_pnio_255 = -1;

static int hf_pn_io_alarm_type = -1;
static int hf_pn_io_alarm_specifier = -1;
static int hf_pn_io_alarm_specifier_sequence = -1;
static int hf_pn_io_alarm_specifier_channel = -1;
static int hf_pn_io_alarm_specifier_manufacturer = -1;
static int hf_pn_io_alarm_specifier_submodule = -1;
static int hf_pn_io_alarm_specifier_ardiagnosis = -1;

static int hf_pn_io_alarm_dst_endpoint = -1;
static int hf_pn_io_alarm_src_endpoint = -1;
static int hf_pn_io_pdu_type = -1;
static int hf_pn_io_pdu_type_type = -1;
static int hf_pn_io_pdu_type_version = -1;
static int hf_pn_io_add_flags = -1;
static int hf_pn_io_window_size = -1;
static int hf_pn_io_tack = -1;
static int hf_pn_io_send_seq_num = -1;
static int hf_pn_io_ack_seq_num = -1;
static int hf_pn_io_var_part_len = -1;

static int hf_pn_io_number_of_modules = -1;
static int hf_pn_io_module_ident_number = -1;
static int hf_pn_io_module_properties = -1;
static int hf_pn_io_module_state = -1;
static int hf_pn_io_number_of_submodules = -1;
static int hf_pn_io_submodule_ident_number = -1;
static int hf_pn_io_submodule_properties = -1;
static int hf_pn_io_submodule_properties_type = -1;
static int hf_pn_io_submodule_properties_shared_input = -1;
static int hf_pn_io_submodule_properties_reduce_input_submodule_data_length = -1;
static int hf_pn_io_submodule_properties_reduce_output_submodule_data_length = -1;
static int hf_pn_io_submodule_properties_discard_ioxs = -1;
static int hf_pn_io_submodule_properties_reserved = -1;

static int hf_pn_io_submodule_state = -1;
static int hf_pn_io_submodule_state_format_indicator = -1;
static int hf_pn_io_submodule_state_add_info = -1;
static int hf_pn_io_submodule_state_qualified_info = -1;
static int hf_pn_io_submodule_state_maintenance_required = -1;
static int hf_pn_io_submodule_state_maintenance_demanded = -1;
static int hf_pn_io_submodule_state_diag_info = -1;
static int hf_pn_io_submodule_state_ar_info = -1;
static int hf_pn_io_submodule_state_ident_info = -1;
static int hf_pn_io_submodule_state_detail = -1;

static int hf_pn_io_data_description_tree = -1;
static int hf_pn_io_data_description = -1;
static int hf_pn_io_submodule_data_length = -1;
static int hf_pn_io_length_iocs = -1;
static int hf_pn_io_length_iops = -1;

static int hf_pn_io_iocs = -1;
static int hf_pn_io_iops = -1;
static int hf_pn_io_ioxs = -1;
static int hf_pn_io_ioxs_extension = -1;
static int hf_pn_io_ioxs_res14 = -1;
static int hf_pn_io_ioxs_instance = -1;
static int hf_pn_io_ioxs_datastate = -1;

static int hf_pn_io_address_resolution_properties = -1;
static int hf_pn_io_mci_timeout_factor = -1;
static int hf_pn_io_provider_station_name = -1;

static int hf_pn_io_user_structure_identifier = -1;

static int hf_pn_io_channel_number = -1;
static int hf_pn_io_channel_properties = -1;
static int hf_pn_io_channel_properties_type = -1;
static int hf_pn_io_channel_properties_accumulative = -1;
static int hf_pn_io_channel_properties_maintenance = -1;
/* replaced with 2 bit values
static int hf_pn_io_channel_properties_maintenance_required = -1;
static int hf_pn_io_channel_properties_maintenance_demanded = -1;
*/
static int hf_pn_io_NumberOfSubframeBlocks = -1;
static int hf_pn_io_channel_properties_specifier = -1;
static int hf_pn_io_channel_properties_direction = -1;

static int hf_pn_io_channel_error_type = -1;
static int hf_pn_io_ext_channel_error_type0 = -1;
static int hf_pn_io_ext_channel_error_type0x8000 = -1;
static int hf_pn_io_ext_channel_error_type0x8001 = -1;
static int hf_pn_io_ext_channel_error_type0x8002 = -1;
static int hf_pn_io_ext_channel_error_type0x8003 = -1;
static int hf_pn_io_ext_channel_error_type0x8004 = -1;
static int hf_pn_io_ext_channel_error_type0x8005 = -1;
static int hf_pn_io_ext_channel_error_type0x8007 = -1;
static int hf_pn_io_ext_channel_error_type0x8008 = -1;
static int hf_pn_io_ext_channel_error_type0x800A = -1;
static int hf_pn_io_ext_channel_error_type0x800B = -1;
static int hf_pn_io_ext_channel_error_type0x800C = -1;

static int hf_pn_io_ext_channel_error_type = -1;

static int hf_pn_io_ext_channel_add_value = -1;

static int hf_pn_io_ptcp_subdomain_id = -1;
static int hf_pn_io_ir_data_id = -1;
static int hf_pn_io_max_bridge_delay = -1;
static int hf_pn_io_number_of_ports = -1;
static int hf_pn_io_max_port_tx_delay = -1;
static int hf_pn_io_max_port_rx_delay = -1;

static int hf_pn_io_max_line_rx_delay = -1;
static int hf_pn_io_yellowtime = -1;
static int hf_pn_io_reserved_interval_begin = -1;
static int hf_pn_io_reserved_interval_end = -1;
static int hf_pn_io_pllwindow = -1;
static int hf_pn_io_sync_send_factor = -1;
static int hf_pn_io_sync_properties = -1;
static int hf_pn_io_sync_frame_address = -1;
static int hf_pn_io_ptcp_timeout_factor = -1;
static int hf_pn_io_ptcp_takeover_timeout_factor = -1;
static int hf_pn_io_ptcp_master_startup_time = -1;
static int hf_pn_io_ptcp_master_priority_1 = -1;
static int hf_pn_io_ptcp_master_priority_2 = -1;
static int hf_pn_io_ptcp_length_subdomain_name = -1;
static int hf_pn_io_ptcp_subdomain_name = -1;

/* added Portstatistics */
static int hf_pn_io_pdportstatistic_ifInOctets = -1;
static int hf_pn_io_pdportstatistic_ifOutOctets = -1;
static int hf_pn_io_pdportstatistic_ifInDiscards = -1;
static int hf_pn_io_pdportstatistic_ifOutDiscards = -1;
static int hf_pn_io_pdportstatistic_ifInErrors = -1;
static int hf_pn_io_pdportstatistic_ifOutErrors = -1;
/* end of port statistics */

static int hf_pn_io_domain_boundary = -1;
static int hf_pn_io_domain_boundary_ingress = -1;
static int hf_pn_io_domain_boundary_egress = -1;
static int hf_pn_io_multicast_boundary = -1;
static int hf_pn_io_adjust_properties = -1;
static int hf_pn_io_PreambleLength = -1;
static int hf_pn_io_mau_type = -1;
static int hf_pn_io_mau_type_mode = -1;
static int hf_pn_io_port_state = -1;
static int hf_pn_io_line_delay = -1;
static int hf_pn_io_number_of_peers = -1;
static int hf_pn_io_length_peer_port_id = -1;
static int hf_pn_io_peer_port_id = -1;
static int hf_pn_io_length_peer_chassis_id = -1;
static int hf_pn_io_peer_chassis_id = -1;
static int hf_pn_io_length_own_port_id = -1;
static int hf_pn_io_own_port_id = -1;
static int hf_pn_io_peer_macadd = -1;
static int hf_pn_io_media_type = -1;
static int hf_pn_io_macadd = -1;
static int hf_pn_io_length_own_chassis_id = -1;
static int hf_pn_io_own_chassis_id = -1;

static int hf_pn_io_ethertype = -1;
static int hf_pn_io_rx_port = -1;
static int hf_pn_io_frame_details = -1;
static int hf_pn_io_frame_details_sync_frame = -1;
static int hf_pn_io_frame_details_meaning_frame_send_offset = -1;
static int hf_pn_io_frame_details_reserved = -1;
static int hf_pn_io_nr_of_tx_port_groups = -1;
static int hf_pn_io_TxPortGroupProperties = -1;
static int hf_pn_io_TxPortGroupProperties_bit0 = -1;
static int hf_pn_io_TxPortGroupProperties_bit1 = -1;
static int hf_pn_io_TxPortGroupProperties_bit2 = -1;
static int hf_pn_io_TxPortGroupProperties_bit3 = -1;
static int hf_pn_io_TxPortGroupProperties_bit4 = -1;
static int hf_pn_io_TxPortGroupProperties_bit5 = -1;
static int hf_pn_io_TxPortGroupProperties_bit6 = -1;
static int hf_pn_io_TxPortGroupProperties_bit7 = -1;

static int hf_pn_io_start_of_red_frame_id = -1;
static int hf_pn_io_end_of_red_frame_id = -1;
static int hf_pn_io_ir_begin_end_port = -1;
static int hf_pn_io_number_of_assignments = -1;
static int hf_pn_io_number_of_phases = -1;
static int hf_pn_io_red_orange_period_begin = -1;
static int hf_pn_io_orange_period_begin = -1;
static int hf_pn_io_green_period_begin = -1;
static int hf_pn_io_tx_phase_assignment = -1;
static int hf_pn_io_rx_phase_assignment = -1;

static int hf_pn_io_slot = -1;
static int hf_pn_io_subslot = -1;
static int hf_pn_io_number_of_slots = -1;
static int hf_pn_io_number_of_subslots = -1;

static int hf_pn_io_maintenance_required_drop_budget = -1;
static int hf_pn_io_maintenance_demanded_drop_budget = -1;
static int hf_pn_io_error_drop_budget = -1;

static int hf_pn_io_maintenance_required_power_budget = -1;
static int hf_pn_io_maintenance_demanded_power_budget = -1;
static int hf_pn_io_error_power_budget = -1;

static int hf_pn_io_fiber_optic_type = -1;
static int hf_pn_io_fiber_optic_cable_type = -1;

static int hf_pn_io_controller_appl_cycle_factor = -1;
static int hf_pn_io_time_data_cycle = -1;
static int hf_pn_io_time_io_input = -1;
static int hf_pn_io_time_io_output = -1;
static int hf_pn_io_time_io_input_valid = -1;
static int hf_pn_io_time_io_output_valid = -1;

static int hf_pn_io_maintenance_status = -1;
static int hf_pn_io_maintenance_status_required = -1;
static int hf_pn_io_maintenance_status_demanded = -1;

static int hf_pn_io_vendor_id_high = -1;
static int hf_pn_io_vendor_id_low = -1;
static int hf_pn_io_vendor_block_type = -1;
static int hf_pn_io_order_id = -1;
static int hf_pn_io_im_serial_number = -1;
static int hf_pn_io_im_hardware_revision = -1;
static int hf_pn_io_im_revision_prefix = -1;
static int hf_pn_io_im_sw_revision_functional_enhancement = -1;
static int hf_pn_io_im_revision_bugfix = -1;
static int hf_pn_io_im_sw_revision_internal_change = -1;
static int hf_pn_io_im_revision_counter = -1;
static int hf_pn_io_im_profile_id = -1;
static int hf_pn_io_im_profile_specific_type = -1;
static int hf_pn_io_im_version_major = -1;
static int hf_pn_io_im_version_minor = -1;
static int hf_pn_io_im_supported = -1;

static int hf_pn_io_number_of_ars = -1;

static int hf_pn_io_cycle_counter = -1;
static int hf_pn_io_data_status = -1;
static int hf_pn_io_data_status_res67 = -1;
static int hf_pn_io_data_status_ok = -1;
static int hf_pn_io_data_status_operate = -1;
static int hf_pn_io_data_status_res3 = -1;
static int hf_pn_io_data_status_valid = -1;
static int hf_pn_io_data_status_res1 = -1;
static int hf_pn_io_data_status_primary = -1;
static int hf_pn_io_transfer_status = -1;

static int hf_pn_io_actual_local_time_stamp = -1;
static int hf_pn_io_number_of_log_entries = -1;
static int hf_pn_io_local_time_stamp = -1;
static int hf_pn_io_entry_detail = -1;

static int hf_pn_io_ip_address = -1;
static int hf_pn_io_subnetmask = -1;
static int hf_pn_io_standard_gateway = -1;

static int hf_pn_io_mrp_domain_uuid = -1;
static int hf_pn_io_mrp_role = -1;
static int hf_pn_io_mrp_length_domain_name = -1;
static int hf_pn_io_mrp_domain_name = -1;

static int hf_pn_io_mrp_prio = -1;
static int hf_pn_io_mrp_topchgt = -1;
static int hf_pn_io_mrp_topnrmax = -1;
static int hf_pn_io_mrp_tstshortt = -1;
static int hf_pn_io_mrp_tstdefaultt = -1;
static int hf_pn_io_mrp_tstnrmax = -1;
static int hf_pn_io_mrp_check = -1;

static int hf_pn_io_mrp_rtmode = -1;
static int hf_pn_io_mrp_rtmode_rtclass12 = -1;
static int hf_pn_io_mrp_rtmode_rtclass3 = -1;
static int hf_pn_io_mrp_rtmode_reserved1 = -1;
static int hf_pn_io_mrp_rtmode_reserved2 = -1;

static int hf_pn_io_mrp_lnkdownt = -1;
static int hf_pn_io_mrp_lnkupt = -1;
static int hf_pn_io_mrp_lnknrmax = -1;
static int hf_pn_io_mrp_version = -1;

static int hf_pn_io_substitute_active_flag = -1;
static int hf_pn_io_length_data = -1;

static int hf_pn_io_mrp_ring_state = -1;
static int hf_pn_io_mrp_rt_state = -1;

static int hf_pn_io_im_tag_function = -1;
static int hf_pn_io_im_tag_location = -1;
static int hf_pn_io_im_date = -1;
static int hf_pn_io_im_descriptor = -1;

static int hf_pn_io_fs_hello_mode = -1;
static int hf_pn_io_fs_hello_interval = -1;
static int hf_pn_io_fs_hello_retry = -1;
static int hf_pn_io_fs_hello_delay = -1;

static int hf_pn_io_fs_parameter_mode = -1;
static int hf_pn_io_fs_parameter_uuid = -1;


static int hf_pn_io_check_sync_mode = -1;
static int hf_pn_io_check_sync_mode_reserved = -1;
static int hf_pn_io_check_sync_mode_sync_master = -1;
static int hf_pn_io_check_sync_mode_cable_delay = -1;

static int hf_pn_io_profisafe_f_prm_flag1 = -1;
static int hf_pn_io_profisafe_f_prm_flag1_chck_seq = -1;
static int hf_pn_io_profisafe_f_prm_flag1_chck_ipar = -1;
static int hf_pn_io_profisafe_f_prm_flag1_sil = -1;
static int hf_pn_io_profisafe_f_prm_flag1_crc_len = -1;
static int hf_pn_io_profisafe_f_prm_flag1_reserved = -1;
static int hf_pn_io_profisafe_f_prm_flag2 = -1;
static int hf_pn_io_profisafe_f_src_addr = -1;
static int hf_pn_io_profisafe_f_dst_addr = -1;
static int hf_pn_io_profisafe_f_wd_time = -1;
static int hf_pn_io_profisafe_f_par_crc = -1;
static int hf_pn_io_profisafe_f_prm_flag2_reserved = -1;
static int hf_pn_io_profisafe_f_prm_flag2_f_block_id = -1;
static int hf_pn_io_profisafe_f_prm_flag2_f_par_version = -1;

static int hf_pn_io_profidrive_request_reference = -1;
static int hf_pn_io_profidrive_request_id = -1;
static int hf_pn_io_profidrive_do_id = -1;
static int hf_pn_io_profidrive_no_of_parameters = -1;
static int hf_pn_io_profidrive_response_id = -1;
static int hf_pn_io_profidrive_param_attribute = -1;
static int hf_pn_io_profidrive_param_no_of_elems = -1;
static int hf_pn_io_profidrive_param_number = -1;
static int hf_pn_io_profidrive_param_subindex = -1;
static int hf_pn_io_profidrive_param_format = -1;
static int hf_pn_io_profidrive_param_no_of_values = -1;
static int hf_pn_io_profidrive_param_value = -1;

static int hf_pn_io_packedframe_SFCRC = -1;
static gint ett_pn_io = -1;
static gint ett_pn_io_block = -1;
static gint ett_pn_io_block_header = -1;
static gint ett_pn_io_status = -1;
static gint ett_pn_io_rtc = -1;
static gint ett_pn_io_rta = -1;
static gint ett_pn_io_pdu_type = -1;
static gint ett_pn_io_add_flags = -1;
static gint ett_pn_io_control_command = -1;
static gint ett_pn_io_ioxs = -1;
static gint ett_pn_io_api = -1;
static gint ett_pn_io_data_description = -1;
static gint ett_pn_io_module = -1;
static gint ett_pn_io_submodule = -1;
static gint ett_pn_io_io_data_object = -1;
static gint ett_pn_io_io_cs = -1;
static gint ett_pn_io_ar_properties = -1;
static gint ett_pn_io_iocr_properties = -1;
static gint ett_pn_io_submodule_properties = -1;
static gint ett_pn_io_alarmcr_properties = -1;
static gint ett_pn_io_submodule_state = -1;
static gint ett_pn_io_channel_properties = -1;
static gint ett_pn_io_slot = -1;
static gint ett_pn_io_subslot = -1;
static gint ett_pn_io_maintenance_status = -1;
static gint ett_pn_io_data_status = -1;
static gint ett_pn_io_iocr = -1;
static gint ett_pn_io_mrp_rtmode = -1;
static gint ett_pn_io_control_block_properties = -1;
static gint ett_pn_io_check_sync_mode = -1;
static gint ett_pn_io_ir_frame_data = -1;
static gint ett_pn_io_ar_info = -1;
static gint ett_pn_io_ar_data = -1;
static gint ett_pn_io_ir_begin_end_port = -1;
static gint ett_pn_io_subframe_data =-1;
static gint ett_pn_io_frame_defails = -1;
static gint ett_pn_io_profisafe_f_parameter = -1;
static gint ett_pn_io_profisafe_f_parameter_prm_flag1 = -1;
static gint ett_pn_io_profisafe_f_parameter_prm_flag2 = -1;
static gint ett_pn_io_profidrive_parameter_request = -1;
static gint ett_pn_io_profidrive_parameter_response = -1;
static gint ett_pn_io_profidrive_parameter_address = -1;
static gint ett_pn_io_profidrive_parameter_value = -1;

static gint ett_pn_io_GroupProperties = -1;

static e_uuid_t uuid_pn_io_device = { 0xDEA00001, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_device = 1;

static e_uuid_t uuid_pn_io_controller = { 0xDEA00002, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_controller = 1;

static e_uuid_t uuid_pn_io_supervisor = { 0xDEA00003, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_supervisor = 1;

static e_uuid_t uuid_pn_io_parameterserver = { 0xDEA00004, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_parameterserver = 1;

/* Allow heuristic dissection */
static heur_dissector_list_t heur_pn_subdissector_list;

static const value_string pn_io_block_type[] = {
    { 0x0000, "Reserved" },
    { 0x0001, "Alarm Notification High"},
    { 0x0002, "Alarm Notification Low"},
    { 0x0008, "IODWriteReqHeader"},
    { 0x8008, "IODWriteResHeader"},
    { 0x0009, "IODReadReqHeader"},
    { 0x8009, "IODReadResHeader"},
    { 0x0010, "DiagnosisData"},
    { 0x0011, "Reserved"},
    { 0x0012, "ExpectedIdentificationData"},
    { 0x0013, "RealIdentificationData"},
    { 0x0014, "SubstituteValue"},
    { 0x0015, "RecordInputDataObjectElement"},
    { 0x0016, "RecordOutputDataObjectElement"},
    { 0x0017, "reserved"},
    { 0x0018, "ARData"},
    { 0x0019, "LogData"},
    { 0x001A, "APIData"},
    { 0x001b, "SRLData"},
    { 0x0020, "I&M0"},
    { 0x0021, "I&M1"},
    { 0x0022, "I&M2"},
    { 0x0023, "I&M3"},
    { 0x0024, "I&M4"},
    { 0x0025, "I&M5"},
    { 0x0026, "I&M6"},
    { 0x0027, "I&M7"},
    { 0x0028, "I&M8"},
    { 0x0029, "I&M9"},
    { 0x002A, "I&M10"},
    { 0x002B, "I&M11"},
    { 0x002C, "I&M12"},
    { 0x002D, "I&M13"},
    { 0x002E, "I&M14"},
    { 0x002F, "I&M15"},
    { 0x0030, "I&M0FilterDataSubmodul"},
    { 0x0031, "I&M0FilterDataModul"},
    { 0x0032, "I&M0FilterDataDevice"},
    { 0x8001, "Alarm Ack High"},
    { 0x8002, "Alarm Ack Low"},
    { 0x0101, "ARBlockReq"},
    { 0x8101, "ARBlockRes"},
    { 0x0102, "IOCRBlockReq"},
    { 0x8102, "IOCRBlockRes"},
    { 0x0103, "AlarmCRBlockReq"},
    { 0x8103, "AlarmCRBlockRes"},
    { 0x0104, "ExpectedSubmoduleBlockReq"},
    { 0x8104, "ModuleDiffBlock"},
    { 0x0105, "PrmServerBlockReq"},
    { 0x8105, "PrmServerBlockRes"},
    { 0x0106, "MCRBlockReq"},
    { 0x8106, "ARServerBlock"},
    { 0x0107, "SubFrameBlock"},
    { 0x0108, "ARVendorBlock"},
    { 0x0109, "IRInfoBlock"},
    { 0x010A, "SRInfoBlock"},
    { 0x010B, "ARFSUBlock"},
	{ 0x0110, "IODControlReq Prm End.req"},
	{ 0x8110, "IODControlRes Prm End.rsp"},
	{ 0x0111, "IODControlReq Prm End.req"},
	{ 0x8111, "IODControlRes Prm End.rsp"},
	{ 0x0112, "IOXBlockReq Application Ready.req"},
	{ 0x8112, "IOXBlockRes Application Ready.rsp"},
	{ 0x0113, "IOXBlockReq Application Ready.req"},
	{ 0x8113, "IOXBlockRes Application Ready.rsp"},
	{ 0x0114, "IODReleaseReq"},
	{ 0x8114, "IODReleaseRes"},
    { 0x0115, "ARRPCServerBlockReq"},
    { 0x8115, "ARRPCServerBlockRes"},
	{ 0x0116, "IOXControlReq Ready for Companion.req"},
	{ 0x8116, "IOXControlRes Ready for Companion.rsp"},
	{ 0x0117, "IOXControlReq Ready for RT_CLASS_3.req"},
	{ 0x8117, "IOXControlRes Ready for RT_CLASS_3.rsp"},
    { 0x0118, "ControlBlockPrmBegin"},
    { 0x0119, "SubmoduleListBlock"},
    { 0x8118, "ControlBlockPrmBeginRes"},

    { 0x0200, "PDPortDataCheck"},
    { 0x0201, "PDevData"},
    { 0x0202, "PDPortDataAdjust"},
    { 0x0203, "PDSyncData"},
    { 0x0204, "IsochronousModeData"},
    { 0x0205, "PDIRData"},
    { 0x0206, "PDIRGlobalData"},
    { 0x0207, "PDIRFrameData"},
    { 0x0208, "PDIRBeginEndData"},
    { 0x0209, "AdjustDomainBoundary"},
    { 0x020A, "CheckPeers"},
    { 0x020B, "CheckLineDelay"},
    { 0x020C, "Checking MAUType"},
    { 0x020E, "Adjusting MAUType"},
    { 0x020F, "PDPortDataReal"},
    { 0x0210, "AdjustMulticastBoundary"},
    { 0x0211, "PDInterfaceMrpDataAdjust"},
    { 0x0212, "PDInterfaceMrpDataReal"},
    { 0x0213, "PDInterfaceMrpDataCheck"},
    { 0x0214, "PDPortMrpDataAdjust"},
    { 0x0215, "PDPortMrpDataReal"},
    { 0x0216, "Media redundancy manager parameters"},
    { 0x0217, "Media redundancy client parameters"},
    { 0x0218, "Media redundancy RT mode for manager"},
    { 0x0219, "Media redundancy ring state data"},
    { 0x021A, "Media redundancy RT ring state data"},
    { 0x021B, "Adjust LinkState"},
    { 0x021C, "Checking LinkState"},
    { 0x021D, "Media redundancy RT mode for clients"},
    { 0x021E, "CheckSyncDifference"},
    { 0x021F, "CheckMAUTypeDifference"},
    { 0x0220, "PDPortFODataReal"},
    { 0x0221, "Reading real fiber optic manufacturerspecific data"},
    { 0x0222, "PDPortFODataAdjust"},
    { 0x0223, "PDPortFODataCheck"},
    { 0x0224, "Adjust PeerToPeerBoundary"},
    { 0x0225, "Adjust DCPBoundary"},
    { 0x0226, "Adjust PreambleLength"},
    { 0x0227, "Adjust FastForwardingBoundary"},
    { 0x022A, "PDIRSubframeData"},
    { 0x022B, "SubframeBlock"},
    { 0x0230, "PDNCDataCheck"},
    { 0x0240, "PDInterfaceDataReal"},
    { 0x0251, "PDPortStatistic"},
    { 0x0400, "MultipleBlockHeader"},
    { 0x0500, "RecordDataReadQuery"},
    { 0x0600, "FSHello"},
    { 0x0601, "FSParameterBlock"},
    { 0x0608, "PDInterfaceFSUDataAdjust"},
    { 0x0609, "ARFSUDataAdjust"},
    { 0x0700, "AutoConfiguration"},
    { 0x0701, "AutoConfiguration Communication"},
    { 0x0702, "AutoConfiguration Configuration"},
    { 0xB050, "Ext-PLL Control / RTC+RTA SyncID 0 (EDD)" },
    { 0xB051, "Ext-PLL Control / RTA SyncID 1 (GSY)" },

    { 0xB060, "EDD Trace Unit (EDD)" },
    { 0xB061, "EDD Trace Unit (EDD)" },

    { 0xB070, "OHA Info (OHA)" },

    { 0x0F00, "MaintenanceItem"},
    { 0x0F01, "Upload selected Records within Upload&RetrievalItem"},
    { 0x0F02, "iParameterItem"},
    { 0x0F03, "Retrieve selected Records within Upload&RetrievalItem"},
    { 0x0F04, "Retrieve all Records within Upload&RetrievalItem"},
    { 0, NULL }
};

static const value_string pn_io_alarm_type[] = {
    { 0x0000, "Reserved" },
    { 0x0001, "Diagnosis" },
    { 0x0002, "Process" },
    { 0x0003, "Pull" },
    { 0x0004, "Plug" },
    { 0x0005, "Status" },
    { 0x0006, "Update" },
    { 0x0007, "Redundancy" },
    { 0x0008, "Controlled by supervisor" },
    { 0x0009, "Released" },
    { 0x000A, "Plug wrong submodule" },
    { 0x000B, "Return of submodule" },
    { 0x000C, "Diagnosis disappears" },
    { 0x000D, "Multicast communication mismatch notification" },
    { 0x000E, "Port data change notification" },
    { 0x000F, "Sync data changed notification" },
    { 0x0010, "Isochronous mode problem notification" },
    { 0x0011, "Network component problem notification" },
    { 0x0012, "Time data changed notification" },
    { 0x0013, "Dynamic Frame Packing problem notification" },
    /*0x0014 - 0x001D reserved */
    { 0x001E, "Upload and retrieval notification" },
    { 0x001F, "Pull module" },
    /*0x0020 - 0x007F manufacturer specific */
    /*0x0080 - 0x00FF reserved for profiles */
    /*0x0100 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_pdu_type[] = {
    { 0x01, "Data-RTA-PDU" },
    { 0x02, "NACK-RTA-PDU" },
    { 0x03, "ACK-RTA-PDU" },
    { 0x04, "ERR-RTA-PDU" },
    { 0, NULL }
};

static const value_string pn_io_frame_data_properties[] = {
    { 0x00, "absolute mode use interface MAC" },
    { 0x01, "relative mode use interface MAC" },
    { 0x02, "absolute mode use RT_CLASS_3 destination MAC" },
    { 0x03, "relative mode use RT_CLASS_3 destination MAC" },
    { 0x04, "absolute mode use FastForwarding destination MAC" },
    { 0x05, "relative mode use FastForwarding destination MAC" },
    { 0x06, "absolute mode use FastForwarding MAC" },
    { 0x07, "relative mode use FastForwarding MAC" },
    { 0, NULL }
};

static const value_string pn_io_DFPRedundantPathLayout_decode[] = {
    { 0x00, "The Frame for the redundant path contains the ordering shown by SubframeData" },
    { 0x01, "The Frame for the redundant path contains the inverse ordering shown by SubframeData" },
    { 0, NULL }
};

static const value_string pn_io_SFCRC16_Decode[] = {
    { 0x00, "SFCRC16 and SFCycleCounter shall be created or set to zero by the sender and not checked by the receiver" },
    { 0x01, "SFCRC16 and SFCycleCounter shall be created by the sender and checked by the receiver." },
    { 0, NULL }
};

static const value_string pn_io_txgroup_state[] = {
    { 0x00, "Transmission off" },
    { 0x01, "Transmission on " },
    { 0, NULL }
};

static const value_string pn_io_error_code[] = {
    { 0x00, "OK" },
    { 0x81, "PNIO" },
    { 0xCF, "RTA error" },
    { 0xDA, "AlarmAck" },
    { 0xDB, "IODConnectRes" },
    { 0xDC, "IODReleaseRes" },
    { 0xDD, "IODControlRes" },
    { 0xDE, "IODReadRes" },
    { 0xDF, "IODWriteRes" },
    { 0, NULL }
};

static const value_string pn_io_error_decode[] = {
    { 0x00, "OK" },
    { 0x80, "PNIORW" },
    { 0x81, "PNIO" },
    { 0, NULL }
};

/* dummy for unknown decode */
static const value_string pn_io_error_code1[] = {
    { 0x00, "OK" },
    { 0, NULL }
};

/* dummy for unknown decode/code1 combination */
static const value_string pn_io_error_code2[] = {
    { 0x00, "OK" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pniorw[] = {
    /* high nibble 0-9 not specified -> legacy codes */
    { 0xa0, "application: read error" },
    { 0xa1, "application: write error" },
    { 0xa2, "application: module failure" },
    { 0xa3, "application: not specified" },
    { 0xa4, "application: not specified" },
    { 0xa5, "application: not specified" },
    { 0xa6, "application: not specified" },
    { 0xa7, "application: busy" },
    { 0xa8, "application: version conflict" },
    { 0xa9, "application: feature not supported" },
    { 0xaa, "application: User specific 1" },
    { 0xab, "application: User specific 2" },
    { 0xac, "application: User specific 3" },
    { 0xad, "application: User specific 4" },
    { 0xae, "application: User specific 5" },
    { 0xaf, "application: User specific 6" },
    { 0xb0, "access: invalid index" },
    { 0xb1, "access: write length error" },
    { 0xb2, "access: invalid slot/subslot" },
    { 0xb3, "access: type conflict" },
    { 0xb4, "access: invalid area" },
    { 0xb5, "access: state conflict" },
    { 0xb6, "access: access denied" },
    { 0xb7, "access: invalid range" },
    { 0xb8, "access: invalid parameter" },
    { 0xb9, "access: invalid type" },
    { 0xba, "access: backup" },
    { 0xbb, "access: User specific 7" },
    { 0xbc, "access: User specific 8" },
    { 0xbd, "access: User specific 9" },
    { 0xbe, "access: User specific 10" },
    { 0xbf, "access: User specific 11" },
    { 0xc0, "resource: read constrain conflict" },
    { 0xc1, "resource: write constrain conflict" },
    { 0xc2, "resource: resource busy" },
    { 0xc3, "resource: resource unavailable" },
    { 0xc4, "resource: not specified" },
    { 0xc5, "resource: not specified" },
    { 0xc6, "resource: not specified" },
    { 0xc7, "resource: not specified" },
    { 0xc8, "resource: User specific 12" },
    { 0xc9, "resource: User specific 13" },
    { 0xca, "resource: User specific 14" },
    { 0xcb, "resource: User specific 15" },
    { 0xcc, "resource: User specific 16" },
    { 0xcd, "resource: User specific 17" },
    { 0xce, "resource: User specific 18" },
    { 0xcf, "resource: User specific 19" },
    /* high nibble d-f user specific */
    { 0, NULL }
};

static const value_string pn_io_error_code2_pniorw[] = {
    /* all values are user specified */
    { 0, NULL }
};

static const value_string pn_io_error_code1_pnio[] = {
    { 0x00 /*  0*/, "Reserved" },
    { 0x01 /*  1*/, "Connect: Faulty ARBlockReq" },
    { 0x02 /*  2*/, "Connect: Faulty IOCRBlockReq" },
    { 0x03 /*  3*/, "Connect: Faulty ExpectedSubmoduleBlockReq" },
    { 0x04 /*  4*/, "Connect: Faulty AlarmCRBlockReq" },
    { 0x05 /*  5*/, "Connect: Faulty PrmServerBlockReq" },
    { 0x06 /*  6*/, "Connect: Faulty MCRBlockReq" },
    { 0x07 /*  7*/, "Connect: Faulty ARRPCBlockReq" },
    { 0x08 /*  8*/, "Read/Write Record: Faulty Record" },
    { 0x09 /*  9*/, "Connect: Faulty SubFrameBlock" },
    { 0x0A /* 10*/, "Connect: Faulty IRTFrameBlock" },

    { 0x14 /* 20*/, "IODControl: Faulty ControlBlockConnect" },
    { 0x15 /* 21*/, "IODControl: Faulty ControlBlockPlug" },
    { 0x16 /* 22*/, "IOXControl: Faulty ControlBlock after a connect est." },
    { 0x17 /* 23*/, "IOXControl: Faulty ControlBlock a plug alarm" },

    { 0x28 /* 40*/, "Release: Faulty ReleaseBlock" },

    { 0x32 /* 50*/, "Response: Faulty ARBlockRes" },
    { 0x33 /* 51*/, "Response: Faulty IOCRBlockRes" },
    { 0x34 /* 52*/, "Response: Faulty AlarmCRBlockRes" },
    { 0x35 /* 53*/, "Response: Faulty ModuleDifflock" },
    { 0x36 /* 54*/, "Response: Faulty ARRPCBlockRes" },

    { 0x3c /* 60*/, "AlarmAck Error Codes" },
    { 0x3d /* 61*/, "CMDEV" },
    { 0x3e /* 62*/, "CMCTL" },
    { 0x3f /* 63*/, "NRPM" },
    { 0x40 /* 64*/, "RMPM" },
    { 0x41 /* 65*/, "ALPMI" },
    { 0x42 /* 66*/, "ALPMR" },
    { 0x43 /* 67*/, "LMPM" },
    { 0x44 /* 68*/, "MMAC" },
    { 0x45 /* 69*/, "RPC" },
    { 0x46 /* 70*/, "APMR" },
    { 0x47 /* 71*/, "APMS" },
    { 0x48 /* 72*/, "CPM" },
    { 0x49 /* 73*/, "PPM" },
    { 0x4a /* 74*/, "DCPUCS" },
    { 0x4b /* 75*/, "DCPUCR" },
    { 0x4c /* 76*/, "DCPMCS" },
    { 0x4d /* 77*/, "DCPMCR" },
    { 0x4e /* 78*/, "FSPM" },
    { 0xfd /*253*/, "RTA_ERR_CLS_PROTOCOL" },
    { 0xff /*255*/, "User specific" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_1[] = {
    /* CheckingRules for ARBlockReq */
    {  0, "Error in Parameter BlockType" },
    {  1, "Error in Parameter BlockLength" },
    {  2, "Error in Parameter BlockVersionHigh" },
    {  3, "Error in Parameter BlockVersionLow" },
    {  4, "Error in Parameter ARType" },
    {  5, "Error in Parameter ARUUID" },
    {  7, "Error in Parameter CMInitiatorMACAddress" },
    {  8, "Error in Parameter CMInitiatorObjectUUID" },
    {  9, "Error in Parameter ARProperties" },
    { 10, "Error in Parameter CMInitiatorActivityTimeoutFactor" },
    { 11, "Error in Parameter InitiatorUDPRTPort" },
    { 12, "Error in Parameter StationNameLength" },
    { 13, "Error in Parameter CMInitiatorStationName" },
    {  0, NULL }
};

static const value_string pn_io_error_code2_pnio_2[] = {
    /* CheckingRules for IOCRBlockReq */
    {  0, "Error in Parameter BlockType" },
    {  1, "Error in Parameter BlockLength" },
    {  2, "Error in Parameter BlockVersionHigh" },
    {  3, "Error in Parameter BlockVersionLow" },
    {  4, "Error in Parameter IOCRType" },
    {  5, "Error in Parameter IOCRReference" },
    {  6, "Error in Parameter LT" },
    {  7, "Error in Parameter IOCRProperties" },
    {  8, "Error in Parameter DataLength" },
    {  9, "Error in Parameter FrameID" },
    { 10, "Error in Parameter SendClockFactor" },
    { 11, "Error in Parameter ReductionRatio" },
    { 12, "Error in Parameter Phase" },
    { 14, "Error in Parameter FrameSendOffset" },
    { 15, "Error in Parameter WatchdogFactor" },
    { 16, "Error in Parameter DataHoldFactor" },
    { 17, "Error in Parameter IOCRTagHeader" },
    { 18, "Error in Parameter IOCRMulticastMacAddress" },
    { 19, "Error in Parameter NumberOfAPI" },
    { 10, "Error in Parameter API" },
    { 21, "Error in Parameter NumberOfIODataObjects" },
    { 22, "Error in Parameter SlotNumber" },
    { 23, "Error in Parameter SubslotNumber" },
    { 24, "Error in Parameter IODataObjectFrameOffset" },
    { 25, "Error in Parameter NumberOfIOCS" },
    { 26, "Error in Parameter SlotNumber" },
    { 27, "Error in Parameter SubslotNumber" },
    { 28, "Error in Parameter IOCSFrameOffset" },
    {  0, NULL }
};

static const value_string pn_io_error_code2_pnio_3[] = {
    /* CheckingRules for ExpectedSubmoduleBlockReq */
    {  0, "Error in Parameter BlockType" },
    {  1, "Error in Parameter BlockLength" },
    {  2, "Error in Parameter BlockVersionHigh" },
    {  3, "Error in Parameter BlockVersionLow" },
    {  4, "Error in Parameter NumberOfAPI" },
    {  5, "Error in Parameter API" },
    {  6, "Error in Parameter SlotNumber" },
    {  7, "Error in Parameter ModuleIdentNumber" },
    {  8, "Error in Parameter ModuleProperties" },
    {  9, "Error in Parameter NumberOfSubmodules" },
    { 10, "Error in Parameter SubslotNumber" },
    { 12, "Error in Parameter SubmoduleProperties" },
    { 13, "Error in Parameter DataDescription" },
    { 14, "Error in Parameter SubmoduleDataLength" },
    { 15, "Error in Parameter LengthIOPS" },
    { 16, "Error in Parameter LengthIOCS" },
    {  0, NULL }
};


static const value_string pn_io_error_code2_pnio_4[] = {
    /* CheckingRules for AlarmCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter AlarmCRType" },
    { 5, "Error in Parameter LT" },
    { 6, "Error in Parameter AlarmCRProperties" },
    { 7, "Error in Parameter RTATimeoutFactor" },
    { 8, "Error in Parameter RTARetries" },
    { 10, "Error in Parameter MaxAlarmDataLength" },
    { 11, "Error in Parameter AlarmCRTagHeaderHigh" },
    { 12, "Error in Parameter AlarmCRTagHeaderLow" },
    {  0, NULL }
};

static const value_string pn_io_error_code2_pnio_5[] = {
    /* CheckingRules for PrmServerBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 6, "Error in Parameter CMInitiatorActivityTimeoutFactor" },
    { 7, "Error in Parameter StationNameLength" },
    { 8, "Error in Parameter ParameterServerStationName" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_6[] = {
    /* CheckingRules for MCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter IOCRReference" },
    { 5, "Error in Parameter AddressResolutionProperties" },
    { 6, "Error in Parameter MCITimeoutFactor" },
    { 7, "Error in Parameter StationNameLength" },
    { 8, "Error in Parameter ProviderStationName" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_7[] = {
    /* CheckingRules for MCRBlockReq */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter InitiatorRPCServerPort" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_8[] = {
    /* CheckingRules for Read/Write ParameterReqHeader */
    {  0, "Error in Parameter BlockType" },
    {  1, "Error in Parameter BlockLength" },
    {  2, "Error in Parameter BlockVersionHigh" },
    {  3, "Error in Parameter BlockVersionLow" },
    {  5, "Error in Parameter ARUUID" },
    {  6, "Error in Parameter API" },
    {  7, "Error in Parameter SlotNumber" },
    {  8, "Error in Parameter SubslotNumber" },
    {  9, "Error in Parameter Padding" },
    { 10, "Error in Parameter Index" },
    { 11, "Error in Parameter RecordDataLength" },
    { 12, "Error in Parameter TargetARUUID" },
    {  0, NULL }
};

static const value_string pn_io_error_code2_pnio_20[] = {
    /* CheckingRules for ControlBlockConnect */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_21[] = {
    /* CheckingRules for ControlBlockPlug */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter AlarmSequenceNumber" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_22[] = {
    /* CheckingRule for ControlBlockConnect */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_23[] = {
    /* CheckingRules for ControlBlockPlug */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter AlarmSequenceNumber" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_40[] = {
    /* CheckingRules for ReleaseBlock */
    { 0, "Error in Parameter BlockType" },
    { 1, "Error in Parameter BlockLength" },
    { 2, "Error in Parameter BlockVersionHigh" },
    { 3, "Error in Parameter BlockVersionLow" },
    { 4, "Error in Parameter Padding" },
    { 6, "Error in Parameter SessionKey" },
    { 7, "Error in Parameter Padding" },
    { 8, "Error in Parameter ControlCommand" },
    { 9, "Error in Parameter ControlBlockProperties" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_61[] = {
    /* CMDEV */
    { 0, "State Conflict" },
    { 1, "Resources" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_62[] = {
    /* CMCTL */
    { 0, "State Conflict" },
    { 1, "Timeout" },
    { 2, "No data send" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_63[] = {
    /* NRPM */
    { 0, "No DCP active" },
    { 1, "DNS Unknown_RealStationName" },
    { 2, "DCP No_RealStationName" },
    { 3, "DCP Multiple_RealStationName" },
    { 4, "DCP No_StationName" },
    { 5, "No_IP_Addr" },
    { 6, "DCP_Set_Error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_64[] = {
    /* RMPM */
    { 0, "ArgsLength invalid" },
    { 1, "Unknown Blocks" },
    { 2, "IOCR Missing" },
    { 3, "Wrong AlarmCRBlock count" },
    { 4, "Out of AR Resources" },
    { 5, "AR UUID unknown" },
    { 6, "State conflict" },
    { 7, "Out of Provider, Consumer or Alarm Resources" },
    { 8, "Out of Memory" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_65[] = {
    /* ALPMI */
    { 0, "Invalid State" },
    { 1, "Wrong ACK-PDU" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_66[] = {
    /* ALPMR */
    { 0, "Invalid State" },
    { 1, "Wrong Notification PDU" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_70[] = {
    /* APMR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_71[] = {
    /* APMS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled error" },
    { 2, "Timeout" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_72[] = {
    /* CPM */
    { 1, "Invalid State" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_73[] = {
    /* PPM */
    { 1, "Invalid State" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_74[] = {
    /* DCPUCS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 2, "Timeout" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_75[] = {
    /* DCPUCR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_76[] = {
    /* DCPMCS */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_77[] = {
    /* DCPMCR */
    { 0, "Invalid State" },
    { 1, "LMPM signaled an error" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_253[] = {
    {  0, "reserved" },
    {  1, "Error within the coordination of sequence numbers (RTA_ERR_CODE_SEQ) error" },
    {  2, "Instance closed (RTA_ERR_ABORT)" },
    {  3, "AR out of memory (RTA_ERR_ABORT)" },
    {  4, "AR add provider or consumer failed (RTA_ERR_ABORT)" },
    {  5, "AR consumer DHT/WDT expired (RTA_ERR_ABORT)" },
    {  6, "AR cmi timeout (RTA_ERR_ABORT)" },
    {  7, "AR alarm-open failed (RTA_ERR_ABORT)" },
    {  8, "AR alarm-send.cnf(-) (RTA_ERR_ABORT)" },
    {  9, "AR alarm-ack-send.cnf(-) (RTA_ERR_ABORT)" },
    { 10, "AR alarm data too long (RTA_ERR_ABORT)" },
    { 11, "AR alarm.ind(err) (RTA_ERR_ABORT)" },
    { 12, "AR rpc-client call.cnf(-) (RTA_ERR_ABORT)" },
    { 13, "AR abort.req (RTA_ERR_ABORT)" },
    { 14, "AR re-run aborts existing (RTA_ERR_ABORT)" },
    { 15, "AR release.ind received (RTA_ERR_ABORT)" },
    { 16, "AR device deactivated (RTA_ERR_ABORT)" },
    { 17, "AR removed (RTA_ERR_ABORT)" },
    { 18, "AR protocol violation (RTA_ERR_ABORT)" },
    { 19, "AR name resolution error (RTA_ERR_ABORT)" },
    { 20, "AR RPC-Bind error (RTA_ERR_ABORT)" },
    { 21, "AR RPC-Connect error (RTA_ERR_ABORT)" },
    { 22, "AR RPC-Read error (RTA_ERR_ABORT)" },
    { 23, "AR RPC-Write error (RTA_ERR_ABORT)" },
    { 24, "AR RPC-Control error (RTA_ERR_ABORT)" },
    { 25, "AR forbidden pull or plug after check.rsp and before in-data.ind (RTA_ERR_ABORT)" },
    { 26, "AR AP removed (RTA_ERR_ABORT)" },
    { 27, "AR link down (RTA_ERR_ABORT)" },
    { 28, "AR could not register multicast-mac address (RTA_ERR_ABORT)" },
    { 29, "not synchronized (cannot start companion-ar) (RTA_ERR_ABORT)" },
    { 30, "wrong topology (cannot start companion-ar) (RTA_ERR_ABORT)" },
    { 31, "dcp, station-name changed (RTA_ERR_ABORT)" },
    { 32, "dcp, reset to factory-settings (RTA_ERR_ABORT)" },
    { 33, "cannot start companion-AR because a 0x8ipp submodule in the first AR... (RTA_ERR_ABORT)" },
    { 34, "no irdata record yet (RTA_ERR_ABORT)" },
    { 35, "PDEV (RTA_ERROR_ABORT)" },
    { 36, "PDEV, no port offers required speed/duplexity (RTA_ERROR_ABORT)" },
    { 37, "IP-Suite [of the IOC] changed by means of DCP_Set(IPParameter) or local engineering (RTA_ERROR_ABORT)" },
    { 0, NULL }
};

static const value_string pn_io_error_code2_pnio_255[] = {
    /* User specific */
    { 255, "User abort" },
    { 0, NULL }
};

static const value_string pn_io_ioxs[] = {
    { 0x00 /*  0*/, "detected by subslot" },
    { 0x01 /*  1*/, "detected by slot" },
    { 0x02 /*  2*/, "detected by IO device" },
    { 0x03 /*  3*/, "detected by IO controller" },
    { 0, NULL }
};


static const value_string pn_io_ar_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "IOCARSingle" },
    { 0x0002, "reserved" },
    { 0x0003, "IOCARCIR" },
    { 0x0004, "IOCAR_IOControllerRedundant" },
    { 0x0005, "IOCAR_IODeviceRedundant" },
    { 0x0006, "IOSAR" },
    /*0x0007 - 0x000F reserved */
    { 0x0010, "IOCARSingle using RT_CLASS_3"},
    /*0x0011 - 0x001F reserved */
    { 0x0020, "IOCARSR" },
    /*0x0007 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_iocr_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "Input CR" },
    { 0x0002, "Output CR" },
    { 0x0003, "Multicast Provider CR" },
    { 0x0004, "Multicast Consumer CR" },
    /*0x0005 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_data_description[] = {
    { 0x0000, "reserved" },
    { 0x0001, "Input" },
    { 0x0002, "Output" },
    { 0x0003, "reserved" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};



static const value_string pn_io_module_state[] = {
    { 0x0000, "no module" },
    { 0x0001, "wrong module" },
    { 0x0002, "proper module" },
    { 0x0003, "substitute" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_arproperties_state[] = {
    { 0x00000000, "Reserved" },
    { 0x00000001, "Active" },
    { 0x00000002, "reserved" },
    { 0x00000003, "reserved" },
    { 0x00000004, "reserved" },
    { 0x00000005, "reserved" },
    { 0x00000006, "reserved" },
    { 0x00000007, "reserved" },
    { 0, NULL }
};

static const value_string pn_io_arproperties_supervisor_takeover_allowed[] = {
    { 0x00000000, "not allowed" },
    { 0x00000001, "allowed" },
    { 0, NULL }
};

static const value_string pn_io_arproperties_parametrization_server[] = {
    { 0x00000000, "External PrmServer" },
    { 0x00000001, "CM Initiator" },
    { 0, NULL }
};
/* BIT 8 */
static const value_string pn_io_arproperties_DeviceAccess[] = {
    { 0x00000000, "Only the submodules from the ExpectedSubmoduleBlock are accessible" },
    { 0x00000001, "Submodule access is controlled by IO device application" },
    { 0, NULL }
};

/* Bit 9 - 10 */
static const value_string pn_io_arproperties_companion_ar[] = {
    { 0x00000000, "Single AR" },
    { 0x00000001, "First AR of a companion pair and a companion AR shall follow" },
    { 0x00000002, "Companion AR" },
    { 0x00000003, "Reserved" },
    { 0, NULL }
};
/* REMOVED with 2.3
static const value_string pn_io_arproperties_data_rate[] = {
    { 0x00000000, "at least 100 MB/s or more" },
    { 0x00000001, "100 MB/s" },
    { 0x00000002, "1 GB/s" },
    { 0x00000003, "10 GB/s" },
    { 0, NULL }
};
*/

/* BIT 11 */
static const value_string pn_io_arproperties_acknowldege_companion_ar[] = {
    { 0x00000000, "No companion AR or no acknowledge for the companion AR required" },
    { 0x00000001, "Companion AR with acknowledge" },
    { 0, NULL }
};

/* bit 30 */
static const value_string pn_io_arpropertiesStartupMode[] = {
    { 0x00000000, "Legacy" },
    { 0x00000001, "Advanced" },
    { 0, NULL }
};

/* bit 31 */
static const value_string pn_io_arproperties_pull_module_alarm_allowed[] = {
    { 0x00000000, "AlarmType(=Pull) shall signal pulling of submodule and module" },
    { 0x00000001, "AlarmType(=Pull) shall signal pulling of submodule" },
    { 0, NULL }
};

static const value_string pn_io_RedundancyInfo[] = {
    { 0x00000000, "Reserved" },
    { 0x00000001, "The delivering node is the left or below one" },
    { 0x00000002, "The delivering node is the right or above one" },
    { 0x00000003, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_iocr_properties_rtclass[] = {
    { 0x00000000, "reserved" },
    { 0x00000001, "RT_CLASS_1" },
    { 0x00000002, "RT_CLASS_2" },
    { 0x00000003, "RT_CLASS_3" },
    { 0x00000004, "RT_CLASS_UDP" },
    /*0x00000005 - 0x00000007 reserved */
    { 0, NULL }
};

static const value_string pn_io_sr_properties_BackupAR[] = {
    { 0x00000000, "The device may deliver valid input data" },
    { 0x00000001, "The device shall deliver valid input data" },
    { 0, NULL }
};

static const value_string pn_io_sr_properties_ActivateRedundancyAlarm[] = {
    { 0x00000000, "The device shall not send Redundancy alarm" },
    { 0x00000001, "The device shall send Redundancy alarm" },
    { 0, NULL }
};

static const value_string pn_io_iocr_properties_media_redundancy[] = {
    { 0x00000000, "No media redundant frame transfer" },
    { 0x00000001, "Media redundant frame transfer" },
    { 0, NULL }
};


static const value_string pn_io_submodule_properties_type[] = {
    { 0x0000, "no input and no output data" },
    { 0x0001, "input data" },
    { 0x0002, "output data" },
    { 0x0003, "input and output data" },
    { 0, NULL }
};

static const value_string pn_io_submodule_properties_shared_input[] = {
    { 0x0000, "IO controller" },
    { 0x0001, "IO controller shared" },
    { 0, NULL }
};

static const value_string pn_io_submodule_properties_reduce_input_submodule_data_length[] = {
    { 0x0000, "Expected" },
    { 0x0001, "Zero" },
    { 0, NULL }
};

static const value_string pn_io_submodule_properties_reduce_output_submodule_data_length[] = {
    { 0x0000, "Expected" },
    { 0x0001, "Zero" },
    { 0, NULL }
};

static const value_string pn_io_submodule_properties_discard_ioxs[] = {
    { 0x0000, "Expected" },
    { 0x0001, "Zero" },
    { 0, NULL }
};

static const value_string pn_io_alarmcr_properties_priority[] = {
    { 0x0000, "user priority (default)" },
    { 0x0001, "use only low priority" },
    { 0, NULL }
};

static const value_string pn_io_alarmcr_properties_transport[] = {
    { 0x0000, "RTA_CLASS_1" },
    { 0x0001, "RTA_CLASS_UDP" },
    { 0, NULL }
};


static const value_string pn_io_submodule_state_format_indicator[] = {
    { 0x0000, "Coding uses Detail" },
    { 0x0001, "Coding uses .IdentInfo, ..." },
    { 0, NULL }
};

static const value_string pn_io_submodule_state_add_info[] = {
    { 0x0000, "None" },
    { 0x0001, "Takeover not allowed" },
    /*0x0002 - 0x0007 reserved */
    { 0, NULL }
};

static const value_string pn_io_submodule_state_qualified_info[] = {
    { 0x0000, "No QualifiedInfo available" },
    { 0x0001, "QualifiedInfo available" },
    { 0, NULL }
};

static const value_string pn_io_submodule_state_maintenance_required[] = {
    { 0x0000, "No MaintenanceRequired available" },
    { 0x0001, "MaintenanceRequired available" },
    { 0, NULL }
};

static const value_string pn_io_submodule_state_maintenance_demanded[] = {
    { 0x0000, "No MaintenanceDemanded available" },
    { 0x0001, "MaintenanceDemanded available" },
    { 0, NULL }
};

static const value_string pn_io_submodule_state_diag_info[] = {
    { 0x0000, "No DiagnosisData available" },
    { 0x0001, "DiagnosisData available" },
    { 0, NULL }
};

static const value_string pn_io_submodule_state_ar_info[] = {
    { 0x0000, "Own" },
    { 0x0001, "ApplicationReadyPending (ARP)" },
    { 0x0002, "Superordinated Locked (SO)" },
    { 0x0003, "Locked By IO Controller (IOC)" },
    { 0x0004, "Locked By IO Supervisor (IOS)" },
    /*0x0005 - 0x000F reserved */
    { 0, NULL }
};

static const value_string pn_io_submodule_state_ident_info[] = {
    { 0x0000, "OK" },
    { 0x0001, "Substitute (SU)" },
    { 0x0002, "Wrong (WR)" },
    { 0x0003, "NoSubmodule (NO)" },
    /*0x0004 - 0x000F reserved */
    { 0, NULL }
};

static const value_string pn_io_submodule_state_detail[] = {
    { 0x0000, "no submodule" },
    { 0x0001, "wrong submodule" },
    { 0x0002, "locked by IO controller" },
    { 0x0003, "reserved" },
    { 0x0004, "application ready pending" },
    { 0x0005, "reserved" },
    { 0x0006, "reserved" },
    { 0x0007, "Substitute" },
    /*0x0008 - 0x7FFF reserved */
    { 0, NULL }
};

static const value_string pn_io_substitutionmode[] = {
    { 0x0000, "ZERO" },
    { 0x0001, "Last value" },
    { 0x0002, "Replacement value" },
    /*0x0003 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_index[] = {
    /*0x0008 - 0x7FFF user specific */

    /* PROFISafe */
    { 0x0100, "PROFISafe" },

    /* subslot specific */
    { 0x8000, "ExpectedIdentificationData for one subslot" },
    { 0x8001, "RealIdentificationData for one subslot" },
    /*0x8002 - 0x8009 reserved */
    { 0x800A, "Diagnosis in channel coding for one subslot" },
    { 0x800B, "Diagnosis in all codings for one subslot" },
    { 0x800C, "Diagnosis, Maintenance, Qualified and Status for one subslot" },
    /*0x800D - 0x800F reserved */
    { 0x8010, "Maintenance required in channel coding for one subslot" },
    { 0x8011, "Maintenance demanded in channel coding for one subslot" },
    { 0x8012, "Maintenance required in all codings for one subslot" },
    { 0x8013, "Maintenance demanded in all codings for one subslot" },
    /*0x8014 - 0x801D reserved */
    { 0x801E, "SubstituteValues for one subslot" },
    /*0x801F - 0x8027 reserved */
    { 0x8028, "RecordInputDataObjectElement for one subslot" },
    { 0x8029, "RecordOutputDataObjectElement for one subslot" },
    { 0x802A, "PDPortDataReal for one subslot" },
    { 0x802B, "PDPortDataCheck for one subslot" },
    { 0x802C, "PDIRData for one subslot" },
    { 0x802D, "Expected PDSyncData for one subslot with SyncID value 0" },
    /*0x802E reserved */
    { 0x802F, "PDPortDataAdjust for one subslot" },
    { 0x8030, "IsochronousModeData for one subslot" },
    { 0x8031, "Expected PDSyncData for one subslot with SyncID value 1" },
    { 0x8032, "Expected PDSyncData for one subslot with SyncID value 2" },
    { 0x8033, "Expected PDSyncData for one subslot with SyncID value 3" },
    { 0x8034, "Expected PDSyncData for one subslot with SyncID value 4" },
    { 0x8035, "Expected PDSyncData for one subslot with SyncID value 5" },
    { 0x8036, "Expected PDSyncData for one subslot with SyncID value 6" },
    { 0x8037, "Expected PDSyncData for one subslot with SyncID value 7" },
    { 0x8038, "Expected PDSyncData for one subslot with SyncID value 8" },
    { 0x8039, "Expected PDSyncData for one subslot with SyncID value 9" },
    { 0x803A, "Expected PDSyncData for one subslot with SyncID value 10" },
    { 0x803B, "Expected PDSyncData for one subslot with SyncID value 11" },
    { 0x803C, "Expected PDSyncData for one subslot with SyncID value 12" },
    { 0x803D, "Expected PDSyncData for one subslot with SyncID value 13" },
    { 0x803E, "Expected PDSyncData for one subslot with SyncID value 14" },
    { 0x803F, "Expected PDSyncData for one subslot with SyncID value 15" },
    { 0x8040, "Expected PDSyncData for one subslot with SyncID value 16" },
    { 0x8041, "Expected PDSyncData for one subslot with SyncID value 17" },
    { 0x8042, "Expected PDSyncData for one subslot with SyncID value 18" },
    { 0x8043, "Expected PDSyncData for one subslot with SyncID value 19" },
    { 0x8044, "Expected PDSyncData for one subslot with SyncID value 20" },
    { 0x8045, "Expected PDSyncData for one subslot with SyncID value 21" },
    { 0x8046, "Expected PDSyncData for one subslot with SyncID value 22" },
    { 0x8047, "Expected PDSyncData for one subslot with SyncID value 23" },
    { 0x8048, "Expected PDSyncData for one subslot with SyncID value 24" },
    { 0x8049, "Expected PDSyncData for one subslot with SyncID value 25" },
    { 0x804A, "Expected PDSyncData for one subslot with SyncID value 26" },
    { 0x804B, "Expected PDSyncData for one subslot with SyncID value 27" },
    { 0x804C, "Expected PDSyncData for one subslot with SyncID value 28" },
    { 0x804D, "Expected PDSyncData for one subslot with SyncID value 29" },
    { 0x804E, "Expected PDSyncData for one subslot with SyncID value 30" },
    { 0x804F, "Expected PDSyncData for one subslot with SyncID value 31" },
    { 0x8050, "PDInterfaceMrpDataReal for one subslot" },
    { 0x8051, "PDInterfaceMrpDataCheck for one subslot" },
    { 0x8052, "PDInterfaceMrpDataAdjust for one subslot" },
    { 0x8053, "PDPortMrpDataAdjust for one subslot" },
    { 0x8054, "PDPortMrpDataReal for one subslot" },
    /*0x8055 - 0x805F reserved */
    { 0x8060, "PDPortFODataReal for one subslot" },
    { 0x8061, "PDPortFODataCheck for one subslot" },
    { 0x8062, "PDPortFODataAdjust for one subslot" },
    /*0x8063 - 0x806F reserved */
    { 0x8070, "PDNCDataCheck for one subslot" },
    { 0x8071, "PDInterfaceAdjust for one subslot" },
    { 0x8072, "PDPortStatistic for one subslot" },
    /*0x8071 - 0x807F reserved */
    { 0x8080, "PDInterfaceDataReal" },
    /*0x8081 - 0x808F reserved */
    { 0x8090, "Expected PDInterfaceFSUDataAdjust" },
    /*0x8091 - 0xAFEF reserved */
    { 0xAFF0, "I&M0" },
    { 0xAFF1, "I&M1" },
    { 0xAFF2, "I&M2" },
    { 0xAFF3, "I&M3" },
    { 0xAFF4, "I&M4" },
    { 0xAFF5, "I&M5" },
    { 0xAFF6, "I&M6" },
    { 0xAFF7, "I&M7" },
    { 0xAFF8, "I&M8" },
    { 0xAFF9, "I&M9" },
    { 0xAFFA, "I&M10" },
    { 0xAFFB, "I&M11" },
    { 0xAFFC, "I&M12" },
    { 0xAFFD, "I&M13" },
    { 0xAFFE, "I&M14" },
    { 0xAFFF, "I&M15" },
    /*0xB000 - 0xB02D reserved for profiles */
    { 0xB000, "Sync-Log / RTA SyncID 0 (GSY)" },
    { 0xB001, "Sync-Log / RTA SyncID 1 (GSY)" },
    { 0xB002, "reserved for profiles" },
    { 0xB003, "reserved for profiles" },
    { 0xB004, "reserved for profiles" },
    { 0xB005, "reserved for profiles" },
    { 0xB006, "reserved for profiles" },
    { 0xB007, "reserved for profiles" },
    { 0xB008, "reserved for profiles" },
    { 0xB009, "reserved for profiles" },
    { 0xB00A, "reserved for profiles" },
    { 0xB00B, "reserved for profiles" },
    { 0xB00C, "reserved for profiles" },
    { 0xB00D, "reserved for profiles" },
    { 0xB00E, "reserved for profiles" },
    { 0xB00F, "reserved for profiles" },
    { 0xB010, "reserved for profiles" },
    { 0xB011, "reserved for profiles" },
    { 0xB012, "reserved for profiles" },
    { 0xB013, "reserved for profiles" },
    { 0xB014, "reserved for profiles" },
    { 0xB015, "reserved for profiles" },
    { 0xB016, "reserved for profiles" },
    { 0xB017, "reserved for profiles" },
    { 0xB018, "reserved for profiles" },
    { 0xB019, "reserved for profiles" },
    { 0xB01A, "reserved for profiles" },
    { 0xB01B, "reserved for profiles" },
    { 0xB01C, "reserved for profiles" },
    { 0xB01D, "reserved for profiles" },
    { 0xB01E, "reserved for profiles" },
    { 0xB01F, "reserved for profiles" },
    { 0xB020, "reserved for profiles" },
    { 0xB001, "reserved for profiles" },
    { 0xB022, "reserved for profiles" },
    { 0xB023, "reserved for profiles" },
    { 0xB024, "reserved for profiles" },
    { 0xB025, "reserved for profiles" },
    { 0xB026, "reserved for profiles" },
    { 0xB027, "reserved for profiles" },
    { 0xB028, "reserved for profiles" },
    { 0xB029, "reserved for profiles" },
    { 0xB02A, "reserved for profiles" },
    { 0xB02B, "reserved for profiles" },
    { 0xB02C, "reserved for profiles" },
    { 0xB02D, "reserved for profiles" },
    /* PROFIDrive */
    { 0xB02E, "PROFIDrive Parameter Access - Local"},
    { 0xB02F, "PROFIDrive Parameter Access - Global"},

    /*0xB030 - 0xBFFF reserved for profiles */
    { 0xB050, "Ext-PLL Control / RTC+RTA SyncID 0 (EDD)" },
    { 0xB051, "Ext-PLL Control / RTA SyncID 1 (GSY)" },

    { 0xB060, "EDD Trace Unit (EDD" },
    { 0xB061, "EDD Trace Unit (EDD" },

    { 0xB070, "OHA Info (OHA)" },


    /* slot specific */
    { 0xC000, "ExpectedIdentificationData for one slot" },
    { 0xC001, "RealIdentificationData for one slot" },
    /*0xC002 - 0xC009 reserved */
    { 0xC00A, "Diagnosis in channel coding for one slot" },
    { 0xC00B, "Diagnosis in all codings for one slot" },
    { 0xC00C, "Diagnosis, Maintenance, Qualified and Status for one slot" },
    /*0xC00D - 0xC00F reserved */
    { 0xC010, "Maintenance required in channel coding for one slot" },
    { 0xC011, "Maintenance demanded in channel coding for one slot" },
    { 0xC012, "Maintenance required in all codings for one slot" },
    { 0xC013, "Maintenance demanded in all codings for one slot" },
    /*0xC014 - 0xCFFF reserved */
    /*0xD000 - 0xDFFF reserved for profiles */

    /* AR specific */
    { 0xE000, "ExpectedIdentificationData for one AR" },
    { 0xE001, "RealIdentificationData for one AR" },
    { 0xE002, "ModuleDiffBlock for one AR" },
    /*0xE003 - 0xE009 reserved */
    { 0xE00A, "Diagnosis in channel coding for one AR" },
    { 0xE00B, "Diagnosis in all codings for one AR" },
    { 0xE00C, "Diagnosis, Maintenance, Qualified and Status for one AR" },
    /*0xE00D - 0xE00F reserved */
    { 0xE010, "Maintenance required in channel coding for one AR" },
    { 0xE011, "Maintenance demanded in channel coding for one AR" },
    { 0xE012, "Maintenance required in all codings for one AR" },
    { 0xE013, "Maintenance demanded in all codings for one AR" },
    /*0xE014 - 0xE02F reserved */
    { 0xE030, "IsochronousModeData for one AR" },
    /*0xE031 - 0xE03F reserved */
    { 0xE040, "MultipleWrite" },
    /*0xE041 - 0xE04F reserved */
    { 0xE050, "ARFSUDataAdjust data for one AR" },
    /*0xE051 - 0xE05F reserved */
    /*0xEC00 - 0xEFFF reserved */

    /* API specific */
    { 0xF000, "RealIdentificationData for one API" },
    /*0xF001 - 0xF009 reserved */
    { 0xF00A, "Diagnosis in channel coding for one API" },
    { 0xF00B, "Diagnosis in all codings for one API" },
    { 0xF00C, "Diagnosis, Maintenance, Qualified and Status for one API" },
    /*0xF00D - 0xF00F reserved */
    { 0xF010, "Maintenance required in channel coding for one API" },
    { 0xF011, "Maintenance demanded in channel coding for one API" },
    { 0xF012, "Maintenance required in all codings for one API" },
    { 0xF013, "Maintenance demanded in all codings for one API" },
    /*0xF014 - 0xF01F reserved */
    { 0xF020, "ARData for one API" },
    /*0xF021 - 0xF3FF reserved */
    /*0xF400 - 0xF7FF reserved */

    /* device specific */
    /*0xF800 - 0xF80B reserved */
    { 0xF80C, "Diagnosis, Maintenance, Qualified and Status for one device" },
    /*0xF80D - 0xF81F reserved */
    { 0xF820, "ARData" },
    { 0xF821, "APIData" },
    /*0xF822 - 0xF82F reserved */
    { 0xF830, "LogData" },
    { 0xF831, "PDevData" },
    /*0xF832 - 0xF83F reserved */
    { 0xF840, "I&M0FilterData" },
    { 0xF841, "PDRealData" },
    { 0xF842, "PDExpectedData" },
    /*0xF843 - 0xF84F reserved */
    { 0xF850, "AutoConfigurarion" },
    /*0xF851 - 0xFBFF reserved */
    /*0xFC00 - 0xFFFF reserved for profiles */
    { 0, NULL }
};

static const value_string pn_io_user_structure_identifier[] = {
    /*0x0000 - 0x7FFF manufacturer specific */
    { 0x8000, "ChannelDiagnosis" },
    { 0x8001, "Multiple" },
    { 0x8002, "ExtChannelDiagnosis" },
    { 0x8003, "QualifiedChannelDiagnosis" },
    /*0x8004 - 0x80FF reserved */
    { 0x8100, "Maintenance" },
    /*0x8101 - 0x8FFF reserved */
    /*0x9000 - 0x9FFF reserved for profiles */
    /*0xA000 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_channel_number[] = {
    /*0x0000 - 0x7FFF manufacturer specific */
    { 0x8000, "Submodule" },
    /*0x8001 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_channel_error_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "short circuit" },
    { 0x0002, "Undervoltage" },
    { 0x0003, "Overvoltage" },
    { 0x0004, "Overload" },
    { 0x0005, "Overtemperature" },
    { 0x0006, "line break" },
    { 0x0007, "upper limit value exceeded" },
    { 0x0008, "lower limit value exceeded" },
    { 0x0009, "Error" },
    /*0x000A - 0x000F reserved */
    { 0x0010, "parametrization fault" },
    { 0x0011, "power supply fault" },
    { 0x0012, "fuse blown / open" },
    { 0x0013, "Manufacturer specific" },
    { 0x0014, "ground fault" },
    { 0x0015, "reference point lost" },
    { 0x0016, "process event lost / sampling error" },
    { 0x0017, "threshold warning" },
    { 0x0018, "output disabled" },
    { 0x0019, "safety event" },
    { 0x001A, "external fault" },
    /*0x001B - 0x001F manufacturer specific */
    /*0x0020 - 0x00FF reserved for common profiles */
    /*0x0100 - 0x7FFF manufacturer specific */
    { 0x8000, "Data transmission impossible" },
    { 0x8001, "Remote mismatch" },
    { 0x8002, "Media redundancy mismatch" },
    { 0x8003, "Sync mismatch" },
    { 0x8004, "IsochronousMode mismatch" },
    { 0x8005, "Multicast CR mismatch" },
    { 0x8006, "reserved" },
    { 0x8007, "Fiber optic mismatch" },
    { 0x8008, "Network component function mismatch" },
    { 0x8009, "Time mismatch" },
    /* added values for IEC version 2.3: */
    { 0x800A, "Dynamic frame packing function mismatch" },
    { 0x800B, "Media redundancy with planned duplication mismatch"},
    { 0x800C, "System redundancy mismatch"},
    /* ends */
    /*0x800D - 0x8FFF reserved */
    /*0x9000 - 0x9FFF reserved for profile */
    /*0xA000 - 0xFFFF reserved */
    { 0, NULL }
};
    /* ExtChannelErrorType for ChannelErrorType 0 - 0x7FFF */

static const value_string pn_io_ext_channel_error_type0[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Accumulative Info"},
    /* 0x8001 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};


    /* ExtChannelErrorType for ChannelErrorType "Data transmission impossible" */
static const value_string pn_io_ext_channel_error_type0x8000[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Link State mismatch - Link down"},
    { 0x8001, "MAUType mismatch"},
    { 0x8002, "Line Delay mismatch"},
    /* 0x8003 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Remote mismatch" */
static const value_string pn_io_ext_channel_error_type0x8001[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Peer Chassis ID mismatch"},
    { 0x8001, "Peer Port ID mismatch"},
    { 0x8002, "Peer RT_CLASS_3 mismatch a"},
    { 0x8003, "Peer MAUType mismatch"},
    { 0x8004, "Peer MRP domain mismatch"},
    { 0x8005, "No peer detected"},
    { 0x8006, "Reserved"},
    { 0x8007, "Peer Line Delay mismatch"},
    { 0x8008, "Peer PTCP mismatch b"},
    { 0x8009, "Peer Preamble Length mismatch"},
    { 0x800A, "Peer Fragmentation mismatch"},
    /* 0x800B - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Media redundancy mismatch" 0x8002 */
static const value_string pn_io_ext_channel_error_type0x8002[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Manager role fail"},
    { 0x8001, "MRP ring open"},
    { 0x8002, "Reserved"},
    { 0x8003, "Multiple mananger"},
    /* 0x8004 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Sync mismatch" and for ChannelErrorType "Time mismatch" 0x8003 and 0x8009*/
static const value_string pn_io_ext_channel_error_type0x8003[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "No sync message received"},
    { 0x8001, "- 0x8002 Reserved"},
    { 0x8003, "Jitter out of boundary"},
    /* 0x8004 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /*ExtChannelErrorType for ChannelErrorType "Isochronous mode mismatch" 0x8004 */
static const value_string pn_io_ext_channel_error_type0x8004[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Output Time Failure - Output update missing or out of order"},
    { 0x8001, "Input Time Failure"},
    { 0x8002, "Master Life Sign Failure - Error in MLS update detected"},
    /* 0x8003 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Multicast CR mismatch" 0x8005 */
static const value_string pn_io_ext_channel_error_type0x8005[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Multicast Consumer CR timed out"},
    { 0x8001, "Address resolution failed"},
    /* 0x8002 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Fiber optic mismatch" 0x8007*/
static const value_string pn_io_ext_channel_error_type0x8007[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Power Budget"},
    /* 0x8001 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Network component function mismatch" 0x8008 */
static const value_string pn_io_ext_channel_error_type0x8008[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Frame dropped - no resource"},
    /* 0x8001 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Dynamic Frame Packing function mismatch" 0x800A */
static const value_string pn_io_ext_channel_error_type0x800A[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    /* 0x8000 - 0x80FF Reserved */
    { 0x8100, "Frame late error for FrameID (0x0100)"},
    /* 0x8101 + 0x8FFE See Equation (56) */
    { 0x8FFF, "Frame late error for FrameID (0x0FFF)"},
    /* 0x8001 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Media redundancy with planned duplication mismatch" 0x800B */
static const value_string pn_io_ext_channel_error_type0x800B[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    /* 0x8000 - 0x86FF Reserved */
    { 0x8700, "MRPD duplication void for FrameID (0x0700)"},
    /* 0x8701 + 0x8FFE See Equation (57) */
    { 0x8FFF, "MRPD duplication void for FrameID (0x0FFF)"},
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "System redundancy mismatch" 0x800C */
static const value_string pn_io_ext_channel_error_type0x800C[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "System redundancy event"},
    /* 0x8001 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

static const value_string pn_io_channel_properties_type[] = {
    { 0x0000, "submodule or unspecified" },
    { 0x0001, "1 Bit" },
    { 0x0002, "2 Bit" },
    { 0x0003, "4 Bit" },
    { 0x0004, "8 Bit" },
    { 0x0005, "16 Bit" },
    { 0x0006, "32 Bit" },
    { 0x0007, "64 Bit" },
    /*0x0008 - 0x00FF reserved */
    { 0, NULL }
};

static const value_string pn_io_channel_properties_maintenance[] = {
    { 0x0000, "Diagnosis" },
    { 0x0001, "Maintenance required" },
    { 0x0002, "Maintenance demanded" },
    { 0x0003, "Qualified diagnosis" },
    { 0, NULL }
};

static const value_string pn_io_channel_properties_specifier[] = {
    { 0x0000, "All subsequent disappears" },
    { 0x0001, "Appears" },
    { 0x0002, "Disappears" },
    { 0x0003, "Disappears but others remain" },
    { 0, NULL }
};

static const value_string pn_io_channel_properties_direction[] = {
    { 0x0000, "Manufacturer-specific" },
    { 0x0001, "Input" },
    { 0x0002, "Output" },
    { 0x0003, "Input/Output" },
    /*0x0004 - 0x0007 reserved */
    { 0, NULL }
};

static const value_string pn_io_alarmcr_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "Alarm CR" },
    /*0x0002 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_mau_type[] = {
    /*0x0000 - 0x0004 reserved */
    { 0x0005, "10BASET" },
    /*0x0006 - 0x0009 reserved */
    { 0x000A, "10BASETXHD" },
    { 0x000B, "10BASETXFD" },
    { 0x000C, "10BASEFLHD" },
    { 0x000D, "10BASEFLFD" },
    { 0x000F, "100BASETXHD" },
    { 0x0010, "100BASETXFD" },
    { 0x0011, "100BASEFXHD" },
    { 0x0012, "100BASEFXFD" },
    /*0x0013 - 0x0014 reserved */
    { 0x0015, "1000BASEXHD" },
    { 0x0016, "1000BASEXFD" },
    { 0x0017, "1000BASELXHD" },
    { 0x0018, "1000BASELXFD" },
    { 0x0019, "1000BASESXHD" },
    { 0x001A, "1000BASESXFD" },
    /*0x001B - 0x001C reserved */
    { 0x001D, "1000BASETHD" },
    { 0x001E, "1000BASETFD" },
    { 0x001F, "10GigBASEFX" },
    /*0x0020 - 0x002D reserved */
    { 0x002E, "100BASELX10" },
    /*0x002F - 0x0035 reserved */
    { 0x0036, "100BASEPXFD" },
    /*0x0037 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_preamble_length[] = {
    { 0x0000, "Seven octets Preamble shall be used" },
    { 0x0001, "One octet Preamble shall be used" },
    /*0x0002 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_mau_type_mode[] = {
    { 0x0000, "OFF" },
    { 0x0001, "ON" },
    /*0x0002 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_port_state[] = {
    { 0x0000, "reserved" },
    { 0x0001, "up" },
    { 0x0002, "down" },
    { 0x0003, "testing" },
    { 0x0004, "unknown" },
    /*0x0005 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_media_type[] = {
    { 0x0000, "Unknown" },
    { 0x0001, "Copper cable" },
    { 0x0002, "Fiber optic cable" },
    { 0x0003, "Radio communication" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_fiber_optic_type[] = {
    { 0x0000, "No fiber type adjusted" },
    { 0x0001, "9 um single mode fiber" },
    { 0x0002, "50 um multi mode fiber" },
    { 0x0003, "62,5 um multi mode fiber" },
    { 0x0004, "SI-POF, NA=0.5" },
    { 0x0005, "SI-PCF, NA=0.36" },
    { 0x0006, "LowNA-POF, NA=0.3" },
    { 0x0007, "GI-POF" },
    /*0x0008 - 0xFFFF reserved */
    { 0, NULL }
};


static const value_string pn_io_fiber_optic_cable_type[] = {
    { 0x0000, "No cable specified" },
    { 0x0001, "Inside/outside cable, fixed installation" },
    { 0x0002, "Inside/outside cable, flexible installation" },
    { 0x0003, "Outdoor cable, fixed installation" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_im_revision_prefix_vals[] = {
    { 'V', "V - Officially released version" },
    { 'R', "R - Revision" },
    { 'P', "P - Prototype" },
    { 'U', "U - Under Test (Field Test)" },
    { 'T', "T - Test Device" },
    /*all others reserved */
    { 0, NULL }
};


static const value_string pn_io_mrp_role_vals[] = {
    { 0x0000, "Media Redundancy disabled" },
    { 0x0001, "Media Redundancy Client" },
    { 0x0002, "Media Redundancy Manager" },
    /*all others reserved */
    { 0, NULL }
};


static const value_string pn_io_mrp_prio_vals[] = {
    { 0x0000, "Highest priority redundancy manager" },
    /* 0x1000 - 0x7000 High priorities */
    { 0x8000, "Default priority for redundancy manager" },
    /* 0x9000 - 0xE000 Low priorities */
    { 0xF000, "Lowest priority redundancy manager" },
    /*all others reserved */
    { 0, NULL }
};

static const value_string pn_io_mrp_rtmode_rtclass12_vals[] = {
    { 0x0000, "RT_CLASS_1 and RT_CLASS_2 redundancy mode deactivated" },
    { 0x0001, "RT_CLASS_1 and RT_CLASS_2 redundancy mode activated" },
    { 0, NULL }
};

static const value_string pn_io_mrp_rtmode_rtclass3_vals[] = {
    { 0x0000, "RT_CLASS_3 redundancy mode deactivated" },
    { 0x0001, "RT_CLASS_3 redundancy mode activated" },
    { 0, NULL }
};

static const value_string pn_io_mrp_ring_state_vals[] = {
    { 0x0000, "Ring open" },
    { 0x0001, "Ring closed" },
    { 0, NULL }
};

static const value_string pn_io_mrp_rt_state_vals[] = {
    { 0x0000, "RT media redundancy lost" },
    { 0x0001, "RT media redundancy available" },
    { 0, NULL }
};

static const value_string pn_io_control_properties_vals[] = {
    { 0x0000, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_control_properties_prmbegin_vals[] = {
    { 0x0000, "No PrmBegin" },
    { 0x0001, "The IO controller starts the transmisson of the stored start-up parameter" },
    { 0, NULL }
};
static const value_string pn_io_control_properties_application_ready_vals[] = {
    { 0x0000, "Wait for explicit ControlCommand.ReadyForCompanion" },
    { 0x0001, "Implicit ControlCommand.ReadyForCompanion" },
    { 0, NULL }
};

static const value_string pn_io_fs_hello_mode_vals[] = {
    { 0x0000, "OFF" },
    { 0x0001, "Send req on LinkUp" },
    { 0x0002, "Send req on LinkUp after HelloDelay" },
    { 0, NULL }
};

static const value_string pn_io_fs_parameter_mode_vals[] = {
    { 0x0000, "OFF" },
    { 0x0001, "ON" },
    { 0x0002, "Reserved" },
    { 0x0003, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_frame_details_sync_master_vals[] = {
    { 0x0000, "No Sync Frame" },
    { 0x0001, "Primary sync frame" },
    { 0x0002, "Secondary sync frame" },
    { 0x0003, "Reserved" },
    { 0, NULL }
};
static const value_string pn_io_frame_details_meaning_frame_send_offset_vals[] = {
    { 0x0000, "Field FrameSendOffset specifies the point of time for receiving or transmitting a frame " },
    { 0x0001, "Field FrameSendOffset specifies the beginning of the RT_CLASS_3 interval within a phase" },
    { 0x0002, "Field FrameSendOffset specifies the ending of the RT_CLASS_3 interval within a phase" },
    { 0x0003, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_f_check_seqnr[] = {
    { 0x00, "consecutive number not included in crc" },
    { 0x01, "consecutive number included in crc" },
    { 0, NULL }
};

static const value_string pn_io_f_check_ipar[] = {
    { 0x00, "no check" },
    { 0x01, "check" },
    { 0, NULL }
};

static const value_string pn_io_f_sil[] = {
    { 0x00, "SIL1" },
    { 0x01, "SIL2" },
    { 0x02, "SIL3" },
    { 0x03, "NoSIL" },
    { 0, NULL }
};

static const value_string pn_io_f_crc_len[] = {
    { 0x00, "3 octet CRC" },
    { 0x01, "2 octet CRC" },
    { 0x02, "4 octet CRC" },
    { 0x03, "reserved" },
    { 0, NULL }
};

static const value_string pn_io_f_block_id[] = {
    { 0x00, "Parameter set for F-Host/F-Device relationship" },
    { 0x01, "Additional F_Address parameter block" },
    /* 0x02..0x07 reserved */
    { 0, NULL }
};

static const value_string pn_io_f_par_version[] = {
    { 0x00, "Valid for V1-mode" },
    { 0x01, "Valid for V2-mode" },
    /* 0x02..0x03 reserved */
    { 0, NULL }
};

static const value_string pn_io_profidrive_request_id_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Read request" },
    { 0x02, "Change request" },
    { 0, NULL }
};

static const value_string pn_io_profidrive_response_id_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Positive read response" },
    { 0x02, "Positive change response" },
    { 0x81, "Negative read response" },
    { 0x82, "Negative change response" },
    { 0, NULL }
};

static const value_string pn_io_profidrive_attribute_vals[] = {
    { 0x00, "Reserved" },
    { 0x10, "Value" },
    { 0x20, "Description" },
    { 0x30, "Text" },
    { 0, NULL }
};

static const value_string pn_io_profidrive_format_vals[] = {
    { 0x00, "Reserved" },
    { 0x40, "Zero" },
    { 0x41, "Byte" },
    { 0x42, "Word" },
    { 0x43, "Double Word" },
    { 0x44, "Error" },
    { 0, NULL }
};

GList *pnio_ars;

typedef struct pnio_ar_s {
    /* generic */
    e_uuid_t        aruuid;
    guint16         inputframeid;
    guint16         outputframeid;

    /* controller only */
    /*const char      controllername[33];*/
    const guint8    controllermac[6];
    guint16         controlleralarmref;

    /* device only */
    const guint8    devicemac[6];
    guint16         devicealarmref;
    guint16         arType;
} pnio_ar_t;



static void
pnio_ar_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, pnio_ar_t *ar)
{
    proto_item *item;
    proto_item *sub_item;
    proto_tree *sub_tree;


    pinfo->profinet_conv = ar;
    pinfo->profinet_type = 10;

    if (tree) {
        sub_item = proto_tree_add_text(tree, tvb, 0, 0, "ARUUID:%s ContrMAC:%s ContrAlRef:0x%x DevMAC:%s DevAlRef:0x%x InCR:0x%x OutCR=0x%x",
            guid_to_str((const e_guid_t*) &ar->aruuid),
            ether_to_str((const guint8 *)ar->controllermac), ar->controlleralarmref,
            ether_to_str((const guint8 *)ar->devicemac), ar->devicealarmref,
            ar->inputframeid, ar->outputframeid);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_ar_info);
        PROTO_ITEM_SET_GENERATED(sub_item);

        item = proto_tree_add_guid(sub_tree, hf_pn_io_ar_uuid, tvb, 0, 0, (e_guid_t *) &ar->aruuid);
        PROTO_ITEM_SET_GENERATED(item);

        item = proto_tree_add_ether(sub_tree, hf_pn_io_cminitiator_macadd, tvb, 0, 0, ar->controllermac);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_localalarmref, tvb, 0, 0, ar->controlleralarmref);
        PROTO_ITEM_SET_GENERATED(item);

        item = proto_tree_add_ether(sub_tree, hf_pn_io_cmresponder_macadd, tvb, 0, 0, ar->devicemac);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_localalarmref, tvb, 0, 0, ar->devicealarmref);
        PROTO_ITEM_SET_GENERATED(item);

        item = proto_tree_add_uint(sub_tree, hf_pn_io_frame_id, tvb, 0, 0, ar->inputframeid);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_frame_id, tvb, 0, 0, ar->outputframeid);
        PROTO_ITEM_SET_GENERATED(item);
    }
}




static int dissect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar);

static int dissect_a_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep);

static int dissect_blocks(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep);

static int dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, int hfindex);





static pnio_ar_t *
pnio_ar_find_by_aruuid(packet_info *pinfo _U_, e_uuid_t *aruuid)
{
    GList       *ars;
    pnio_ar_t   *ar;


    /* find pdev */
    for(ars = pnio_ars; ars != NULL; ars = g_list_next(ars)) {
        ar = ars->data;

        if( memcmp(&ar->aruuid, aruuid, sizeof(e_uuid_t)) == 0) {
            return ar;
        }
    }

    return NULL;
}


static pnio_ar_t *
pnio_ar_new(e_uuid_t *aruuid)
{
    pnio_ar_t *ar;


    ar = se_alloc0(sizeof(pnio_ar_t));

    memcpy(&ar->aruuid, aruuid, sizeof(e_uuid_t));

    ar->controlleralarmref  = 0xffff;
    ar->devicealarmref      = 0xffff;

    pnio_ars = g_list_append(pnio_ars, ar);

    return ar;
}



/* dissect the four status (error) fields */
static int
dissect_PNIO_status(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8  u8ErrorCode;
    guint8  u8ErrorDecode;
    guint8  u8ErrorCode1;
    guint8  u8ErrorCode2;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;
    int bytemask = (drep[0] & DREP_LITTLE_ENDIAN) ? 3 : 0;
    const value_string *error_code1_vals;
    const value_string *error_code2_vals = pn_io_error_code2;   /* defaults */



    /* status */
    sub_item = proto_tree_add_item(tree, hf_pn_io_status, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_status);
    u32SubStart = offset;

    /* the PNIOStatus field is existing in both the RPC and the application data,
     * depending on the current PDU.
     * As the byte representation of these layers are different, this has to be handled
     * in a somewhat different way than elsewhere. */

    dissect_dcerpc_uint8(tvb, offset+(0^bytemask), pinfo, sub_tree, drep,
                         hf_pn_io_error_code, &u8ErrorCode);
    dissect_dcerpc_uint8(tvb, offset+(1^bytemask), pinfo, sub_tree, drep,
                         hf_pn_io_error_decode, &u8ErrorDecode);

    switch(u8ErrorDecode) {
    case(0x80): /* PNIORW */
        dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep,
                             hf_pn_io_error_code1_pniorw, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pniorw;

        /* u8ErrorCode2 for PNIORW is always user specific */
        dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                             hf_pn_io_error_code2_pniorw, &u8ErrorCode2);

        error_code2_vals = pn_io_error_code2_pniorw;

        break;
    case(0x81): /* PNIO */
        dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep,
                             hf_pn_io_error_code1_pnio, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pnio;

        switch(u8ErrorCode1) {
        case(1):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_1, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_1;
            break;
        case(2):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_2, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_2;
            break;
        case(3):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_3, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_3;
            break;
        case(4):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_4, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_4;
            break;
        case(5):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_5, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_5;
            break;
        case(6):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_6, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_6;
            break;
        case(7):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_7, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_7;
            break;
        case(8):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_8, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_8;
            break;
        case(20):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_20, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_20;
            break;
        case(21):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_21, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_21;
            break;
        case(22):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_22, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_22;
            break;
        case(23):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_23, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_23;
            break;
        case(40):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_40, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_40;
            break;
        case(61):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_61, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_61;
            break;
        case(62):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_62, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_62;
            break;
        case(63):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_63, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_63;
            break;
        case(64):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_64, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_64;
            break;
        case(65):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_65, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_65;
            break;
        case(66):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_66, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_66;
            break;
        case(70):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_70, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_70;
            break;
        case(71):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_71, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_71;
            break;
        case(72):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_72, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_72;
            break;
        case(73):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_73, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_73;
            break;
        case(74):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_74, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_74;
            break;
        case(75):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_75, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_75;
            break;
        case(76):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_76, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_76;
            break;
        case(77):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_77, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_77;
            break;
        case(253):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_253, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_253;
            break;
        case(255):
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2_pnio_255, &u8ErrorCode2);
            error_code2_vals = pn_io_error_code2_pnio_255;
            break;
        default:
            /* don't know this u8ErrorCode1 for PNIO, use defaults */
            dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                                 hf_pn_io_error_code2, &u8ErrorCode2);
            expert_add_info_format(pinfo, sub_item, PI_UNDECODED, PI_WARN,
                "Unknown ErrorCode1 0x%x (for ErrorDecode==PNIO)", u8ErrorCode1);
            break;
        }
        break;
    default:
        dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep,
                             hf_pn_io_error_code1, &u8ErrorCode1);
        if(u8ErrorDecode!=0) {
            expert_add_info_format(pinfo, sub_item, PI_UNDECODED, PI_WARN,
            "Unknown ErrorDecode 0x%x", u8ErrorDecode);
        }
        error_code1_vals = pn_io_error_code1;

        /* don't know this u8ErrorDecode, use defaults */
        dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep,
                             hf_pn_io_error_code2, &u8ErrorCode2);
        if(u8ErrorDecode != 0) {
            expert_add_info_format(pinfo, sub_item, PI_UNDECODED, PI_WARN,
            "Unknown ErrorDecode 0x%x", u8ErrorDecode);
        }
    }

    offset +=4;

    if(u8ErrorCode == 0 && u8ErrorDecode == 0 && u8ErrorCode1 == 0 && u8ErrorCode2 == 0) {
        proto_item_append_text(sub_item, ": OK");
        col_append_str(pinfo->cinfo, COL_INFO, ", OK");
    } else {
        proto_item_append_text(sub_item, ": Error: \"%s\", \"%s\", \"%s\", \"%s\"",
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(u8ErrorCode1, error_code1_vals, "(0x%x)"),
            val_to_str(u8ErrorCode2, error_code2_vals, "(0x%x)"));
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: \"%s\", \"%s\", \"%s\", \"%s\"",
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(u8ErrorCode1, error_code1_vals, "(0x%x)"),
            val_to_str(u8ErrorCode2, error_code2_vals, "(0x%x)"));
    }
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect the alarm specifier */
static int
dissect_Alarm_specifier(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmSpecifierSequence;
    guint16 u16AlarmSpecifierChannel;
    guint16 u16AlarmSpecifierManufacturer;
    guint16 u16AlarmSpecifierSubmodule;
    guint16 u16AlarmSpecifierAR;
    proto_item *sub_item;
    proto_tree *sub_tree;

    /* alarm specifier */
    sub_item = proto_tree_add_item(tree, hf_pn_io_alarm_specifier, tvb, offset, 2, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pdu_type);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarm_specifier_sequence, &u16AlarmSpecifierSequence);
    u16AlarmSpecifierSequence &= 0x07FF;
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarm_specifier_channel, &u16AlarmSpecifierChannel);
    u16AlarmSpecifierChannel = (u16AlarmSpecifierChannel &0x0800) >> 11;
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarm_specifier_manufacturer, &u16AlarmSpecifierManufacturer);
    u16AlarmSpecifierManufacturer = (u16AlarmSpecifierManufacturer &0x1000) >> 12;
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarm_specifier_submodule, &u16AlarmSpecifierSubmodule);
    u16AlarmSpecifierSubmodule = (u16AlarmSpecifierSubmodule & 0x2000) >> 13;
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarm_specifier_ardiagnosis, &u16AlarmSpecifierAR);
    u16AlarmSpecifierAR = (u16AlarmSpecifierAR & 0x8000) >> 15;


    proto_item_append_text(sub_item, ", Sequence: %u, Channel: %u, Manuf: %u, Submodule: %u AR: %u",
        u16AlarmSpecifierSequence, u16AlarmSpecifierChannel,
        u16AlarmSpecifierManufacturer, u16AlarmSpecifierSubmodule, u16AlarmSpecifierAR);

    return offset;
}


/* dissect the alarm header */
static int
dissect_Alarm_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16AlarmType;
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_alarm_type, &u16AlarmType);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ", %s, API:%u, Slot:0x%x/0x%x",
        val_to_str(u16AlarmType, pn_io_alarm_type, "(0x%x)"),
        u32Api, u16SlotNr, u16SubslotNr);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Slot: 0x%x/0x%x",
        val_to_str(u16AlarmType, pn_io_alarm_type, "(0x%x)"),
        u16SlotNr, u16SubslotNr);

    return offset;
}


static int
dissect_ChannelProperties(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16 u16ChannelProperties;


    sub_item = proto_tree_add_item(tree, hf_pn_io_channel_properties, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_channel_properties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_direction, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_specifier, &u16ChannelProperties);
/* replaced with 2 bit values
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_maintenance_demanded, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_maintenance_required, &u16ChannelProperties);
*/
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_maintenance, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_accumulative, &u16ChannelProperties);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_type, &u16ChannelProperties);

    return offset;
}


static int
dissect_AlarmUserStructure(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
        guint16 *body_length, guint16 u16UserStructureIdentifier)
{
    guint16 u16ChannelNumber;
    guint16 u16ChannelErrorType;
    guint16 u16ExtChannelErrorType;
    guint32 u32ExtChannelAddValue;
    guint16 u16Index;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    switch(u16UserStructureIdentifier) {
    case(0x8000):   /* ChannelDiagnosisData */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_number, &u16ChannelNumber);
        offset = dissect_ChannelProperties(tvb, offset, pinfo, tree, item, drep);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_error_type, &u16ChannelErrorType);
        *body_length -= 6;
        break;
    case(0x8002):   /* ExtChannelDiagnosisData */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_number, &u16ChannelNumber);

        offset = dissect_ChannelProperties(tvb, offset, pinfo, tree, item, drep);

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_error_type, &u16ChannelErrorType);

        if(u16ChannelErrorType < 0x7fff)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8000)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8000, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8001)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8001, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8002)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8002, &u16ExtChannelErrorType);
        }
        else if((u16ChannelErrorType == 0x8003)||(u16ChannelErrorType == 0x8009))
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8003, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8004)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8004, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8005)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8005, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8007)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8007, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x8008)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x8008, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x800A)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x800A, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x800B)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x800B, &u16ExtChannelErrorType);
        }
        else if(u16ChannelErrorType == 0x800C)
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type0x800C, &u16ExtChannelErrorType);
        }
        else
        {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type, &u16ExtChannelErrorType);
        }
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_add_value, &u32ExtChannelAddValue);
        *body_length -= 12;
        break;
    case(0x8100):   /* MaintenanceItem */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        *body_length -= 12;
        break;
    /* XXX - dissect remaining user structures of [AlarmItem] */
    case(0x8001):   /* DiagnosisData */
    case(0x8003):   /* QualifiedChannelDiagnosisData */
    default:
        if(u16UserStructureIdentifier >= 0x8000) {
            offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, *body_length);
        } else {
            offset = dissect_pn_user_data(tvb, offset, pinfo, tree, *body_length, "UserData");
        }

        *body_length = 0;
    }

    return offset;
}



/* dissect the alarm notification block */
static int
dissect_AlarmNotification_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 body_length)
{
    guint32 u32ModuleIdentNumber;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16UserStructureIdentifier;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, item, drep);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    proto_item_append_text(item, ", Ident:0x%x, SubIdent:0x%x",
        u32ModuleIdentNumber, u32SubmoduleIdentNumber);

    body_length -= 20;

    /* the rest of the block contains optional: [MaintenanceItem] and/or [AlarmItem] */
    while(body_length) {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_user_structure_identifier, &u16UserStructureIdentifier);
        proto_item_append_text(item, ", USI:0x%x", u16UserStructureIdentifier);
        body_length -= 2;

        offset = dissect_AlarmUserStructure(tvb, offset, pinfo, tree, item, drep, &body_length, u16UserStructureIdentifier);
    }

    return offset;
}


static int
dissect_IandM0_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8 u8VendorIDHigh;
    guint8 u8VendorIDLow;
    char *pOrderID;
    char *pIMSerialNumber;
    guint16 u16IMHardwareRevision;
    guint8 u8SWRevisionPrefix;
    guint8 u8IMSWRevisionFunctionalEnhancement;
    guint8 u8IMSWRevisionBugFix;
    guint8 u8IMSWRevisionInternalChange;
    guint16 u16IMRevisionCounter;
    guint16 u16IMProfileID;
    guint16 u16IMProfileSpecificType;
    guint8 u8IMVersionMajor;
    guint8 u8IMVersionMinor;
    guint16 u16IMSupported;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* x8 VendorIDHigh */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_high, &u8VendorIDHigh);
    /* x8 VendorIDLow */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_low, &u8VendorIDLow);
    /* c8[20] OrderID */
    pOrderID = ep_alloc(20+1);
    tvb_memcpy(tvb, (guint8 *) pOrderID, offset, 20);
    pOrderID[20] = '\0';
    proto_tree_add_string (tree, hf_pn_io_order_id, tvb, offset, 20, pOrderID);
    offset += 20;

    /* c8[16] IM_Serial_Number */
    pIMSerialNumber = ep_alloc(16+1);
    tvb_memcpy(tvb, (guint8 *) pIMSerialNumber, offset, 16);
    pIMSerialNumber[16] = '\0';
    proto_tree_add_string (tree, hf_pn_io_im_serial_number, tvb, offset, 16, pIMSerialNumber);
    offset += 16;

    /* x16 IM_Hardware_Revision */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_hardware_revision, &u16IMHardwareRevision);
    /* c8 SWRevisionPrefix */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_revision_prefix, &u8SWRevisionPrefix);
    /* x8 IM_SWRevision_Functional_Enhancement */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_sw_revision_functional_enhancement, &u8IMSWRevisionFunctionalEnhancement);
    /* x8 IM_SWRevision_Bug_Fix */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_revision_bugfix, &u8IMSWRevisionBugFix);
    /* x8 IM_SWRevision_Internal_Change */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_sw_revision_internal_change, &u8IMSWRevisionInternalChange);
    /* x16 IM_Revision_Counter */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_revision_counter, &u16IMRevisionCounter);
    /* x16 IM_Profile_ID */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_profile_id, &u16IMProfileID);
    /* x16 IM_Profile_Specific_Type */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_profile_specific_type, &u16IMProfileSpecificType);
    /* x8 IM_Version_Major (values) */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_version_major, &u8IMVersionMajor);
    /* x8 IM_Version_Minor (values) */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_version_minor, &u8IMVersionMinor);
    /* x16 IM_Supported (bitfield) */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_supported, &u16IMSupported);

    return offset;
}


static int
dissect_IandM1_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pTagFunction;
    char *pTagLocation;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Tag_Function [32] */
    pTagFunction = ep_alloc(32+1);
    tvb_memcpy(tvb, (guint8 *) pTagFunction, offset, 32);
    pTagFunction[32] = '\0';
    proto_tree_add_string (tree, hf_pn_io_im_tag_function, tvb, offset, 32, pTagFunction);
    offset += 32;

    /* IM_Tag_Location [22] */
    pTagLocation = ep_alloc(22+1);
    tvb_memcpy(tvb, (guint8 *) pTagLocation, offset, 22);
    pTagLocation[22] = '\0';
    proto_tree_add_string (tree, hf_pn_io_im_tag_location, tvb, offset, 22, pTagLocation);
    offset += 22;

    proto_item_append_text(item, ": TagFunction:\"%s\", TagLocation:\"%s\"", pTagFunction, pTagLocation);

    return offset;
}


static int
dissect_IandM2_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pDate;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Date [16] */
    pDate = ep_alloc(16+1);
    tvb_memcpy(tvb, (guint8 *) pDate, offset, 16);
    pDate[16] = '\0';
    proto_tree_add_string (tree, hf_pn_io_im_date, tvb, offset, 16, pDate);
    offset += 16;

    proto_item_append_text(item, ": Date:\"%s\"", pDate);

    return offset;
}


static int
dissect_IandM3_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pDescriptor;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Descriptor [54] */
    pDescriptor = ep_alloc(54+1);
    tvb_memcpy(tvb, (guint8 *) pDescriptor, offset, 54);
    pDescriptor[54] = '\0';
    proto_tree_add_string (tree, hf_pn_io_im_descriptor, tvb, offset, 54, pDescriptor);
    offset += 54;

    proto_item_append_text(item, ": Descriptor:\"%s\"", pDescriptor);

    return offset;
}


static int
dissect_IandM4_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    dissect_pn_user_data(tvb, offset, pinfo, tree, 54, "IM Signature");

    return offset;
}


static int
dissect_IandM0FilterData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16NumberOfModules;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16NumberOfSubmodules;
    guint16 u16SubslotNr;
    guint32 u32SubmoduleIdentNumber;
    proto_item *subslot_item;
    proto_tree *subslot_tree;
    proto_item *module_item;
    proto_tree *module_tree;
    guint32 u32ModuleStart;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
        /* NumberOfModules */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_modules, &u16NumberOfModules);

        while(u16NumberOfModules--) {
            module_item = proto_tree_add_item(tree, hf_pn_io_subslot, tvb, offset, 6, ENC_NA);
            module_tree = proto_item_add_subtree(module_item, ett_pn_io_module);

            u32ModuleStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                            hf_pn_io_slot_nr, &u16SlotNr);
            /* ModuleIdentNumber */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, module_tree, drep,
                            hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
            /* NumberOfSubmodules */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                            hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

            proto_item_append_text(module_item, ": Slot:%u, Ident:0x%x Submodules:%u",
                u16SlotNr, u32ModuleIdentNumber, u16NumberOfSubmodules);

            while(u16NumberOfSubmodules--) {
                subslot_item = proto_tree_add_item(module_tree, hf_pn_io_subslot, tvb, offset, 6, ENC_NA);
                subslot_tree = proto_item_add_subtree(subslot_item, ett_pn_io_subslot);

                /* SubslotNumber */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, subslot_tree, drep,
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, subslot_tree, drep,
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

                proto_item_append_text(subslot_item, ": Number:0x%x, Ident:0x%x",
                    u16SubslotNr, u32SubmoduleIdentNumber);
            }

            proto_item_set_len(module_item, offset-u32ModuleStart);
        }
    }

    return offset;
}


/* dissect the IdentificationData block */
static int
dissect_IdentificationData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs = 1;
    guint32 u32Api;
    guint16 u16NumberOfSlots;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16NumberOfSubslots;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubslotNr;
    proto_item *slot_item;
    proto_tree *slot_tree;
    guint32 u32SlotStart;
    proto_item *subslot_item;
    proto_tree *subslot_tree;


    if(u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if(u8BlockVersionLow == 1) {
        /* NumberOfAPIs */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_number_of_apis, &u16NumberOfAPIs);
    }

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        if(u8BlockVersionLow == 1) {
            /* API */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_api, &u32Api);
        }

        /* NumberOfSlots */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_number_of_slots, &u16NumberOfSlots);

        proto_item_append_text(item, ", Slots:%u", u16NumberOfSlots);

        while(u16NumberOfSlots--) {
            slot_item = proto_tree_add_item(tree, hf_pn_io_slot, tvb, offset, 0, ENC_NA);
            slot_tree = proto_item_add_subtree(slot_item, ett_pn_io_slot);
            u32SlotStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, slot_tree, drep,
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* ModuleIdentNumber */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, slot_tree, drep,
                                hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
            /* NumberOfSubslots */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, slot_tree, drep,
                                hf_pn_io_number_of_subslots, &u16NumberOfSubslots);

            proto_item_append_text(slot_item, ": SlotNr:%u Ident:0x%x Subslots:%u",
                u16SlotNr, u32ModuleIdentNumber, u16NumberOfSubslots);

            while(u16NumberOfSubslots--) {
                subslot_item = proto_tree_add_item(slot_tree, hf_pn_io_subslot, tvb, offset, 6, ENC_NA);
                subslot_tree = proto_item_add_subtree(subslot_item, ett_pn_io_subslot);

                /* SubslotNumber */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, subslot_tree, drep,
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, subslot_tree, drep,
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

                proto_item_append_text(subslot_item, ": Number:0x%x, Ident:0x%x",
                    u16SubslotNr, u32SubmoduleIdentNumber);
            }

            proto_item_set_len(slot_item, offset-u32SlotStart);
        }
    }

    return offset;
}


/* dissect the substitute value block */
static int
dissect_SubstituteValue_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16 u16SubstitutionMode;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* SubstitutionMode */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_substitutionmode, &u16SubstitutionMode);


    /* SubstituteDataItem */
    /* IOCS */
    offset = dissect_PNIO_IOxS(tvb, offset, pinfo, tree, drep, hf_pn_io_iocs);
    u16BodyLength -= 3;
    /* SubstituteDataObjectElement */
    dissect_pn_user_data_bytes(tvb, offset, pinfo, tree, u16BodyLength, "SubstituteDataObjectElement");

    return offset;
}


/* dissect the RecordInputDataObjectElement block */
static int
dissect_RecordInputDataObjectElement_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8 u8LengthIOCS;
    guint8 u8LengthIOPS;
    guint16 u16LengthData;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* LengthIOCS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_iocs, &u8LengthIOCS);
    /* IOCS */
    offset = dissect_PNIO_IOxS(tvb, offset, pinfo, tree, drep, hf_pn_io_iocs);
    /* LengthIOPS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_iops, &u8LengthIOPS);
    /* IOPS */
    offset = dissect_PNIO_IOxS(tvb, offset, pinfo, tree, drep, hf_pn_io_iops);
    /* LengthData */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_data, &u16LengthData);
    /* Data */
    offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16LengthData, "Data");

    return offset;
}


/* dissect the RecordOutputDataObjectElement block */
static int
dissect_RecordOutputDataObjectElement_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16SubstituteActiveFlag;
    guint8 u8LengthIOCS;
    guint8 u8LengthIOPS;
    guint16 u16LengthData;
    guint16 u16Index;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* SubstituteActiveFlag */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                hf_pn_io_substitute_active_flag, &u16SubstituteActiveFlag);

    /* LengthIOCS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_iocs, &u8LengthIOCS);
    /* LengthIOPS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_iops, &u8LengthIOPS);
    /* LengthData */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_data, &u16LengthData);
    /* DataItem (IOCS, Data, IOPS) */
    offset = dissect_PNIO_IOxS(tvb, offset, pinfo, tree, drep, hf_pn_io_iocs);

    offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16LengthData, "Data");

    offset = dissect_PNIO_IOxS(tvb, offset, pinfo, tree, drep, hf_pn_io_iops);

    /* SubstituteValue */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    return offset;
}


/* dissect the alarm acknowledge block */
static int
dissect_Alarm_ack_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    col_append_str(pinfo->cinfo, COL_INFO, ", Alarm Ack");

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, item, drep);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect the maintenance block */
static int
dissect_Maintenance_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32MaintenanceStatus;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    sub_item = proto_tree_add_item(tree, hf_pn_io_maintenance_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_maintenance_status);

    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_maintenance_status_demanded, &u32MaintenanceStatus);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_maintenance_status_required, &u32MaintenanceStatus);

    if(u32MaintenanceStatus & 0x0002) {
        proto_item_append_text(item, ", Demanded");
        proto_item_append_text(sub_item, ", Demanded");
    }

    if(u32MaintenanceStatus & 0x0001) {
        proto_item_append_text(item, ", Required");
        proto_item_append_text(sub_item, ", Required");
    }

    return offset;
}


/* dissect the read/write header */
static int
dissect_ReadWrite_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint16 *u16Index, e_uuid_t *aruuid)
{
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16SeqNr;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_seq_number, &u16SeqNr);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, aruuid);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);
        /* padding doesn't match offset required for align4 */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_index, u16Index);

    proto_item_append_text(item, ": Seq:%u, Api:0x%x, Slot:0x%x/0x%x",
        u16SeqNr, u32Api, u16SlotNr, u16SubslotNr);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api:0x%x, Slot:0x%x/0x%x, Index:%s",
        u32Api, u16SlotNr, u16SubslotNr,
        val_to_str(*u16Index, pn_io_index, "(0x%x)"));

    return offset;
}


/* dissect the write request block */
static int
dissect_IODWriteReqHeader_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t ** ar)
{
    e_uuid_t aruuid;
    e_uuid_t null_uuid;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "IODWriteReq: AR information not found!");
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_uuid_t));
    if(memcmp(&aruuid, &null_uuid, sizeof (e_uuid_t)) == 0) {
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_target_ar_uuid, &aruuid);
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 24);

    proto_item_append_text(item, ", Len:%u", *u32RecDataLen);

    if (*u32RecDataLen != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the read request block */
static int
dissect_IODReadReqHeader_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    e_uuid_t aruuid;
    e_uuid_t null_uuid;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "IODReadReq: AR information not found!");
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_uuid_t));
    if(memcmp(&aruuid, &null_uuid, sizeof (e_uuid_t)) == 0) {
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_target_ar_uuid, &aruuid);
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 8);
    } else {
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 24);
    }

    proto_item_append_text(item, ", Len:%u", *u32RecDataLen);

    if (*u32RecDataLen != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the write response block */
static int
dissect_IODWriteResHeader_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    e_uuid_t aruuid;
    guint16 u16AddVal1;
    guint16 u16AddVal2;
    guint32 u32Status;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "IODWriteRes: AR information not found!");
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_add_val1, &u16AddVal1);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_add_val2, &u16AddVal2);

    u32Status = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letohl (tvb, offset)
            : tvb_get_ntohl (tvb, offset));

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 16);

    proto_item_append_text(item, ", Len:%u, Index:0x%x, Status:0x%x, Val1:%u, Val2:%u",
        *u32RecDataLen, *u16Index, u32Status, u16AddVal1, u16AddVal2);

    if (*u32RecDataLen != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the read response block */
static int
dissect_IODReadResHeader_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    e_uuid_t aruuid;
    guint16 u16AddVal1;
    guint16 u16AddVal2;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "IODReadRes: AR information not found!");
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_add_val1, &u16AddVal1);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_add_val2, &u16AddVal2);

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 20);

    proto_item_append_text(item, ", Len:%u, AddVal1:%u, AddVal2:%u",
        *u32RecDataLen, u16AddVal1, u16AddVal2);

    if (*u32RecDataLen != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the control/connect block */
static int
dissect_ControlConnect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t **ar)
{
    e_uuid_t    ar_uuid;
    guint16     u16SessionKey;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16     u16Command;
    guint16     u16Properties;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &ar_uuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &ar_uuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "ControlConnect: AR information not found!");
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, &u16SessionKey);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    sub_item = proto_tree_add_item(tree, hf_pn_io_control_command, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_command);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmend, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_applready, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_release, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_done, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_ready_for_companion, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_ready_for_rt_class3, &u16Command);
	/* Prm.Begin */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmbegin, &u16Command);

    if(u16Command & 0x0002) {
        /* ApplicationReady: special decode */
        sub_item = proto_tree_add_item(tree, hf_pn_io_control_block_properties_applready, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_block_properties);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_control_block_properties_applready0, &u16Properties);
    } else {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_control_block_properties, &u16Properties);
    }

    proto_item_append_text(item, ": Session:%u, Command:", u16SessionKey);

    if(u16Command & 0x0001) {
        proto_item_append_text(sub_item, ", ParameterEnd");
        proto_item_append_text(item, " ParameterEnd");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: ParameterEnd");
    }
    if(u16Command & 0x0002) {
        proto_item_append_text(sub_item, ", ApplicationReady");
        proto_item_append_text(item, " ApplicationReady");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: ApplicationReady");
    }
    if(u16Command & 0x0004) {
        proto_item_append_text(sub_item, ", Release");
        proto_item_append_text(item, " Release");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: Release");
    }
    if(u16Command & 0x0008) {
        proto_item_append_text(sub_item, ", Done");
        proto_item_append_text(item, ", Done");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: Done");
    }

    proto_item_append_text(item, ", Properties:0x%x", u16Properties);

    return offset;
}

/* dissect the ControlBlockPrmBegin block */
static int
dissect_ControlBlockPrmBegin(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint32 u32RecDataLen,
    pnio_ar_t **ar)
{
    e_uuid_t    ar_uuid;
    guint16     u16SessionKey;
    guint16     u16Command;
	proto_item *sub_item;
	proto_tree *sub_tree;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    if(u32RecDataLen != 28-2) /* must be 28 see specification (version already dissected) */
    {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block length of %u is invalid!", u32RecDataLen);
        return offset;
    }
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* ARUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, hf_pn_io_ar_uuid, &ar_uuid);

    *ar = pnio_ar_find_by_aruuid(pinfo, &ar_uuid);
    if(*ar == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "ControlBlockPrmBegin: AR information not found! (partial capture?)");
    }
    /* SessionKey */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_sessionkey, &u16SessionKey);

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* ControlCommand */
    sub_item = proto_tree_add_item(tree, hf_pn_io_control_command, tvb, offset, 2, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_command);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmend, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_applready, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_release, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_done, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_ready_for_companion, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_ready_for_rt_class3, &u16Command);
	/* Prm.Begin */
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmbegin, &u16Command);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_reserved_7_15, &u16Command);

    /* ControlBlockProperties.reserved */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_control_command_reserved, NULL);
    return offset;
}

/* dissect the SubmoduleListBlock  block */
static int
dissect_SubmoduleListBlock(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint32 u32RecDataLen _U_,
    pnio_ar_t **ar _U_)
{
    guint16     u16Entries;
    guint32     u32API;
    guint16     u16SlotNumber;
    guint16     u16SubSlotNumber;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_SubmoduleListEntries, &u16Entries);

    while (u16Entries --)
    {
        /*API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_api, &u32API);
        /*SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_slot_nr, &u16SlotNumber);
        /* SubSlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_subslot_nr, &u16SubSlotNumber);
    }
    return offset;
}


/* dissect the PDevData block */
static int
dissect_PDevData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* dissect the AdjustPreambleLength block */
static int
dissect_AdjustPreambleLength_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16AdjustProperties;
    guint16  u16PreambleLength;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* PreambleLength */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_PreambleLength, &u16PreambleLength);


    /* AdjustProperties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_adjust_properties, &u16AdjustProperties);

    return offset;
}

/* dissect the PDPortDataAdjust block */
static int
dissect_PDPortData_Adjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    tvbuff_t *new_tvb;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Slot:0x%x/0x%x", u16SlotNr, u16SubslotNr);

    u16BodyLength -= 6;

    new_tvb = tvb_new_subset(tvb, offset, u16BodyLength, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    /* XXX - do we have to free the new_tvb somehow? */

    return offset;
}


/* dissect the PDPortDataCheck blocks */
static int
dissect_PDPortData_Check_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    tvbuff_t *new_tvb;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Slot:0x%x/0x%x", u16SlotNr, u16SubslotNr);

    u16BodyLength -= 6;

    new_tvb = tvb_new_subset(tvb, offset, u16BodyLength, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    /* XXX - do we have to free the new_tvb somehow? */

    return offset;
}


/* dissect the PDPortDataReal blocks */
static int
dissect_PDPortDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint8 u8LengthOwnPortID;
    char *pOwnPortID;
    guint8 u8NumberOfPeers;
    guint8 u8I;
    guint8 u8LengthPeerPortID;
    char *pPeerPortID;
    guint8 u8LengthPeerChassisID;
    char *pPeerChassisID;
    guint32 u32LineDelay;
    guint8 mac[6];
    guint16 u16MAUType;
    guint32 u32DomainBoundary;
    guint32 u32MulticastBoundary;
    guint16 u16PortState;
    guint32 u32MediaType;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    /* LengthOwnPortID */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_length_own_port_id, &u8LengthOwnPortID);
    /* OwnPortID */
    pOwnPortID = ep_alloc(u8LengthOwnPortID+1);
    tvb_memcpy(tvb, (guint8 *) pOwnPortID, offset, u8LengthOwnPortID);
    pOwnPortID[u8LengthOwnPortID] = '\0';
    proto_tree_add_string (tree, hf_pn_io_own_port_id, tvb, offset, u8LengthOwnPortID, pOwnPortID);
    offset += u8LengthOwnPortID;

    /* NumberOfPeers */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    u8I = u8NumberOfPeers;
    while(u8I--) {
        /* LengthPeerPortID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_port_id, &u8LengthPeerPortID);
        /* PeerPortID */
        pPeerPortID = ep_alloc(u8LengthPeerPortID+1);
        tvb_memcpy(tvb, (guint8 *) pPeerPortID, offset, u8LengthPeerPortID);
        pPeerPortID[u8LengthPeerPortID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID, pPeerPortID);
        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        pPeerChassisID = ep_alloc(u8LengthPeerChassisID+1);
        tvb_memcpy(tvb, (guint8 *) pPeerChassisID, offset, u8LengthPeerChassisID);
        pPeerChassisID[u8LengthPeerChassisID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_chassis_id, tvb, offset, u8LengthPeerChassisID, pPeerChassisID);
        offset += u8LengthPeerChassisID;

        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        /* LineDelay */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_line_delay, &u32LineDelay);

        /* PeerMACAddress */
        offset = dissect_pn_mac(tvb, offset, pinfo, tree,
                            hf_pn_io_peer_macadd, mac);
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    }

    /* MAUType */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mau_type, &u16MAUType);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* DomainBoundary */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_domain_boundary, &u32DomainBoundary);
    /* MulticastBoundary */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_multicast_boundary, &u32MulticastBoundary);
    /* PortState */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_port_state, &u16PortState);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MediaType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_media_type, &u32MediaType);

    proto_item_append_text(item, ": Slot:0x%x/0x%x, OwnPortID:%s, Peers:%u PortState:%s MediaType:%s",
        u16SlotNr, u16SubslotNr, pOwnPortID, u8NumberOfPeers,
        val_to_str(u16PortState, pn_io_port_state, "0x%x"),
        val_to_str(u32MediaType, pn_io_media_type, "0x%x"));

    return offset;
}


static int
dissect_PDInterfaceMrpDataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    e_uuid_t uuid;
    guint16 u16Role;
    guint8 u8LengthDomainName;
    char *pDomainName;
    int iStartOffset = offset;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mrp_domain_uuid, &uuid);
    /* MRP_Role */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_role, &u16Role);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_LengthDomainName */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_length_domain_name, &u8LengthDomainName);
    /* MRP_DomainName */
    pDomainName = ep_alloc(u8LengthDomainName+1);
    tvb_memcpy(tvb, (guint8 *) pDomainName, offset, u8LengthDomainName);
    pDomainName[u8LengthDomainName] = '\0';
    proto_tree_add_string (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, pDomainName);
    offset += u8LengthDomainName;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    if((offset - iStartOffset) < u16BodyLength)
    {
        offset = dissect_blocks(tvb, offset, pinfo, tree, drep);
    }
    return offset;
}


static int
dissect_PDInterfaceMrpDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,guint16 u16BodyLength)
{
    e_uuid_t uuid;
    guint16 u16Role;
    guint16 u16Version;
    guint8 u8LengthDomainName;
    char *pDomainName;
    int endoffset = offset + u16BodyLength;

    /* added blockversion 1 */
    if(u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mrp_domain_uuid, &uuid);
    /* MRP_Role */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_role, &u16Role);

    if(u8BlockVersionLow == 1){
        /* MRP_Version */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_version, &u16Version);
    }
    /* MRP_LengthDomainName */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_length_domain_name, &u8LengthDomainName);
    /* MRP_DomainName */
    pDomainName = ep_alloc(u8LengthDomainName+1);
    tvb_memcpy(tvb, (guint8 *) pDomainName, offset, u8LengthDomainName);
    pDomainName[u8LengthDomainName] = '\0';
    proto_tree_add_string (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, pDomainName);
    offset += u8LengthDomainName;

    if(u8BlockVersionLow == 0){
        /* MRP_Version */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_version, &u16Version);
    }
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    while(endoffset < offset)
    {
        offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
    }
    return offset;
}


static int
dissect_PDInterfaceMrpDataCheck_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_uuid_t uuid;
    guint16 u16Check;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mrp_domain_uuid, &uuid);

    /* MRP_Check */
    /* XXX - this field is 32bit in the spec but 16 bit in the implementation */
    /* this will be fixed in the next implementation release */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_check, &u16Check);

    return offset;
}


static int
dissect_PDPortMrpData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_uuid_t uuid;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mrp_domain_uuid, &uuid);
    return offset;
}


static int
dissect_MrpManagerParams_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16Prio;
    guint16 u16TOPchgT;
    guint16 u16TOPNRmax;
    guint16 u16TSTshortT;
    guint16 u16TSTdefaultT;
    guint16 u16TSTNRmax;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MRP_Prio */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_prio, &u16Prio);
    /* MRP_TOPchgT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_topchgt, &u16TOPchgT);
    /* MRP_TOPNRmax */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_topnrmax, &u16TOPNRmax);
    /* MRP_TSTshortT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_tstshortt, &u16TSTshortT);
    /* MRP_TSTdefaultT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_tstdefaultt, &u16TSTdefaultT);
    /* MSP_TSTNRmax */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_tstnrmax, &u16TSTNRmax);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    return offset;
}


static int
dissect_MrpRTMode(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32RTMode;


    /* MRP_RTMode */
    sub_item = proto_tree_add_item(tree, hf_pn_io_mrp_rtmode, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_mrp_rtmode);

    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_mrp_rtmode_reserved2, &u32RTMode);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_mrp_rtmode_reserved1, &u32RTMode);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_mrp_rtmode_rtclass3, &u32RTMode);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_mrp_rtmode_rtclass12, &u32RTMode);

    return offset;
}


static int
dissect_MrpRTModeManagerData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16TSTNRmax;
    guint16 u16TSTdefaultT;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MSP_TSTNRmax */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_tstnrmax, &u16TSTNRmax);
    /* MRP_TSTdefaultT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_tstdefaultt, &u16TSTdefaultT);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_RTMode */
    offset = dissect_MrpRTMode(tvb, offset, pinfo, tree, item, drep);

    return offset;
}


static int
dissect_MrpRingStateData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16RingState;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MRP_RingState */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_ring_state, &u16RingState);

    return offset;
}


static int
dissect_MrpRTStateData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16RTState;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MRP_RTState */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_rt_state, &u16RTState);

    return offset;
}


static int
dissect_MrpClientParams_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MRP_LNKdownT;
    guint16 u16MRP_LNKupT;
    guint16 u16MRP_LNKNRmax;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MRP_LNKdownT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_lnkdownt, &u16MRP_LNKdownT);
    /* MRP_LNKupT */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_lnkupt, &u16MRP_LNKupT);
    /* MRP_LNKNRmax u16 */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_lnknrmax, &u16MRP_LNKNRmax);

    return offset;
}


static int
dissect_MrpRTModeClientData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MRP_RTMode */
    offset = dissect_MrpRTMode(tvb, offset, pinfo, tree, item, drep);

    return offset;
}


static int
dissect_CheckSyncDifference_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16 u16CheckSyncMode;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    sub_item = proto_tree_add_item(tree, hf_pn_io_check_sync_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_check_sync_mode);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_check_sync_mode_reserved, &u16CheckSyncMode);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_check_sync_mode_sync_master, &u16CheckSyncMode);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_check_sync_mode_cable_delay, &u16CheckSyncMode);


    proto_item_append_text(sub_item, "CheckSyncMode: SyncMaster:%d, CableDelay:%d",
        (u16CheckSyncMode & 0x2) && 1, (u16CheckSyncMode & 0x1) && 1);

    proto_item_append_text(item, " : SyncMaster:%d, CableDelay:%d",
        (u16CheckSyncMode >> 1) & 1, u16CheckSyncMode & 1);

    return offset;
}


static int
dissect_CheckMAUTypeDifference_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MAUTypeMode;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mau_type_mode, &u16MAUTypeMode);

    proto_item_append_text(item, ": MAUTypeMode:%s",
        val_to_str(u16MAUTypeMode, pn_io_mau_type_mode, "0x%x"));

    return offset;
}


/* dissect the AdjustDomainBoundary blocks */
static int
dissect_AdjustDomainBoundary_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32DomainBoundary;
    guint32 u32DomainBoundaryIngress;
    guint32 u32DomainBoundaryEgress;
    guint16 u16AdjustProperties;


    if(u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    switch(u8BlockVersionLow) {
        case(0):
        /* DomainBoundary */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_domain_boundary, &u32DomainBoundary);
        /* AdjustProperties */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_adjust_properties, &u16AdjustProperties);
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        proto_item_append_text(item, ": Boundary:0x%x, Properties:0x%x",
            u32DomainBoundary, u16AdjustProperties);

        break;
        case(1):
        /* DomainBoundaryIngress */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_domain_boundary_ingress, &u32DomainBoundaryIngress);
        /* DomainBoundaryEgress */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_domain_boundary_egress, &u32DomainBoundaryEgress);
        /* AdjustProperties */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_adjust_properties, &u16AdjustProperties);
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        proto_item_append_text(item, ": BoundaryIngress:0x%x, BoundaryEgress:0x%x, Properties:0x%x",
            u32DomainBoundaryIngress, u32DomainBoundaryEgress, u16AdjustProperties);

        break;
        default:
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    return offset;
}


/* dissect the AdjustMulticastBoundary blocks */
static int
dissect_AdjustMulticastBoundary_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32MulticastBoundary;
    guint16 u16AdjustProperties;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* Boundary */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_multicast_boundary, &u32MulticastBoundary);
    /* AdjustProperties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_adjust_properties, &u16AdjustProperties);

    proto_item_append_text(item, ": Boundary:0x%x, Properties:0x%x",
        u32MulticastBoundary, u16AdjustProperties);

    return offset;
}


/* dissect the AdjustMAUType block */
static int
dissect_AdjustMAUType_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MAUType;
    guint16 u16AdjustProperties;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MAUType */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mau_type, &u16MAUType);
    /* AdjustProperties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_adjust_properties, &u16AdjustProperties);

    proto_item_append_text(item, ": MAUType:%s, Properties:0x%x",
        val_to_str(u16MAUType, pn_io_mau_type, "0x%x"),
        u16AdjustProperties);

    return offset;
}


/* dissect the CheckMAUType block */
static int
dissect_CheckMAUType_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MAUType;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MAUType */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mau_type, &u16MAUType);

    proto_item_append_text(item, ": MAUType:%s",
        val_to_str(u16MAUType, pn_io_mau_type, "0x%x"));

    return offset;
}


/* dissect the CheckLineDelay block */
static int
dissect_CheckLineDelay_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32LineDelay;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* LineDelay */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_line_delay, &u32LineDelay);

    proto_item_append_text(item, ": LineDelay:%uns", u32LineDelay);

    return offset;
}


/* dissect the CheckPeers block */
static int
dissect_CheckPeers_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8 u8NumberOfPeers;
    guint8 u8I;
    guint8 u8LengthPeerPortID;
    char *pPeerPortID;
    guint8 u8LengthPeerChassisID;
    char *pPeerChassisID;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfPeers */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);

    u8I = u8NumberOfPeers;
    while(u8I--) {
        /* LengthPeerPortID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_port_id, &u8LengthPeerPortID);
        /* PeerPortID */
        pPeerPortID = ep_alloc(u8LengthPeerPortID+1);
        tvb_memcpy(tvb, (guint8 *) pPeerPortID, offset, u8LengthPeerPortID);
        pPeerPortID[u8LengthPeerPortID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID, pPeerPortID);
        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        pPeerChassisID = ep_alloc(u8LengthPeerChassisID+1);
        tvb_memcpy(tvb, (guint8 *) pPeerChassisID, offset, u8LengthPeerChassisID);
        pPeerChassisID[u8LengthPeerChassisID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_chassis_id, tvb, offset, u8LengthPeerChassisID, pPeerChassisID);
        offset += u8LengthPeerChassisID;
    }

    proto_item_append_text(item, ": NumberOfPeers:%u", u8NumberOfPeers);

    return offset;
}


/* dissect the AdjustPortState block */
static int
dissect_AdjustPortState_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16PortState;
    guint16 u16AdjustProperties;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* PortState */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_port_state, &u16PortState);
    /* AdjustProperties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_adjust_properties, &u16AdjustProperties);

    proto_item_append_text(item, ": PortState:%s, Properties:0x%x",
        val_to_str(u16PortState, pn_io_port_state, "0x%x"),
        u16AdjustProperties);

    return offset;
}


/* dissect the CheckPortState block */
static int
dissect_CheckPortState_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16PortState;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* PortState */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_port_state, &u16PortState);

    proto_item_append_text(item, ": %s",
        val_to_str(u16PortState, pn_io_port_state, "0x%x"));
    return offset;
}


/* dissect the PDPortFODataReal block */
static int
dissect_PDPortFODataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint32 u32FiberOpticType;
    guint32 u32FiberOpticCableType;
    guint16 u16Index;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* FiberOpticType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fiber_optic_type, &u32FiberOpticType);

    /* FiberOpticCableType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fiber_optic_cable_type, &u32FiberOpticCableType);

    /* optional: FiberOpticManufacturerSpecific */
    if(u16BodyLength != 10) {
        dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
    }

    return offset;
}


/* dissect the FiberOpticManufacturerSpecific block */
static int
dissect_FiberOpticManufacturerSpecific_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint8 u8VendorIDHigh;
    guint8 u8VendorIDLow;
    guint16 u16VendorBlockType;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* x8 VendorIDHigh */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_high, &u8VendorIDHigh);
    /* x8 VendorIDLow */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_low, &u8VendorIDLow);

    /* VendorBlockType */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_block_type, &u16VendorBlockType);
    /* Data */
    offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16BodyLength-4, "Data");

    return offset;
}


/* dissect the PDPortFODataAdjust block */
static int
dissect_PDPortFODataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FiberOpticType;
    guint32 u32FiberOpticCableType;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* FiberOpticType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fiber_optic_type, &u32FiberOpticType);

    /* FiberOpticCableType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fiber_optic_cable_type, &u32FiberOpticCableType);

/*
    proto_item_append_text(item, ": %s",
        val_to_str(u16PortState, pn_io_port_state, "0x%x"));*/

    return offset;
}


/* dissect the PDPortFODataCheck block */
static int
dissect_PDPortFODataCheck_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FiberOpticPowerBudget;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MaintenanceRequiredPowerBudget */
    /* XXX - decode the u32FiberOpticPowerBudget better */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maintenance_required_power_budget, &u32FiberOpticPowerBudget);

    /* MaintenanceDemandedPowerBudget */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maintenance_demanded_power_budget, &u32FiberOpticPowerBudget);

    /* ErrorPowerBudget */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_error_power_budget, &u32FiberOpticPowerBudget);

/*
    proto_item_append_text(item, ": %s",
        val_to_str(u16PortState, pn_io_port_state, "0x%x"));*/

    return offset;
}

#if 0
/* dissect the PDNCDataCheck block */
static int
dissect_PDNCDataCheck_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32NCDropBudget;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MaintenanceRequiredDropBudget */
    /* XXX - decode the u32NCDropBudget better */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maintenance_required_drop_budget, &u32NCDropBudget);

    /* MaintenanceDemandedDropBudget */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maintenance_demanded_drop_budget, &u32NCDropBudget);

    /* ErrorDropBudget */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_error_drop_budget, &u32NCDropBudget);

/*
    proto_item_append_text(item, ": %s",
        val_to_str(u16PortState, pn_io_port_state, "0x%x"));*/

    return offset;
}
#endif

/* PDPortStatistic for one subslot */
static int
dissect_PDPortStatistic_block(tvbuff_t *tvb, int offset,
 packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32     u32StatValue;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifInOctets, &u32StatValue);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifOutOctets, &u32StatValue);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifInDiscards, &u32StatValue);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifOutDiscards, &u32StatValue);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifInErrors, &u32StatValue);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_pdportstatistic_ifOutErrors, &u32StatValue);

    return offset;
}


/* dissect the PDInterfaceDataReal block */
static int
dissect_PDInterfaceDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8 u8LengthOwnChassisID;
    char *pOwnChassisID;
    guint8 mac[6];
    guint32 ip;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* LengthOwnChassisID */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_length_own_chassis_id, &u8LengthOwnChassisID);
    /* OwnChassisID */
    pOwnChassisID = ep_alloc(u8LengthOwnChassisID+1);
    tvb_memcpy(tvb, (guint8 *) pOwnChassisID, offset, u8LengthOwnChassisID);
    pOwnChassisID[u8LengthOwnChassisID] = '\0';
    proto_tree_add_string (tree, hf_pn_io_own_chassis_id, tvb, offset, u8LengthOwnChassisID, pOwnChassisID);
    offset += u8LengthOwnChassisID;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MACAddressValue */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_io_macadd, mac);

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* IPAddress */
    offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_io_ip_address, &ip);
    /*proto_item_append_text(block_item, ", IP: %s", ip_to_str((guint8*)&ip));*/

    /* Subnetmask */
    offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_io_subnetmask, &ip);
    /*proto_item_append_text(block_item, ", Subnet: %s", ip_to_str((guint8*)&ip));*/

    /* StandardGateway */
    offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_io_standard_gateway, &ip);
    /*proto_item_append_text(block_item, ", Router: %s", ip_to_str((guint8*)&ip));*/


    return offset;
}


/* dissect the PDSyncData block */
static int
dissect_PDSyncData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    e_uuid_t uuid;
    guint32 u32ReservedIntervalBegin;
    guint32 u32ReservedIntervalEnd;
    guint32 u32PLLWindow;
    guint32 u32SyncSendFactor;
    guint16 u16SendClockFactor;
    guint16 u16SyncProperties;
    guint16 u16SyncFrameAddress;
    guint16 u16PTCPTimeoutFactor;
    guint16 u16PTCPTakeoverTimeoutFactor;
    guint16 u16PTCPMasterStartupTime;
    guint8 u8MasterPriority1;
    guint8 u8MasterPriority2;
    guint8 u8LengthSubdomainName;
    char *pSubdomainName;


    if(u8BlockVersionHigh != 1) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    switch(u8BlockVersionLow) {
    case(0):
        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_slot_nr, &u16SlotNr);
        /* Subslotnumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_subslot_nr, &u16SubslotNr);
        /* PTCPSubdomainID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_subdomain_id, &uuid);
        /* IRDataID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ir_data_id, &uuid);
        /* ReservedIntervalBegin */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_reserved_interval_begin, &u32ReservedIntervalBegin);
        /* ReservedIntervalEnd */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_reserved_interval_end, &u32ReservedIntervalEnd);
        /* PLLWindow enum */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_pllwindow, &u32PLLWindow);
        /* SyncSendFactor 32 enum */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_sync_send_factor, &u32SyncSendFactor);
        /* SendClockFactor 16 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_send_clock_factor, &u16SendClockFactor);
        /* SyncProperties 16 bitfield */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_sync_properties, &u16SyncProperties);
        /* SyncFrameAddress 16 bitfield */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_sync_frame_address, &u16SyncFrameAddress);
        /* PTCPTimeoutFactor 16 enum */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_timeout_factor, &u16PTCPTimeoutFactor);

        proto_item_append_text(item, ": Slot:0x%x/0x%x, Interval:%u-%u, PLLWin:%u, Send:%u, Clock:%u",
            u16SlotNr, u16SubslotNr, u32ReservedIntervalBegin, u32ReservedIntervalEnd,
            u32PLLWindow, u32SyncSendFactor, u16SendClockFactor);
        break;
    case(2):
        /* PTCPSubdomainID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_subdomain_id, &uuid);
        /* ReservedIntervalBegin */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_reserved_interval_begin, &u32ReservedIntervalBegin);
        /* ReservedIntervalEnd */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_reserved_interval_end, &u32ReservedIntervalEnd);
        /* PLLWindow enum */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_pllwindow, &u32PLLWindow);
        /* SyncSendFactor 32 enum */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_sync_send_factor, &u32SyncSendFactor);
        /* SendClockFactor 16 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_send_clock_factor, &u16SendClockFactor);
        /* PTCPTimeoutFactor 16 enum */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_timeout_factor, &u16PTCPTimeoutFactor);
        /* PTCPTakeoverTimeoutFactor 16 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_takeover_timeout_factor, &u16PTCPTakeoverTimeoutFactor);
        /* PTCPMasterStartupTime 16 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_master_startup_time, &u16PTCPMasterStartupTime);
        /* SyncProperties 16 bitfield */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_sync_properties, &u16SyncProperties);
        /* PTCP_MasterPriority1 */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_master_priority_1, &u8MasterPriority1);
        /* PTCP_MasterPriority2 */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_master_priority_2, &u8MasterPriority2);
        /* PTCPLengthSubdomainName */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_ptcp_length_subdomain_name, &u8LengthSubdomainName);
        /* PTCPSubdomainName */
        pSubdomainName = ep_alloc(u8LengthSubdomainName+1);
        tvb_memcpy(tvb, (guint8 *) pSubdomainName, offset, u8LengthSubdomainName);
        pSubdomainName[u8LengthSubdomainName] = '\0';
        proto_tree_add_string (tree, hf_pn_io_ptcp_subdomain_name, tvb, offset, u8LengthSubdomainName, pSubdomainName);
        offset += u8LengthSubdomainName;

        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        proto_item_append_text(item, ": Interval:%u-%u, PLLWin:%u, Send:%u, Clock:%u",
            u32ReservedIntervalBegin, u32ReservedIntervalEnd,
            u32PLLWindow, u32SyncSendFactor, u16SendClockFactor);
        break;
    default:
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
    }

    return offset;
}


/* dissect the PDIRData block */
static int
dissect_PDIRData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16Index;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;

    /* versions decoded are High: 1 and LOW 0..2 */
    if(u8BlockVersionHigh != 1 || (u8BlockVersionLow > 2 ) ) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Slot:0x%x/0x%x",
        u16SlotNr, u16SubslotNr);

    /* PDIRGlobalData */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
    if(u8BlockVersionLow == 0) {
        /* PDIRFrameData */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
    } else if (u8BlockVersionLow == 1) {
        /* [PDIRFrameData] */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        /* PDIRBeginEndData */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
    }else if (u8BlockVersionLow == 2) {
        /* [PDIRFrameData] */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        /* PDIRBeginEndData */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
    }
    return offset;
}


/* dissect the PDIRGlobalData block */
static int
dissect_PDIRGlobalData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_uuid_t uuid;
    guint32 u32MaxBridgeDelay;
    guint32 u32NumberOfPorts;
    guint32 u32MaxPortTxDelay;
    guint32 u32MaxPortRxDelay;
    guint32 u32MaxLineRxDelay;
    guint32 u32YellowTime;
    guint32 u32Tmp;

    /* added blockversion 2 */
    if(u8BlockVersionHigh != 1 || (u8BlockVersionLow > 2)) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* IRDataID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ir_data_id, &uuid);

    if(u8BlockVersionLow <= 2) {
        /* MaxBridgeDelay */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                     hf_pn_io_max_bridge_delay, &u32MaxBridgeDelay);
        /* NumberOfPorts */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                     hf_pn_io_number_of_ports, &u32NumberOfPorts);
        u32Tmp = u32NumberOfPorts;

        while(u32Tmp--) {
            /* MaxPortTxDelay */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                         hf_pn_io_max_port_tx_delay, &u32MaxPortTxDelay);
            /* MaxPortRxDelay */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                         hf_pn_io_max_port_rx_delay, &u32MaxPortRxDelay);
            if (u8BlockVersionLow >= 2){
                /* MaxLineRxDelay */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_max_line_rx_delay, &u32MaxLineRxDelay);
                /* YellowTime */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_yellowtime, &u32YellowTime);
            }
        }
        proto_item_append_text(item, ": MaxBridgeDelay:%u, NumberOfPorts:%u",
                             u32MaxBridgeDelay, u32NumberOfPorts);

    }
    return offset;
}


/* dissect the PDIRFrameData block */
static int
dissect_PDIRFrameData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint32 u32FrameSendOffset;
    guint32 u32FrameDataProperties;
    guint16 u16DataLength;
    guint16 u16ReductionRatio;
    guint16 u16Phase;
    guint16 u16FrameID;
    guint16 u16Ethertype;
    guint8 u8RXPort;
    guint8 u8FrameDetails;
    guint8 u8NumberOfTxPortGroups;
    guint8 u8TxPortGroupArray;
    guint16 u16TxPortGroupArraySize;
    guint16 u16EndOffset;
    proto_tree *ir_frame_data_tree = NULL;
    proto_item *ir_frame_data_sub_item = NULL;
    guint16 n=0;
    proto_item *sub_item;
    proto_tree *sub_tree;

    /* added low version 1 */
    if(u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    u16EndOffset = offset + u16BodyLength -2;
    if(u8BlockVersionLow > 0){
        /* for low version 1 FrameDataProperties is added */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_frame_data_tree, drep,
            hf_pn_io_frame_data_properties, &u32FrameDataProperties);
    }
    /* dissect all IR frame data */
    while (offset < u16EndOffset)
    {
      n++;

     /* new subtree for each IR frame */
      ir_frame_data_sub_item = proto_tree_add_item(tree, hf_pn_io_ir_frame_data, tvb, offset, 17, ENC_NA);
      ir_frame_data_tree = proto_item_add_subtree(ir_frame_data_sub_item, ett_pn_io_ir_frame_data);

      /* FrameSendOffset */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_frame_send_offset, &u32FrameSendOffset);
      /* DataLength */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_data_length, &u16DataLength);
      /* ReductionRatio */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_reduction_ratio, &u16ReductionRatio);
      /* Phase */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_phase, &u16Phase);
      /* FrameID */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_frame_id, &u16FrameID);

      /* Ethertype */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                     hf_pn_io_ethertype, &u16Ethertype);
      /* RxPort */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                    hf_pn_io_rx_port, &u8RXPort);
      /* FrameDetails */
        sub_item = proto_tree_add_item(ir_frame_data_tree, hf_pn_io_frame_details, tvb, offset, 1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_frame_defails);
        dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_frame_details_sync_frame, &u8FrameDetails);
        dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_frame_details_meaning_frame_send_offset, &u8FrameDetails);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_frame_details_reserved, &u8FrameDetails);
      /* TxPortGroup */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, ir_frame_data_tree, drep,
                                    hf_pn_io_nr_of_tx_port_groups, &u8NumberOfTxPortGroups);
        if((u8NumberOfTxPortGroups > 21) || ((u8NumberOfTxPortGroups & 0x1) !=1)){
            proto_tree_add_text(ir_frame_data_tree, tvb, offset -1, 1, "Not allowed value of NumberOfTxPortGroups");
        }

      /* TxPortArray */
        u16TxPortGroupArraySize =  (u8NumberOfTxPortGroups + 7 / 8);
        sub_item = proto_tree_add_item(ir_frame_data_tree, hf_pn_io_TxPortGroupProperties, tvb, offset, u16TxPortGroupArraySize, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_GroupProperties);
        while(u16TxPortGroupArraySize > 0)
        {
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit0, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit1, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit2, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit3, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit4, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit5, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit6, &u8TxPortGroupArray);
            dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_TxPortGroupProperties_bit7, &u8TxPortGroupArray);

            offset+=1;
            u16TxPortGroupArraySize --;
        }

      /* align to next dataset */
      offset = dissect_pn_align4(tvb, offset, pinfo, ir_frame_data_tree);

      proto_item_append_text(ir_frame_data_tree, ": Offset:%u, Len:%u, Ratio:%u, Phase:%u, FrameID:0x%04x",
                             u32FrameSendOffset, u16DataLength, u16ReductionRatio, u16Phase, u16FrameID);

    }

    proto_item_append_text(item, ": Frames:%u", n);

    return offset;
}


static int
dissect_PDIRBeginEndData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16 u16StartOfRedFrameID;
    guint16 u16EndOfRedFrameID;
    guint32 u32NumberOfPorts;
    guint32 u32NumberOfAssignments;
    guint32 u32NumberOfPhases;
    guint32 u32RedOrangePeriodBegin;
    guint32 u32OrangePeriodBegin;
    guint32 u32GreenPeriodBegin;
    guint16 u16TXPhaseAssignment;
    guint16 u16RXPhaseAssignment;
    proto_tree *ir_begin_end_port_tree = NULL;
    proto_item *ir_begin_end_port_sub_item = NULL;
    guint32 u32SubStart;
    guint32 u32Tmp;
    guint32 u32Tmp2;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_start_of_red_frame_id, &u16StartOfRedFrameID);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_end_of_red_frame_id, &u16EndOfRedFrameID);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_ports, &u32NumberOfPorts);
    u32Tmp2 = u32NumberOfPorts;
    while(u32Tmp2--) {
        /* new subtree for each Port */
        ir_begin_end_port_sub_item = proto_tree_add_item(tree, hf_pn_io_ir_begin_end_port, tvb, offset, 0, ENC_NA);
        ir_begin_end_port_tree = proto_item_add_subtree(ir_begin_end_port_sub_item, ett_pn_io_ir_begin_end_port);
        u32SubStart = offset;

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_number_of_assignments, &u32NumberOfAssignments);
        u32Tmp = u32NumberOfAssignments;
        while(u32Tmp--) {
            /* TXBeginEndAssignment */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_red_orange_period_begin, &u32RedOrangePeriodBegin);
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_orange_period_begin, &u32OrangePeriodBegin);
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_green_period_begin, &u32GreenPeriodBegin);

            /* RXBeginEndAssignment */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_red_orange_period_begin, &u32RedOrangePeriodBegin);
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_orange_period_begin, &u32OrangePeriodBegin);
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                hf_pn_io_green_period_begin, &u32GreenPeriodBegin);
        }

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_number_of_phases, &u32NumberOfPhases);
        u32Tmp = u32NumberOfPhases;
        while(u32Tmp--) {
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_tx_phase_assignment, &u16TXPhaseAssignment);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_rx_phase_assignment, &u16RXPhaseAssignment);
        }

        proto_item_append_text(ir_begin_end_port_sub_item, ": Assignments:%u, Phases:%u",
            u32NumberOfAssignments, u32NumberOfPhases);

        proto_item_set_len(ir_begin_end_port_sub_item, offset - u32SubStart);
    }

    proto_item_append_text(item, ": StartOfRed: 0x%x, EndOfRed: 0x%x, Ports:%u",
        u16StartOfRedFrameID, u16EndOfRedFrameID, u32NumberOfPorts);

    return offset+u16BodyLength;
}


/* dissect the DiagnosisData block */
static int
dissect_DiagnosisData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 body_length)
{
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16ChannelNumber;
    guint16 u16UserStructureIdentifier;


    if(u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if(u8BlockVersionLow == 1) {
        /* API */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
        body_length-=4;
    }

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_subslot_nr, &u16SubslotNr);
    /* ChannelNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_channel_number, &u16ChannelNumber);
    /* ChannelProperties */
    offset = dissect_ChannelProperties(tvb, offset, pinfo, tree, item, drep);
    body_length-=8;

    /* UserStructureIdentifier */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_user_structure_identifier, &u16UserStructureIdentifier);
    proto_item_append_text(item, ", USI:0x%x", u16UserStructureIdentifier);
    body_length-=2;

    /* the rest of the block contains optional: [MaintenanceItem] and/or [AlarmItem] */
    while(body_length) {
        offset = dissect_AlarmUserStructure(tvb, offset, pinfo, tree, item, drep,
            &body_length, u16UserStructureIdentifier);
    }

    return offset;
}


static int
dissect_ARProperties(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
        guint32 u32ARProperties;


    sub_item = proto_tree_add_item(tree, hf_pn_io_ar_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_ar_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_pull_module_alarm_allowed, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_arproperties_StartupMode, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_reserved, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_achnowledge_companion_ar, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_companion_ar, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_device_access, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_reserved_1, &u32ARProperties);
/* removed within 2.3
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_data_rate, &u32ARProperties);
*/
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_parametrization_server, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_supervisor_takeover_allowed, &u32ARProperties);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_state, &u32ARProperties);

    return offset;
}


/* dissect the IOCRProperties */
static int
dissect_IOCRProperties(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32IOCRProperties;

    sub_item = proto_tree_add_item(tree, hf_pn_io_iocr_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_iocr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_full_subframe_structure, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_distributed_subframe_watchdog, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_fast_forwarding_mac_adr, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_reserved_3, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_reserved_2, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_media_redundancy, &u32IOCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_reserved_1, &u32IOCRProperties);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_iocr_properties_rtclass, &u32IOCRProperties);

    return offset;
}


/* dissect the ARData block */
static int
dissect_ARData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BlockLength)
{
    guint16 u16NumberOfARs;
    guint16 u16NumberofEntries;
    e_uuid_t aruuid;
    e_uuid_t uuid;
    guint16 u16ARType;
    char *pStationName;
    guint16 u16NameLength;
    guint16 u16NumberOfIOCRs;
    guint16 u16IOCRType;
    guint16 u16FrameID;
    guint16 u16CycleCounter;
    guint8  u8DataStatus;
    guint8  u8TransferStatus;
    proto_item *ds_item;
    proto_tree *ds_tree;
    guint16 u16UDPRTPort;
    guint16 u16AlarmCRType;
    guint16 u16LocalAlarmReference;
    guint16 u16RemoteAlarmReference;
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    proto_item *iocr_item;
    proto_tree *iocr_tree;
	proto_item *ar_item;
    proto_tree *ar_tree;
    guint32 u32IOCRStart;
    gint32  i32EndOffset;
	guint32 u32ARDataStart;

    /* added BlockversionLow == 1  */
    if(u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    i32EndOffset = offset + u16BlockLength;
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_ars, &u16NumberOfARs);
    /* BlockversionLow:  0 */
    if(u8BlockVersionLow == 0){
    while(u16NumberOfARs--) {
			ar_item = proto_tree_add_item(tree, hf_pn_io_ar_data, tvb, offset, 0, ENC_BIG_ENDIAN);
			ar_tree = proto_item_add_subtree(ar_item, ett_pn_io_ar_data);
			u32ARDataStart = offset;
			offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep,
                            hf_pn_io_ar_uuid, &aruuid);
			proto_item_append_text(ar_item,"ARUUID:%s",guid_to_str((const e_guid_t*) &aruuid));
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_ar_type, &u16ARType);
			offset = dissect_ARProperties(tvb, offset, pinfo, ar_tree, item, drep);
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep,
                         hf_pn_io_cminitiator_objectuuid, &uuid);
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);
        pStationName = ep_alloc(u16NameLength+1);
        tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
        pStationName[u16NameLength] = '\0';
			proto_tree_add_string (ar_tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pStationName);
        offset += u16NameLength;

			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_number_of_iocrs, &u16NumberOfIOCRs);

        while(u16NumberOfIOCRs--) {
            iocr_item = proto_tree_add_item(ar_tree, hf_pn_io_iocr_tree, tvb, offset, 0, ENC_NA);
            iocr_tree = proto_item_add_subtree(iocr_item, ett_pn_io_iocr);
            u32IOCRStart = offset;

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                            hf_pn_io_iocr_type, &u16IOCRType);
            offset = dissect_IOCRProperties(tvb, offset, pinfo, iocr_tree, drep);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                            hf_pn_io_frame_id, &u16FrameID);

            proto_item_append_text(iocr_item, ": FrameID:0x%x", u16FrameID);

            /* add cycle counter */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                            hf_pn_io_cycle_counter, &u16CycleCounter);

        u8DataStatus = tvb_get_guint8(tvb, offset);
        u8TransferStatus = tvb_get_guint8(tvb, offset+1);

            /* add data status subtree */
            ds_item = proto_tree_add_uint_format(iocr_tree, hf_pn_io_data_status,
                tvb, offset, 1, u8DataStatus,
                "DataStatus: 0x%02x (Frame: %s and %s, Provider: %s and %s)",
                u8DataStatus,
                (u8DataStatus & 0x04) ? "Valid" : "Invalid",
                (u8DataStatus & 0x01) ? "Primary" : "Backup",
                (u8DataStatus & 0x20) ? "Ok" : "Problem",
                (u8DataStatus & 0x10) ? "Run" : "Stop");
            ds_tree = proto_item_add_subtree(ds_item, ett_pn_io_data_status);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res67, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_ok, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_operate, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res3, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_valid, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res1, tvb, offset, 1, u8DataStatus);
            proto_tree_add_uint(ds_tree, hf_pn_io_data_status_primary, tvb, offset, 1, u8DataStatus);

            offset++;

            /* add transfer status */
            if (u8TransferStatus) {
                proto_tree_add_uint_format(iocr_tree, hf_pn_io_transfer_status, tvb,
                offset, 1, u8TransferStatus,
                "TransferStatus: 0x%02x (ignore this frame)", u8TransferStatus);
            } else {
                proto_tree_add_uint_format(iocr_tree, hf_pn_io_transfer_status, tvb,
                offset, 1, u8TransferStatus,
                "TransferStatus: 0x%02x (OK)", u8TransferStatus);
            }

            offset++;

            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                            hf_pn_io_cminitiator_udprtport, &u16UDPRTPort);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                            hf_pn_io_cmresponder_udprtport, &u16UDPRTPort);

            proto_item_set_len(iocr_item, offset - u32IOCRStart);
        }

        /* AlarmCRType */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
        /* LocalAlarmReference */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
        /* RemoteAlarmReference */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_remotealarmref, &u16RemoteAlarmReference);
        /* ParameterServerObjectUUID */
			offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep,
                            hf_pn_io_parameter_server_objectuuid, &uuid);
        /* StationNameLength */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);
        /* ParameterServerStationName */
        pStationName = ep_alloc(u16NameLength+1);
        tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
        pStationName[u16NameLength] = '\0';
			proto_tree_add_string (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, pStationName);
        offset += u16NameLength;
        /* NumberOfAPIs */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);
        /* API */
        if (u16NumberOfAPIs > 0){
				offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ar_tree, drep,
                hf_pn_io_api, &u32Api);
            }
			proto_item_set_len(ar_item, offset - u32ARDataStart);
        }
    }
    else
    {    /* BlockversionLow == 1 */
        while(u16NumberOfARs--) {
			ar_item = proto_tree_add_item(tree, hf_pn_io_ar_data, tvb, offset, 0, ENC_NA);
			ar_tree = proto_item_add_subtree(ar_item, ett_pn_io_ar_data);
			u32ARDataStart = offset;
            /*ARUUID */
			offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_ar_uuid, &aruuid);
			proto_item_append_text(ar_item,"ARUUID:%s",guid_to_str((const e_guid_t*) &aruuid));
            /* CMInitiatorObjectUUID */
			offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_cminitiator_objectuuid, &uuid);
            /* ParameterServerObjectUUID */
			offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_parameter_server_objectuuid, &uuid);
            /* ARProperties*/
			offset = dissect_ARProperties(tvb, offset, pinfo, ar_tree, item, drep);
            /* ARType*/
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_ar_type, &u16ARType);
            /* AlarmCRType */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_alarmcr_type, &u16AlarmCRType);
            /* LocalAlarmReference */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_localalarmref, &u16LocalAlarmReference);
            /* RemoteAlarmReference */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_remotealarmref, &u16RemoteAlarmReference);
            /* InitiatorUDPRTPort*/
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_cminitiator_udprtport, &u16UDPRTPort);
            /* ResponderUDPRTPort*/
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_cmresponder_udprtport, &u16UDPRTPort);
            /* CMInitiatorStationName*/
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_station_name_length, &u16NameLength);
            pStationName = ep_alloc(u16NameLength+1);
            tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
            pStationName[u16NameLength] = '\0';
			proto_tree_add_string (ar_tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pStationName);
            offset += u16NameLength;
            /** align padding! **/
			offset = dissect_pn_align4(tvb, offset, pinfo, ar_tree);

            /* StationNameLength */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_station_name_length, &u16NameLength);
            if(u16NameLength != 0){
                /* ParameterServerStationName */
                pStationName = ep_alloc(u16NameLength+1);
                tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
                pStationName[u16NameLength] = '\0';
				proto_tree_add_string (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, pStationName);
                offset += u16NameLength;
            }
			else
			{ /* display no name present */
				proto_tree_add_string (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, " <no ParameterServerStationName present>");
			}
            /** align padding! **/
			offset = dissect_pn_align4(tvb, offset, pinfo, ar_tree);

            /* NumberOfIOCRs*/
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,hf_pn_io_number_of_iocrs, &u16NumberOfIOCRs);
            /* align to next 32 bit */
			offset = dissect_pn_padding(tvb, offset, pinfo, ar_tree, 2);

            while(u16NumberOfIOCRs--) {
                iocr_item = proto_tree_add_item(ar_tree, hf_pn_io_iocr_tree, tvb, offset, 0, ENC_NA);
                iocr_tree = proto_item_add_subtree(iocr_item, ett_pn_io_iocr);
                u32IOCRStart = offset;

                /* IOCRProperties*/
                offset = dissect_IOCRProperties(tvb, offset, pinfo, iocr_tree, drep);
                /* IOCRType*/
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep, hf_pn_io_iocr_type, &u16IOCRType);
                /* FrameID*/
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep, hf_pn_io_frame_id, &u16FrameID);
                proto_item_append_text(iocr_item, ": FrameID:0x%x", u16FrameID);

                /* add cycle counter */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, iocr_tree, drep,
                    hf_pn_io_cycle_counter, &u16CycleCounter);

                u8DataStatus = tvb_get_guint8(tvb, offset);
                u8TransferStatus = tvb_get_guint8(tvb, offset+1);

                /* add data status subtree */
                ds_item = proto_tree_add_uint_format(iocr_tree, hf_pn_io_data_status,
                    tvb, offset, 1, u8DataStatus,
                    "DataStatus: 0x%02x (Frame: %s and %s, Provider: %s and %s)",
                    u8DataStatus,
                    (u8DataStatus & 0x04) ? "Valid" : "Invalid",
                    (u8DataStatus & 0x01) ? "Primary" : "Backup",
                    (u8DataStatus & 0x20) ? "Ok" : "Problem",
                    (u8DataStatus & 0x10) ? "Run" : "Stop");
                ds_tree = proto_item_add_subtree(ds_item, ett_pn_io_data_status);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res67, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_ok, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_operate, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res3, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_valid, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_res1, tvb, offset, 1, u8DataStatus);
                proto_tree_add_uint(ds_tree, hf_pn_io_data_status_primary, tvb, offset, 1, u8DataStatus);

                offset++;

                /* add transfer status */
                if (u8TransferStatus) {
                    proto_tree_add_uint_format(iocr_tree, hf_pn_io_transfer_status, tvb,
                        offset, 1, u8TransferStatus,
                        "TransferStatus: 0x%02x (ignore this frame)", u8TransferStatus);
                } else {
                    proto_tree_add_uint_format(iocr_tree, hf_pn_io_transfer_status, tvb,
                        offset, 1, u8TransferStatus,
                        "TransferStatus: 0x%02x (OK)", u8TransferStatus);
                }
                offset++;
				proto_item_set_len(iocr_item, offset - u32IOCRStart);
            }
            /* NumberOfAPIs */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_number_of_apis, &u16NumberOfAPIs);
            /* align to next 32 bit */
			offset = dissect_pn_padding(tvb, offset, pinfo, ar_tree, 2);
            /* API */
            if (u16NumberOfAPIs > 0){
				offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_api, &u32Api);
            }
            /* get the number of subblocks an dissect them */
			offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_number_of_ARDATAInfo, &u16NumberofEntries);

			offset = dissect_pn_padding(tvb, offset, pinfo, ar_tree, 2);

            while ((offset < i32EndOffset) && (u16NumberofEntries > 0)){
				offset = dissect_a_block(tvb, offset, pinfo, ar_tree, drep);
                u16NumberofEntries--;
            }
			proto_item_set_len(ar_item, offset - u32ARDataStart);
        }
    }
    return offset;
}


/* dissect the APIData block */
static int
dissect_APIData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
    }

    return offset;
}
/* dissect the SLRData block */
static int
dissect_SRLData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 RedundancyInfo;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* bit 0 ..1  EndPoint1 and EndPoint2*/
    dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_RedundancyInfo, &RedundancyInfo);
    /* bit 2 .. 15 reserved */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_RedundancyInfo_reserved, &RedundancyInfo);
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);
    return offset;
}

/* dissect the LogData block */
static int
dissect_LogData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint64 u64ActualLocaltimeStamp;
    guint16 u16NumberOfLogEntries;
    guint64 u64LocaltimeStamp;
    e_uuid_t aruuid;
    guint32 u32EntryDetail;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* ActualLocalTimeStamp */
    offset = dissect_dcerpc_uint64(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_actual_local_time_stamp, &u64ActualLocaltimeStamp);
    /* NumberOfLogEntries */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_log_entries, &u16NumberOfLogEntries);

    while(u16NumberOfLogEntries--) {
        /* LocalTimeStamp */
        offset = dissect_dcerpc_uint64(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_local_time_stamp, &u64LocaltimeStamp);
        /* ARUUID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &aruuid);
        /* PNIOStatus */
        offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);
        /* EntryDetail */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_entry_detail, &u32EntryDetail);
    }

    return offset;
}


/* dissect the FS Hello block */
static int
dissect_FSHello_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FSHelloMode;
    guint32 u32FSHelloInterval;
    guint32 u32FSHelloRetry;
    guint32 u32FSHelloDelay;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* FSHelloMode */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_hello_mode, &u32FSHelloMode);
    /* FSHelloInterval */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_hello_interval, &u32FSHelloInterval);
    /* FSHelloRetry */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_hello_retry, &u32FSHelloRetry);
    /* FSHelloDelay */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_hello_delay, &u32FSHelloDelay);

    proto_item_append_text(item, ": Mode:%s, Interval:%ums, Retry:%u, Delay:%ums",
        val_to_str(u32FSHelloMode, pn_io_fs_hello_mode_vals, "0x%x"),
        u32FSHelloInterval, u32FSHelloRetry, u32FSHelloDelay);

    return offset;
}


/* dissect the FS Parameter block */
static int
dissect_FSParameter_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FSParameterMode;
    e_uuid_t FSParameterUUID;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* FSParameterMode */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_parameter_mode, &u32FSParameterMode);
    /* FSParameterUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_fs_parameter_uuid, &FSParameterUUID);

    proto_item_append_text(item, ": Mode:%s",
        val_to_str(u32FSParameterMode, pn_io_fs_parameter_mode_vals, "0x%x"));

    return offset;
}




/* dissect the FSUDataAdjust block */
static int
dissect_PDInterfaceFSUDataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    tvbuff_t *new_tvb;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    u16BodyLength -= 2;

    /* sub blocks */
    new_tvb = tvb_new_subset(tvb, offset, u16BodyLength, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    return offset;
}


/* dissect the ARFSUDataAdjust block */
static int
dissect_ARFSUDataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    tvbuff_t *new_tvb;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    u16BodyLength -= 2;

    /* sub blocks */
    new_tvb = tvb_new_subset(tvb, offset, u16BodyLength, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    return offset;
}

/* dissect the ARBlockReq */
static int
dissect_ARBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t ** ar)
{
    guint16 u16ARType;
    e_uuid_t aruuid;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint16 u16TimeoutFactor;
    guint16 u16UDPRTPort;
    guint16 u16NameLength;
    char *pStationName;
    pnio_ar_t * par;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &aruuid);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_pn_mac(tvb, offset, pinfo, tree,
                        hf_pn_io_cminitiator_macadd, mac);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_cminitiator_objectuuid, &uuid);


    offset = dissect_ARProperties(tvb, offset, pinfo, tree, item, drep);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_cminitiator_activitytimeoutfactor, &u16TimeoutFactor);   /* XXX - special values */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_cminitiator_udprtport, &u16UDPRTPort);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);

    pStationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
    pStationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pStationName);
    offset += u16NameLength;

    proto_item_append_text(item, ": %s, Session:%u, MAC:%02x:%02x:%02x:%02x:%02x:%02x, Port:0x%x, Station:%s",
        val_to_str(u16ARType, pn_io_ar_type, "0x%x"),
        u16SessionKey,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        u16UDPRTPort,
        pStationName);

    par = pnio_ar_find_by_aruuid(pinfo, &aruuid);
    if(par == NULL) {
        par = pnio_ar_new(&aruuid);
        memcpy( (void *) (&par->controllermac), mac, sizeof(par->controllermac));
        par->arType = u16ARType; /* store AR-type for filter generation */
        /*strncpy( (char *) (&par->controllername), pStationName, sizeof(par->controllername));*/
    } else {
        /*expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "ARBlockReq: AR already existing!");*/
    }
    *ar = par;

    return offset;
}


/* dissect the ARBlockRes */
static int
dissect_ARBlockRes_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t ** ar)
{
    guint16 u16ARType;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint16 u16UDPRTPort;
    pnio_ar_t * par;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &uuid);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_pn_mac(tvb, offset, pinfo, tree,
                        hf_pn_io_cmresponder_macadd, mac);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_cmresponder_udprtport, &u16UDPRTPort);

    proto_item_append_text(item, ": %s, Session:%u, MAC:%02x:%02x:%02x:%02x:%02x:%02x, Port:0x%x",
        val_to_str(u16ARType, pn_io_ar_type, "0x%x"),
        u16SessionKey,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        u16UDPRTPort);

    par = pnio_ar_find_by_aruuid(pinfo, &uuid);
    if(par == NULL) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_NOTE, "ARBlockRes: AR information not found!");
    } else {
        memcpy( (void *) (&par->devicemac), mac, sizeof(par->controllermac));
    }
    *ar = par;

    return offset;
}


/* dissect the IOCRBlockReq */
static int
dissect_IOCRBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t *ar)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16LT;
    guint16 u16DataLength;
    guint16 u16FrameID;
    guint16 u16SendClockFactor;
    guint16 u16ReductionRatio;
    guint16 u16Phase;
    guint16 u16Sequence;
    guint32 u32FrameSendOffset;
    guint16 u16WatchdogFactor;
    guint16 u16DataHoldFactor;
    guint16 u16IOCRTagHeader;
    guint8 mac[6];
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16NumberOfIODataObjects;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16IODataObjectFrameOffset;
    guint16 u16NumberOfIOCS;
    guint16 u16IOCSFrameOffset;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32 u32ApiStart;
    guint16 u16Tmp;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_type, &u16IOCRType);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_reference, &u16IOCRReference);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_lt, &u16LT);

        offset = dissect_IOCRProperties(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_data_length, &u16DataLength);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_frame_id, &u16FrameID);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_send_clock_factor, &u16SendClockFactor);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reduction_ratio, &u16ReductionRatio);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_phase, &u16Phase);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sequence, &u16Sequence);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_frame_send_offset, &u32FrameSendOffset);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_watchdog_factor, &u16WatchdogFactor);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_data_hold_factor, &u16DataHoldFactor);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_tag_header, &u16IOCRTagHeader);
    offset = dissect_pn_mac(tvb, offset, pinfo, tree,
                        hf_pn_io_iocr_multicast_mac_add, mac);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": %s, Ref:0x%x, Len:%u, FrameID:0x%x, Clock:%u, Ratio:%u, Phase:%u APIs:%u",
        val_to_str(u16IOCRType, pn_io_iocr_type, "0x%x"),
        u16IOCRReference, u16DataLength, u16FrameID,
        u16SendClockFactor, u16ReductionRatio, u16Phase, u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, ENC_NA);
        api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_api, &u32Api);
        /* NumberOfIODataObjects */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_io_data_objects, &u16NumberOfIODataObjects);

        u16Tmp = u16NumberOfIODataObjects;
        while(u16Tmp--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_data_object, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_io_data_object);
            u32SubStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* Subslotnumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* IODataObjectFrameOffset */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_io_data_object_frame_offset, &u16IODataObjectFrameOffset);

            proto_item_append_text(sub_item, ": Slot: 0x%x, Subslot: 0x%x FrameOffset: %u",
                u16SlotNr, u16SubslotNr, u16IODataObjectFrameOffset);

            proto_item_set_len(sub_item, offset - u32SubStart);
        }
        /* NumberOfIOCS */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_iocs, &u16NumberOfIOCS);

        u16Tmp = u16NumberOfIOCS;
        while(u16Tmp--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_cs, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_io_cs);
            u32SubStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* Subslotnumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* IOCSFrameOffset */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_iocs_frame_offset, &u16IOCSFrameOffset);

            proto_item_append_text(sub_item, ": Slot: 0x%x, Subslot: 0x%x FrameOffset: %u",
                u16SlotNr, u16SubslotNr, u16IOCSFrameOffset);

            proto_item_set_len(sub_item, offset - u32SubStart);
        }

        proto_item_append_text(api_item, ": 0x%x, NumberOfIODataObjects: %u NumberOfIOCS: %u",
            u32Api, u16NumberOfIODataObjects, u16NumberOfIOCS);

        proto_item_set_len(api_item, offset - u32ApiStart);
    }

    if(ar != NULL) {
        switch(u16IOCRType) {
        case(1): /* Input CR */
            if(ar->inputframeid != 0 && ar->inputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockReq: input frameID changed from %u to %u!",
                    ar->inputframeid, u16FrameID);
            }
            ar->inputframeid = u16FrameID;
            break;
        case(2): /* Output CR */
#if 0
            /* will usually contain invalid marker 0xffff here */
            if(ar->outputframeid != 0 && ar->outputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockReq: output frameID changed from %u to %u!",
                    ar->outputframeid, u16FrameID);
            }
            ar->outputframeid = u16FrameID;
#endif
            break;
        default:
            expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockReq: IOCRType %u undecoded!", u16IOCRType);
        }
    } else {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockReq: no corresponding AR found!");
    }

    return offset;
}


/* dissect the AlarmCRBlockReq */
static int
dissect_AlarmCRBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t *ar)
{
    guint16 u16AlarmCRType;
    guint16 u16LT;
    guint32 u32AlarmCRProperties;
    guint16 u16RTATimeoutFactor;
    guint16 u16RTARetries;
    guint16 u16LocalAlarmReference;
    guint16 u16MaxAlarmDataLength;
    guint16 u16AlarmCRTagHeaderHigh;
    guint16 u16AlarmCRTagHeaderLow;
    proto_item *sub_item;
    proto_tree *sub_tree;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_lt, &u16LT);

    sub_item = proto_tree_add_item(tree, hf_pn_io_alarmcr_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_alarmcr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarmcr_properties_reserved, &u32AlarmCRProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarmcr_properties_transport, &u32AlarmCRProperties);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_alarmcr_properties_priority, &u32AlarmCRProperties);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_rta_timeoutfactor, &u16RTATimeoutFactor);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_rta_retries, &u16RTARetries);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maxalarmdatalength, &u16MaxAlarmDataLength);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_alarmcr_tagheaderhigh, &u16AlarmCRTagHeaderHigh);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_alarmcr_tagheaderlow, &u16AlarmCRTagHeaderLow);

    proto_item_append_text(item, ": %s, LT:0x%x, TFactor:%u, Retries:%u, Ref:0x%x, Len:%u Tag:0x%x/0x%x",
        val_to_str(u16AlarmCRType, pn_io_alarmcr_type, "0x%x"),
        u16LT, u16RTATimeoutFactor, u16RTARetries, u16LocalAlarmReference, u16MaxAlarmDataLength,
        u16AlarmCRTagHeaderHigh, u16AlarmCRTagHeaderLow);

    if(ar != NULL) {
        if(ar->controlleralarmref != 0xffff && ar->controlleralarmref != u16LocalAlarmReference) {
            expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "AlarmCRBlockReq: local alarm ref changed from %u to %u!",
                ar->controlleralarmref, u16LocalAlarmReference);
        }
        ar->controlleralarmref = u16LocalAlarmReference;
    } else {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "AlarmCRBlockReq: no corresponding AR found!");
    }

    return offset;
}


/* dissect the AlarmCRBlockRes */
static int
dissect_AlarmCRBlockRes_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t *ar)
{
    guint16 u16AlarmCRType;
    guint16 u16LocalAlarmReference;
    guint16 u16MaxAlarmDataLength;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maxalarmdatalength, &u16MaxAlarmDataLength);

    proto_item_append_text(item, ": %s, Ref:0x%04x, MaxDataLen:%u",
        val_to_str(u16AlarmCRType, pn_io_alarmcr_type, "0x%x"),
        u16LocalAlarmReference, u16MaxAlarmDataLength);

    if(ar != NULL) {
        if(ar->devicealarmref != 0xffff && ar->devicealarmref != u16LocalAlarmReference) {
            expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "AlarmCRBlockRes: local alarm ref changed from %u to %u!",
                ar->devicealarmref, u16LocalAlarmReference);
        }
        ar->devicealarmref = u16LocalAlarmReference;
    } else {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "AlarmCRBlockRes: no corresponding AR found!");
    }

    return offset;
}
/* dissect the ARServerBlock */
static int
dissect_ARServerBlock(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pStationName;
    guint16 u16NameLength, u16padding;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);

    pStationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
    pStationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pStationName);
    offset += u16NameLength;
    /* Padding to next 4 byte allignment in this block */
    u16padding = (u16NameLength-2) & 0x3;
    if(u16padding >0)
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, u16padding);
    return offset;
}



/* dissect the IOCRBlockRes */
static int
dissect_IOCRBlockRes_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t *ar)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16FrameID;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_type, &u16IOCRType);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_reference, &u16IOCRReference);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_frame_id, &u16FrameID);

    proto_item_append_text(item, ": %s, Ref:0x%04x, FrameID:0x%04x",
        val_to_str(u16IOCRType, pn_io_iocr_type, "0x%x"),
        u16IOCRReference, u16FrameID);

    if(ar != NULL) {
        switch(u16IOCRType) {
        case(1): /* Input CR */
            if(ar->inputframeid != 0 && ar->inputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockRes: input frameID changed from %u to %u!",
                    ar->inputframeid, u16FrameID);
            }
            ar->inputframeid = u16FrameID;
            break;
        case(2): /* Output CR */
            if(ar->outputframeid != 0 && ar->outputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockRes: output frameID changed from %u to %u!",
                    ar->outputframeid, u16FrameID);
            }
            ar->outputframeid = u16FrameID;
            break;
        default:
            expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockRes: IOCRType %u undecoded!", u16IOCRType);
        }
    } else {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "IOCRBlockRes: no corresponding AR found!");
    }

    return offset;
}



/* dissect the MCRBlockReq */
static int
dissect_MCRBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16IOCRReference;
    guint32 u32AddressResolutionProperties;
    guint16 u16MCITimeoutFactor;
    guint16 u16NameLength;
    char *pStationName;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_reference, &u16IOCRReference);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_address_resolution_properties, &u32AddressResolutionProperties);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mci_timeout_factor, &u16MCITimeoutFactor);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);

    pStationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, (guint8 *) pStationName, offset, u16NameLength);
    pStationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_provider_station_name, tvb, offset, u16NameLength, pStationName);
    offset += u16NameLength;

    proto_item_append_text(item, ", CRRef:%u, Properties:0x%x, TFactor:%u, Station:%s",
        u16IOCRReference, u32AddressResolutionProperties, u16MCITimeoutFactor, pStationName);

    return offset;
}



/* dissect the SubFrameBlock */
static int
dissect_SubFrameBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16 u16IOCRReference;
    guint8 mac[6];
    guint32 u32SubFrameData;
    guint16 u16Tmp;
    proto_item *sub_item;
    proto_tree *sub_tree;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* IOCRReference */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_reference, &u16IOCRReference);

    /* CMInitiatorMACAdd */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree,
                        hf_pn_io_cminitiator_macadd, mac);

    /* SubFrameData n*32 */
    u16BodyLength -= 10;
    u16Tmp = u16BodyLength;
    do {
        sub_item = proto_tree_add_item(tree, hf_pn_io_subframe_data, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_subframe_data);
        /* 31-16 reserved_2 */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_subframe_data_reserved2, &u32SubFrameData);
        /* 15- 8 DataLength */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_subframe_data_length, &u32SubFrameData);
        /*    7 reserved_1 */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_subframe_data_reserved1, &u32SubFrameData);
        /*  6-0 Position */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_subframe_data_position, &u32SubFrameData);

        proto_item_append_text(sub_item, ", Length:%u, Pos:%u",
            (u32SubFrameData & 0x0000FF00) >> 8, u32SubFrameData & 0x0000007F);
    } while(u16Tmp -= 4);

    proto_item_append_text(item, ", CRRef:%u, %u*Data",
        u16IOCRReference, u16BodyLength/4);

    return offset;
}

/* dissect the (PD)SubFrameBlock  0x022B */
static int
dissect_PDSubFrameBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32SFIOCRProperties;
    guint32 u32SubFrameData;
    guint16 u16FrameID;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* FrameID */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_frame_id, &u16FrameID);
    /* SFIOCRProperties */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties, &u32SFIOCRProperties);
    /*  bit 0..7 SFIOCRProperties.DistributedWatchDogFactor */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_DistributedWatchDogFactor, &u32SFIOCRProperties);
    /*  Bit 8 - 15: SFIOCRProperties.RestartFactorForDistributedWD */
/*      0x00    Mandatory    No restart delay necessary
        0x01 - 0x09    Optional    Less than 1 s restart delay
        0x0A - 0x50    Mandatory    1 s to 8 s restart delay
        0x51 - 0xFF    Optional    More than 8 s restart delay */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_RestartFactorForDistributedWD, &u32SFIOCRProperties);
    /* Bit 16 - 23: SFIOCRProperties.DFPmode */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties_DFPmode, &u32SFIOCRProperties);
    /* Bit 24 - 27: SFIOCRProperties.reserved_1 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties_reserved_1, &u32SFIOCRProperties);
    /* Bit 28 - 29: SFIOCRProperties.reserved_2 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties_reserved_2, &u32SFIOCRProperties);
    /* Bit 30: SFIOCRProperties.DFPRedundantPathLayout */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties_DFPRedundantPathLayout, &u32SFIOCRProperties);
    /* Bit 31: SFIOCRProperties.SFCRC16 */
    offset = /* it is the last one, so advance! */
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_SFIOCRProperties_SFCRC16, &u32SFIOCRProperties);

    /* SubframeData */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_subframe_data, &u32SubFrameData);
    /* Bit 0 - 6: SubframeData.Position */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_subframe_data_position, &u32SubFrameData);
    /* Bit 7: SubframeData.reserved_1 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_subframe_reserved1, &u32SubFrameData);
    /* Bit 8 - 15: SubframeData.DataLength */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_subframe_data_length, &u32SubFrameData);
    /* Bit 16 - 31: SubframeData.reserved_2 */
    offset =
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_subframe_reserved2, &u32SubFrameData);


    return offset;
}


/* dissect the IRInfoBlock */
static int
dissect_IRInfoBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength _U_)
{
    guint16  u16NumberOfIOCR;
    guint16  u16SubframeOffset;
    guint32  u32SubframeData;
    guint16  u16IOCRReference;
    e_uuid_t IRDataUUID;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_IRData_uuid, &IRDataUUID);

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* Numbers of IOCRs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_iocrs, &u16NumberOfIOCR);

    while(u16NumberOfIOCR--)
    {   /* IOCRReference */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_iocr_reference, &u16IOCRReference);

        /* SubframeOffset 16 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_iocr_SubframeOffset, &u16SubframeOffset);

        /* SubframeData  32 */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_iocr_SubframeData, &u32SubframeData);
    }
    return offset;
}

/* dissect the SRInfoBlock */
static int
dissect_SRInfoBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength _U_)
{
    guint16 u16RedundancyDataHoldFactor;
    guint32 u32sr_properties;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_RedundancyDataHoldFactor, &u16RedundancyDataHoldFactor);

    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_sr_properties, &u32sr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_sr_properties_InputValidOnBackupAR, &u32sr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_sr_properties_ActivateRedundancyAlarm, &u32sr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_sr_properties_Reserved_1, &u32sr_properties);
    offset =
       dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_sr_properties_Reserved_2, &u32sr_properties);
    return offset;
}

/* dissect the PDIRSubframeData block  0x022a */
static int
dissect_PDIRSubframeData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfSubframeBlocks;
    proto_item *sub_item;
    proto_tree *sub_tree;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_NumberOfSubframeBlocks, &u16NumberOfSubframeBlocks);

    while(u16NumberOfSubframeBlocks --)
    {   /* dissect the Subframe Block  */
        sub_item = proto_tree_add_item(tree, hf_pn_io_subframe_data, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_subframe_data);
        dissect_a_block(tvb, offset, pinfo, sub_tree, drep);

    }

    return offset;
}


static int
dissect_IRTFrameBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength _U_)
{
    guint16 u16IOCRReference;
    guint8 u8IOCRTxPortsRedundantPort;
    guint8 u8IOCRTxPortsPort;
    guint32 u32FrameSendOffset;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* IOCRReference */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_reference, &u16IOCRReference);

    /* IOCRTxPortsRedundantPort */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_txports_redundantport, &u8IOCRTxPortsRedundantPort);

    /* IOCRTxPortsPort */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_iocr_txports_port, &u8IOCRTxPortsPort);

    /* FrameSendOffset */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_frame_send_offset, &u32FrameSendOffset);

    proto_item_append_text(item, ", CRRef:%u, Port:%u, RedPort:%u, Offset:%u",
        u16IOCRReference, u8IOCRTxPortsPort, u8IOCRTxPortsRedundantPort, u32FrameSendOffset);

    return offset;
}


/* dissect the DataDescription */
static int
dissect_DataDescription(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16DataDescription;
    guint16 u16SubmoduleDataLength;
    guint8  u8LengthIOCS;
    guint8  u8LengthIOPS;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;


    sub_item = proto_tree_add_item(tree, hf_pn_io_data_description_tree, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_data_description);
    u32SubStart = offset;

    /* DataDescription */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_data_description, &u16DataDescription);
    /* SubmoduleDataLength */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_submodule_data_length, &u16SubmoduleDataLength);
    /* LengthIOCS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_length_iocs, &u8LengthIOCS);
    /* LengthIOPS */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_length_iops, &u8LengthIOPS);

    proto_item_append_text(sub_item, ": %s, SubmoduleDataLength: %u, LengthIOCS: %u, u8LengthIOPS: %u",
        val_to_str(u16DataDescription, pn_io_data_description, "(0x%x)"),
        u16SubmoduleDataLength, u8LengthIOCS, u8LengthIOPS);
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect the ExpectedSubmoduleBlockReq */
static int
dissect_ExpectedSubmoduleBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16ModuleProperties;
    guint16 u16NumberOfSubmodules;
    guint16 u16SubslotNr;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubmoduleProperties;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32 u32ApiStart;
    proto_item *sub_item;
    proto_tree *sub_tree;
    proto_item *submodule_item;
    proto_tree *submodule_tree;
    guint32 u32SubStart;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, ENC_NA);
        api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_api, &u32Api);
        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_slot_nr, &u16SlotNr);
        /* ModuleIdentNumber */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
        /* ModuleProperties */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_module_properties, &u16ModuleProperties);
        /* NumberOfSubmodules */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

        proto_item_append_text(api_item, ": %u, Slot:0x%x, IdentNumber:0x%x Properties:0x%x Submodules:%u",
            u32Api, u16SlotNr, u32ModuleIdentNumber, u16ModuleProperties, u16NumberOfSubmodules);

        proto_item_append_text(item, ", Submodules:%u", u16NumberOfSubmodules);

        while(u16NumberOfSubmodules--) {
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_submodule_tree, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
            u32SubStart = offset;

            /* Subslotnumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* SubmoduleIdentNumber */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
            /* SubmoduleProperties */
            submodule_item = proto_tree_add_item(sub_tree, hf_pn_io_submodule_properties, tvb, offset, 2, ENC_BIG_ENDIAN);
            submodule_tree = proto_item_add_subtree(submodule_item, ett_pn_io_submodule_properties);
            dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_reserved, &u16SubmoduleProperties);
            dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_discard_ioxs, &u16SubmoduleProperties);
            dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_reduce_output_submodule_data_length, &u16SubmoduleProperties);
            dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_reduce_input_submodule_data_length, &u16SubmoduleProperties);
            dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_shared_input, &u16SubmoduleProperties);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                            hf_pn_io_submodule_properties_type, &u16SubmoduleProperties);

            switch(u16SubmoduleProperties & 0x03) {
            case(0x00): /* no input and no output data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x01): /* input data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x02): /* output data (one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            case(0x03): /* input and output data (one Input and one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep);
                break;
            }

            proto_item_append_text(sub_item, ": Subslot:0x%x, Ident:0x%x Properties:0x%x",
                u16SubslotNr, u32SubmoduleIdentNumber, u16SubmoduleProperties);
            proto_item_set_len(sub_item, offset - u32SubStart);
        }

        proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect the ModuleDiffBlock */
static int
dissect_ModuleDiffBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs;
    guint32 u32Api;
    guint16 u16NumberOfModules;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16ModuleState;
    guint16 u16NumberOfSubmodules;
    guint16 u16SubslotNr;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubmoduleState;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32 u32ApiStart;
    proto_item *module_item;
    proto_tree *module_tree;
    guint32 u32ModuleStart;
    proto_item *sub_item;
    proto_tree *sub_tree;
    proto_item *submodule_item;
    proto_tree *submodule_tree;
    guint32 u32SubStart;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, ENC_NA);
        api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_api, &u32Api);
        /* NumberOfModules */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_modules, &u16NumberOfModules);

        proto_item_append_text(api_item, ": %u, Modules: %u",
            u32Api, u16NumberOfModules);

        proto_item_append_text(item, ", Modules:%u", u16NumberOfModules);

        while(u16NumberOfModules--) {
            module_item = proto_tree_add_item(api_tree, hf_pn_io_module_tree, tvb, offset, 0, ENC_NA);
            module_tree = proto_item_add_subtree(module_item, ett_pn_io_module);
            u32ModuleStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* ModuleIdentNumber */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, module_tree, drep,
                                hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
            /* ModuleState */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                                hf_pn_io_module_state, &u16ModuleState);
            /* NumberOfSubmodules */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                                hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

            proto_item_append_text(module_item, ": Slot 0x%x, Ident: 0x%x State: %s Submodules: %u",
                u16SlotNr, u32ModuleIdentNumber,
                val_to_str(u16ModuleState, pn_io_module_state, "(0x%x)"),
                u16NumberOfSubmodules);

            proto_item_append_text(item, ", Submodules:%u", u16NumberOfSubmodules);

            while(u16NumberOfSubmodules--) {
                sub_item = proto_tree_add_item(module_tree, hf_pn_io_submodule_tree, tvb, offset, 0, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
                u32SubStart = offset;

                /* Subslotnumber */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
                /* SubmoduleState */
                submodule_item = proto_tree_add_item(sub_tree, hf_pn_io_submodule_state, tvb, offset, 2, ENC_BIG_ENDIAN);
                submodule_tree = proto_item_add_subtree(submodule_item, ett_pn_io_submodule_state);
                dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                hf_pn_io_submodule_state_format_indicator, &u16SubmoduleState);
                if(u16SubmoduleState & 0x8000) {
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_ident_info, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_ar_info, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_diag_info, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_maintenance_demanded, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_maintenance_required, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_qualified_info, &u16SubmoduleState);
                    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_add_info, &u16SubmoduleState);
                } else {
                    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_detail, &u16SubmoduleState);
                }

                proto_item_append_text(sub_item, ": Subslot 0x%x, IdentNumber: 0x%x, State: 0x%x",
                    u16SubslotNr, u32SubmoduleIdentNumber, u16SubmoduleState);

                proto_item_set_len(sub_item, offset - u32SubStart);
            } /* NumberOfSubmodules */

            proto_item_set_len(module_item, offset - u32ModuleStart);
        }

        proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect the IsochronousModeData block */
static int
dissect_IsochronousModeData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint16 u16ControllerApplicationCycleFactor;
    guint16 u16TimeDataCycle;
    guint32 u32TimeIOInput;
    guint32 u32TimeIOOutput;
    guint32 u32TimeIOInputValid;
    guint32 u32TimeIOOutputValid;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    /* ControllerApplicationCycleFactor */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_controller_appl_cycle_factor, &u16ControllerApplicationCycleFactor);
    /* TimeDataCycle */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_time_data_cycle, &u16TimeDataCycle);
    /* TimeIOInput (ns) */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_time_io_input, &u32TimeIOInput);
    /* TimeIOOutput (ns) */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_time_io_output, &u32TimeIOOutput);
    /* TimeIOInputValid (ns) */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_time_io_input_valid, &u32TimeIOInputValid);
    /* TimeIOOutputValid (ns) */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_time_io_output_valid, &u32TimeIOOutputValid);


    return offset+1;
}


/* dissect the MultipleBlockHeader block */
static int
dissect_MultipleBlockHeader_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint32 u32Api;
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    tvbuff_t *new_tvb;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_api, &u32Api);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_slot_nr, &u16SlotNr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Api:0x%x Slot:%u Subslot:0x%x",
        u32Api, u16SlotNr, u16SubslotNr);

    new_tvb = tvb_new_subset(tvb, offset, u16BodyLength-10, u16BodyLength-10);
    offset = dissect_blocks(new_tvb, 0, pinfo, tree, drep);

    /*offset += u16BodyLength;*/

    return offset;
}


static const gchar *
indexReservedForProfiles(guint16 u16Index)
{
    /* "reserved for profiles" */
    if(u16Index >= 0xb000 && u16Index <= 0xbfff) {
        return "Reserved for Profiles (subslot specific)";
    }
    if(u16Index >= 0xd000 && u16Index <= 0xdfff) {
        return "Reserved for Profiles (slot specific)";
    }
    if(u16Index >= 0xec00 && u16Index <= 0xefff) {
        return "Reserved for Profiles (AR specific)";
    }
    if(u16Index >= 0xf400 && u16Index <= 0xf7ff) {
        return "Reserved for Profiles (API specific)";
    }
    if(u16Index >= 0xfc00 /* up to 0xffff */) {
        return "Reserved for Profiles (device specific)";
    }

    return NULL;
}


/* dissect the RecordDataReadQuery block */
static int
dissect_RecordDataReadQuery_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16Index, guint16 u16BodyLength)
{
    const gchar *userProfile;


    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* user specified format? */
    if(u16Index < 0x8000) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16BodyLength, "User Specified Data");
        return offset;
    }

    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if(userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16BodyLength, userProfile);
        return offset;
    }

    return dissect_pn_undecoded(tvb, offset, pinfo, tree, u16BodyLength);
}


/* dissect one PN-IO block (depending on the block type) */
static int
dissect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    guint16 u16BlockType;
    guint16 u16BlockLength;
    guint8 u8BlockVersionHigh;
    guint8 u8BlockVersionLow;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;
    guint16 u16BodyLength;
    proto_item *header_item;
    proto_tree *header_tree;
    gint remainingBytes;

    /* from here, we only have big endian (network byte ordering)!!! */
    drep[0] &= ~DREP_LITTLE_ENDIAN;

    sub_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_block);
    u32SubStart = offset;

    header_item = proto_tree_add_item(sub_tree, hf_pn_io_block_header, tvb, offset, 6, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_pn_io_block_header);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, header_tree, drep,
                        hf_pn_io_block_type, &u16BlockType);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, header_tree, drep,
                        hf_pn_io_block_length, &u16BlockLength);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, header_tree, drep,
                        hf_pn_io_block_version_high, &u8BlockVersionHigh);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, header_tree, drep,
                        hf_pn_io_block_version_low, &u8BlockVersionLow);

    proto_item_append_text(header_item, ": Type=%s, Length=%u(+4), Version=%u.%u",
        val_to_str(u16BlockType, pn_io_block_type, "Unknown (0x%04x)"),
        u16BlockLength, u8BlockVersionHigh, u8BlockVersionLow);

    proto_item_set_text(sub_item, "%s",
        val_to_str(u16BlockType, pn_io_block_type, "Unknown (0x%04x)"));

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
        val_to_str(u16BlockType, pn_io_block_type, "Unknown"));

    /* block length is without type and length fields, but with version field */
    /* as it's already dissected, remove it */
    u16BodyLength = u16BlockLength - 2;
    remainingBytes = tvb_reported_length_remaining(tvb, offset);
    if (remainingBytes +2 < u16BodyLength)
    {
        proto_item_append_text(sub_item, " Block_Length: %d greater than remaining Bytes, trying with Blocklen = remaining (%d)", u16BodyLength, remainingBytes);
        u16BodyLength = remainingBytes;
    }
    switch(u16BlockType) {
    case(0x0001):
    case(0x0002):
        dissect_AlarmNotification_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0008):
        dissect_IODWriteReqHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16Index, u32RecDataLen, ar);
        break;
    case(0x0009):
        dissect_IODReadReqHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16Index, u32RecDataLen, ar);
        break;
    case(0x0010):
        dissect_DiagnosisData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0012):   /* ExpectedIdentificationData */
    case(0x0013):   /* RealIdentificationData */
        dissect_IdentificationData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0014):
        dissect_SubstituteValue_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0015):
        dissect_RecordInputDataObjectElement_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0016):
        dissect_RecordOutputDataObjectElement_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    /*   0x0017 reserved */
    case(0x0018):
        dissect_ARData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,u16BodyLength);
        break;
    case(0x0019):
        dissect_LogData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x001A):
        dissect_APIData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x001B):
        dissect_SRLData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0020):
        dissect_IandM0_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0021):
        dissect_IandM1_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0022):
        dissect_IandM2_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0023):
        dissect_IandM3_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0024):
        dissect_IandM4_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0030):
        dissect_IandM0FilterData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0031):
        dissect_IandM0FilterData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0032):
        dissect_IandM0FilterData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0101):
        dissect_ARBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            ar);
        break;
    case(0x0102):
        dissect_IOCRBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            *ar);
        break;
    case(0x0103):
        dissect_AlarmCRBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            *ar);
        break;
    case(0x0104):
        dissect_ExpectedSubmoduleBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0106):
        dissect_MCRBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0107):
        dissect_SubFrameBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0108):
        dissect_IRTFrameBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0109):
        dissect_IRInfoBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x010A):
        dissect_SRInfoBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;


    case(0x0110):
    case(0x0111):
    case(0x0112):
    case(0x0113):
    case(0x0114):
    case(0x0116):
    case(0x0117):
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, ar);
        break;

    case(0x0118):
        dissect_ControlBlockPrmBegin(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength, ar);
        break;

    case(0x0119):
        dissect_SubmoduleListBlock(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength, ar);
        break;

    case(0x0200): /* PDPortDataCheck */
        dissect_PDPortData_Check_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0201):
        dissect_PDevData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0202): /*dissect_PDPortData_Adjust_block */
        dissect_PDPortData_Adjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0203):
        dissect_PDSyncData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0204):
        dissect_IsochronousModeData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0205):
        dissect_PDIRData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0206):
        dissect_PDIRGlobalData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0207):
        dissect_PDIRFrameData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0208):
        dissect_PDIRBeginEndData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16BodyLength);
        break;
    case(0x0209):
        dissect_AdjustDomainBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x020A):
        dissect_CheckPeers_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x020B):
        dissect_CheckLineDelay_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x020C):
        dissect_CheckMAUType_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x020E):
        dissect_AdjustMAUType_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x020F):
        dissect_PDPortDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0210):
        dissect_AdjustMulticastBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0211):
        dissect_PDInterfaceMrpDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,u16BodyLength);
        break;
    case(0x0212):
        dissect_PDInterfaceMrpDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,u16BodyLength);
        break;
    case(0x0213):
        dissect_PDInterfaceMrpDataCheck_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0214):
    case(0x0215):
        dissect_PDPortMrpData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0216):
        dissect_MrpManagerParams_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0217):
        dissect_MrpClientParams_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0218):
        dissect_MrpRTModeManagerData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0219):
        dissect_MrpRingStateData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021A):
        dissect_MrpRTStateData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021B):
        dissect_AdjustPortState_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021C):
        dissect_CheckPortState_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021D):
        dissect_MrpRTModeClientData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021E):
        dissect_CheckSyncDifference_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x021F):
        dissect_CheckMAUTypeDifference_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0220):
        dissect_PDPortFODataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0221):
        dissect_FiberOpticManufacturerSpecific_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0222):
        dissect_PDPortFODataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0223):
        dissect_PDPortFODataCheck_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0226):
        dissect_AdjustPreambleLength_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x022A):
        dissect_PDIRSubframeData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x022B):
        dissect_PDSubFrameBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;

    case(0x0230):
        dissect_PDPortFODataCheck_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0240):
        dissect_PDInterfaceDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0251):
        dissect_PDPortStatistic_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0400):
        dissect_MultipleBlockHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0500):
        dissect_RecordDataReadQuery_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, *u16Index, u16BodyLength);
        break;
    case(0x0600):
        dissect_FSHello_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0601):
        dissect_FSParameter_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0608):
        dissect_PDInterfaceFSUDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x010B):
    case(0x0609):
        dissect_ARFSUDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0f00):
        dissect_Maintenance_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x8001):
    case(0x8002):
        dissect_Alarm_ack_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x8008):
        dissect_IODWriteResHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16Index, u32RecDataLen, ar);
        break;
    case(0x8009):
        dissect_IODReadResHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,
            u16Index, u32RecDataLen, ar);
        break;
    case(0x8101):
        dissect_ARBlockRes_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, ar);
        break;
    case(0x8102):
        dissect_IOCRBlockRes_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, *ar);
        break;
    case(0x8103):
        dissect_AlarmCRBlockRes_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, *ar);
        break;
    case(0x8104):
        dissect_ModuleDiffBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x8106):
        dissect_ARServerBlock(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x8110):
    case(0x8111):
    case(0x8112):
    case(0x8113):
    case(0x8114):
    case(0x8116):
    case(0x8117):
    case(0x8118):
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow,ar);
        break;
    default:
        dissect_pn_undecoded(tvb, offset, pinfo, sub_tree, u16BodyLength);
    }
    offset += u16BodyLength;

    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect any PN-IO block */
static int
dissect_a_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;

    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    if(ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}

/* dissect any number of PN-IO blocks */
static int
dissect_blocks(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    while(tvb_length(tvb) > (guint) offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        u16Index++;
    }

    if(ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}


/* dissect a PN-IO (DCE-RPC) request header */
static int
dissect_IPNIO_rqst_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ArgsMax;
    guint32 u32ArgsLen;
    guint32 u32MaxCount;
    guint32 u32Offset;
    guint32 u32ArraySize;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    /* args_max */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_args_max, &u32ArgsMax);
    /* args_len */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_max_count, &u32MaxCount);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_offset, &u32Offset);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_act_count, &u32ArraySize);

    proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u",
        u32MaxCount, u32Offset, u32ArraySize);
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO (DCE-RPC) response header */
static int
dissect_IPNIO_resp_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32ArgsLen;
    guint32 u32MaxCount;
    guint32 u32Offset;
    guint32 u32ArraySize;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    /* args_len */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_max_count, &u32MaxCount);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_offset, &u32Offset);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_array_act_count, &u32ArraySize);

    proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u",
        u32MaxCount, u32Offset, u32ArraySize);
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO request */
static int
dissect_IPNIO_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO response */
static int
dissect_IPNIO_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* dissect a PROFIDrive parameter request */
static int
dissect_ProfiDriveParameterRequest(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8 request_reference;
    guint8 request_id;
    guint8 do_id;
    guint8 no_of_parameters;
    guint8 addr_idx;
    proto_item *profidrive_item;
    proto_tree *profidrive_tree;

    profidrive_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
    profidrive_tree = proto_item_add_subtree(profidrive_item, ett_pn_io_profidrive_parameter_request);
    proto_item_set_text(profidrive_item, "PROFIDrive Parameter Request: ");

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_request_reference, &request_reference);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_request_id, &request_id);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_do_id, &do_id);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_no_of_parameters, &no_of_parameters);

    proto_item_append_text(profidrive_item, "ReqRef:0x%02x, ReqId:%s, DO:%u, NoOfParameters:%u",
        request_reference, val_to_str(request_id, pn_io_profidrive_request_id_vals, "Unknown"),
        do_id, no_of_parameters);

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "PROFIDrive Write Request, ReqRef:0x%02x, %s DO:%u",
            request_reference,
            request_id==0x01 ? "Read" :
            request_id==0x02 ? "Change" :
                               "",
            do_id);

    /* Parameter address list */
    for(addr_idx=0; addr_idx<no_of_parameters; addr_idx++) {
        guint8 attribute;
        guint8 no_of_elems;
        guint16 parameter;
        guint16 idx;
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(profidrive_tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_profidrive_parameter_address);
        proto_item_set_text(sub_item, "Parameter Address %u: ", addr_idx+1);

        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_attribute, &attribute);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_no_of_elems, &no_of_elems);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_number, &parameter);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_subindex, &idx);

        proto_item_append_text(sub_item, "Attr:%s, Elems:%u, Parameter:%u, Index:%u",
            val_to_str(attribute, pn_io_profidrive_attribute_vals, "Unknown"), no_of_elems,
            parameter, idx);

            if(no_of_elems>1) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", P%d[%d..%d]", parameter, idx, idx+no_of_elems-1);
            }
            else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", P%d[%d]", parameter, idx);
            }
        }

    /* in case of change request parameter value list */
    if(request_id == 0x02) {
        for(addr_idx=0; addr_idx<no_of_parameters; addr_idx++) {
            guint8 format;
            guint8 no_of_vals;
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(profidrive_tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_profidrive_parameter_value);
            proto_item_set_text(sub_item, "Parameter Value %u: ", addr_idx+1);

            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_profidrive_param_format, &format);
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_profidrive_param_no_of_values, &no_of_vals);

            proto_item_append_text(sub_item, "Format:%s, NoOfVals:%u",
                val_to_str(format, pn_io_profidrive_format_vals, "Unknown"), no_of_vals);

            while(no_of_vals--) {
                guint16 value;

                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_profidrive_param_value, &value);

            }
        }
    }

    return offset;
}

static int
dissect_ProfiDriveParameterResponse(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8 request_reference;
    guint8 response_id;
    guint8 do_id;
    guint8 no_of_parameters;
    guint8 val_idx;
    proto_item *profidrive_item;
    proto_tree *profidrive_tree;

    profidrive_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
    profidrive_tree = proto_item_add_subtree(profidrive_item, ett_pn_io_profidrive_parameter_response);
    proto_item_set_text(profidrive_item, "PROFIDrive Parameter Response: ");

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_request_reference, &request_reference);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_response_id, &response_id);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_do_id, &do_id);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, profidrive_tree, drep,
                        hf_pn_io_profidrive_no_of_parameters, &no_of_parameters);

    proto_item_append_text(profidrive_item, "ReqRef:0x%02x, RspId:%s, DO:%u, NoOfParameters:%u",
        request_reference, val_to_str(response_id, pn_io_profidrive_response_id_vals, "Unknown"),
        do_id, no_of_parameters);

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "PROFIDrive Read Response, ReqRef:0x%02x, RspId:%s",
                           request_reference,
                           val_to_str(response_id, pn_io_profidrive_response_id_vals, "Unknown response"));

    val_idx = 1;
    while(no_of_parameters--) {
        guint8 format;
        guint8 no_of_vals;
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(profidrive_tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_profidrive_parameter_value);
        proto_item_set_text(sub_item, "Parameter Value %u: ", val_idx++);

        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_format, &format);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_no_of_values, &no_of_vals);

        proto_item_append_text(sub_item, "Format:%s, NoOfVals:%u",
            val_to_str(format, pn_io_profidrive_format_vals, "Unknown"), no_of_vals);

        while(no_of_vals--) {
            guint16 value;

            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_profidrive_param_value, &value);
        }
    }

    return offset;
}

static int
dissect_RecordDataRead(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    const gchar *userProfile;
    pnio_ar_t *ar = NULL;


    /* user specified format? */
    if(u16Index < 0x8000) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, "User Specified Data");
        return offset;
    }

    /* profidrive parameter access response */
    if(u16Index == 0xb02e || u16Index == 0xb02f) {
        return dissect_ProfiDriveParameterResponse(tvb, offset, pinfo, tree, drep);
    }

    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if(userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, userProfile);
        return offset;
    }

    /* see: pn_io_index */
    /* single block only */
    switch(u16Index) {
    case(0x8010):   /* Maintenance required in channel coding for one subslot */
    case(0x8011):   /* Maintenance demanded in channel coding for one subslot */
    case(0x8012):   /* Maintenance required in all codings for one subslot */
    case(0x8013):   /* Maintenance demanded in all codings for one subslot */
    case(0x801e):   /* SubstituteValues for one subslot */
    case(0x8028):   /* RecordInputDataObjectElement for one subslot */
    case(0x8029):   /* RecordOutputDataObjectElement for one subslot */
    case(0x8050):   /* PDInterfaceMrpDataReal for one subslot */
    case(0x8051):   /* PDInterfaceMrpDataCheck for one subslot */
    case(0x8052):   /* PDInterfaceMrpDataAdjust for one subslot */
    case(0x8053):   /* PDPortMrpDataAdjust for one subslot */
    case(0x8054):   /* PDPortMrpDataReal for one subslot */
    case(0x8060):   /* PDPortFODataReal for one subslot */
    case(0x8061):   /* PDPortFODataCheck for one subslot */
    case(0x8062):   /* PDPortFODataAdjust for one subslot */
    case(0x8070):   /* PDNCDataCheck for one subslot */
    case(0x8071):   /* PDPortStatistic for one subslot */
    case(0x8080):   /* PDInterfaceDataReal */
    case(0x8090):   /* PDInterfaceFSUDataAdjust */

    case(0xaff0):   /* I&M0 */
    case(0xaff1):   /* I&M1 */
    case(0xaff2):   /* I&M2 */
    case(0xaff3):   /* I&M3 */
    case(0xaff4):   /* I&M4 */
    case(0xaff5):   /* I&M5 */
    case(0xaff6):   /* I&M6 */
    case(0xaff7):   /* I&M7 */
    case(0xaff8):   /* I&M8 */
    case(0xaff9):   /* I&M9 */
    case(0xaffa):   /* I&M10 */
    case(0xaffb):   /* I&M11 */
    case(0xaffc):   /* I&M12 */
    case(0xaffd):   /* I&M13 */
    case(0xaffe):   /* I&M14 */
    case(0xafff):   /* I&M15 */

    case(0xc010):   /* Maintenance required in channel coding for one slot */
    case(0xc011):   /* Maintenance demanded in channel coding for one slot */
    case(0xc012):   /* Maintenance required in all codings for one slot */
    case(0xc013):   /* Maintenance demanded in all codings for one slot */

    case(0xe002):   /* ModuleDiffBlock for one AR */
    case(0xe010):   /* Maintenance required in channel coding for one AR */
    case(0xe011):   /* Maintenance demanded in channel coding for one AR */
    case(0xe012):   /* Maintenance required in all codings for one AR */
    case(0xe013):   /* Maintenance demanded in all codings for one AR */

    case(0xf010):   /* Maintenance required in channel coding for one API */
    case(0xf011):   /* Maintenance demanded in channel coding for one API */
    case(0xf012):   /* Maintenance required in all codings for one API */
    case(0xf013):   /* Maintenance demanded in all codings for one API */
    case(0xf020):   /* ARData for one API */

    case(0xf820):   /* ARData */
    case(0xf821):   /* APIData */
    case(0xf830):   /* LogData */
    case(0xf831):   /* PDevData */
    case(0xf840):   /* I&M0FilterData */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;

    case(0xB050):
    case(0xB051):
    case(0xB060):
    case(0xB061):

       offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;


    /*** multiple blocks possible ***/
    case(0x8000):   /* ExpectedIdentificationData for one subslot */
    case(0x8001):   /* RealIdentificationData for one subslot */
    case(0x800a):   /* Diagnosis in channel decoding for one subslot */
    case(0x800b):   /* Diagnosis in all codings for one subslot */
    case(0x800c):   /* Diagnosis, Maintenance, Qualified and Status for one subslot */

    case(0x802a):   /* PDPortDataReal */
    case(0x802b):   /* PDPortDataCheck */
    case(0x802d):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTA */
    case(0x802e):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTC */
    case(0x802f):   /* PDPortDataAdjust */
    case(0x8030):   /* IsochronousModeData for one subslot */
    case(0x8031):   /* Expected PDSyncData for one subslot with SyncID value 1 */
    case(0x8032):
    case(0x8033):
    case(0x8034):
    case(0x8035):
    case(0x8036):
    case(0x8037):
    case(0x8038):
    case(0x8039):
    case(0x803a):
    case(0x803b):
    case(0x803c):
    case(0x803d):
    case(0x803e):
    case(0x803f):
    case(0x8040):   /* Expected PDSyncData for one subslot with SyncID value 2 ... 30 */
    case(0x8041):
    case(0x8042):
    case(0x8043):
    case(0x8044):
    case(0x8045):
    case(0x8046):
    case(0x8047):
    case(0x8048):
    case(0x8049):
    case(0x804a):
    case(0x804b):
    case(0x804c):
    case(0x804d):
    case(0x804e):
    case(0x804f):   /* Expected PDSyncData for one subslot with SyncID value 31 */
    case(0x8072):    /* PDPortStatistic for one subslot */
    case(0xc000):   /* ExpectedIdentificationData for one slot */
    case(0xc001):   /* RealIdentificationData for one slot */
    case(0xc00a):   /* Diagnosis in channel coding for one slot */
    case(0xc00b):   /* Diagnosis in all codings for one slot */
    case(0xc00c):   /* Diagnosis, Maintenance, Qualified and Status for one slot */

    case(0xe000):   /* ExpectedIdentificationData for one AR */
    case(0xe001):   /* RealIdentificationData for one AR */
    case(0xe00a):   /* Diagnosis in channel decoding for one AR */
    case(0xe00b):   /* Diagnosis in all codings for one AR */
    case(0xe00c):   /* Diagnosis, Maintenance, Qualified and Status for one AR */
    case(0xe030):   /* IsochronousModeData for one AR */

    case(0xf000):   /* RealIdentificationData for one API */
    case(0xf00a):   /* Diagnosis in channel decoding for one API */
    case(0xf00b):   /* Diagnosis in all codings for one API */
    case(0xf00c):   /* Diagnosis, Maintenance, Qualified and Status for one API */

    case(0xf80c):   /* Diagnosis, Maintenance, Qualified and Status for one device */
    case(0xf841):   /* PDRealData */
    case(0xf842):   /* PDExpectedData */
        offset = dissect_blocks(tvb, offset, pinfo, tree, drep);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, u32RecDataLen);
    }

    return offset;
}


/* dissect a PN-IO read response */
static int
dissect_IPNIO_Read_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODReadHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    /* RecordDataRead */
    if(u32RecDataLen != 0) {
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
    }

    if(ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}

/* F-Parameter record data object */
static int
dissect_ProfiSafeParameterRequest(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *f_item;
    proto_tree *f_tree;
    proto_item *flags1_item;
    proto_tree *flags1_tree;
    proto_item *flags2_item;
    proto_tree *flags2_tree;
    guint16 src_addr;
    guint16 dst_addr;
    guint16 wd_time;
    guint16 par_crc;
    guint8 prm_flag1;
    guint8 prm_flag1_chck_seq;
    guint8 prm_flag1_chck_ipar;
    guint8 prm_flag1_sil;
    guint8 prm_flag1_crc_len;
    guint8 prm_flag1_reserved;
    guint8 prm_flag2;
    guint8 prm_flag2_reserved;
    guint8 prm_flag2_f_block_id;
    guint8 prm_flag2_f_par_version;

    prm_flag1 = 0;
    prm_flag2 = 0;

    f_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
    f_tree = proto_item_add_subtree(f_item, ett_pn_io_profisafe_f_parameter);
    proto_item_set_text(f_item, "F-Parameter: ");


    flags1_item = proto_tree_add_item(f_tree, hf_pn_io_profisafe_f_prm_flag1, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags1_tree = proto_item_add_subtree(flags1_item, ett_pn_io_profisafe_f_parameter_prm_flag1);

    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_profisafe_f_prm_flag1_chck_seq, &prm_flag1_chck_seq);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_profisafe_f_prm_flag1_chck_ipar, &prm_flag1_chck_ipar);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_profisafe_f_prm_flag1_sil, &prm_flag1_sil);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_profisafe_f_prm_flag1_crc_len, &prm_flag1_crc_len);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_profisafe_f_prm_flag1_reserved, &prm_flag1_reserved);
    prm_flag1 = prm_flag1_chck_seq|prm_flag1_chck_ipar|prm_flag1_sil|prm_flag1_reserved;
    offset++;

    flags2_item = proto_tree_add_item(f_tree, hf_pn_io_profisafe_f_prm_flag2, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags2_tree = proto_item_add_subtree(flags2_item, ett_pn_io_profisafe_f_parameter_prm_flag2);

    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_profisafe_f_prm_flag2_reserved, &prm_flag2_reserved);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_profisafe_f_prm_flag2_f_block_id, &prm_flag2_f_block_id);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_profisafe_f_prm_flag2_f_par_version, &prm_flag2_f_par_version);
    prm_flag2 = prm_flag2_reserved|prm_flag2_f_block_id|prm_flag2_f_par_version;
    offset++;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_profisafe_f_src_addr, &src_addr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_profisafe_f_dst_addr, &dst_addr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_profisafe_f_wd_time, &wd_time);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_profisafe_f_par_crc, &par_crc);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", F-Parameter record, prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x, dst:0x%04x, wd_time:%d, crc:0x%04x",
        prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, par_crc);

    proto_item_append_text(f_item, "prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x, dst:0x%04x, wd_time:%d, crc:0x%04x",
            prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, par_crc);

    return offset;
}
static int
dissect_RecordDataWrite(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    const gchar *userProfile;
    pnio_ar_t *ar = NULL;

    /* PROFISafe */
    if(u16Index == 0x0100) {
        return dissect_ProfiSafeParameterRequest(tvb, offset, pinfo, tree, drep);
    }

    /* user specified format? */
    if(u16Index < 0x8000) {
        return dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, "User Specified Data");
    }

    /* profidrive parameter request */
    if(u16Index == 0xb02e || u16Index == 0xb02f) {
        return dissect_ProfiDriveParameterRequest(tvb, offset, pinfo, tree, drep);
    }

    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if(userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, userProfile);
        return offset;
    }

    /* see: pn_io_index */
    switch(u16Index) {
    case(0x8020):   /* PDIRSubframeData */
    case(0x801e):   /* SubstituteValues for one subslot */
    case(0x802b):   /* PDPortDataCheck for one subslot */
    case(0x802c):   /* PDirData for one subslot */
    case(0x802d):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTA */
    case(0x802e):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTC */
    case(0x802f):   /* PDPortDataAdjust for one subslot */
    case(0x8030):   /* IsochronousModeData for one subslot */
    case(0x8051):   /* PDInterfaceMrpDataCheck for one subslot */
    case(0x8052):   /* PDInterfaceMrpDataAdjust for one subslot */
    case(0x8053):   /* PDPortMrpDataAdjust for one subslot */
    case(0x8061):   /* PDPortFODataCheck for one subslot */
    case(0x8062):   /* PDPortFODataAdjust for one subslot */
    case(0x8070):   /* PDNCDataCheck for one subslot */
    case(0x8090):   /* PDInterfaceFSUDataAdjust */

    case(0xe030):   /* IsochronousModeData for one AR */
    case(0xe050):   /* FastStartUp data for one AR */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, u32RecDataLen);
    }

    return offset;
}


static int
dissect_IODWriteReq(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, pnio_ar_t **ar)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    /* IODWriteHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, ar);

    /* IODWriteMultipleReq? */
    if(u16Index == 0xe040) {
        while(tvb_length_remaining(tvb, offset) > 0) {
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, ar);
        }
    } else {
        tvbuff_t *tvb_new = tvb_new_subset(tvb, offset, u32RecDataLen, u32RecDataLen);
        /* RecordDataWrite */
        offset += dissect_RecordDataWrite(tvb_new, 0, pinfo, tree, drep, u16Index, u32RecDataLen);

        /* Padding */
        switch(offset % 4) {
        case(3):
            offset += 1;
            break;
        case(2):
            offset += 2;
            break;
        case(1):
            offset += 3;
            break;
        }
    }

    return offset;
}

/* dissect a PN-IO write request */
static int
dissect_IPNIO_Write_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    pnio_ar_t *ar = NULL;

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, &ar);

    if(ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}



static int
dissect_IODWriteRes(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    /* IODWriteResHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    /* IODWriteMultipleRes? */
    if(u16Index == 0xe040) {
        while(tvb_length_remaining(tvb, offset) > 0) {
            offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        }
    }

    if(ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}


/* dissect a PN-IO write response */
static int
dissect_IPNIO_Write_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect the IOxS (IOCS, IOPS) field */
static int
dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_, int hfindex)
{
    guint8 u8IOxS;
    proto_item *ioxs_item = NULL;
    proto_tree *ioxs_tree = NULL;


    u8IOxS = tvb_get_guint8(tvb, offset);

    /* add ioxs subtree */
    ioxs_item = proto_tree_add_uint(tree, hfindex, tvb, offset, 1, u8IOxS);
    proto_item_append_text(ioxs_item,
        " (%s%s)",
        (u8IOxS & 0x01) ? "another IOxS follows " : "",
        (u8IOxS & 0x80) ? "good" : "bad");
    ioxs_tree = proto_item_add_subtree(ioxs_item, ett_pn_io_ioxs);

    proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_datastate, tvb, offset, 1, u8IOxS);
    proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_instance, tvb, offset, 1, u8IOxS);
    proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_res14, tvb, offset, 1, u8IOxS);
    proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_extension, tvb, offset, 1, u8IOxS);

    return offset + 1;
}


/* dissect a PN-IO Cyclic Service Data Unit (on top of PN-RT protocol) */
static int
dissect_PNIO_C_SDU(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *data_item;
    proto_tree *data_tree;
    /*gint iTotalLen = 0;*/
    /*gint iSubFrameLen = 0;*/


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");

    if(tree) {
        data_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb),
                    "PROFINET IO Cyclic Service Data Unit: %u bytes", tvb_length(tvb));
        data_tree = proto_item_add_subtree(data_item, ett_pn_io_rtc);

        /*dissect_dcerpc_uint16(tvb, offset, pinfo, data_tree, drep,hf_pn_io_packedframe_SFCRC, &u16SFCRC);*/
        if(!(dissect_CSF_SDU_heur(tvb, pinfo, data_tree) == FALSE))
            return(tvb_length(tvb));
        /* XXX - dissect the remaining data */
        /* this will be one or more DataItems followed by an optional GAP and RTCPadding */
        /* as we don't have the required context information to dissect the specific DataItems, this will be tricky :-( */
        offset = dissect_PNIO_IOxS(tvb, offset, pinfo, data_tree, drep, hf_pn_io_ioxs);
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset), "User Data (including GAP and RTCPadding)");

    }

    return offset;
}


/* dissect a PN-IO RTA PDU (on top of PN-RT protocol) */
static int
dissect_PNIO_RTA(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16AlarmDstEndpoint;
    guint16 u16AlarmSrcEndpoint;
    guint8  u8PDUType;
    guint8  u8PDUVersion;
    guint8  u8WindowSize;
    guint8  u8Tack;
    guint16 u16SendSeqNum;
    guint16 u16AckSeqNum;
    guint16 u16VarPartLen;
    int     start_offset = offset;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    pnio_ar_t *ar = NULL;


    proto_item *rta_item;
    proto_tree *rta_tree;

    proto_item *sub_item;
    proto_tree *sub_tree;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-AL");

    rta_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb),
        "PROFINET IO Alarm");
    rta_tree = proto_item_add_subtree(rta_item, ett_pn_io_rta);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
                    hf_pn_io_alarm_dst_endpoint, &u16AlarmDstEndpoint);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
                    hf_pn_io_alarm_src_endpoint, &u16AlarmSrcEndpoint);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: 0x%x, Dst: 0x%x",
        u16AlarmSrcEndpoint, u16AlarmDstEndpoint);

    /* PDU type */
    sub_item = proto_tree_add_item(rta_tree, hf_pn_io_pdu_type, tvb, offset, 1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pdu_type);
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_pdu_type_type, &u8PDUType);
    u8PDUType &= 0x0F;
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_pdu_type_version, &u8PDUVersion);
    u8PDUVersion >>= 4;
    proto_item_append_text(sub_item, ", Type: %s, Version: %u",
        val_to_str(u8PDUType, pn_io_pdu_type, "Unknown"),
        u8PDUVersion);

    /* additional flags */
    sub_item = proto_tree_add_item(rta_tree, hf_pn_io_add_flags, tvb, offset, 1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_add_flags);
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_window_size, &u8WindowSize);
    u8WindowSize &= 0x0F;
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_tack, &u8Tack);
    u8Tack >>= 4;
    proto_item_append_text(sub_item, ", Window Size: %u, Tack: %u",
        u8WindowSize, u8Tack);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
                    hf_pn_io_send_seq_num, &u16SendSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
                    hf_pn_io_ack_seq_num, &u16AckSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
                    hf_pn_io_var_part_len, &u16VarPartLen);

    switch(u8PDUType & 0x0F) {
    case(1):    /* Data-RTA */
            col_append_str(pinfo->cinfo, COL_INFO, ", Data-RTA");
        offset = dissect_block(tvb, offset, pinfo, rta_tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;
    case(2):    /* NACK-RTA */
            col_append_str(pinfo->cinfo, COL_INFO, ", NACK-RTA");
        /* no additional data */
        break;
    case(3):    /* ACK-RTA */
            col_append_str(pinfo->cinfo, COL_INFO, ", ACK-RTA");
        /* no additional data */
        break;
    case(4):    /* ERR-RTA */
            col_append_str(pinfo->cinfo, COL_INFO, ", ERR-RTA");
        offset = dissect_PNIO_status(tvb, offset, pinfo, rta_tree, drep);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_length(tvb));
    }

    proto_item_set_len(rta_item, offset - start_offset);

    return offset;
}


/* possibly dissect a PN-IO related PN-RT packet */
static gboolean
dissect_PNIO_heur(tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree)
{
    guint8  drep_data = 0;
    guint8  *drep = &drep_data;
    guint8  u8CBAVersion;
    guint16 u16FrameID;

    /*
     * In case the packet is a protocol encoded in the basic PNIO transport stream,
     * give that protocol a chance to make a heuristic dissection, before we continue
     * to dissect it as a normal PNIO packet.
     */
    if (dissector_try_heuristic(heur_pn_subdissector_list, tvb, pinfo, tree))
      return FALSE;

    /* the sub tvb will NOT contain the frame_id here! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

    u8CBAVersion = tvb_get_guint8 (tvb, 0);

    /* is this a (none DFP) PNIO class 3 data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=3) */
    if ((u16FrameID >= 0x0100 && u16FrameID <= 0x6FF /*0x04ff*/) || /* non redundant */
        (u16FrameID >= 0x700/*0x0800*/ && u16FrameID <= 0x0fff)) { /* redundant */
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a (none DFP) PNIO class 2 data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=2) and
     * first byte (CBA version field) has to be != 0x11 */
    if ((
        (u16FrameID >= 0x5000 && u16FrameID <= 0x57ff) || /* redundant */
        (u16FrameID >= 0x6000 && u16FrameID <= 0x67ff) || /* non redundant */
        (u16FrameID >= 0x7000 && u16FrameID <= 0x77ff) || /* redundant */
        (u16FrameID >= 0x8000 && u16FrameID <= 0xbfff))   /* non redundant */
        && u8CBAVersion != 0x11) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO class 1 data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=1) and
     * first byte (CBA version field) has to be != 0x11 */
    if (u16FrameID >= 0xc000 && u16FrameID < 0xfbff && u8CBAVersion != 0x11) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO high priority alarm packet? */
    if(u16FrameID == 0xfc01) {
        col_set_str(pinfo->cinfo, COL_INFO, "Alarm High");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO low priority alarm packet? */
    if(u16FrameID == 0xfe01) {
        col_set_str(pinfo->cinfo, COL_INFO, "Alarm Low");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* this PN-RT packet doesn't seem to be PNIO specific */
    return FALSE;
}



gboolean
pn_io_ar_conv_valid(packet_info *pinfo)
{
    return (pinfo->profinet_type == 10);
}

const gchar *
pn_io_ar_conv_filter(packet_info *pinfo)
{
    pnio_ar_t *ar = pinfo->profinet_conv;
    char* buf;

    if(pinfo->profinet_type != 10) {
        return NULL;
    }

    buf = g_strdup_printf(
        "pn_io.ar_uuid == %s || "                                   /* ARUUID */
        "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "   /* Alarm CR (contr -> dev) */
        "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",      /* Alarm CR (dev -> contr) */
        guid_to_str((const e_guid_t*) &ar->aruuid),
        ar->controlleralarmref, ether_to_str((const guint8 *)ar->controllermac),
        ar->devicealarmref, ether_to_str((const guint8 *)ar->devicemac));
    return buf;
}

const gchar *
pn_io_ar_conv_data_filter(packet_info *pinfo)
{
    pnio_ar_t *ar = pinfo->profinet_conv;
    char* buf;

    if(pinfo->profinet_type != 10) {
        return NULL;
    }
    if(ar->arType == 0x0010) /* IOCARSingle using RT_CLASS_3 */
    {
        buf = g_strdup_printf(
            "pn_io.ar_uuid == %s || "                                           /* ARUUID */
            "(pn_rt.frame_id == 0x%x) || (pn_rt.frame_id == 0x%x) || "
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "           /* Alarm CR (contr -> dev) */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",              /* Alarm CR (dev -> contr) */
            guid_to_str((const e_guid_t*) &ar->aruuid),
            ar->inputframeid,ar->outputframeid,
            ar->controlleralarmref, ether_to_str((const guint8 *)ar->controllermac),
            ar->devicealarmref, ether_to_str((const guint8 *)ar->devicemac));
    }
    else
    {
        buf = g_strdup_printf(
            "pn_io.ar_uuid == %s || "                                           /* ARUUID */
            "(pn_rt.frame_id == 0x%x && eth.src == %s && eth.dst == %s) || "    /* Input CR && dev MAC -> contr MAC */
            "(pn_rt.frame_id == 0x%x && eth.src == %s && eth.dst == %s) || "    /* Output CR && contr MAC -> dev MAC */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "           /* Alarm CR (contr -> dev) */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",              /* Alarm CR (dev -> contr) */
            guid_to_str((const e_guid_t*) &ar->aruuid),
            ar->inputframeid, ether_to_str((const guint8 *)ar->devicemac), ether_to_str((const guint8 *)ar->controllermac),
            ar->outputframeid, ether_to_str((const guint8 *)ar->controllermac), ether_to_str((const guint8 *)ar->devicemac),
            ar->controlleralarmref, ether_to_str((const guint8 *)ar->controllermac),
            ar->devicealarmref, ether_to_str((const guint8 *)ar->devicemac));
    }
    return buf;
}



/* the PNIO dcerpc interface table */
static dcerpc_sub_dissector pn_io_dissectors[] = {
{ 0, "Connect", dissect_IPNIO_rqst, dissect_IPNIO_resp },
{ 1, "Release", dissect_IPNIO_rqst, dissect_IPNIO_resp },
{ 2, "Read",    dissect_IPNIO_rqst,    dissect_IPNIO_Read_resp },
{ 3, "Write",   dissect_IPNIO_Write_rqst,   dissect_IPNIO_Write_resp },
{ 4, "Control", dissect_IPNIO_rqst, dissect_IPNIO_resp },
{ 5, "Read Implicit",    dissect_IPNIO_rqst,    dissect_IPNIO_Read_resp },
    { 0, NULL, NULL, NULL }
};


static void pnio_reinit( void) {
    pnio_ars = NULL;
}


void
proto_register_pn_io (void)
{
    static hf_register_info hf[] = {
    { &hf_pn_io_opnum,
        { "Operation", "pn_io.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_reserved16,
        { "Reserved", "pn_io.reserved16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_array,
        { "Array", "pn_io.array", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_status,
        { "Status", "pn_io.status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_args_max,
        { "ArgsMaximum", "pn_io.args_max", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_args_len,
        { "ArgsLength", "pn_io.args_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_array_max_count,
        { "MaximumCount", "pn_io.array_max_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_array_offset,
        { "Offset", "pn_io.array_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_array_act_count,
        { "ActualCount", "pn_io.array_act_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_pn_io_ar_data,
	{ "ARDATA for AR:", "pn_io.ar_data", FT_NONE, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
    { &hf_pn_io_ar_type,
    { "ARType", "pn_io.ar_type", FT_UINT16, BASE_HEX, VALS(pn_io_ar_type), 0x0, NULL, HFILL }},
    { &hf_pn_io_cminitiator_macadd,
      { "CMInitiatorMacAdd", "pn_io.cminitiator_mac_add", FT_ETHER, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
    { &hf_pn_io_cminitiator_objectuuid,
      { "CMInitiatorObjectUUID", "pn_io.cminitiator_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
        { &hf_pn_io_parameter_server_objectuuid,
      { "ParameterServerObjectUUID", "pn_io.parameter_server_objectuuid", FT_GUID, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
    { &hf_pn_io_ar_properties,
        { "ARProperties", "pn_io.ar_properties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ar_properties_state,
        { "State", "pn_io.ar_properties.state", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_state), 0x00000007, NULL, HFILL }},
    { &hf_pn_io_ar_properties_supervisor_takeover_allowed,
        { "SupervisorTakeoverAllowed", "pn_io.ar_properties.supervisor_takeover_allowed", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_supervisor_takeover_allowed), 0x00000008, NULL, HFILL }},
    { &hf_pn_io_ar_properties_parametrization_server,
        { "ParametrizationServer", "pn_io.ar_properties.parametrization_server", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_parametrization_server), 0x00000010, NULL, HFILL }},
/*removed with 2.3
    { &hf_pn_io_ar_properties_data_rate,
        { "DataRate", "pn_io.ar_properties.data_rate", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_data_rate), 0x00000060, NULL, HFILL }},
*/
    { &hf_pn_io_ar_properties_reserved_1,
        { "Reserved_1", "pn_io.ar_properties.reserved_1", FT_UINT32, BASE_HEX, NULL, 0x000000E0, NULL, HFILL }},
    { &hf_pn_io_ar_properties_device_access,
        { "DeviceAccess", "pn_io.ar_properties.device_access", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_DeviceAccess), 0x00000100, NULL, HFILL }},
    { &hf_pn_io_ar_properties_companion_ar,
        { "CompanionAR", "pn_io.ar_properties.companion_ar", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_companion_ar), 0x00000600, NULL, HFILL }},
    { &hf_pn_io_ar_properties_achnowledge_companion_ar,
        { "AcknowledgeCompanionAR", "pn_io.ar_properties.acknowledge_companion_ar", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_acknowldege_companion_ar), 0x00000800, NULL, HFILL }},

    { &hf_pn_io_arproperties_StartupMode,
        { "StartupMode", "pn_io.ar_properties.StartupMode", FT_UINT32, BASE_HEX, VALS(pn_io_arpropertiesStartupMode), 0x40000000, NULL, HFILL }},

    { &hf_pn_io_ar_properties_reserved,
        { "Reserved", "pn_io.ar_properties.reserved", FT_UINT32, BASE_HEX, NULL, 0x3FFFF000, NULL, HFILL }},
    { &hf_pn_io_ar_properties_pull_module_alarm_allowed,
        { "PullModuleAlarmAllowed", "pn_io.ar_properties.pull_module_alarm_allowed", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_pull_module_alarm_allowed), 0x80000000, NULL, HFILL }},

    { &hf_pn_RedundancyInfo,
        { "RedundancyInfo.EndPoint", "pn_io.srl_data.redundancyInfo", FT_UINT16, BASE_HEX, VALS(pn_io_RedundancyInfo), 0x0000003, NULL, HFILL }},
    { &hf_pn_RedundancyInfo_reserved,
        { "RedundancyInfo.reserved", "pn_io.srl_data.redundancyInfoReserved", FT_UINT16, BASE_HEX, NULL, 0xFFFFFFFC, NULL, HFILL }},
    { &hf_pn_io_number_of_ARDATAInfo,
    { "ARDataInfo.NumberOfEntries", "pn_io.number_of_ARDATAInfo", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_cminitiator_activitytimeoutfactor,
        { "CMInitiatorActivityTimeoutFactor", "pn_io.cminitiator_activitytimeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */
    { &hf_pn_io_cminitiator_udprtport,
        { "CMInitiatorUDPRTPort", "pn_io.cminitiator_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */
    { &hf_pn_io_station_name_length,
        { "StationNameLength", "pn_io.station_name_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_cminitiator_station_name,
        { "CMInitiatorStationName", "pn_io.cminitiator_station_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_responder_station_name,
        { "CMResponderrStationName", "pn_io.cmresponder_station_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_parameter_server_station_name,
        { "ParameterServerStationName", "pn_io.parameter_server_station_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_cmresponder_macadd,
      { "CMResponderMacAdd", "pn_io.cmresponder_macadd", FT_ETHER, BASE_NONE, 0x0, 0x0, NULL, HFILL }},
    { &hf_pn_io_cmresponder_udprtport,
        { "CMResponderUDPRTPort", "pn_io.cmresponder_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */

    { &hf_pn_io_number_of_iocrs,
    { "NumberOfIOCRs", "pn_io.number_of_iocrs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_tree,
    { "IOCR", "pn_io.iocr_tree", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_type,
    { "IOCRType", "pn_io.iocr_type", FT_UINT16, BASE_HEX, VALS(pn_io_iocr_type), 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_reference,
    { "IOCRReference", "pn_io.iocr_reference", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_txports_port,
    { "IOCRTxPorts.Port", "pn_io.iocr_txports_port", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_txports_redundantport,
    { "IOCRTxPorts.RedundantPort", "pn_io.iocr_txports_redundantport", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_iocr_SubframeOffset,
    { "SubframeOffset", "pn_io.subframe_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_SubframeData,
    { "SubframeData", "pn_io.subframe_data", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_RedundancyDataHoldFactor,
    { "RedundancyDataHoldFactor", "pn_io.RedundancyDataHoldFactor", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_sr_properties,
    { "SRProperties", "pn_io.sr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_sr_properties_InputValidOnBackupAR,
    { "InputValidOnBackupAR", "pn_io.sr_properties.InputValidOnBackupAR", FT_UINT32, BASE_HEX, VALS(pn_io_sr_properties_BackupAR), 0x01, NULL, HFILL }},
    { &hf_pn_io_sr_properties_ActivateRedundancyAlarm,
    { "ActivateRedundancyAlarm", "pn_io.sr_properties.ActivateRedundancyAlarm", FT_UINT32, BASE_HEX,  VALS(pn_io_sr_properties_ActivateRedundancyAlarm), 0x02, NULL, HFILL }},
    { &hf_pn_io_sr_properties_Reserved_1,
    { "Reserved_1", "pn_io.sr_properties.Reserved_1", FT_UINT32, BASE_HEX, NULL, 0x0FFFC, NULL, HFILL }},
    { &hf_pn_io_sr_properties_Reserved_2,
    { "Reserved_2", "pn_io.sr_properties.Reserved_2", FT_UINT32, BASE_HEX, NULL, 0x0FFFF0000, NULL, HFILL }},

    { &hf_pn_io_lt,
    { "LT", "pn_io.lt", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_iocr_properties,
    { "IOCRProperties", "pn_io.iocr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_rtclass,
    { "RTClass", "pn_io.iocr_properties.rtclass", FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_rtclass), 0x0000000F, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_reserved_1,
    { "Reserved1", "pn_io.iocr_properties.reserved1", FT_UINT32, BASE_HEX, NULL, 0x000007F0, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_media_redundancy,
    { "MediaRedundancy", "pn_io.iocr_properties.media_redundancy", FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_media_redundancy), 0x00000800, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_reserved_2,
    { "Reserved2", "pn_io.iocr_properties.reserved2", FT_UINT32, BASE_HEX, NULL, 0x00FFF000, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_reserved_3,
    { "Reserved3", "pn_io.iocr_properties.reserved3", FT_UINT32, BASE_HEX, NULL, 0x1F000000, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_fast_forwarding_mac_adr,
    { "FastForwardingMACAdr", "pn_io.iocr_properties.fast_forwarding_mac_adr", FT_UINT32, BASE_HEX, NULL, 0x20000000, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_distributed_subframe_watchdog,
    { "DistributedSubFrameWatchDog", "pn_io.iocr_properties.distributed_subframe_watchdog", FT_UINT32, BASE_HEX, NULL, 0x40000000, NULL, HFILL }},
    { &hf_pn_io_iocr_properties_full_subframe_structure,
    { "FullSubFrameStructure", "pn_io.iocr_properties.full_subframe_structure", FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties,
      { "SFIOCRProperties", "pn_io.SFIOCRProperties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_DistributedWatchDogFactor,
      { "SFIOCRProperties.DistributedWatchDogFactor", "pn_io.SFIOCRProperties.DistributedWatchDogFactor", FT_UINT32, BASE_HEX, NULL, 0x0FF, NULL, HFILL }},
    { &hf_pn_io_RestartFactorForDistributedWD,
      { "SFIOCRProperties.RestartFactorForDistributedWD", "pn_io.SFIOCRProperties.RestartFactorForDistributedWD", FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties_DFPmode,
      { "SFIOCRProperties.DFPmode", "pn_io.SFIOCRProperties.DFPmode", FT_UINT32, BASE_HEX, NULL, 0xFF0000, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties_reserved_1,
      { "SFIOCRProperties.reserved_1", "pn_io.SFIOCRProperties.reserved_1", FT_UINT32, BASE_HEX, NULL, 0x0F000000, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties_reserved_2,
      { "SFIOCRProperties.reserved_2", "pn_io.SFIOCRProperties.reserved_2", FT_UINT32, BASE_HEX, NULL, 0x030000000, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties_DFPRedundantPathLayout,
      { "SFIOCRProperties.DFPRedundantPathLayout", "pn_io.SFIOCRProperties.DFPRedundantPathLayout", FT_UINT32, BASE_HEX, VALS(pn_io_DFPRedundantPathLayout_decode), 0x040000000, NULL, HFILL }},
    { &hf_pn_io_SFIOCRProperties_SFCRC16,
      { "SFIOCRProperties.SFCRC16", "pn_io.SFIOCRProperties.SFCRC16", FT_UINT32, BASE_HEX, VALS(pn_io_SFCRC16_Decode), 0x080000000, NULL, HFILL }},

    { &hf_pn_io_data_length,
      { "DataLength", "pn_io.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ir_frame_data,
      { "Frame data", "pn_io.ir_frame_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_frame_id,
      { "FrameID", "pn_io.frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_send_clock_factor,
      { "SendClockFactor", "pn_io.send_clock_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}, /* XXX - special values */
    { &hf_pn_io_reduction_ratio,
      { "ReductionRatio", "pn_io.reduction_ratio", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}, /* XXX - special values */
    { &hf_pn_io_phase,
      { "Phase", "pn_io.phase", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_sequence,
      { "Sequence", "pn_io.sequence", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_frame_send_offset,
      { "FrameSendOffset", "pn_io.frame_send_offset", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_frame_data_properties,
      { "FrameDataProperties", "pn_io.frame_data_properties", FT_UINT32, BASE_HEX, VALS(pn_io_frame_data_properties), 0x0, NULL, HFILL }},
    { &hf_pn_io_watchdog_factor,
      { "WatchdogFactor", "pn_io.watchdog_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_data_hold_factor,
      { "DataHoldFactor", "pn_io.data_hold_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_tag_header,
      { "IOCRTagHeader", "pn_io.iocr_tag_header", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocr_multicast_mac_add,
      { "IOCRMulticastMACAdd", "pn_io.iocr_multicast_mac_add", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_apis,
      { "NumberOfAPIs", "pn_io.number_of_apis", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_io_data_objects,
      { "NumberOfIODataObjects", "pn_io.number_of_io_data_objects", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_io_data_object_frame_offset,
      { "IODataObjectFrameOffset", "pn_io.io_data_object_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_iocs,
      { "NumberOfIOCS", "pn_io.number_of_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iocs_frame_offset,
      { "IOCSFrameOffset", "pn_io.iocs_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_alarmcr_type,
    { "AlarmCRType", "pn_io.alarmcr_type", FT_UINT16, BASE_HEX, VALS(pn_io_alarmcr_type), 0x0, NULL, HFILL }},

    { &hf_pn_io_alarmcr_properties,
    { "AlarmCRProperties", "pn_io.alarmcr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_alarmcr_properties_priority,
    { "priority", "pn_io.alarmcr_properties.priority", FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_priority), 0x00000001, NULL, HFILL }},
    { &hf_pn_io_alarmcr_properties_transport,
    { "Transport", "pn_io.alarmcr_properties.transport", FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_transport), 0x00000002, NULL, HFILL }},
    { &hf_pn_io_alarmcr_properties_reserved,
    { "Reserved", "pn_io.alarmcr_properties.reserved", FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC, NULL, HFILL }},

    { &hf_pn_io_rta_timeoutfactor,
        { "RTATimeoutFactor", "pn_io.rta_timeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */
    { &hf_pn_io_rta_retries,
        { "RTARetries", "pn_io.rta_retries", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},  /* XXX - only values 3 - 15 allowed */
    { &hf_pn_io_localalarmref,
        { "LocalAlarmReference", "pn_io.localalarmref", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */
    { &hf_pn_io_remotealarmref,
        { "RemoteAlarmReference", "pn_io.remotealarmref", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - special values */
    { &hf_pn_io_maxalarmdatalength,
        { "MaxAlarmDataLength", "pn_io.maxalarmdatalength", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},  /* XXX - only values 200 - 1432 allowed */
    { &hf_pn_io_alarmcr_tagheaderhigh,
        { "AlarmCRTagHeaderHigh", "pn_io.alarmcr_tagheaderhigh", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - 16 bitfield! */
    { &hf_pn_io_alarmcr_tagheaderlow,
        { "AlarmCRTagHeaderLow", "pn_io.alarmcr_tagheaderlow", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},  /* XXX - 16 bitfield!*/

    { &hf_pn_io_api_tree,
      { "API", "pn_io.api", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_module_tree,
      { "Module", "pn_io.module", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_submodule_tree,
      { "Submodule", "pn_io.submodule", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_io_data_object,
      { "IODataObject", "pn_io.io_data_object", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_io_cs,
      { "IOCS", "pn_io.io_cs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_substitutionmode,
      { "Substitutionmode", "pn_io.substitutionmode", FT_UINT16, BASE_HEX, VALS(pn_io_substitutionmode), 0x0, NULL, HFILL }},

    { &hf_pn_io_IRData_uuid,
      { "IRDataUUID", "pn_io.IRData_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_ar_uuid,
      { "ARUUID", "pn_io.ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_target_ar_uuid,
      { "TargetARUUID", "pn_io.target_ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_api,
      { "API", "pn_io.api", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_slot_nr,
      { "SlotNumber", "pn_io.slot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_subslot_nr,
      { "SubslotNumber", "pn_io.subslot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_index,
      { "Index", "pn_io.index", FT_UINT16, BASE_HEX, VALS(pn_io_index), 0x0, NULL, HFILL }},
    { &hf_pn_io_seq_number,
      { "SeqNumber", "pn_io.seq_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_record_data_length,
      { "RecordDataLength", "pn_io.record_data_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_add_val1,
      { "AdditionalValue1", "pn_io.add_val1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_add_val2,
      { "AdditionalValue2", "pn_io.add_val2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_block_header,
      { "BlockHeader", "pn_io.block_header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_block_type,
      { "BlockType", "pn_io.block_type", FT_UINT16, BASE_HEX, VALS(pn_io_block_type), 0x0, NULL, HFILL }},
    { &hf_pn_io_block_length,
      { "BlockLength", "pn_io.block_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_block_version_high,
      { "BlockVersionHigh", "pn_io.block_version_high", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_block_version_low,
      { "BlockVersionLow", "pn_io.block_version_low", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_sessionkey,
      { "SessionKey", "pn_io.session_key", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_control_command,
      { "ControlCommand", "pn_io.control_command", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_control_command_reserved,
      { "ControlBlockProperties.reserved", "pn_io.control_properties_reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_control_command_prmend,
      { "PrmEnd", "pn_io.control_command.prmend", FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL }},
    { &hf_pn_io_control_command_applready,
      { "ApplicationReady", "pn_io.control_command.applready", FT_UINT16, BASE_DEC, NULL, 0x0002, NULL, HFILL }},
    { &hf_pn_io_control_command_release,
      { "Release", "pn_io.control_command.release", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL }},
    { &hf_pn_io_control_command_done,
      { "Done", "pn_io.control_command.done", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL }},
    { &hf_pn_io_control_command_ready_for_companion,
      { "ReadyForCompanion", "pn_io.control_command.ready_for_companion", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL }},
    { &hf_pn_io_control_command_ready_for_rt_class3,
      { "ReadyForRT Class 3", "pn_io.control_command.ready_for_rt_class3", FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL }},
    { &hf_pn_io_control_command_prmbegin,
      { "PrmBegin", "pn_io.control_command.prmbegin", FT_UINT16,BASE_DEC, VALS(pn_io_control_properties_prmbegin_vals), 0x0040, NULL, HFILL }},
    { &hf_pn_io_control_command_reserved_7_15,
      { "ControlBlockProperties.reserved", "pn_io.control_properties_reserved_7_15", FT_UINT16, BASE_HEX, NULL, 0x0FF80, NULL, HFILL }},

    { &hf_pn_io_control_block_properties,
      { "ControlBlockProperties", "pn_io.control_block_properties", FT_UINT16, BASE_HEX, VALS(pn_io_control_properties_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_control_block_properties_applready,
      { "ControlBlockProperties", "pn_io.control_block_properties.appl_ready", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_control_block_properties_applready0,
      { "ApplicationReady", "pn_io.control_block_properties.appl_ready0", FT_UINT16, BASE_HEX, VALS(pn_io_control_properties_application_ready_vals), 0x0001, NULL, HFILL }},
    { &hf_pn_io_AlarmSequenceNumber,
      { "AlarmSequenceNumber", "pn_io.AlarmSequenceNumber", FT_UINT16, BASE_HEX,NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_SubmoduleListEntries,
      { "NumberOfEntries", "pn_io.SubmoduleListEntries", FT_UINT16, BASE_DEC,NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_error_code,
      { "ErrorCode", "pn_io.error_code", FT_UINT8, BASE_HEX, VALS(pn_io_error_code), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_decode,
      { "ErrorDecode", "pn_io.error_decode", FT_UINT8, BASE_HEX, VALS(pn_io_error_decode), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code1,
      { "ErrorCode1", "pn_io.error_code1", FT_UINT8, BASE_DEC, VALS(pn_io_error_code1), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code1_pniorw,
      { "ErrorCode1", "pn_io.error_code1", FT_UINT8, BASE_DEC, VALS(pn_io_error_code1_pniorw), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pniorw,
      { "ErrorCode2 for PNIORW is user specified!", "pn_io.error_code2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code1_pnio,
      { "ErrorCode1", "pn_io.error_code1", FT_UINT8, BASE_DEC, VALS(pn_io_error_code1_pnio), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_1,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_1), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_2,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_2), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_3,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_3), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_4,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_4), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_5,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_5), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_6,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_6), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_7,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_7), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_8,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_8), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_20,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_20), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_21,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_21), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_22,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_22), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_23,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_23), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_40,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_40), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_61,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_61), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_62,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_62), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_63,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_63), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_64,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_64), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_65,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_65), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_66,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_66), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_70,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_70), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_71,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_71), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_72,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_72), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_73,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_73), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_74,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_74), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_75,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_75), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_76,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_76), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_77,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_77), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_253,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_253), 0x0, NULL, HFILL }},
    { &hf_pn_io_error_code2_pnio_255,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_DEC, VALS(pn_io_error_code2_pnio_255), 0x0, NULL, HFILL }},

    { &hf_pn_io_block,
    { "Block", "pn_io.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_alarm_type,
      { "AlarmType", "pn_io.alarm_type", FT_UINT16, BASE_HEX, VALS(pn_io_alarm_type), 0x0, NULL, HFILL }},

    { &hf_pn_io_alarm_specifier,
      { "AlarmSpecifier", "pn_io.alarm_specifier", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_alarm_specifier_sequence,
      { "SequenceNumber", "pn_io.alarm_specifier.sequence", FT_UINT16, BASE_HEX, NULL, 0x07FF, NULL, HFILL }},
    { &hf_pn_io_alarm_specifier_channel,
      { "ChannelDiagnosis", "pn_io.alarm_specifier.channel", FT_UINT16, BASE_HEX, NULL, 0x0800, NULL, HFILL }},
    { &hf_pn_io_alarm_specifier_manufacturer,
      { "ManufacturerSpecificDiagnosis", "pn_io.alarm_specifier.manufacturer", FT_UINT16, BASE_HEX, NULL, 0x1000, NULL, HFILL }},
    { &hf_pn_io_alarm_specifier_submodule,
      { "SubmoduleDiagnosisState", "pn_io.alarm_specifier.submodule", FT_UINT16, BASE_HEX, NULL, 0x2000, NULL, HFILL }},
    { &hf_pn_io_alarm_specifier_ardiagnosis,
      { "ARDiagnosisState", "pn_io.alarm_specifier.ardiagnosis", FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL }},

    { &hf_pn_io_alarm_dst_endpoint,
      { "AlarmDstEndpoint", "pn_io.alarm_dst_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_alarm_src_endpoint,
      { "AlarmSrcEndpoint", "pn_io.alarm_src_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdu_type,
      { "PDUType", "pn_io.pdu_type", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdu_type_type,
      { "Type", "pn_io.pdu_type.type", FT_UINT8, BASE_HEX, VALS(pn_io_pdu_type), 0x0F, NULL, HFILL }},
    { &hf_pn_io_pdu_type_version,
      { "Version", "pn_io.pdu_type.version", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
    { &hf_pn_io_add_flags,
      { "AddFlags", "pn_io.add_flags", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_window_size,
      { "WindowSize", "pn_io.window_size", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
    { &hf_pn_io_tack,
      { "TACK", "pn_io.tack", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
    { &hf_pn_io_send_seq_num,
      { "SendSeqNum", "pn_io.send_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ack_seq_num,
      { "AckSeqNum", "pn_io.ack_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_var_part_len,
      { "VarPartLen", "pn_io.var_part_len", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_module_ident_number,
      { "ModuleIdentNumber", "pn_io.module_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_submodule_ident_number,
      { "SubmoduleIdentNumber", "pn_io.submodule_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_number_of_modules,
      { "NumberOfModules", "pn_io.number_of_modules", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_module_properties,
      { "ModuleProperties", "pn_io.module_properties", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_module_state,
      { "ModuleState", "pn_io.module_state", FT_UINT16, BASE_HEX, VALS(pn_io_module_state), 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_submodules,
      { "NumberOfSubmodules", "pn_io.number_of_submodules", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_submodule_properties,
      { "SubmoduleProperties", "pn_io.submodule_properties", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_type,
      { "Type", "pn_io.submodule_properties.type", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_type), 0x0003, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_shared_input,
      { "SharedInput", "pn_io.submodule_properties.shared_input", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_shared_input), 0x0004, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_reduce_input_submodule_data_length,
      { "ReduceInputSubmoduleDataLength", "pn_io.submodule_properties.reduce_input_submodule_data_length", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_input_submodule_data_length), 0x0008, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_reduce_output_submodule_data_length,
      { "ReduceOutputSubmoduleDataLength", "pn_io.submodule_properties.reduce_output_submodule_data_length", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_output_submodule_data_length), 0x0010, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_discard_ioxs,
      { "DiscardIOXS", "pn_io.submodule_properties.discard_ioxs", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_discard_ioxs), 0x0020, NULL, HFILL }},
    { &hf_pn_io_submodule_properties_reserved,
      { "Reserved", "pn_io.submodule_properties.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFC0, NULL, HFILL }},

    { &hf_pn_io_submodule_state,
      { "SubmoduleState", "pn_io.submodule_state", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_submodule_state_format_indicator,
      { "FormatIndicator", "pn_io.submodule_state.format_indicator", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_format_indicator), 0x8000, NULL, HFILL }},
    { &hf_pn_io_submodule_state_add_info,
      { "AddInfo", "pn_io.submodule_state.add_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_add_info), 0x0007, NULL, HFILL }},
    { &hf_pn_io_submodule_state_qualified_info,
      { "QualifiedInfo", "pn_io.submodule_state.qualified_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_qualified_info), 0x0008, NULL, HFILL }},
    { &hf_pn_io_submodule_state_maintenance_required,
      { "MaintenanceRequired", "pn_io.submodule_state.maintenance_required", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_required), 0x0010, NULL, HFILL }},
    { &hf_pn_io_submodule_state_maintenance_demanded,
      { "MaintenanceDemanded", "pn_io.submodule_state.maintenance_demanded", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_demanded), 0x0020, NULL, HFILL }},
    { &hf_pn_io_submodule_state_diag_info,
      { "DiagInfo", "pn_io.submodule_state.diag_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_diag_info), 0x0040, NULL, HFILL }},
    { &hf_pn_io_submodule_state_ar_info,
      { "ARInfo", "pn_io.submodule_state.ar_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ar_info), 0x0780, NULL, HFILL }},
    { &hf_pn_io_submodule_state_ident_info,
      { "IdentInfo", "pn_io.submodule_state.ident_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ident_info), 0x7800, NULL, HFILL }},
    { &hf_pn_io_submodule_state_detail,
      { "Detail", "pn_io.submodule_state.detail", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_detail), 0x7FFF, NULL, HFILL }},

    { &hf_pn_io_data_description_tree,
      { "DataDescription", "pn_io.data_description", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_data_description,
      { "DataDescription", "pn_io.data_description", FT_UINT16, BASE_HEX, VALS(pn_io_data_description), 0x0, NULL, HFILL }},
    { &hf_pn_io_submodule_data_length,
      { "SubmoduleDataLength", "pn_io.submodule_data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_iocs,
      { "LengthIOCS", "pn_io.length_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_iops,
      { "LengthIOPS", "pn_io.length_iops", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_iocs,
      { "IOCS", "pn_io.ioxs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_iops,
      { "IOPS", "pn_io.ioxs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ioxs,
      { "IOxS", "pn_io.ioxs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ioxs_extension,
      { "Extension (1:another IOxS follows/0:no IOxS follows)", "pn_io.ioxs.extension", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }},
    { &hf_pn_io_ioxs_res14,
      { "Reserved (should be zero)", "pn_io.ioxs.res14", FT_UINT8, BASE_HEX, NULL, 0x1E, NULL, HFILL }},
    { &hf_pn_io_ioxs_instance,
      { "Instance (only valid, if DataState is bad)", "pn_io.ioxs.instance", FT_UINT8, BASE_HEX, VALS(pn_io_ioxs), 0x60, NULL, HFILL }},
    { &hf_pn_io_ioxs_datastate,
      { "DataState (1:good/0:bad)", "pn_io.ioxs.datastate", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }},

    { &hf_pn_io_address_resolution_properties,
      { "AddressResolutionProperties", "pn_io.address_resolution_properties", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_mci_timeout_factor,
      { "MCITimeoutFactor", "pn_io.mci_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_provider_station_name,
      { "ProviderStationName", "pn_io.provider_station_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_user_structure_identifier,
      { "UserStructureIdentifier", "pn_io.user_structure_identifier", FT_UINT16, BASE_HEX, VALS(pn_io_user_structure_identifier), 0x0, NULL, HFILL }},


    { &hf_pn_io_subframe_data,
      { "SubFrameData", "pn_io.subframe_data", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_subframe_reserved2,
      { "Reserved1", "pn_io.subframe_data.reserved1", FT_UINT32, BASE_DEC, NULL, 0xFFFF0000, NULL, HFILL }},
    { &hf_pn_io_subframe_data_length,
      { "DataLength", "pn_io.subframe_data.data_length", FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }},
    { &hf_pn_io_subframe_reserved1,
      { "Reserved1", "pn_io.subframe_data.reserved1", FT_UINT32, BASE_DEC, NULL, 0x00000080, NULL, HFILL }},
    { &hf_pn_io_subframe_data_position,
      { "DataPosition", "pn_io.subframe_data.position", FT_UINT32, BASE_DEC, NULL, 0x0000007F, NULL, HFILL }},

    { &hf_pn_io_channel_number,
      { "ChannelNumber", "pn_io.channel_number", FT_UINT16, BASE_HEX, VALS(pn_io_channel_number), 0x0, NULL, HFILL }},

    { &hf_pn_io_channel_properties,
      { "ChannelProperties", "pn_io.channel_properties", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_channel_properties_type,
      { "Type", "pn_io.channel_properties.type", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_type), 0x00FF, NULL, HFILL }},
    { &hf_pn_io_channel_properties_accumulative,
      { "Accumulative", "pn_io.channel_properties.accumulative", FT_UINT16, BASE_HEX, NULL, 0x0100, NULL, HFILL }},
/* replaced with 2 bit values
    { &hf_pn_io_channel_properties_maintenance_required,
      { "MaintenanceRequired", "pn_io.channel_properties.maintenance_required", FT_UINT16, BASE_HEX, NULL, 0x0200, NULL, HFILL }},
    { &hf_pn_io_channel_properties_maintenance_demanded,
      { "MaintenanceDemanded", "pn_io.channel_properties.maintenance_demanded", FT_UINT16, BASE_HEX, NULL, 0x0400, NULL, HFILL }},
*/
    { &hf_pn_io_NumberOfSubframeBlocks,
      { "NumberOfSubframeBlocks", "pn_io.NumberOfSubframeBlocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_channel_properties_maintenance,
      { "Maintenance", "pn_io.channel_properties.maintenance", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_maintenance), 0x0600, NULL, HFILL }},
      { &hf_pn_io_channel_properties_specifier,
      { "Specifier", "pn_io.channel_properties.specifier", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_specifier), 0x1800, NULL, HFILL }},
    { &hf_pn_io_channel_properties_direction,
      { "Direction", "pn_io.channel_properties.direction", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_direction), 0xE000, NULL, HFILL }},

    { &hf_pn_io_channel_error_type,
      { "ChannelErrorType", "pn_io.channel_error_type", FT_UINT16, BASE_HEX, VALS(pn_io_channel_error_type), 0x0, NULL, HFILL }},

    { &hf_pn_io_ext_channel_error_type0,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type0", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8000,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type0800", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8000), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8001,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8001", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8001), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8002,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8002", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8002), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8003,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8003", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8003), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8004,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8004", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8004), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8005,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8005", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8005), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8007,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8007", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8007), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x8008,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8008", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8008), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x800A,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800A", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800A), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x800B,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800B", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800B), 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_error_type0x800C,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800C", FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800C), 0x0, NULL, HFILL }},

    { &hf_pn_io_ext_channel_error_type,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ext_channel_add_value,
      { "ExtChannelAddValue", "pn_io.ext_channel_add_value", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_ptcp_subdomain_id,
      { "PTCPSubdomainID", "pn_io.ptcp_subdomain_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ir_data_id,
      { "IRDataID", "pn_io.ir_data_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_max_bridge_delay,
      { "MaxBridgeDelay", "pn_io.max_bridge_delay", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_ports,
      { "NumberOfPorts", "pn_io.number_of_ports", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_max_port_tx_delay,
      { "MaxPortTxDelay", "pn_io.max_port_tx_delay", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_max_port_rx_delay,
      { "MaxPortRxDelay", "pn_io.max_port_rx_delay", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
   { &hf_pn_io_max_line_rx_delay,
      { "MaxLineRxDelay", "pn_io.max_line_rx_delay", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
   { &hf_pn_io_yellowtime,
      { "YellowTime", "pn_io.yellowtime", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_reserved_interval_begin,
      { "ReservedIntervalBegin", "pn_io.reserved_interval_begin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_reserved_interval_end,
      { "ReservedIntervalEnd", "pn_io.reserved_interval_end", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pllwindow,
      { "PLLWindow", "pn_io.pllwindow", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_sync_send_factor,
      { "SyncSendFactor", "pn_io.sync_send_factor", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_sync_properties,
      { "SyncProperties", "pn_io.sync_properties", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_sync_frame_address,
      { "SyncFrameAddress", "pn_io.sync_frame_address", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_timeout_factor,
      { "PTCPTimeoutFactor", "pn_io.ptcp_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_takeover_timeout_factor,
      { "PTCPTakeoverTimeoutFactor", "pn_io.ptcp_takeover_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_master_startup_time,
      { "PTCPMasterStartupTime", "pn_io.ptcp_master_startup_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_master_priority_1,
      { "PTCP_MasterPriority1", "pn_io.ptcp_master_priority_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_master_priority_2,
      { "PTCP_MasterPriority2", "pn_io.ptcp_master_priority_2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_length_subdomain_name,
      { "PTCPLengthSubdomainName", "pn_io.ptcp_length_subdomain_name", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ptcp_subdomain_name,
      { "PTCPSubdomainName", "pn_io.ptcp_subdomain_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifInOctets,
      { "ifInOctets", "pn_io.ifInOctets", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifOutOctets,
      { "ifOutOctets", "pn_io.ifOutOctets", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifInDiscards,
      { "ifInDiscards", "pn_io.ifInDiscards", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifOutDiscards,
      { "ifOutDiscards", "pn_io.ifOutDiscards", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifInErrors,
      { "ifInErrors", "pn_io.ifInErrors", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_pdportstatistic_ifOutErrors,
      { "ifOutErrors", "pn_io.ifOutErrors", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_domain_boundary,
      { "DomainBoundary", "pn_io.domain_boundary", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_domain_boundary_ingress,
      { "DomainBoundaryIngress", "pn_io.domain_boundary.ingress", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_domain_boundary_egress,
      { "DomainBoundaryEgress", "pn_io.domain_boundary.egress", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_multicast_boundary,
      { "MulticastBoundary", "pn_io.multicast_boundary", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_adjust_properties,
      { "AdjustProperties", "pn_io.adjust_properties", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_PreambleLength,
      { "Preamble Length", "pn_io.preamble_length", FT_UINT16, BASE_HEX, VALS(pn_io_preamble_length), 0x0, NULL, HFILL }},
    { &hf_pn_io_mau_type,
      { "MAUType", "pn_io.mau_type", FT_UINT16, BASE_HEX, VALS(pn_io_mau_type), 0x0, NULL, HFILL }},
    { &hf_pn_io_mau_type_mode,
      { "MAUTypeMode", "pn_io.mau_type_mode", FT_UINT16, BASE_HEX, VALS(pn_io_mau_type_mode), 0x0, NULL, HFILL }},
    { &hf_pn_io_port_state,
      { "PortState", "pn_io.port_state", FT_UINT16, BASE_HEX, VALS(pn_io_port_state), 0x0, NULL, HFILL }},
    { &hf_pn_io_line_delay,
      { "LineDelay", "pn_io.line_delay", FT_UINT32, BASE_DEC, NULL, 0x0, "LineDelay in nanoseconds", HFILL }},
    { &hf_pn_io_number_of_peers,
      { "NumberOfPeers", "pn_io.number_of_peers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_peer_port_id,
      { "LengthPeerPortID", "pn_io.length_peer_port_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_peer_port_id,
      { "PeerPortID", "pn_io.peer_port_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_peer_chassis_id,
      { "LengthPeerChassisID", "pn_io.length_peer_chassis_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_peer_chassis_id,
      { "PeerChassisID", "pn_io.peer_chassis_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_own_chassis_id,
      { "LengthOwnChassisID", "pn_io.length_own_chassis_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_own_chassis_id,
      { "OwnChassisID", "pn_io.own_chassis_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_own_port_id,
      { "LengthOwnPortID", "pn_io.length_own_port_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_own_port_id,
      { "OwnPortID", "pn_io.own_port_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_peer_macadd,
      { "PeerMACAddress", "pn_io.peer_macadd", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_macadd,
      { "MACAddress", "pn_io.macadd", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_media_type,
      { "MediaType", "pn_io.media_type", FT_UINT32, BASE_HEX, VALS(pn_io_media_type), 0x0, NULL, HFILL }},

    { &hf_pn_io_ethertype,
      { "Ethertype", "pn_io.ethertype", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_rx_port,
      { "RXPort", "pn_io.rx_port", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_frame_details,
      { "FrameDetails", "pn_io.frame_details", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_frame_details_sync_frame,
      { "SyncFrame", "pn_io.frame_details.sync_frame", FT_UINT8, BASE_HEX, VALS(pn_io_frame_details_sync_master_vals), 0x03, NULL, HFILL }},
    { &hf_pn_io_frame_details_meaning_frame_send_offset,
      { "Meaning", "pn_io.frame_details.meaning_frame_send_offset", FT_UINT8, BASE_HEX, VALS(pn_io_frame_details_meaning_frame_send_offset_vals), 0x0C, NULL, HFILL }},
    { &hf_pn_io_frame_details_reserved,
      { "Reserved", "pn_io.frame_details.reserved", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
    { &hf_pn_io_nr_of_tx_port_groups,
      { "NumberOfTxPortGroups", "pn_io.nr_of_tx_port_groups", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties,
      { "TxPortGroupProperties", "pn_io.tx_port_properties", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit0,
      { "TxPortLocal", "pn_io.tx_port_properties_bit_0", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x01, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit1,
      { "TxPort_1", "pn_io.tx_port_properties_bit_1", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x02, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit2,
      { "TxPort_2", "pn_io.tx_port_properties_bit_2", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x04, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit3,
      { "TxPort_3", "pn_io.tx_port_properties_bit_3", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x08, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit4,
      { "TxPort_4", "pn_io.tx_port_properties_bit_4", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x10, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit5,
      { "TxPort_5", "pn_io.tx_port_properties_bit_5", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x20, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit6,
      { "TxPort_6", "pn_io.tx_port_properties_bit_6", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x40, NULL, HFILL }},
    { &hf_pn_io_TxPortGroupProperties_bit7,
      { "TxPort_7", "pn_io.tx_port_properties_bit_7", FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x80, NULL, HFILL }},

    { &hf_pn_io_start_of_red_frame_id,
      { "StartOfRedFrameID", "pn_io.start_of_red_frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_end_of_red_frame_id,
      { "EndOfRedFrameID", "pn_io.end_of_red_frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_ir_begin_end_port,
      { "Port", "pn_io.ir_begin_end_port", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_assignments,
      { "NumberOfAssignments", "pn_io.number_of_assignments", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_phases,
      { "NumberOfPhases", "pn_io.number_of_phases", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_red_orange_period_begin,
      { "RedOrangePeriodBegin", "pn_io.red_orange_period_begin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_orange_period_begin,
      { "OrangePeriodBegin", "pn_io.orange_period_begin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_green_period_begin,
      { "GreenPeriodBegin", "pn_io.green_period_begin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_tx_phase_assignment,
      { "TXPhaseAssignment", "pn_io.tx_phase_assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_rx_phase_assignment,
      { "RXPhaseAssignment", "pn_io.rx_phase_assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_slot,
      { "Slot", "pn_io.slot", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_subslot,
      { "Subslot", "pn_io.subslot", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_slots,
      { "NumberOfSlots", "pn_io.number_of_slots", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_subslots,
      { "NumberOfSubslots", "pn_io.number_of_subslots", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_maintenance_required_drop_budget,
      { "MaintenanceRequiredDropBudget", "pn_io.maintenance_required_drop_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_maintenance_demanded_drop_budget,
      { "MaintenanceDemandedDropBudget", "pn_io.maintenance_demanded_drop_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_error_drop_budget,
      { "ErrorDropBudget", "pn_io.error_drop_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_maintenance_required_power_budget,
      { "MaintenanceRequiredPowerBudget", "pn_io.maintenance_required_power_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_maintenance_demanded_power_budget,
      { "MaintenanceDemandedPowerBudget", "pn_io.maintenance_demanded_power_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_error_power_budget,
      { "ErrorPowerBudget", "pn_io.error_power_budget", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_fiber_optic_type,
      { "FiberOpticType", "pn_io.fiber_optic_type", FT_UINT32, BASE_HEX, VALS(pn_io_fiber_optic_type), 0x0, NULL, HFILL }},
    { &hf_pn_io_fiber_optic_cable_type,
      { "FiberOpticCableType", "pn_io.fiber_optic_cable_type", FT_UINT32, BASE_HEX, VALS(pn_io_fiber_optic_cable_type), 0x0, NULL, HFILL }},

    { &hf_pn_io_controller_appl_cycle_factor,
      { "ControllerApplicationCycleFactor", "pn_io.controller_appl_cycle_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_time_data_cycle,
      { "TimeDataCycle", "pn_io.time_data_cycle", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_time_io_input,
      { "TimeIOInput", "pn_io.time_io_input", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_time_io_output,
      { "TimeIOOutput", "pn_io.time_io_output", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_time_io_input_valid,
      { "TimeIOInputValid", "pn_io.time_io_input_valid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_time_io_output_valid,
      { "TimeIOOutputValid", "pn_io.time_io_output_valid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_maintenance_status,
      { "MaintenanceStatus", "pn_io.maintenance_status", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_maintenance_status_required,
      { "Required", "pn_io.maintenance_status_required", FT_UINT32, BASE_HEX, NULL, 0x0001, NULL, HFILL }},
    { &hf_pn_io_maintenance_status_demanded,
      { "Demanded", "pn_io.maintenance_status_demanded", FT_UINT32, BASE_HEX, NULL, 0x0002, NULL, HFILL }},


    { &hf_pn_io_vendor_id_high,
      { "VendorIDHigh", "pn_io.vendor_id_high", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_vendor_id_low,
      { "VendorIDLow", "pn_io.vendor_id_low", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_vendor_block_type,
      { "VendorBlockType", "pn_io.vendor_block_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_order_id,
    { "OrderID", "pn_io.order_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_serial_number,
    { "IMSerialNumber", "pn_io.im_serial_number", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_hardware_revision,
      { "IMHardwareRevision", "pn_io.im_hardware_revision", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

      /* XXX - better use a simple char here -> vals */
    { &hf_pn_io_im_revision_prefix,
      { "IMRevisionPrefix", "pn_io.im_revision_prefix", FT_UINT8, BASE_HEX, VALS(pn_io_im_revision_prefix_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_im_sw_revision_functional_enhancement,
      { "IMSWRevisionFunctionalEnhancement", "pn_io.im_sw_revision_functional_enhancement", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_revision_bugfix,
      { "IM_SWRevisionBugFix", "pn_io.im_revision_bugfix", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_sw_revision_internal_change,
      { "IMSWRevisionInternalChange", "pn_io.im_sw_revision_internal_change", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_revision_counter,
      { "IMRevisionCounter", "pn_io.im_revision_counter", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_profile_id,
      { "IMProfileID", "pn_io.im_profile_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_profile_specific_type,
      { "IMProfileSpecificType", "pn_io.im_profile_specific_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_version_major,
      { "IMVersionMajor", "pn_io.im_version_major", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_version_minor,
      { "IMVersionMinor", "pn_io.im_version_minor", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_supported,
      { "IM_Supported", "pn_io.im_supported", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_number_of_ars,
      { "NumberOfARs", "pn_io.number_of_ars", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_cycle_counter,
      { "CycleCounter", "pn_io.cycle_counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_data_status,
      { "DataStatus", "pn_io.ds", FT_UINT8, BASE_HEX, 0, 0x0, NULL, HFILL }},
    { &hf_pn_io_data_status_res67,
      { "Reserved (should be zero)", "pn_io.ds_res67", FT_UINT8, BASE_HEX, 0, 0xc0, NULL, HFILL }},
    { &hf_pn_io_data_status_ok,
      { "StationProblemIndicator (1:Ok/0:Problem)", "pn_io.ds_ok", FT_UINT8, BASE_HEX, 0, 0x20, NULL, HFILL }},
    { &hf_pn_io_data_status_operate,
      { "ProviderState (1:Run/0:Stop)", "pn_io.ds_operate", FT_UINT8, BASE_HEX, 0, 0x10, NULL, HFILL }},
    { &hf_pn_io_data_status_res3,
      { "Reserved (should be zero)", "pn_io.ds_res3", FT_UINT8, BASE_HEX, 0, 0x08, NULL, HFILL }},
    { &hf_pn_io_data_status_valid,
      { "DataValid (1:Valid/0:Invalid)", "pn_io.ds_valid", FT_UINT8, BASE_HEX, 0, 0x04, NULL, HFILL }},
    { &hf_pn_io_data_status_res1,
	  { "primary AR of a given AR-set is present (0:One/ 1:None)", "pn_io.ds_res1", FT_UINT8, BASE_HEX, 0, 0x02, NULL, HFILL }},
    { &hf_pn_io_data_status_primary,
      { "State (1:Primary/0:Backup)", "pn_io.ds_primary", FT_UINT8, BASE_HEX, 0, 0x01, NULL, HFILL }},
    { &hf_pn_io_transfer_status,
      { "TransferStatus", "pn_io.transfer_status", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_actual_local_time_stamp,
      { "ActualLocalTimeStamp", "pn_io.actual_local_time_stamp", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_local_time_stamp,
      { "LocalTimeStamp", "pn_io.local_time_stamp", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_number_of_log_entries,
      { "NumberOfLogEntries", "pn_io.number_of_log_entries", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_entry_detail,
      { "EntryDetail", "pn_io.entry_detail", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_ip_address,
        { "IPAddress", "pn_io.ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_subnetmask,
        { "Subnetmask", "pn_io.subnetmask", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_standard_gateway,
        { "StandardGateway", "pn_io.standard_gateway", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_mrp_domain_uuid,
      { "MRP_DomainUUID", "pn_io.mrp_domain_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_role,
      { "MRP_Role", "pn_io.mrp_role", FT_UINT16, BASE_HEX, VALS(pn_io_mrp_role_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_length_domain_name,
        { "MRP_LengthDomainName", "pn_io.mrp_length_domain_name", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_domain_name,
        { "MRP_DomainName", "pn_io.mrp_domain_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_mrp_prio,
        { "MRP_Prio", "pn_io.mrp_prio", FT_UINT16, BASE_HEX, VALS(pn_io_mrp_prio_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_topchgt,
        { "MRP_TOPchgT", "pn_io.mrp_topchgt", FT_UINT16, BASE_DEC, NULL, 0x0, "time base 10ms", HFILL }},
    { &hf_pn_io_mrp_topnrmax,
        { "MRP_TOPNRmax", "pn_io.mrp_topnrmax", FT_UINT16, BASE_DEC, NULL, 0x0, "number of iterations", HFILL }},
    { &hf_pn_io_mrp_tstshortt,
        { "MRP_TSTshortT", "pn_io.mrp_tstshortt", FT_UINT16, BASE_DEC, NULL, 0x0, "time base 1 ms", HFILL }},
    { &hf_pn_io_mrp_tstdefaultt,
        { "MRP_TSTdefaultT", "pn_io.mrp_tstdefaultt", FT_UINT16, BASE_DEC, NULL, 0x0, "time base 1ms", HFILL }},
    { &hf_pn_io_mrp_tstnrmax,
        { "MRP_TSTNRmax", "pn_io.mrp_tstnrmax", FT_UINT16, BASE_DEC, NULL, 0x0, "number of outstanding test indications causes ring failure", HFILL }},
    { &hf_pn_io_mrp_check,
        { "MRP_Check", "pn_io.mrp_check", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_mrp_rtmode,
        { "MRP_RTMode", "pn_io.mrp_rtmode", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_rtmode_rtclass12,
        { "RTClass1_2", "pn_io.mrp_rtmode.class1_2", FT_UINT32, BASE_HEX, VALS(pn_io_mrp_rtmode_rtclass12_vals), 0x00000001, NULL, HFILL }},
    { &hf_pn_io_mrp_rtmode_rtclass3,
        { "RTClass1_3", "pn_io.mrp_rtmode.class3", FT_UINT32, BASE_HEX, VALS(pn_io_mrp_rtmode_rtclass3_vals), 0x00000002, NULL, HFILL }},
    { &hf_pn_io_mrp_rtmode_reserved1,
        { "Reserved_1", "pn_io.mrp_rtmode.reserved_1", FT_UINT32, BASE_HEX, NULL, 0x00fffffc, NULL, HFILL }},
    { &hf_pn_io_mrp_rtmode_reserved2,
        { "Reserved_2", "pn_io.mrp_rtmode.reserved_2", FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL }},

    { &hf_pn_io_mrp_lnkdownt,
        { "MRP_LNKdownT", "pn_io.mrp_lnkdownt", FT_UINT16, BASE_HEX, NULL, 0x0, "Link down Interval in ms", HFILL }},
    { &hf_pn_io_mrp_lnkupt,
        { "MRP_LNKupT", "pn_io.mrp_lnkupt", FT_UINT16, BASE_HEX, NULL, 0x0, "Link up Interval in ms", HFILL }},
    { &hf_pn_io_mrp_lnknrmax,
        { "MRP_LNKNRmax", "pn_io.mrp_lnknrmax", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_version,
        { "MRP_Version", "pn_io.mrp_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_substitute_active_flag,
        { "SubstituteActiveFlag", "pn_io.substitute_active_flag", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_length_data,
        { "LengthData", "pn_io.length_data", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_mrp_ring_state,
        { "MRP_RingState", "pn_io.mrp_ring_state", FT_UINT16, BASE_HEX, VALS(pn_io_mrp_ring_state_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_mrp_rt_state,
        { "MRP_RTState", "pn_io.mrp_rt_state", FT_UINT16, BASE_HEX, VALS(pn_io_mrp_rt_state_vals), 0x0, NULL, HFILL }},

    { &hf_pn_io_im_tag_function,
        { "IM_Tag_Function", "pn_io.im_tag_function", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_tag_location,
        { "IM_Tag_Location", "pn_io.im_tag_location", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_date,
        { "IM_Date", "pn_io.im_date", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_im_descriptor,
        { "IM_Descriptor", "pn_io.im_descriptor", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_fs_hello_mode,
        { "FSHelloMode", "pn_io.fs_hello_mode", FT_UINT32, BASE_HEX, VALS(pn_io_fs_hello_mode_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_fs_hello_interval,
        { "FSHelloInterval", "pn_io.fs_hello_interval", FT_UINT32, BASE_DEC, NULL, 0x0, "ms before conveying a second DCP_Hello.req", HFILL }},
    { &hf_pn_io_fs_hello_retry,
        { "FSHelloRetry", "pn_io.fs_hello_retry", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_fs_hello_delay,
        { "FSHelloDelay", "pn_io.fs_hello_delay", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_fs_parameter_mode,
        { "FSParameterMode", "pn_io.fs_parameter_mode", FT_UINT32, BASE_HEX, VALS(pn_io_fs_parameter_mode_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_fs_parameter_uuid,
        { "FSParameterUUID", "pn_io.fs_parameter_uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_io_check_sync_mode,
      { "CheckSyncMode", "pn_io.check_sync_mode", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_check_sync_mode_reserved,
      { "Reserved", "pn_io.check_sync_mode.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFFC, NULL, HFILL }},
    { &hf_pn_io_check_sync_mode_sync_master,
      { "SyncMaster", "pn_io.check_sync_mode.sync_master", FT_UINT16, BASE_HEX, NULL, 0x0002, NULL, HFILL }},
    { &hf_pn_io_check_sync_mode_cable_delay,
      { "CableDelay", "pn_io.check_sync_mode.cable_delay", FT_UINT16, BASE_HEX, NULL, 0x0001, NULL, HFILL }},

    /* profisafe parameter */
    { &hf_pn_io_profisafe_f_prm_flag1,
      { "F_Prm_Flag1", "pn_io.profisafe.f_prm_flag1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag1_chck_seq,
      { "F_Check_SeqNr", "pn_io.profisafe.f_prm_flag1.f_check_seqnr", FT_UINT8, BASE_HEX, VALS(pn_io_f_check_seqnr), 0x01, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag1_chck_ipar,
      { "F_Check_iPar", "pn_io.profisafe.f_prm_flag1.f_check_ipar", FT_UINT8, BASE_HEX, VALS(pn_io_f_check_ipar), 0x02, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag1_sil,
      { "F_SIL", "pn_io.profisafe.f_prm_flag1.f_sil", FT_UINT8, BASE_HEX, VALS(pn_io_f_sil), 0xc, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag1_crc_len,
      { "F_CRC_Length", "pn_io.profisafe.f_prm_flag1.f_crc_len", FT_UINT8, BASE_HEX, VALS(pn_io_f_crc_len), 0x30, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag1_reserved,
      { "Reserved", "pn_io.profisafe.f_prm_flag1.reserved", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag2,
      { "F_Prm_Flag2", "pn_io.profisafe.f_prm_flag2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag2_reserved,
      { "Reserved", "pn_io.profisafe.f_prm_flag2.reserved", FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag2_f_block_id,
      { "F_BlockId", "pn_io.profisafe.f_prm_flag2.f_block_id", FT_UINT8, BASE_HEX, VALS(pn_io_f_block_id), 0x38, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_prm_flag2_f_par_version,
      { "F_ParVersion", "pn_io.profisafe.f_prm_flag2.f_par_version", FT_UINT8, BASE_HEX, VALS(pn_io_f_par_version), 0xC0, NULL, HFILL }},
      { &hf_pn_io_profisafe_f_src_addr,
      { "F_Source_Address", "pn_io.profisafe.f_src_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_dst_addr,
      { "F_Destination_Address", "pn_io.profisafe.f_dst_addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_wd_time,
      { "F_WD_Time", "pn_io.profisafe._f_wd_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profisafe_f_par_crc,
      { "F_Par_CRC", "pn_io.profisafe._f_par_crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    /* profidrive parameter access */
    { &hf_pn_io_profidrive_request_reference,
      { "RequestReference", "pn_io.profidrive.parameter.request_reference", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_request_id,
      { "RequestID", "pn_io.profidrive.parameter.request_id", FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_request_id_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_do_id,
      { "DO", "pn_io.profidrive.parameter.do", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_no_of_parameters,
      { "NoOfParameters", "pn_io.profidrive.parameter.no_of_parameters", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_attribute,
      { "Attribute", "pn_io.profidrive.parameter.attribute", FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_attribute_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_no_of_elems,
      { "NoOfElements", "pn_io.profidrive.parameter.no_of_elems", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_number,
      { "Parameter", "pn_io.profidrive.parameter.number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_subindex,
      { "Index", "pn_io.profidrive.parameter.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_response_id,
      { "ResponseID", "pn_io.profidrive.parameter.response_id", FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_response_id_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_format,
      { "Format", "pn_io.profidrive.parameter.format", FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_format_vals), 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_no_of_values,
      { "NoOfValues", "pn_io.profidrive.parameter.no_of_values", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_profidrive_param_value,
      { "Value", "pn_io.profidrive.parameter.value", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_io_packedframe_SFCRC,
      { "SFCRC16", "pn_io.packedframe.sfcrc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_pn_io,
        &ett_pn_io_block,
        &ett_pn_io_block_header,
        &ett_pn_io_status,
        &ett_pn_io_rtc,
        &ett_pn_io_rta,
        &ett_pn_io_pdu_type,
        &ett_pn_io_add_flags,
        &ett_pn_io_control_command,
        &ett_pn_io_ioxs,
        &ett_pn_io_api,
        &ett_pn_io_data_description,
        &ett_pn_io_module,
        &ett_pn_io_submodule,
        &ett_pn_io_io_data_object,
        &ett_pn_io_io_cs,
        &ett_pn_io_ar_properties,
        &ett_pn_io_iocr_properties,
        &ett_pn_io_submodule_properties,
        &ett_pn_io_alarmcr_properties,
        &ett_pn_io_submodule_state,
        &ett_pn_io_channel_properties,
        &ett_pn_io_slot,
        &ett_pn_io_subslot,
        &ett_pn_io_maintenance_status,
        &ett_pn_io_data_status,
        &ett_pn_io_iocr,
        &ett_pn_io_mrp_rtmode,
        &ett_pn_io_control_block_properties,
        &ett_pn_io_check_sync_mode,
        &ett_pn_io_ir_frame_data,
        &ett_pn_io_ar_info,
        &ett_pn_io_ar_data,
        &ett_pn_io_ir_begin_end_port,
        &ett_pn_io_subframe_data,
        &ett_pn_io_frame_defails,
        &ett_pn_io_profisafe_f_parameter,
        &ett_pn_io_profisafe_f_parameter_prm_flag1,
        &ett_pn_io_profisafe_f_parameter_prm_flag2,
        &ett_pn_io_profidrive_parameter_request,
        &ett_pn_io_profidrive_parameter_response,
        &ett_pn_io_profidrive_parameter_address,
        &ett_pn_io_profidrive_parameter_value,
        &ett_pn_io_GroupProperties
    };

    proto_pn_io = proto_register_protocol ("PROFINET IO", "PNIO", "pn_io");
    proto_register_field_array (proto_pn_io, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    /* subdissector code */
    new_register_dissector("pn_io", dissect_PNIO_heur, proto_pn_io);
    register_heur_dissector_list("pn_io", &heur_pn_subdissector_list);

    register_init_routine(pnio_reinit);

    register_dissector_filter("PN-IO AR", pn_io_ar_conv_valid, pn_io_ar_conv_filter);
    register_dissector_filter("PN-IO AR (with data)", pn_io_ar_conv_valid, pn_io_ar_conv_data_filter);
}

void
proto_reg_handoff_pn_io (void)
{
    /* Register the protocols as dcerpc */
    dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_device, ver_pn_io_device, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_controller, ver_pn_io_controller, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_supervisor, ver_pn_io_supervisor, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io, ett_pn_io, &uuid_pn_io_parameterserver, ver_pn_io_parameterserver, pn_io_dissectors, hf_pn_io_opnum);

    heur_dissector_add("pn_rt", dissect_PNIO_heur, proto_pn_io);
}
