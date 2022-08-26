/* packet-dcerpc-pn-io.c
 * Routines for PROFINET IO dissection.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * (like establishing, ...) and is using DCE-RPC as its underlying
 * protocol.
 *
 * The actual cyclic data transfer and acyclic notification uses the
 * "lightweight" PN-RT protocol.
 *
 * There are some other related PROFINET protocols (e.g. PN-DCP, which is
 * handling addressing topics).
 *
 * Please note: the PROFINET CBA protocol is independent of the PN-IO protocol!
 */

/*
 * Cyclic PNIO RTC1 Data Dissection:
 *
 * To dissect cyclic PNIO RTC1 frames, this plug-in has to collect important module
 * information out of "Ident OK", "Connect Request" and "Write Response"
 * frames first. This information will be used within "packet-pn-rtc-one.c" to
 * dissect PNIO and PROFIsafe RTC1 frames.
 *
 * The data of Stationname-, -type and -id will be gained out of
 * packet-pn-dcp.c. The header packet-pn.h will save those data.
 *
 * Overview for cyclic PNIO RTC1 data dissection functions:
 *   -> dissect_IOCRBlockReq_block     (Save amount of IODataObjects, IOCS)
 *   -> dissect_DataDescription        (Save important values for cyclic data)
 *   -> dissect_ExpectedSubmoduleBlockReq_block    (Get GSD information)
 *   -> dissect_ModuleDiffBlock_block  (Module has different ID)
 *   -> dissect_ProfiSafeParameterRequest  (Save PROFIsafe parameters)
 *   -> dissect_RecordDataWrite        (Call ProfiSafeParameterRequest)
 *   -> pnio_rtc1_cleanup              (Reset routine of saved RTC1 information)
 */


#include "config.h"

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/expert.h>
#include <epan/conversation_filter.h>
#include <epan/proto_data.h>

#include <wsutil/file_util.h>
#include <epan/prefs.h>

#include "packet-pn.h"

#include <stdio.h>
#include <stdlib.h>

void proto_register_pn_io(void);
void proto_reg_handoff_pn_io(void);


#define MAX_NAMELENGTH           200    /* max. length of the given paths */
#define F_MESSAGE_TRAILER_4BYTE  4      /* PROFIsafe: Defines the Amount of Bytes for CRC and Status-/Controlbyte */
#define PN_INPUT_CR              1      /* PROFINET Input Connect Request value */
#define PN_INPUT_DATADESCRITPION 1      /* PROFINET Input Data Description value */

#define PA_PROFILE_API 0x9700u
#define PA_PROFILE_DAP_MASK 0xFFFF0000u
#define PA_PROFILE_DAP_IDENT 0x00FD0000u

#define PA_PROFILE_BLOCK_DAP 0u
#define PA_PROFILE_BLOCK_PB 1u
#define PA_PROFILE_BLOCK_FB 2u
#define PA_PROFILE_BLOCK_TB 3u

#define PA_PROFILE_TB_PARENT_PRESSURE 1u
#define PA_PROFILE_TB_PARENT_TEMPERATURE 2u
#define PA_PROFILE_TB_PARENT_FLOW 3u
#define PA_PROFILE_TB_PARENT_LEVEL 1u
#define PA_PROFILE_TB_PARENT_ACTUATOR 1u
#define PA_PROFILE_TB_PARENT_DISCRETE_IO 1u
#define PA_PROFILE_TB_PARENT_LIQUID_ANALYZER 1u
#define PA_PROFILE_TB_PARENT_GAS_ANALYZER 1u
#define PA_PROFILE_TB_PARENT_ENUMERATED_IO 1u
#define PA_PROFILE_TB_PARENT_BINARY_IO 1u



static int proto_pn_io = -1;
static int proto_pn_io_device = -1;
static int proto_pn_io_controller = -1;
static int proto_pn_io_supervisor = -1;
static int proto_pn_io_parameterserver = -1;
static int proto_pn_io_implicitar = -1;
int proto_pn_io_apdu_status = -1;
int proto_pn_io_time_aware_status = -1;

static int hf_pn_io_opnum = -1;
static int hf_pn_io_reserved16 = -1;

static int hf_pn_io_array = -1;
static int hf_pn_io_args_max = -1;
static int hf_pn_io_args_len = -1;
static int hf_pn_io_array_max_count = -1;
static int hf_pn_io_array_offset = -1;
static int hf_pn_io_array_act_count = -1;

static int hf_pn_io_ar_type = -1;
static int hf_pn_io_artype_req = -1;
static int hf_pn_io_cminitiator_macadd = -1;
static int hf_pn_io_cminitiator_objectuuid = -1;
static int hf_pn_io_parameter_server_objectuuid = -1;
static int hf_pn_io_ar_data = -1;
static int hf_pn_io_ar_properties = -1;
static int hf_pn_io_ar_properties_state = -1;
static int hf_pn_io_ar_properties_supervisor_takeover_allowed = -1;
static int hf_pn_io_ar_properties_parameterization_server = -1;
/* removed within 2.3
static int hf_pn_io_ar_properties_data_rate = -1;
*/
static int hf_pn_io_ar_properties_reserved_1 = -1;
static int hf_pn_io_ar_properties_device_access = -1;
static int hf_pn_io_ar_properties_companion_ar = -1;
static int hf_pn_io_ar_properties_achnowledge_companion_ar = -1;
static int hf_pn_io_ar_properties_reserved = -1;
static int hf_pn_io_ar_properties_time_aware_system = -1;
static int hf_pn_io_ar_properties_combined_object_container_with_legacy_startupmode = -1;
static int hf_pn_io_ar_properties_combined_object_container_with_advanced_startupmode = -1;
static int hf_pn_io_ar_properties_pull_module_alarm_allowed = -1;

static int hf_pn_RedundancyInfo = -1;
static int hf_pn_RedundancyInfo_reserved = -1;
static int hf_pn_io_number_of_ARDATAInfo = -1;

static int hf_pn_io_cminitiator_activitytimeoutfactor = -1;
static int hf_pn_io_cminitiator_udprtport = -1;
static int hf_pn_io_station_name_length = -1;
static int hf_pn_io_cminitiator_station_name = -1;
/* static int hf_pn_io_responder_station_name = -1; */
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
/* static int hf_pn_io_iocr_txports_port = -1; */
/* static int hf_pn_io_iocr_txports_redundantport = -1; */
static int hf_pn_io_sr_properties_Reserved_1 = -1;
static int hf_pn_io_sr_properties_Mode = -1;
static int hf_pn_io_sr_properties_Reserved_2 = -1;
static int hf_pn_io_sr_properties_Reserved_3 = -1;
static int hf_pn_io_RedundancyDataHoldFactor = -1;
static int hf_pn_io_sr_properties = -1;
static int hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_0 = -1;
static int hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_1 = -1;

static int hf_pn_io_arvendor_strucidentifier_if0_low = -1;
static int hf_pn_io_arvendor_strucidentifier_if0_high = -1;
static int hf_pn_io_arvendor_strucidentifier_if0_is8000= -1;
static int hf_pn_io_arvendor_strucidentifier_not0 = -1;

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
static int hf_pn_io_frame_data_properties_forwarding_Mode = -1;
static int hf_pn_io_frame_data_properties_FastForwardingMulticastMACAdd = -1;
static int hf_pn_io_frame_data_properties_FragmentMode = -1;
static int hf_pn_io_frame_data_properties_reserved_1 = -1;
static int hf_pn_io_frame_data_properties_reserved_2 = -1;
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
static int hf_pn_io_SFIOCRProperties_DFPType =-1;
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
static int hf_pn_io_ar_discriminator = -1;
static int hf_pn_io_ar_configid = -1;
static int hf_pn_io_ar_arnumber = -1;
static int hf_pn_io_ar_arresource = -1;
static int hf_pn_io_ar_arreserved = -1;
static int hf_pn_io_ar_selector = -1;
static int hf_pn_io_api_tree = -1;
static int hf_pn_io_module_tree = -1;
static int hf_pn_io_submodule_tree = -1;
static int hf_pn_io_io_data_object = -1;
/* General module information */
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
static int hf_pn_io_control_alarm_sequence_number = -1;
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
static int hf_pn_io_control_block_properties_applready_bit0 = -1;
static int hf_pn_io_control_block_properties_applready_bit1 = -1;
static int hf_pn_io_control_block_properties_applready_otherbits = -1;

/* static int hf_pn_io_AlarmSequenceNumber = -1; */
static int hf_pn_io_control_command_reserved = -1;
static int hf_pn_io_SubmoduleListEntries = -1;

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
static int hf_pn_io_submodule_state_advice = -1;
static int hf_pn_io_submodule_state_maintenance_required = -1;
static int hf_pn_io_submodule_state_maintenance_demanded = -1;
static int hf_pn_io_submodule_state_fault = -1;
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
static int hf_pn_io_ioxs_extension = -1;
static int hf_pn_io_ioxs_res14 = -1;
static int hf_pn_io_ioxs_instance = -1;
static int hf_pn_io_ioxs_datastate = -1;

static int hf_pn_io_address_resolution_properties = -1;
static int hf_pn_io_mci_timeout_factor = -1;
static int hf_pn_io_provider_station_name = -1;

static int hf_pn_io_user_structure_identifier = -1;
static int hf_pn_io_user_structure_identifier_manf = -1;

static int hf_pn_io_channel_number = -1;
static int hf_pn_io_channel_properties = -1;
static int hf_pn_io_channel_properties_type = -1;
static int hf_pn_io_channel_properties_accumulative = -1;
static int hf_pn_io_channel_properties_maintenance = -1;


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
static int hf_pn_io_ext_channel_error_type0x8010 = -1;

static int hf_pn_io_ext_channel_error_type = -1;

static int hf_pn_io_ext_channel_add_value = -1;
static int hf_pn_io_qualified_channel_qualifier = -1;

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

static int hf_pn_io_MultipleInterfaceMode_NameOfDevice = -1;
static int hf_pn_io_MultipleInterfaceMode_reserved_1 = -1;
static int hf_pn_io_MultipleInterfaceMode_reserved_2 = -1;
/* added Portstatistics */
static int hf_pn_io_pdportstatistic_counter_status = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifInOctets = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifOutOctets = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifInDiscards = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifOutDiscards = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifInErrors = -1;
static int hf_pn_io_pdportstatistic_counter_status_ifOutErrors = -1;
static int hf_pn_io_pdportstatistic_counter_status_reserved = -1;
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
static int hf_pn_io_link_state_port = -1;
static int hf_pn_io_link_state_link = -1;
static int hf_pn_io_line_delay = -1;
static int hf_pn_io_line_delay_value = -1;
static int hf_pn_io_cable_delay_value = -1;
static int hf_pn_io_line_delay_format_indicator = -1;
static int hf_pn_io_number_of_peers = -1;
static int hf_pn_io_length_peer_port_id = -1;
static int hf_pn_io_peer_port_id = -1;
static int hf_pn_io_length_peer_chassis_id = -1;
static int hf_pn_io_peer_chassis_id = -1;
static int hf_pn_io_neighbor = -1;
static int hf_pn_io_length_peer_port_name = -1;
static int hf_pn_io_peer_port_name = -1;
static int hf_pn_io_length_peer_station_name = -1;
static int hf_pn_io_peer_station_name = -1;
static int hf_pn_io_length_own_port_id = -1;
static int hf_pn_io_own_port_id = -1;
static int hf_pn_io_peer_macadd = -1;
static int hf_pn_io_media_type = -1;
static int hf_pn_io_macadd = -1;
static int hf_pn_io_length_own_chassis_id = -1;
static int hf_pn_io_own_chassis_id = -1;
static int hf_pn_io_rtclass3_port_status = -1;

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
static int hf_pn_io_red_orange_period_begin_tx = -1;
static int hf_pn_io_orange_period_begin_tx = -1;
static int hf_pn_io_green_period_begin_tx = -1;
static int hf_pn_io_red_orange_period_begin_rx = -1;
static int hf_pn_io_orange_period_begin_rx = -1;
static int hf_pn_io_green_period_begin_rx = -1;
/* static int hf_pn_io_tx_phase_assignment = -1; */
static int hf_pn_ir_tx_phase_assignment = -1;
static int hf_pn_ir_rx_phase_assignment = -1;
static int hf_pn_io_tx_phase_assignment_begin_value = -1;
static int hf_pn_io_tx_phase_assignment_orange_begin = -1;
static int hf_pn_io_tx_phase_assignment_end_reserved = -1;
static int hf_pn_io_tx_phase_assignment_reserved = -1;
/* static int hf_pn_io_rx_phase_assignment = -1; */

static int hf_pn_io_slot = -1;
static int hf_pn_io_subslot = -1;
static int hf_pn_io_number_of_slots = -1;
static int hf_pn_io_number_of_subslots = -1;

/* static int hf_pn_io_maintenance_required_drop_budget = -1; */
/* static int hf_pn_io_maintenance_demanded_drop_budget = -1; */
/* static int hf_pn_io_error_drop_budget = -1; */

static int hf_pn_io_tsn_number_of_queues = -1;
static int hf_pn_io_tsn_max_supported_record_size = -1;
static int hf_pn_io_tsn_transfer_time_tx = -1;
static int hf_pn_io_tsn_transfer_time_rx = -1;
static int hf_pn_io_tsn_port_capabilities_time_aware = -1;
static int hf_pn_io_tsn_port_capabilities_preemption = -1;
static int hf_pn_io_tsn_port_capabilities_queue_masking = -1;
static int hf_pn_io_tsn_port_capabilities_reserved = -1;
static int hf_pn_io_tsn_forwarding_group = -1;
static int hf_pn_io_tsn_forwarding_group_ingress = -1;
static int hf_pn_io_tsn_forwarding_group_egress = -1;
static int hf_pn_io_tsn_stream_class = -1;
static int hf_pn_io_tsn_dependent_forwarding_delay = -1;
static int hf_pn_io_tsn_independent_forwarding_delay = -1;
static int hf_pn_io_tsn_forwarding_delay_block_number_of_entries = -1;
static int hf_pn_io_tsn_expected_neighbor_block_number_of_entries = -1;
static int hf_pn_io_tsn_port_id_block_number_of_entries = -1;

static int hf_pn_io_tsn_nme_parameter_uuid = -1;
static int hf_pn_io_tsn_domain_vid_config = -1;
static int hf_pn_io_tsn_domain_vid_config_stream_high_vid = -1;
static int hf_pn_io_tsn_domain_vid_config_stream_high_red_vid = -1;
static int hf_pn_io_tsn_domain_vid_config_stream_low_vid = -1;
static int hf_pn_io_tsn_domain_vid_config_stream_low_red_vid = -1;
static int hf_pn_io_tsn_domain_vid_config_non_stream_vid = -1;
static int hf_pn_io_tsn_domain_vid_config_non_stream_vid_B = -1;
static int hf_pn_io_tsn_domain_vid_config_non_stream_vid_C = -1;
static int hf_pn_io_tsn_domain_vid_config_non_stream_vid_D = -1;
static int hf_pn_io_tsn_domain_vid_config_reserved = -1;
static int hf_pn_io_number_of_tsn_time_data_block_entries = -1;
static int hf_pn_io_number_of_tsn_domain_queue_rate_limiter_entries = -1;
static int hf_pn_io_number_of_tsn_domain_port_ingress_rate_limiter_entries = -1;
static int hf_pn_io_number_of_tsn_domain_port_config_entries = -1;

static int hf_pn_io_tsn_domain_port_config = -1;
static int hf_pn_io_tsn_domain_port_config_preemption_enabled  = -1;
static int hf_pn_io_tsn_domain_port_config_boundary_port_config = -1;
static int hf_pn_io_tsn_domain_port_config_reserved = -1;

static int hf_pn_io_tsn_domain_port_ingress_rate_limiter = -1;
static int hf_pn_io_tsn_domain_port_ingress_rate_limiter_cir = -1;
static int hf_pn_io_tsn_domain_port_ingress_rate_limiter_cbs = -1;
static int hf_pn_io_tsn_domain_port_ingress_rate_limiter_envelope = -1;
static int hf_pn_io_tsn_domain_port_ingress_rate_limiter_rank = -1;

static int hf_pn_io_tsn_domain_queue_rate_limiter = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_cir = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_cbs = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_envelope = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_rank = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_queue_id = -1;
static int hf_pn_io_tsn_domain_queue_rate_limiter_reserved = -1;

static int hf_pn_io_number_of_tsn_domain_queue_config_entries = -1;
static int hf_pn_io_tsn_domain_queue_config = -1;
static int hf_pn_io_tsn_domain_queue_config_queue_id = -1;
static int hf_pn_io_tsn_domain_queue_config_tci_pcp = -1;
static int hf_pn_io_tsn_domain_queue_config_shaper = -1;
static int hf_pn_io_tsn_domain_queue_config_preemption_mode = -1;
static int hf_pn_io_tsn_domain_queue_config_unmask_time_offset = -1;
static int hf_pn_io_tsn_domain_queue_config_mask_time_offset = -1;

static int hf_pn_io_network_deadline = -1;
static int hf_pn_io_time_domain_number = -1;
static int hf_pn_io_time_pll_window = -1;
static int hf_pn_io_message_interval_factor = -1;
static int hf_pn_io_message_timeout_factor = -1;
static int hf_pn_io_time_sync_properties = -1;
static int hf_pn_io_time_sync_properties_role = -1;
static int hf_pn_io_time_sync_properties_reserved = -1;
static int hf_pn_io_time_domain_uuid = -1;
static int hf_pn_io_time_domain_name_length = -1;
static int hf_pn_io_time_domain_name = -1;
static int hf_pn_io_tsn_nme_name_uuid = -1;
static int hf_pn_io_tsn_nme_name_length = -1;
static int hf_pn_io_tsn_nme_name = -1;
static int hf_pn_io_tsn_domain_uuid = -1;
static int hf_pn_io_tsn_domain_name_length = -1;
static int hf_pn_io_tsn_domain_name = -1;

static int hf_pn_io_tsn_fdb_command = -1;
static int hf_pn_io_tsn_dst_add = -1;

static int hf_pn_io_number_of_tsn_domain_sync_tree_entries = -1;
static int hf_pn_io_tsn_domain_sync_port_role = -1;
static int hf_pn_io_tsn_domain_port_id = -1;

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
static int hf_pn_io_im_numberofentries = -1;
static int hf_pn_io_im_annotation = -1;
static int hf_pn_io_im_order_id = -1;

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
static int hf_pn_io_mrp_instances = -1;
static int hf_pn_io_mrp_instance = -1;

static int hf_pn_io_mrp_prio = -1;
static int hf_pn_io_mrp_topchgt = -1;
static int hf_pn_io_mrp_topnrmax = -1;
static int hf_pn_io_mrp_tstshortt = -1;
static int hf_pn_io_mrp_tstdefaultt = -1;
static int hf_pn_io_mrp_tstnrmax = -1;
static int hf_pn_io_mrp_check = -1;
static int hf_pn_io_mrp_check_mrm = -1;
static int hf_pn_io_mrp_check_mrpdomain = -1;
static int hf_pn_io_mrp_check_reserved_1 = -1;
static int hf_pn_io_mrp_check_reserved_2 = -1;

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

/* PROFIsafe fParameters */
static int hf_pn_io_ps_f_prm_flag1 = -1;
static int hf_pn_io_ps_f_prm_flag1_chck_seq = -1;
static int hf_pn_io_ps_f_prm_flag1_chck_ipar = -1;
static int hf_pn_io_ps_f_prm_flag1_sil = -1;
static int hf_pn_io_ps_f_prm_flag1_crc_len = -1;
static int hf_pn_io_ps_f_prm_flag1_crc_seed = -1;
static int hf_pn_io_ps_f_prm_flag1_reserved = -1;
static int hf_pn_io_ps_f_prm_flag2 = -1;
static int hf_pn_io_ps_f_wd_time = -1;
static int hf_pn_io_ps_f_ipar_crc = -1;
static int hf_pn_io_ps_f_par_crc = -1;
static int hf_pn_io_ps_f_src_adr = -1;
static int hf_pn_io_ps_f_dest_adr = -1;
static int hf_pn_io_ps_f_prm_flag2_reserved = -1;
static int hf_pn_io_ps_f_prm_flag2_f_block_id = -1;
static int hf_pn_io_ps_f_prm_flag2_f_par_version = -1;

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
static int hf_pn_io_profidrive_param_value_byte = -1;
static int hf_pn_io_profidrive_param_value_word = -1;
static int hf_pn_io_profidrive_param_value_dword = -1;
static int hf_pn_io_profidrive_param_value_float = -1;
static int hf_pn_io_profidrive_param_value_string = -1;
static int hf_pn_io_profidrive_param_value_error = -1;
static int hf_pn_io_profidrive_param_value_error_sub = -1;


/* Sequence of Events - Reporting System Alarm/Event Information */
static int hf_pn_io_rs_alarm_info_reserved_0_7 = -1;
static int hf_pn_io_rs_alarm_info_reserved_8_15 = -1;
static int hf_pn_io_rs_alarm_info = -1;
static int hf_pn_io_rs_event_info = -1;
static int hf_pn_io_rs_event_block = -1;
static int hf_pn_io_rs_adjust_block = -1;
static int hf_pn_io_rs_event_data_extension = -1;
static int hf_pn_io_number_of_rs_event_info = -1;
static int hf_pn_io_rs_block_type = -1;
static int hf_pn_io_rs_block_length = -1;
static int hf_pn_io_rs_specifier = -1;
static int hf_pn_io_rs_specifier_sequence = -1;
static int hf_pn_io_rs_specifier_reserved = -1;
static int hf_pn_io_rs_specifier_specifier = -1;
static int hf_pn_io_rs_time_stamp = -1;
static int hf_pn_io_rs_time_stamp_status = -1;
static int hf_pn_io_rs_time_stamp_value = -1;
static int hf_pn_io_rs_minus_error = -1;
static int hf_pn_io_rs_plus_error = -1;
static int hf_pn_io_rs_extension_block_type = -1;
static int hf_pn_io_rs_extension_block_length = -1;
static int hf_pn_io_rs_reason_code = -1;
static int hf_pn_io_rs_reason_code_reason = -1;
static int hf_pn_io_rs_reason_code_detail = -1;
static int hf_pn_io_rs_domain_identification = -1;
static int hf_pn_io_rs_master_identification = -1;
static int hf_pn_io_soe_digital_input_current_value = -1;
static int hf_pn_io_soe_digital_input_current_value_value = -1;
static int hf_pn_io_soe_digital_input_current_value_reserved = -1;
static int hf_pn_io_am_device_identification = -1;
static int hf_pn_io_am_device_identification_device_sub_id = -1;
static int hf_pn_io_am_device_identification_device_id = -1;
static int hf_pn_io_am_device_identification_vendor_id = -1;
static int hf_pn_io_am_device_identification_organization = -1;
static int hf_pn_io_rs_adjust_info = -1;
static int hf_pn_io_soe_max_scan_delay = -1;
static int hf_pn_io_soe_adjust_specifier = -1;
static int hf_pn_io_soe_adjust_specifier_reserved = -1;
static int hf_pn_io_soe_adjust_specifier_incident = -1;
static int hf_pn_io_rs_properties = -1;
static int hf_pn_io_rs_properties_alarm_transport = -1;
static int hf_pn_io_rs_properties_reserved1 = -1;
static int hf_pn_io_rs_properties_reserved2 = -1;

static int hf_pn_io_asset_management_info = -1;
static int hf_pn_io_number_of_asset_management_info = -1;
static int hf_pn_io_im_uniqueidentifier = -1;
static int hf_pn_io_am_location_structure = -1;
static int hf_pn_io_am_location_level_0 = -1;
static int hf_pn_io_am_location_level_1 = -1;
static int hf_pn_io_am_location_level_2 = -1;
static int hf_pn_io_am_location_level_3 = -1;
static int hf_pn_io_am_location_level_4 = -1;
static int hf_pn_io_am_location_level_5 = -1;
static int hf_pn_io_am_location_level_6 = -1;
static int hf_pn_io_am_location_level_7 = -1;
static int hf_pn_io_am_location_level_8 = -1;
static int hf_pn_io_am_location_level_9 = -1;
static int hf_pn_io_am_location_level_10 = -1;
static int hf_pn_io_am_location_level_11 = -1;
static int hf_pn_io_am_location = -1;
static int hf_pn_io_am_location_reserved1 = -1;
static int hf_pn_io_am_location_reserved2 = -1;
static int hf_pn_io_am_location_reserved3 = -1;
static int hf_pn_io_am_location_reserved4 = -1;
static int hf_pn_io_am_location_beginslotnum = -1;
static int hf_pn_io_am_location_beginsubslotnum = -1;
static int hf_pn_io_am_location_endslotnum = -1;
static int hf_pn_io_am_location_endsubslotnum = -1;
static int hf_pn_io_am_software_revision = -1;
static int hf_pn_io_am_hardware_revision = -1;
static int hf_pn_io_am_type_identification = -1;
static int hf_pn_io_am_reserved = -1;

static int hf_pn_io_dcp_boundary_value = -1;
static int hf_pn_io_dcp_boundary_value_bit0 = -1;
static int hf_pn_io_dcp_boundary_value_bit1 = -1;
static int hf_pn_io_dcp_boundary_value_otherbits = -1;

static int hf_pn_io_peer_to_peer_boundary_value = -1;
static int hf_pn_io_peer_to_peer_boundary_value_bit0 = -1;
static int hf_pn_io_peer_to_peer_boundary_value_bit1 = -1;
static int hf_pn_io_peer_to_peer_boundary_value_bit2 = -1;
static int hf_pn_io_peer_to_peer_boundary_value_otherbits = -1;

static int hf_pn_io_mau_type_extension = -1;

static int hf_pn_io_pe_operational_mode = -1;

/* static int hf_pn_io_packedframe_SFCRC = -1; */
static gint ett_pn_io = -1;
static gint ett_pn_io_block = -1;
static gint ett_pn_io_block_header = -1;
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
static gint ett_pn_FrameDataProperties = -1;
static gint ett_pn_io_ar_info = -1;
static gint ett_pn_io_ar_data = -1;
static gint ett_pn_io_ir_begin_end_port = -1;
static gint ett_pn_io_ir_tx_phase = -1;
static gint ett_pn_io_ir_rx_phase = -1;
static gint ett_pn_io_subframe_data =-1;
static gint ett_pn_io_SFIOCRProperties = -1;
static gint ett_pn_io_frame_defails = -1;
static gint ett_pn_io_profisafe_f_parameter = -1;
static gint ett_pn_io_profisafe_f_parameter_prm_flag1 = -1;
static gint ett_pn_io_profisafe_f_parameter_prm_flag2 = -1;
static gint ett_pn_io_profidrive_parameter_request = -1;
static gint ett_pn_io_profidrive_parameter_response = -1;
static gint ett_pn_io_profidrive_parameter_address = -1;
static gint ett_pn_io_profidrive_parameter_value = -1;
static gint ett_pn_io_rs_alarm_info = -1;
static gint ett_pn_io_rs_event_info = -1;
static gint ett_pn_io_rs_event_block = -1;
static gint ett_pn_io_rs_adjust_block = -1;
static gint ett_pn_io_rs_event_data_extension = -1;
static gint ett_pn_io_rs_specifier = -1;
static gint ett_pn_io_rs_time_stamp = -1;
static gint ett_pn_io_am_device_identification = -1;
static gint ett_pn_io_rs_reason_code = -1;
static gint ett_pn_io_soe_digital_input_current_value = -1;
static gint ett_pn_io_rs_adjust_info = -1;
static gint ett_pn_io_soe_adjust_specifier = -1;
static gint ett_pn_io_sr_properties = -1;
static gint ett_pn_io_line_delay = -1;
static gint ett_pn_io_counter_status = -1;
static gint ett_pn_io_neighbor = -1;

static gint ett_pn_io_GroupProperties = -1;

static gint ett_pn_io_asset_management_info = -1;
static gint ett_pn_io_asset_management_block = -1;
static gint ett_pn_io_am_location = -1;

static gint ett_pn_io_dcp_boundary = -1;
static gint ett_pn_io_peer_to_peer_boundary = -1;

static gint ett_pn_io_mau_type_extension = -1;

static gint ett_pn_io_pe_operational_mode = -1;

static gint ett_pn_io_tsn_domain_port_config = -1;
static gint ett_pn_io_tsn_domain_port_ingress_rate_limiter = -1;
static gint ett_pn_io_tsn_domain_queue_rate_limiter = -1;
static gint ett_pn_io_tsn_domain_vid_config = -1;
static gint ett_pn_io_tsn_domain_queue_config = -1;
static gint ett_pn_io_time_sync_properties = -1;
static gint ett_pn_io_tsn_domain_port_id = -1;


#define PD_SUB_FRAME_BLOCK_FIOCR_PROPERTIES_LENGTH 4
#define PD_SUB_FRAME_BLOCK_FRAME_ID_LENGTH 2
#define PD_SUB_FRAME_BLOCK_SUB_FRAME_DATA_LENGTH 4

static expert_field ei_pn_io_block_version = EI_INIT;
static expert_field ei_pn_io_block_length = EI_INIT;
static expert_field ei_pn_io_unsupported = EI_INIT;
static expert_field ei_pn_io_localalarmref = EI_INIT;
static expert_field ei_pn_io_mrp_instances = EI_INIT;
static expert_field ei_pn_io_ar_info_not_found = EI_INIT;
static expert_field ei_pn_io_iocr_type = EI_INIT;
static expert_field ei_pn_io_frame_id = EI_INIT;
static expert_field ei_pn_io_nr_of_tx_port_groups = EI_INIT;
static expert_field ei_pn_io_max_recursion_depth_reached = EI_INIT;

static e_guid_t uuid_pn_io_device = { 0xDEA00001, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_device = 1;

static e_guid_t uuid_pn_io_controller = { 0xDEA00002, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_controller = 1;

static e_guid_t uuid_pn_io_supervisor = { 0xDEA00003, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_supervisor = 1;

static e_guid_t uuid_pn_io_parameterserver = { 0xDEA00004, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_parameterserver = 1;

/* According to specification:
 * Value(UUID): 00000000-0000-0000-0000-000000000000
 * Meaning: Reserved
 * Use: The value NIL indicates the usage of the implicit AR.
 */
static e_guid_t uuid_pn_io_implicitar = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static guint16  ver_pn_io_implicitar = 1;

/* PNIO Preference Variables */
gboolean           pnio_ps_selection = TRUE;
static const char *pnio_ps_networkpath = "";

wmem_list_t       *aruuid_frame_setup_list = NULL;
static wmem_map_t *pnio_time_aware_frame_map = NULL;


/* Allow heuristic dissection */
static heur_dissector_list_t heur_pn_subdissector_list;

static const value_string pn_io_block_type[] = {
    { 0x0000, "Reserved" },
    { 0x0001, "Alarm Notification High"},
    { 0x8001, "Alarm Ack High"},
    { 0x0002, "Alarm Notification Low"},
    { 0x8002, "Alarm Ack Low"},
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
    { 0x0033, "Reserved" },
    { 0x0034, "I&M5Data"},
    { 0x0035, "AssetManagementData"},
    { 0x0036, "AM_FullInformation"},
    { 0x0037, "AM_HardwareOnlyInformation"},
    { 0x0038, "AM_FirmwareOnlyInformation" },
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
    { 0x8106, "ARServerBlockRes"},
    { 0x0107, "SubFrameBlock"},
    { 0x8107, "ARRPCBlockRes"},
    { 0x0108, "ARVendorBlockReq"},
    { 0x8108, "ARVendorBlockRes"},
    { 0x0109, "IRInfoBlock"},
    { 0x010A, "SRInfoBlock"},
    { 0x010B, "ARFSUBlock"},
    { 0x010C, "RSInfoBlock"},
    { 0x0110, "IODControlReq Prm End.req"},
    { 0x8110, "IODControlRes Prm End.rsp"},
    { 0x0111, "IODControlReq Plug Prm End.req"},
    { 0x8111, "IODControlRes Plug Prm End.rsp"},
    { 0x0112, "IOXBlockReq Application Ready.req"},
    { 0x8112, "IOXBlockRes Application Ready.rsp"},
    { 0x0113, "IOXBlockReq Plug Application Ready.req"},
    { 0x8113, "IOXBlockRes Plug Application Ready.rsp"},
    { 0x0114, "IODReleaseReq"},
    { 0x8114, "IODReleaseRes"},
    { 0x0115, "ARRPCServerBlockReq"},
    { 0x8115, "ARRPCServerBlockRes"},
    { 0x0116, "IOXControlReq Ready for Companion.req"},
    { 0x8116, "IOXControlRes Ready for Companion.rsp"},
    { 0x0117, "IOXControlReq Ready for RT_CLASS_3.req"},
    { 0x8117, "IOXControlRes Ready for RT_CLASS_3.rsp"},
    { 0x0118, "PrmBeginReq"},
    { 0x8118, "PrmBeginRes"},
    { 0x0119, "SubmoduleListBlock"},

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
    { 0x0227, "CheckMAUType-Extension"},
    { 0x0228, "Reading real fiber optic diagnosis data"},
    { 0x0229, "AdjustMAUType-Extension"},
    { 0x022A, "PDIRSubframeData"},
    { 0x022B, "SubframeBlock"},
    { 0x022C, "PDPortDataRealExtended"},
    { 0x022D, "PDTimeData"},
    { 0x022E, "PDPortSFPDataCheck"},
    { 0x0230, "PDNCDataCheck"},
    { 0x0231, "MrpInstanceDataAdjust"},
    { 0x0232, "MrpInstanceDataReal"},
    { 0x0233, "MrpInstanceDataCheck"},
    { 0x0234, "PDPortMrpIcDataAdjust"},
    { 0x0235, "PDPortMrpIcDataCheck"},
    { 0x0236, "PDPortMrpIcDataReal"},
    { 0x0240, "PDInterfaceDataReal"},
    { 0x0241, "PDRsiInstances"},
    { 0x0250, "PDInterfaceAdjust"},
    { 0x0251, "PDPortStatistic"},
    { 0x0260, "OwnPort"},
    { 0x0261, "Neighbors"},
    { 0x0270, "TSNNetworkControlDataReal"},
    { 0x0271, "TSNNetworkControlDataAdjust"},
    { 0x0272, "TSNDomainPortConfigBlock"},
    { 0x0273, "TSNDomainQueueConfigBlock"},
    { 0x0274, "TSNTimeDataBlock"},
    { 0x0275, "TSNStreamPathData"},
    { 0x0276, "TSNSyncTreeData"},
    { 0x0277, "TSNUploadNetworkAttributes"},
    { 0x0278, "ForwardingDelayBlock"},
    { 0x0279, "TSNExpectedNetworkAttributes"},
    { 0x027A, "TSNStreamPathDataReal"},
    { 0x027B, "TSNDomainPortIngressRateLimiterBlock"},
    { 0x027C, "TSNDomainQueueRateLimiterBlock"},
    { 0x027D, "TSNPortIDBlock"},
    { 0x027E, "TSNExpectedNeighborBlock" },
    { 0x0300, "PDInterfaceSecurityAdjust"},
    { 0x0400, "MultipleBlockHeader"},
    { 0x0401, "COContainerContent"},
    { 0x0500, "RecordDataReadQuery"},
    { 0x0501, "TSNAddStreamReq"},
    { 0x0502, "TSNAddStreamRsp"},
    { 0x0503, "TSNRemoveStreamReq"},
    { 0x0504, "TSNRemoveStreamRsp"},
    { 0x0505, "TSNRenewStreamReq"},
    { 0x0506, "TSNRenewStreamRsp"},
    { 0x0600, "FSHelloBlock"},
    { 0x0601, "FSParameterBlock"},
    { 0x0602, "FastStartUpBlock"},
    { 0x0608, "PDInterfaceFSUDataAdjust"},
    { 0x0609, "ARFSUDataAdjust"},
    { 0x0700, "AutoConfiguration"},
    { 0x0701, "AutoConfiguration Communication"},
    { 0x0702, "AutoConfiguration Configuration"},
    { 0x0703, "AutoConfiguration Isochronous"},
    { 0x0810, "PE_EntityFilterData"},
    { 0x0811, "PE_EntityStatusData"},
    { 0x0900, "RS_AdjustObserver" },
    { 0x0901, "RS_GetEvent" },
    { 0x0902, "RS_AckEvent" },
    { 0x0A00, "Upload BLOB Query" },
    { 0x0A01, "Upload BLOB" },
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
    { 0x0F05, "Signal a PE_OperationalMode change within PE_EnergySavingStatus" },
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

static const value_string hf_pn_io_frame_data_properties_forwardingMode[] = {
    { 0x00, "absolute mode" },
    { 0x01, "relative mode"},
    { 0, NULL }
};
static const value_string hf_pn_io_frame_data_properties_FFMulticastMACAdd[] = {
    { 0x00, "Use interface MAC destination unicast address" },
    { 0x01, "Use RT_CLASS_3 destination multicast address"},
    { 0x02, "Use FastForwardingMulticastMACAdd"},
    { 0x03, "reserved"},
    { 0, NULL }};

static const value_string hf_pn_io_frame_data_properties_FragMode[] = {
    { 0x00, "No fragmentation" },
    { 0x01, "Fragmentation enabled maximum size for static fragmentation 128 bytes"},
    { 0x02, "Fragmentation enabled maximum size for static fragmentation 256 bytes"},
    { 0x03, "reserved"},
    { 0, NULL }};

static const value_string pn_io_SFIOCRProperties_DFPType_vals[] = {
    { 0x00, "DFP_INBOUND" },
    { 0x01, "DFP_OUTBOUND" },
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

static const value_string pn_io_ioxs[] = {
    { 0x00 /*  0*/, "detected by subslot" },
    { 0x01 /*  1*/, "detected by slot" },
    { 0x02 /*  2*/, "detected by IO device" },
    { 0x03 /*  3*/, "detected by IO controller" },
    { 0, NULL }
};


static const value_string pn_io_ar_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "IO Controller AR"},
    { 0x0002, "reserved" },
    { 0x0003, "IOCARCIR" },
    { 0x0004, "reserved" },
    { 0x0005, "reserved" },
    { 0x0006, "IO Supervisor AR / DeviceAccess AR" },
    /*0x0007 - 0x000F reserved */
    { 0x0010, "IO Controller AR (RT_CLASS_3)" },
    /*0x0011 - 0x001F reserved */
    { 0x0020, "IO Controller AR (sysred/CiR)" },
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

static const value_string pn_io_arproperties_parameterization_server[] = {
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

/* Bit 28 */
static const value_string pn_io_arproperties_time_aware_system[] = {
    { 0x00000000, "NonTimeAware" },
    { 0x00000001, "TimeAware" },
    { 0, NULL }
};

/* bit 29 for legacy startup mode*/
static const value_string pn_io_arproperties_combined_object_container_with_legacy_startupmode[] = {
    { 0x00000000, "CombinedObjectContainer not used" },
    { 0x00000001, "Reserved" },
    { 0, NULL }
};

/* bit 29 for advanced statup mode*/
static const value_string pn_io_arproperties_combined_object_container_with_advanced_startupmode[] = {
    { 0x00000000, "CombinedObjectContainer not used" },
    { 0x00000001, "Usage of CombinedObjectContainer required" },
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

static const value_string pn_io_MultipleInterfaceMode_NameOfDevice[] = {
    { 0x00000000, "PortID of LLDP contains name of port (Default)" },
    { 0x00000001, "PortID of LLDP contains name of port and NameOfStation" },
    { 0, NULL }
};

static const true_false_string tfs_pn_io_sr_properties_BackupAR_with_SRProperties_Mode_0 =
    { "The device shall deliver valid input data", "The IO controller shall not evaluate the input data." };

static const true_false_string tfs_pn_io_sr_properties_BackupAR_with_SRProperties_Mode_1 =
    { "The device shall deliver valid input data", "The IO device shall mark the data as invalid using APDU_Status.DataStatus.DataValid == Invalid." };

static const true_false_string tfs_pn_io_sr_properties_Mode =
    { "Default The IO device shall use APDU_Status.DataStatus.DataValid == Invalid if input data is request as not valid.",
      "The IO controller do not support APDU_Status.DataStatus.DataValid == Invalid if input data is request as not valid." };

static const true_false_string tfs_pn_io_sr_properties_Reserved1 =
    { "Legacy mode", "Shall be set to zero for this standard." };

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

static const value_string pn_io_submodule_state_advice[] = {
    { 0x0000, "No Advice available" },
    { 0x0001, "Advice available" },
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

static const value_string pn_io_submodule_state_fault[] = {
    { 0x0000, "No Fault available" },
    { 0x0001, "Fault available" },
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
    /*0x801F reserved */
    { 0x8020, "PDIRSubframeData for one subslot" },
    /*0x8021 - 0x8026 reserved */
    { 0x8027, "PDPortDataRealExtended for one subslot" },
    { 0x8028, "RecordInputDataObjectElement for one subslot" },
    { 0x8029, "RecordOutputDataObjectElement for one subslot" },
    { 0x802A, "PDPortDataReal for one subslot" },
    { 0x802B, "PDPortDataCheck for one subslot" },
    { 0x802C, "PDIRData for one subslot" },
    { 0x802D, "PDSyncData for one subslot with SyncID value 0" },
    /*0x802E reserved */
    { 0x802F, "PDPortDataAdjust for one subslot" },
    { 0x8030, "IsochronousModeData for one subslot" },
    { 0x8031, "PDTimeData for one subslot" },
    /*0x8032 - 0x804F reserved */
    { 0x8050, "PDInterfaceMrpDataReal for one subslot" },
    { 0x8051, "PDInterfaceMrpDataCheck for one subslot" },
    { 0x8052, "PDInterfaceMrpDataAdjust for one subslot" },
    { 0x8053, "PDPortMrpDataAdjust for one subslot" },
    { 0x8054, "PDPortMrpDataReal for one subslot" },
    { 0x8055, "PDPortMrpIcDataAdjust for one subslot" },
    { 0x8056, "PDPortMrpIcDataCheck for one subslot" },
    { 0x8057, "PDPortMrpIcDataReal for one subslot" },
    /*0x8058 - 0x805F reserved */
    { 0x8060, "PDPortFODataReal for one subslot" },
    { 0x8061, "PDPortFODataCheck for one subslot" },
    { 0x8062, "PDPortFODataAdjust for one subslot" },
    { 0x8063, "PDPortSFPDataCheck for one subslot" },
    /*0x8064 - 0x806F reserved */
    { 0x8070, "PDNCDataCheck for one subslot" },
    { 0x8071, "PDInterfaceAdjust for one subslot" },
    { 0x8072, "PDPortStatistic for one subslot" },
    /*0x8071 - 0x807F reserved */
    { 0x8080, "PDInterfaceDataReal" },
    /*0x8081 - 0x808F reserved */
    { 0x8090, "PDInterfaceFSUDataAdjust" },
    /*0x8091 - 0x809F reserved */
    { 0x80A0, "Profiles covering energy saving - Record_0" },
    /*0x80A1 - 0x80AE reserved */
    { 0x80AF, "PE_EntityStatusData for one subslot" },
    { 0x80B0, "CombinedObjectContainer" },
    /*0x80B1 - 0x80CE reserved */
    { 0x80CF, "RS_AdjustObserver" },
    { 0x80D0, "Profiles covering condition monitoring - Record_0" },
    /*0x80D1 - 0x80DF reserved */
    { 0x80F0, "TSNNetworkControlDataReal" },
    { 0x80F1, "TSNStreamPathData" },
    { 0x80F2, "TSNSyncTreeData" },
    { 0x80F3, "TSNUploadNetworkAttributes" },
    { 0x80F4, "TSNExpectedNetworkAttributes" },
    { 0x80F5, "TSNNetworkControlDataAdjust" },
    { 0x80F6, "TSNStreamPathDataReal for stream class High" },
    { 0x80F7, "TSNStreamPathDataReal for stream class High Redundant" },
    { 0x80F8, "TSNStreamPathDataReal for stream class Low" },
    { 0x80F9, "TSNStreamPathDataReal for stream class Low Redundant" },
    /*0x80FA - 0xAFEF reserved */
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
    { 0xB021, "reserved for profiles" },
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
    { 0xE030, "PE_EntityFilterData for one AR" },
    { 0xE031, "PE_EntityStatusData for one AR" },
    /*0xE032 - 0xE03F reserved */
    { 0xE040, "MultipleWrite" },
    { 0xE041, "ApplicationReadyBlock" },
    /*0xE042 - 0xE04F reserved */
    { 0xE050, "ARFSUDataAdjust data for one AR" },
    /*0xE051 - 0xE05F reserved */
    { 0xE060, "RS_GetEvent (using RecordDataRead service)" },
    { 0xE061, "RS_AckEvent (using RecordDataWrite service)" },
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
    { 0xF850, "AutoConfiguration" },
    { 0xF860, "GSD upload using UploadBLOBQuery and UploadBLOB" },
    { 0xF870, "PE_EntityFilterData" },
    { 0xF871, "PE_EntityStatusData" },
    { 0xF880, "AssetManagementData - contains all or first chunk of complete assets" },
    { 0xF881, "AssetManagementData - second chunk" },
    { 0xF882, "AssetManagementData - third chunk" },
    { 0xF883, "AssetManagementData - fourth chunk" },
    { 0xF884, "AssetManagementData - fifth chunk" },
    { 0xF885, "AssetManagementData - sixth chunk" },
    { 0xF886, "AssetManagementData - seventh chunk" },
    { 0xF887, "AssetManagementData - eighth chunk" },
    { 0xF888, "AssetManagementData - ninth chunk" },
    { 0xF889, "AssetManagementData - tenth chunk" },
    { 0xF8F0, "Stream Add using TSNAddStreamReq and TSNAddStreamRsp" },
    { 0xF8F1, "PDRsiInstances" },
    { 0xF8F2, "Stream Remove using TSNRemoveStreamReq and TSNRemoveStreamRsp" },
    { 0xF8F3, "Stream Renew using TSNRenewStreamReq and TSNRenewStreamRsp" },
    { 0xFBFF, "Trigger index for RPC connection monitoring" },
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
    /*0x8101 - 0x8FFF reserved except 8200, 8201, 8300, 8301, 8302, 8303, 8310, 8320 */
    { 0x8200, "Upload&Retrieval" },
    { 0x8201, "iParameter" },
    { 0x8300, "Reporting system RS_LowWatermark" },
    { 0x8301, "Reporting system RS_Timeout" },
    { 0x8302, "Reporting system RS_Overflow" },
    { 0x8303, "Reporting system RS_Event" },
    { 0x8310, "PE_EnergySavingStatus" },
    { 0x8320, "Channel related Process Alarm reasons" },
    /*0x9000 - 0x9FFF reserved for profiles */
    /*0xA000 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_channel_error_type[] = {
    { 0x0000, "reserved" },
    { 0x0001, "short circuit" },
    { 0x0002, "Undervoltage" },
    { 0x0003, "Overvoltage" },
    { 0x0004, "Overload" },
    { 0x0005, "Overtemperature" },
    { 0x0006, "Wire break" },
    { 0x0007, "Upper limit value exceeded" },
    { 0x0008, "Lower limit value exceeded" },
    { 0x0009, "Error" },
    { 0x000A, "Simulation active" },
    /*0x000B - 0x000E reserved */
    { 0x000F, "Parameter missing" },
    { 0x0010, "Parameterization fault" },
    { 0x0011, "Power supply fault" },
    { 0x0012, "Fuse blown / open" },
    { 0x0013, "Manufacturer specific" },
    { 0x0014, "Ground fault" },
    { 0x0015, "Reference point lost" },
    { 0x0016, "Process event lost / sampling error" },
    { 0x0017, "Threshold warning" },
    { 0x0018, "Output disabled" },
    { 0x0019, "FunctionalSafety event" },
    { 0x001A, "External fault" },
    /*0x001B - 0x001F manufacturer specific */
    { 0x001F, "Temporary fault" },
    /*0x0020 - 0x00FF reserved for common profiles */
    { 0x0040, "Mismatch of safety destination address" },
    { 0x0041, "Safety destination address not valid" },
    { 0x0042, "Safety source address not valid" },
    { 0x0043, "Safety watchdog time value is 0ms" },
    { 0x0044, "Parameter F_SIL exceeds SIL of specific application" },
    { 0x0045, "Parameter F_CRC_Length does not match generated values" },
    { 0x0046, "Version of F-Parameter set incorrect" },
    { 0x0047, "Data inconsistent in received F-Parameter block (CRC1 error)" },
    { 0x0048, "Device specific or unspecific diagnosis information, see manual" },
    { 0x0049, "Save iParameter watchdog time exceeded" },
    { 0x004A, "Restore iParameter watchdog time exceeded" },
    { 0x004B, "Inconsistent iParameters (iParCRC error)" },
    { 0x004C, "F_Block_ID not supported" },
    { 0x004D, "Transmission error: data inconsistent (CRC2 error)" },
    { 0x004E, "Transmission error: timeout" },
    { 0x004F, "Acknowledge needed to enable the channel(s)" },
    /*0x0100 - 0x7FFF manufacturer specific */
    { 0x8000, "Data transmission impossible" },
    { 0x8001, "Remote mismatch" },
    { 0x8002, "Media redundancy mismatch - Ring" },
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
    { 0x800D, "Multiple interface mismatch"},
    { 0x8010, "Power failure over Single Pair Ethernet"},
    /* ends */
    /*0x800D - 0x8FFF reserved */
    /*0x9000 - 0x9FFF reserved for profile */
    /*0x9000 - 0x902F NE107 common (PA Profile 4.02) */
    { 0x9000, "Sensor element exciter faulty" },
    { 0x9001, "Error in evaluation electronics" },
    { 0x9002, "Error in internal energy supply" },
    { 0x9003, "Error in sensor element" },
    { 0x9004, "Error in actuator element" },
    { 0x9005, "Faulty installat e.g. dead space" },
    { 0x9006, "Parameter setting error" },
    { 0x9008, "Overloading" },
    { 0x9009, "Wrong polarity of aux power" },
    { 0x900A, "Maximum line length exceeded" },
    { 0x900B, "Corrosion/abrasion by medium" },
    { 0x900C, "Fouling on sensor element" },
    { 0x900D, "Auxil medium missing or insufficient" },
    { 0x900E, "Wear reserve used up (operation)" },
    { 0x900F, "Wear reserve used up (wear)" },
    { 0x9010, "Error in peripherals" },
    { 0x9011, "Electromag interference too high" },
    { 0x9012, "Temperature of medium too high" },
    { 0x9013, "Ambient temperature too high" },
    { 0x9014, "Vibration/Impact load too high" },
    { 0x9015, "Auxiliary power range off-spec" },
    { 0x9016, "Auxiliary medium missing" },
    { 0x9017, "Excessive temperature shock" },
    { 0x9018, "Deviation from measurement" },
    { 0x9019, "Humidity in electronics area" },
    { 0x901A, "Medium in electronics area" },
    { 0x901B, "Mechanical damage" },
    { 0x901C, "Communication error" },
    { 0x901D, "Foreign material in electro area" },
    /*0x9030 - 0x906F NE107 contact thermometer (PA Profile 4.02) */
    { 0x9030, "Immersion depth too limited" },
    { 0x9031, "Unequate medium around sensor" },
    { 0x9032, "Temp distrib not representative" },
    { 0x9033, "Inadequate thermal contact" },
    { 0x9034, "Sensor close to heat source/sink" },
    { 0x9035, "External temperature influence" },
    { 0x9036, "Insufficient thermocoupling" },
    { 0x9037, "Thermocoupling too high" },
    { 0x9038, "Friction heat by flowing gases" },
    { 0x9039, "Thermalcapac of sensor too high" },
    { 0x903A, "Deposits" },
    { 0x903B, "Systemrelated resonant vibration" },
    { 0x903C, "Resonantvibrat excited by flow" },
    { 0x903D, "Leakage" },
    { 0x903E, "Abrasion" },
    { 0x903F, "Corrosion" },
    { 0x9040, "Flow approach speed too high" },
    { 0x9041, "Insulation to ground too low" },
    { 0x9042, "Insulation betw. lines too low" },
    { 0x9043, "Parasitic thermal elements" },
    { 0x9044, "Parasitic galvanic elements" },
    { 0x9045, "Short circuit" },
    { 0x9046, "Shorted coil and break" },
    { 0x9047, "Line/contact resistance too high" },
    { 0x9048, "Compression spring failure" },
    { 0x9049, "Drift of sensor charact curve" },
    { 0x904A, "Insuff contact of meas insert" },
    { 0x904B, "Meas insert mechanical seized" },
    { 0x904C, "Measuring insert in thermowell" },
    { 0x904D, "Measuring insert too short" },
    { 0x904E, "Resistance wire abrasion" },
    { 0x904F, "Mechanic stress character curve" },
    { 0x9050, "Thermal stress character curve" },
    { 0x9051, "Intrinsic heating too severe" },
    { 0x9052, "EMI on measuring circuit" },
    { 0x9053, "Faulty linearisation" },
    { 0x9054, "Incorrect sensor position" },
    { 0x9055, "Faulty comparative point temp" },
    { 0x9056, "Faulty compar of line resistance" },
    { 0x9057, "Unsymmet supply line resistance" },
    { 0x9058, "Wrong material of compens line" },
    { 0x9059, "Damage to supply lines" },
    { 0x905A, "Capacitive feedback" },
    { 0x905B, "Potential transfer" },
    { 0x905C, "Potential differences exceeded" },
    { 0x905D, "Impermiss mix of wire systems" },
    { 0x905E, "Reverse polarity of lines" },
    { 0x905F, "Reverse polarity of lines" },
    /*0x9070 - 0x90A7 NE107 pressure (PA Profile 4.02) */
    { 0x9070, "Pressure peaks outside range" },
    { 0x9071, "Deposits on the seal diaphragm" },
    { 0x9072, "Characteristic curve change" },
    { 0x9073, "Inc. measuring err. (turn down)" },
    { 0x9074, "Wear on the seal diaphragm" },
    { 0x9075, "Process seal at flush diaphragm" },
    { 0x9076, "Offset error due to inst. pos." },
    { 0x9077, "Seal diaphragm deformation" },
    { 0x9078, "Hydrogen penetration" },
    { 0x9079, "Mean value deviation" },
    { 0x907A, "Pressure sensor system leakage" },
    { 0x907B, "Hydrostatic offset" },
    { 0x907C, "Gas seepage from pressure sensor" },
    { 0x907D, "Add. measuring err. due to temp." },
    { 0x907E, "Delta T in capillary tubing" },
    { 0x907F, "Increase in compensation times" },
    { 0x9080, "Oleic acid leak" },
    { 0x9081, "Pulse lines blocked" },
    { 0x9082, "Gas inclusion in liquid medium" },
    { 0x9083, "Delta T in pulse lines" },
    { 0x9084, "Liquid inclusion in gas" },
    { 0x9088, "Sedimentation on sensor" },
    { 0x9089, "Change of density" },
    { 0x908A, "Wrong height / wrong adjustment" },
    { 0x908B, "Clogged membrane" },
    { 0x908C, "Error with pulse line" },
    { 0x908D, "Internal tank pressure influence" },
    { 0x908E, "Influence of temperature" },
    { 0x908F, "Hydrogen diffusion" },
    { 0x9090, "Absence of bubble gas" },
    { 0x9091, "Air-bubble feed line blocked" },
    { 0x9092, "Wear and tear of diaphragm" },
    { 0x9093, "Gas seepage" },
    { 0x9094, "Pressure rise at rel. of bubbles" },
    { 0x9095, "Pressure sensor overload" },
    { 0x9096, "Flow rate of bubble gas too high" },
    /*0x90F8 - 0x910F NE107 coriolis (PA Profile 4.02) */
    { 0x90F8, "Gas bubbles in the liquid" },
    { 0x90F9, "Fouling, clogging" },
    { 0x90FA, "Erosion, corrosion" },
    { 0x90FB, "Faulty mounting" },
    { 0x90FC, "Asymmetry of measuring tubes" },
    { 0x90FD, "External vibrations" },
    { 0x90FE, "Pulsating flow" },
    { 0x90FF, "Incomplete filling" },
    /*0x9110 - 0x9127 NE107 EMF (PA Profile 4.02) */
    { 0x9110, "Gas bubbles in the liquid" },
    { 0x9111, "Corrosion of electrodes" },
    { 0x9112, "Electrical conductivity too low" },
    { 0x9113, "Liner damage" },
    { 0x9114, "Electrode fouling" },
    { 0x9115, "External magnetic fields" },
    { 0x9116, "Electrode short circuit" },
    { 0x9117, "Incomplete filling" },
    /*0x9128 - 0x913F NE107 thermal mass (PA Profile 4.02) */
    /* empty */
    /*0x9140 - 0x915F NE107 ultrasonic (PA Profile 4.02) */
    { 0x9140, "Particle inclusions Check process" },
    { 0x9141, "Gas bubbles in the liquid" },
    { 0x9142, "Body fouling" },
    { 0x9143, "External ultrasonic waves" },
    { 0x9144, "Sensor fouling" },
    { 0x9145, "Erosion" },
    { 0x9146, "Faulty mounting (clamp on)" },
    { 0x9147, "Pulsating flow" },
    { 0x9148, "Sound conductivity" },
    { 0x9149, "Signal lost due to overrange" },
    { 0x914A, "Flow profile disturbance" },
    { 0x914B, "Incomplete filling" },
    /*0x9160 - 0x9177 NE107 variable area (PA Profile 4.02) */
    { 0x9160, "Blocked float" },
    { 0x9161, "Fouling" },
    { 0x9162, "Erosion, corrosion" },
    { 0x9163, "Gas bubbles in the liquid" },
    { 0x9164, "Pulsating flow" },
    { 0x9165, "External magnetic fields" },
    /*0x9178 - 0x9197 NE107 vortex (PA Profile 4.02) */
    { 0x9178, "Gas bubbles in the liquid" },
    { 0x9179, "External vibrations" },
    { 0x917A, "Pulsating flow" },
    { 0x917B, "Two phase flow" },
    { 0x917C, "Cavitation in device" },
    { 0x917D, "Out of linear range" },
    { 0x917E, "Sensor fouling" },
    { 0x917F, "Solid particles" },
    { 0x9180, "Flow profile disturbance" },
    { 0x9181, "Incomplete filling" },
    { 0x9182, "Bluff body fouling" },
    /*0x9198 - 0x91B7 NE107 buoyancy (PA Profile 4.02) */
    { 0x9198, "Gas density change above liquid" },
    { 0x9199, "Vibration/strokes from outside" },
    { 0x919A, "Displacer partly inside compartm" },
    { 0x919B, "Displacer too heavy/too light" },
    { 0x919C, "Density change or displac config" },
    { 0x919D, "Sticking of torque or spring" },
    { 0x919E, "Displacer swinging freedomly" },
    { 0x919F, "Displac mounting faulty" },
    { 0x91A0, "Displacer blocked or bended" },
    { 0x91A1, "Displacer too light, corrosion" },
    { 0x91A2, "Displacer leakage" },
    { 0x91A3, "Force sensor broken" },
    /*0x91B8 - 0x91FF NE107 radar (PA Profile 4.02) */
    { 0x91B8, "Change of running time, encrust?" },
    { 0x91B9, "False echoes, encrustation?" },
    { 0x91BA, "Wrong/no indication, foam" },
    { 0x91BB, "Poor reflection" },
    { 0x91BC, "Problems with tank wall" },
    { 0x91BD, "Surge tube or vent blocked" },
    { 0x91BE, "Nozzle too long/high" },
    { 0x91BF, "No metallic reflecting surface" },
    { 0x91C0, "Blocking distance underrun" },
    { 0x91C1, "Mechanical overloading of probe" },
    { 0x91C2, "Probe lost or torn off" },
    { 0x91C3, "Overload by external power" },
    { 0x91C4, "Product or moisture in coupler" },
    { 0x91C5, "Change of microwave speed" },
    { 0x91C6, "Corr,abras, coating detachment" },
    { 0x91C7, "Probe in filling flow" },
    { 0x91D8, "No clear interface Emulsion?" },
    { 0x91D9, "Wrong indication param setting" },
    { 0x91DA, "Diff dielecon too small" },
    { 0x91DB, "More than one interface" },
    { 0x91DC, "First phase thickness too small" },
    { 0x91E0, "Attenuation due to deposits" },
    { 0x91E1, "False echoes due to deposits" },
    { 0x91E2, "Corrosion surge tube (inside)" },
    { 0x91E3, "Impurity in wave coupler area" },
    { 0x91E4, "Antenna immersed in product" },
    { 0x91E5, "Wrong signal due to foam" },
    { 0x91E6, "Strong signal attenuation" },
    { 0x91E7, "Shift of radar signal speed" },
    { 0x91E8, "Reflection" },
    { 0x91E9, "False interpretation of the echo" },
    { 0x91EA, "Bad polarization of the signal" },
    { 0x91EB, "Surge tube or vent blocked" },
    { 0x91EC, "Nozzle too long for antenna" },
    { 0x91ED, "Wall clearance, not vertical" },
    { 0x91EE, "Corrosion on antenna" },
    { 0x91EF, "Attenuation due to fog or dust" },
    { 0x91F0, "Antenna signal blocked" },
    { 0x91F1, "Blocking distance under-run" },
    { 0x91F2, "Echo too strong (overmodulation)" },
    /*0x9208 - 0x9257 NE107 electro (PA Profile 4.02) */
    { 0x9208, "Faulty torque monitoring" },
    { 0x9209, "Worn gear/spindle" },
    { 0x920A, "Drive torque off-spec" },
    { 0x920B, "Device temperature too high" },
    { 0x920C, "Faulty limit position monitoring" },
    { 0x920D, "Motor overload" },
    { 0x920E, "Oil quality off-spec" },
    { 0x920F, "Oil loss" },
    { 0x9210, "Blocked drive" },
    { 0x9211, "Off-spec seat/plug leakage" },
    { 0x9212, "Off-spec spindle/shaft seal leak" },
    { 0x9213, "Alteration and wear on spindle" },
    { 0x9214, "Altered friction" },
    { 0x9215, "Wear in the valve" },
    { 0x9216, "Blocked valve" },
    { 0x9217, "Change in valve move performance" },
    { 0x9218, "Changed breakaway moment" },
    { 0x9219, "Spindle deformation" },
    { 0x921A, "Plug torn off" },
    { 0x921B, "Off-spec valve temperature" },
    { 0x921C, "Off-spec characteristic line" },
    { 0x921E, "Incorrect position sensing" },
    { 0x921F, "Input signal off-spec" },
    { 0x9220, "Vibration off-spec" },
    { 0x9221, "Temp in positioner too high/low" },
    { 0x9222, "Moisture in positioner" },
    { 0x9223, "Additional IO module defect" },
    { 0x9224, "Signal without end position" },
    { 0x9225, "No signal in end position" },
    { 0x9226, "Control loop oscillation" },
    { 0x9227, "Hysteresis" },
    { 0x9228, "Changed friction" },
    { 0x9229, "Backlash between drive and valve" },
    { 0x922A, "Persistent deviation of control" },
    { 0x922B, "Inadmissible dynamic stress" },
    { 0x922C, "Faulty mounting" },
    { 0x922D, "Faulty mount positioner to motor" },
    { 0x922E, "Leak in piping" },
    { 0x922F, "Insufficient drive power" },
    { 0x9231, "Operator error during operation" },
    { 0x9232, "Inadmissible static stress" },
    { 0x9233, "Recording of pers. control dev." },
    { 0x9234, "Parameter plausibility check" },
    { 0x9235, "Status report on operating mode" },
    { 0x9236, "Histogram for valve positions" },
    { 0x9237, "Zero point and endpoint shift" },
    { 0x9238, "Running time monitoring" },
    { 0x9239, "Evaluation of internal signals" },
    { 0x923A, "Operating hours counter" },
    { 0x923B, "Pressure-displacement diagram" },
    { 0x923C, "Total valve travel" },
    { 0x923D, "Step response diagnostics" },
    { 0x923E, "Internal temperature monitoring" },
    { 0x923F, "Counter for direction changes" },
    { 0x9240, "Operating archive" },
    { 0x9241, "Report archive" },
    { 0x9242, "Status reports on access control" },
    { 0x9243, "Cavitation / flashing" },
    { 0x9244, "Partial stroke test" },
    { 0x9245, "P dif measurement across valve" },
    { 0x9246, "Noise level measurement" },
    /*0x9258 - 0x92A7 NE107 electro pneumatic (PA Profile 4.02) */
    { 0x9258, "Minor drive leakage" },
    { 0x9259, "High friction" },
    { 0x925A, "Feed air pressure off-spec" },
    { 0x925B, "Vent blockage" },
    { 0x925C, "Diaphragm damage" },
    { 0x925D, "Broken spring" },
    { 0x925E, "Moist air in spring chamber" },
    { 0x925F, "Blocked drive" },
    { 0x9260, "Drive leakage too big" },
    { 0x9261, "Off-spec seat/plug leakage" },
    { 0x9262, "Off-spec spindle/shaft seal leak" },
    { 0x9263, "Alteration and wear on spindle" },
    { 0x9264, "Altered friction" },
    { 0x9265, "Wear in the valve" },
    { 0x9266, "Blocked valve" },
    { 0x9267, "Change in valve move performance" },
    { 0x9268, "Changed breakaway moment" },
    { 0x9269, "Spindle deformation" },
    { 0x926A, "Plug torn off" },
    { 0x926B, "Off-spec valve temperature" },
    { 0x926C, "Off-spec characteristic line" },
    { 0x926D, "Fault in the pneumatic unit" },
    { 0x926E, "Incorrect position sensing" },
    { 0x926F, "Input signal off-spec" },
    { 0x9270, "Vibration off-spec" },
    { 0x9271, "Temp in positioner too high/low" },
    { 0x9272, "Moisture in positioner" },
    { 0x9273, "Additional IO module defect" },
    { 0x9274, "Signal without end position" },
    { 0x9275, "No signal in end position" },
    { 0x9276, "Control loop oscillation" },
    { 0x9277, "Hysteresis" },
    { 0x9278, "Changed friction" },
    { 0x9279, "Backlash between drive and valve" },
    { 0x927A, "Persistent deviation of control" },
    { 0x927B, "Inadmissible dynamic stress" },
    { 0x927C, "Faulty mounting" },
    { 0x927D, "Faulty mount positioner to drive" },
    { 0x927E, "Leak in piping" },
    { 0x927F, "Insufficient drive power" },
    { 0x9280, "Quality of feed air off-spec" },
    { 0x9281, "Operator error during operation" },
    { 0x9282, "Inadmissible static stress" },
    { 0x9283, "Recording of pers. control dev." },
    { 0x9284, "Parameter plausibility check" },
    { 0x9285, "Status report on operating mode" },
    { 0x9286, "Histogram for valve positions" },
    { 0x9287, "Zero point and endpoint shift" },
    { 0x9288, "Running time monitoring" },
    { 0x9289, "Evaluation of internal signals" },
    { 0x928A, "Operating hours counter" },
    { 0x928B, "Pressure-displacement diagram" },
    { 0x928C, "Total valve travel" },
    { 0x928D, "Step response diagnostics" },
    { 0x928E, "Internal temperature monitoring" },
    { 0x928F, "Counter for direction changes" },
    { 0x9290, "Operating archive" },
    { 0x9291, "Report archive" },
    { 0x9292, "Status reports on access control" },
    { 0x9293, "Cavitation / flashing" },
    { 0x9294, "Partial stroke test" },
    { 0x9295, "P dif measurement across valve" },
    { 0x9296, "Noise level measurement" },
    /*0x92A8 - 0x92BF NE107 sol valve (PA Profile 4.02) */
    { 0x92A8, "Failure to reach safe position" },
    { 0x92A9, "Failure to reach operat position" },
    { 0x92AA, "High temperature in coil" },
    { 0x92AB, "Moisture, humidity" },
    { 0x92AC, "Signal outside of endposition" },
    { 0x92AD, "No signal at endposition" },
    /*0x92C0 - 0x92DF Physical block (PA Profile 4.02) */
    { 0x92CD, "Maintenance" },
    { 0x92D0, "Maintenance alarm" },
    { 0x92D1, "Maintenance demanded" },
    { 0x92D2, "Function check" },
    { 0x92D3, "Out of spec." },
    { 0x92D4, "Update event" },
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
    { 0x8000, "Peer name of station mismatch"},
    { 0x8001, "Peer name of port mismatch"},
    { 0x8002, "Peer RT_CLASS_3 mismatch a"},
    { 0x8003, "Peer MAUType mismatch"},
    { 0x8004, "Peer MRP domain mismatch"},
    { 0x8005, "No peer detected"},
    { 0x8006, "Reserved"},
    { 0x8007, "Peer Line Delay mismatch"},
    { 0x8008, "Peer PTCP mismatch b"},
    { 0x8009, "Peer Preamble Length mismatch"},
    { 0x800A, "Peer Fragmentation mismatch"},
    { 0x800B, "Peer MRP Interconnection domain mismatch"},
    /* 0x800C - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

    /* ExtChannelErrorType for ChannelErrorType "Media redundancy mismatch" 0x8002 */
static const value_string pn_io_ext_channel_error_type0x8002[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "Manager role fail MRP-instance 1"},
    { 0x8001, "MRP-instance 1 ring open"},
    { 0x8002, "Reserved"},
    { 0x8003, "Multiple manager MRP-instance 1"},
    { 0x8010, "Manager role fail MRP-instance 2"},
    { 0x8011, "MRP-instance 2 ring open"},
    { 0x8012, "Reserved"},
    { 0x8013, "Multiple manager MRP-instance 2"},
    { 0x8020, "Manager role fail MRP-instance 3"},
    { 0x8021, "MRP-instance 3 ring open"},
    { 0x8023, "Multiple manager MRP-instance 3"},
    { 0x8030, "Manager role fail MRP-instance 4"},
    { 0x8031, "MRP-instance 4 ring open"},
    { 0x8033, "Multiple manager MRP-instance 4"},
    { 0x8040, "Manager role fail MRP-instance 5"},
    { 0x8041, "MRP-instance 5 ring open"},
    { 0x8043, "Multiple manager MRP-instance 5"},
    { 0x8050, "Manager role fail MRP-instance 6"},
    { 0x8051, "MRP-instance 6 ring open"},
    { 0x8053, "Multiple manager MRP-instance 6"},
    { 0x8060, "Manager role fail MRP-instance 7"},
    { 0x8061, "MRP-instance 7 ring open"},
    { 0x8063, "Multiple manager MRP-instance 7"},
    { 0x8070, "Manager role fail MRP-instance 8"},
    { 0x8071, "MRP-instance 8 ring open"},
    { 0x8073, "Multiple manager MRP-instance 8"},
    { 0x8080, "Manager role fail MRP-instance 9"},
    { 0x8081, "MRP-instance 9 ring open"},
    { 0x8083, "Multiple manager MRP-instance 9"},
    { 0x8090, "Manager role fail MRP-instance 10"},
    { 0x8091, "MRP-instance 10 ring open"},
    { 0x8093, "Multiple manager MRP-instance 10"},
    { 0x80A0, "Manager role fail MRP-instance 11"},
    { 0x80A1, "MRP-instance 11 ring open"},
    { 0x80A3, "Multiple manager MRP-instance 11"},
    { 0x80B0, "Manager role fail MRP-instance 12"},
    { 0x80B1, "MRP-instance 12 ring open"},
    { 0x80B3, "Multiple manager MRP-instance 12"},
    { 0x80C0, "Manager role fail MRP-instance 13"},
    { 0x80C1, "MRP-instance 13 ring open"},
    { 0x80C3, "Multiple manager MRP-instance 13"},
    { 0x80D0, "Manager role fail MRP-instance 14"},
    { 0x80D1, "MRP-instance 14 ring open"},
    { 0x80D3, "Multiple manager MRP-instance 14"},
    { 0x80E0, "Manager role fail MRP-instance 15"},
    { 0x80E1, "MRP-instance 15 ring open"},
    { 0x80E3, "Multiple manager MRP-instance 15"},
    { 0x80F0, "Manager role fail MRP-instance 16"},
    { 0x80F1, "MRP-instance 16 ring open"},
    { 0x80F3, "Multiple manager MRP-instance 16"},
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
    { 0x8001, "SFP - Temperature threshold violation (High)"},
    { 0x8002, "SFP - TX Bias threshold violation (High)"},
    { 0x8003, "SFP - TX Bias threshold violation (Low)"},
    { 0x8004, "SFP - TX Power threshold violation (High)"},
    { 0x8005, "SFP - TX Power threshold violation (Low)"},
    { 0x8006, "SFP - RX Power threshold violation (High)"},
    { 0x8007, "SFP - RX Power threshold violation (Low)"},
    { 0x8008, "SFP - TX Fault State indication"},
    { 0x8009, "SFP - RX Loss State indication"},
    /* 0x800A - 0x8FFF Reserved */
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

    /* ExtChannelErrorType for ChannelErrorType "Power failure over Single Pair Ethernet" 0x8010 */
static const value_string pn_io_ext_channel_error_type0x8010[] = {
    /* 0x0000 Reserved */
    /* 0x0001 - 0x7FFF Manufacturer specific */
    { 0x8000, "SPE power supply - Short circuit"},
    { 0x8001, "SPE power supply - Open circuit"},
    { 0x8002, "SPE power supply - Voltage level"},
    { 0x8003, "SPE power supply - Current level"},
    /* 0x8004 - 0x8FFF Reserved */
    /* 0x9000 - 0x9FFF Reserved for profiles */
    /* 0xA000 - 0xFFFF Reserved */
    { 0, NULL }
};

/* QualifiedChannelQualifier */
static const value_string pn_io_qualified_channel_qualifier[] = {
    {0x00000001, "Reserved"},
    {0x00000002, "Reserved"},
    {0x00000004, "Reserved"},
    {0x00000008, "Qualifier_3 (Advice)"},
    {0x00000010, "Qualifier_4 (Advice, PA: UpdateEvent)"},
    {0x00000020, "Qualifier_5 (Advice, PA: OutOfSpecification)"},
    {0x00000040, "Qualifier_6 (Advice)"},
    {0x00000080, "Qualifier_7 (MaintenanceRequired)"},
    {0x00000100, "Qualifier_8 (MaintenanceRequired)"},
    {0x00000200, "Qualifier_9 (MaintenanceRequired)"},
    {0x00000400, "Qualifier_10 (MaintenanceRequired)"},
    {0x00000800, "Qualifier_11 (MaintenanceRequired)"},
    {0x00001000, "Qualifier_12 (MaintenanceRequired, PA: MaintenanceRequired)"},
    {0x00002000, "Qualifier_13 (MaintenanceRequired)"},
    {0x00004000, "Qualifier_14 (MaintenanceRequired)"},
    {0x00008000, "Qualifier_15 (MaintenanceRequired)"},
    {0x00010000, "Qualifier_16 (MaintenanceRequired)"},
    {0x00020000, "Qualifier_17 (MaintenanceDemanded)"},
    {0x00040000, "Qualifier_18 (MaintenanceDemanded)"},
    {0x00080000, "Qualifier_19 (MaintenanceDemanded)"},
    {0x00100000, "Qualifier_20 (MaintenanceDemanded)"},
    {0x00200000, "Qualifier_21 (MaintenanceDemanded)"},
    {0x00400000, "Qualifier_22 (MaintenanceDemanded, PA: MaintenanceDemanded)"},
    {0x00800000, "Qualifier_23 (MaintenanceDemanded)"},
    {0x01000000, "Qualifier_24 (MaintenanceDemanded, PA: FunctionCheck)"},
    {0x02000000, "Qualifier_25 (MaintenanceDemanded)"},
    {0x04000000, "Qualifier_26 (MaintenanceDemanded)"},
    {0x08000000, "Qualifier_27 (Fault)"},
    {0x10000000, "Qualifier_28 (Fault)"},
    {0x20000000, "Qualifier_29 (Fault)"},
    {0x40000000, "Qualifier_30 (Fault, PA: Fault)"},
    {0x80000000, "Qualifier_31 (Fault)"},
    {0, NULL}};

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

static const value_string pn_io_channel_properties_accumulative_vals[] = {
    { 0x0000, "Channel" },
    { 0x0001, "ChannelGroup" },
    { 0, NULL }
};

/* We are reading this as a two bit value, but the spec specifies each bit
 * separately. Beware endianness when reading spec
 */
static const value_string pn_io_channel_properties_maintenance[] = {
    { 0x0000, "Failure" },
    { 0x0001, "Maintenance required" },
    { 0x0002, "Maintenance demanded" },
    { 0x0003, "see QualifiedChannelQualifier" },
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
    /*0x0037 - 0x008C reserved */
    { 0x008D, "10BASET1L" },
    /*0x008E - 0xFFFF reserved */
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


static const value_string pn_io_dcp_boundary_value_bit0[] = {
    { 0x00, "Do not block the multicast MAC address 01-0E-CF-00-00-00" },
    { 0x01, "Block an outgoing DCP_Identify frame (egress filter) with the multicast MAC address 01-0E-CF-00-00-00" },
    { 0, NULL }
};

static const value_string pn_io_dcp_boundary_value_bit1[] = {
    { 0x00, "Do not block the multicast MAC address 01-0E-CF-00-00-01" },
    { 0x01, "Block an outgoing DCP_Hello frame (egress filter) with the multicast MAC address 01-0E-CF-00-00-01" },
    { 0, NULL }
};

static const value_string pn_io_peer_to_peer_boundary_value_bit0[] = {
    { 0x00, "The LLDP agent shall send LLDP frames for this port." },
    { 0x01, "The LLDP agent shall not send LLDP frames (egress filter)." },
    { 0, NULL }
};

static const value_string pn_io_peer_to_peer_boundary_value_bit1[] = {
    { 0x00, "The PTCP ASE shall send PTCP_DELAY request frames for this port." },
    { 0x01, "The PTCP ASE shall not send PTCP_DELAY request frames (egress filter)." },
    { 0, NULL }
};

static const value_string pn_io_peer_to_peer_boundary_value_bit2[] = {
    { 0x00, "The Time ASE shall send PATH_DELAY request frames for this port." },
    { 0x01, "The Time ASE shall not send PATH_DELAY request frames (egress filter)." },
    { 0, NULL }
};

static const range_string pn_io_mau_type_extension[] = {
    { 0x0000, 0x0000, "No SubMAUType" },
    { 0x0001, 0x00FF, "Reserved" },
    { 0x0100, 0x0100, "POF" },
    { 0x0101, 0x01FF, "Reserved for SubMAUType" },
    { 0x0200, 0x0200, "APL" },
    { 0x0201, 0xFFEF, "Reserved for SubMAUType" },
    { 0xFFF0, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_io_pe_operational_mode[] = {
    { 0x00, 0x00, "PE_PowerOff" },
    { 0x01, 0x1F, "PE_EnergySavingMode" },
    { 0x20, 0xEF, "Reserved" },
    { 0xF0, 0xF0, "PE_Operate" },
    { 0xF1, 0xFD, "Reserved" },
    { 0xFE, 0xFE, "PE_SleepModeWOL" },
    { 0xFF, 0xFF, "PE_ReadyToOperate" },
    { 0, 0, NULL }
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


static const value_string pn_io_link_state_port[] = {
    { 0x00, "unknown" },
    { 0x01, "disabled/discarding" },
    { 0x02, "blocking" },
    { 0x03, "listening" },
    { 0x04, "learning" },
    { 0x05, "forwarding" },
    { 0x06, "broken" },
    /*0x07 - 0xFF reserved */
    { 0, NULL }
};


static const value_string pn_io_link_state_link[] = {
    { 0x00, "reserved" },
    { 0x01, "up" },
    { 0x02, "down" },
    { 0x03, "testing" },
    { 0x04, "unknown" },
    { 0x05, "dormant" },
    { 0x06, "notpresent" },
    { 0x07, "lowerlayerdown" },
    /*0x08 - 0xFF reserved */
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

static const value_string pn_io_mrp_instance_no[] = {
    { 0x0000, "MRP_Instance 1" },
    { 0x0001, "MRP_Instance 2" },
    { 0x0002, "MRP_Instance 3" },
    { 0x0003, "MRP_Instance 4" },
    { 0x0004, "MRP_Instance 5" },
    { 0x0005, "MRP_Instance 6" },
    { 0x0006, "MRP_Instance 7" },
    { 0x0007, "MRP_Instance 8" },
    { 0x0008, "MRP_Instance 9" },
    { 0x0009, "MRP_Instance 10" },
    { 0x000A, "MRP_Instance 11" },
    { 0x000B, "MRP_Instance 12" },
    { 0x000C, "MRP_Instance 13" },
    { 0x000D, "MRP_Instance 14" },
    { 0x000E, "MRP_Instance 15" },
    { 0x000F, "MRP_Instance 16" },
    /*all others reserved */
    { 0, NULL }
};

static const value_string pn_io_mrp_mrm_on[] = {
    { 0x0000, "Disable MediaRedundancyManager diagnosis" },
    { 0x0001, "Enable MediaRedundancyManager diagnosis"},
    { 0, NULL }
};
static const value_string pn_io_mrp_checkUUID[] = {
    { 0x0000, "Disable the check of the MRP_DomainUUID" },
    { 0x0001, "Enable the check of the MRP_DomainUUID"},
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
    { 0x0001, "The IO controller starts the transmission of the stored start-up parameter" },
    { 0, NULL }
};
static const value_string pn_io_control_properties_application_ready_bit0_vals[] = {
    { 0x0000, "Wait for explicit ControlCommand.ReadyForCompanion" },
    { 0x0001, "Implicit ControlCommand.ReadyForCompanion" },
    { 0, NULL }
};
static const value_string pn_io_control_properties_application_ready_bit1_vals[] = {
    { 0x0000, "Wait for explicit ControlCommand.ReadyForRT_CLASS_3" },
    { 0x0001, "Implicit ControlCommand.ReadyForRT_CLASS_3" },
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

static const value_string pn_io_f_crc_seed[] = {
    { 0x00, "CRC-FP as seed value and counter" },
    { 0x01, "'1' as seed value and CRC-FP+/MNR" },
    { 0, NULL }
};

/* F_Block_ID dissection due to ver2.6 specifikation of PI */
static const value_string pn_io_f_block_id[] = {
    { 0x00, "No F_WD_Time_2, no F_iPar_CRC" },
    { 0x01, "No F_WD_Time_2, F_iPar_CRC" },
    { 0x02, "F_WD_Time_2, no F_iPar_CRC" },
    { 0x03, "F_WD_Time_2, F_iPar_CRC" },
    /* 0x04..0x07 reserved */
    /* { 0x00, "Parameter set for F-Host/F-Device relationship" }, */
    /* { 0x01, "Additional F_Address parameter block" }, */
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
    {0x0, "Zero"},
    {0x01, "Boolean" },
    {0x02, "Integer8" },
    {0x03, "Integer16" },
    {0x04, "Integer32" },
    {0x05, "Unsigned8" },
    {0x06, "Unsigned16" },
    {0x07, "Unsigned32" },
    {0x08, "Float32" },
    {0x09, "VisibleString" },
    {0x0A, "OctetString" },
    {0x0B, "Binary Date"},
    {0x0C, "TimeOfDay" },
    {0x0D, "TimeDifference" },
    {0x0E, "BitString"},
    {0x0F, "Float64"},
    {0x10, "UniversalTime"},
    {0x11, "FieldbusTime"},
    {0x15, "Time Value"},
    {0x16, "Bitstring8"},
    {0x17, "Bitstring16"},
    {0x18, "Bitstring32"},
    {0x19, "VisibleString1"},
    {0x1A, "VisibleString2"},
    {0x1B, "VisibleString4"},
    {0x1C, "VisibleString8"},
    {0x1D, "VisibleString16"},
    {0x1E, "OctetString1"},
    {0x1F, "OctetString2"},
    {0x20, "OctetString4"},
    {0x21, "OctetString8"},
    {0x22, "OctetString16"},
    {0x23, "BCD"},
    {0x24, "UNICODE char"},
    {0x25, "CompactBoolean-Array"},
    {0x26, "CompactBCDArray"},
    {0x27, "UNICODEString"},
    {0x28, "BinaryTime0"},
    {0x29, "BinaryTime1"},
    {0x2A, "BinaryTime2"},
    {0x2B, "BinaryTime3"},
    {0x2C, "BinaryTime4"},
    {0x2D, "BinaryTime5"},
    {0x2E, "BinaryTime6"},
    {0x2F, "BinaryTime7"},
    {0x30, "BinaryTime8"},
    {0x31, "BinaryTime9"},
    {0x32, "Date"},
    {0x33, "BinaryDate2000"},
    {0x34, "TimeOfDay without date indication"},
    {0x35, "TimeDifference with date indication"},
    {0x36, "TimeDifference without date indication"},
    {0x37, "Integer64"},
    {0x38, "Unsigned64"},
    {0x39, "BitString64"},
    {0x3A, "NetworkTime"},
    {0x3B, "NetworkTime-Difference"},

    {0x40, "Zero" },
    {0x41, "Byte" },
    {0x42, "Word" },
    {0x43, "Dword" },
    {0x44, "Error Type" },
    {0x65, "Float32+Unsigned8"},
    {0x66, "Unsigned8+Unsigned8"},
    {0x67, "OctetString2+Unsigned8"},
    {0x68, "Unsigned16_S"},
    {0x69, "Integer16_S"},
    {0x6A, "Unsigned8_S"},
    {0x6B, "OctetString_S"},
    {0x6E, "F message trailer with 4 octets"},
    {0x6F, "F message trailer with 5 octets"},
    {0x70, "F message trailer with 6 octets"},
    {0x71, "N2 Normalized value (16 bit)"},
    {0x72, "N4 Normalized value (32 bit)"},
    {0x73, "V2 Bit sequence" },
    {0x74, "L2 Nibble"},
    {0x75, "R2 Reciprocal time constant"},
    {0x76, "T2 Time constant (16 bit)"},
    {0x77, "T4 Time constant (32 bit)"},
    {0x78, "D2 Time constant"},
    {0x79, "E2 Fixed point value (16 bit)"},
    {0x7A, "C4 Fixed point value (32 bit)"},
    {0x7B, "X2 Normalized value, variable (16bit)"},
    {0x7C, "X4 Normalized value, variables (32bit)"},
    { 0, NULL }
};

static const value_string pn_io_profidrive_parameter_resp_errors[] = 
{
    {0x0, "Disallowed parameter number" },
    {0x1, "The parameter value cannot be changed" },
    {0x2, "Exceed the upper or lower limit" },
    {0x3, "Sub-index error" },
    {0x4, "Non-array" },
    {0x5, "Incorrect data type" },
    {0x6, "Setting is not allowed (can only be reset)" },
    {0x7, "The description element cannot be modified" },
    {0x8, "Reserved" },
    {0x9, "Descriptive data does not exist" },
    {0xA, "Reserved" },
    {0xB, "No operation priority" },
    {0xC, "Reserved" },
    {0xD, "Reserved" },
    {0xE, "Reserved" },
    {0xF, "The text array does not save right" },
    {0x11, "The request cannot be executed because of the working status" },
    {0x12, "Reserved" },
    {0x13, "Reserved" },
    {0x14, "Value is not allowed" },
    {0x15, "Response timeout" },
    {0x16, "Illegal parameter address" },
    {0x17, "Illegal parameter format" },
    {0x18, "The number of values is inconsistent" },
    {0x19, "Axis/DO does not exist" },
    {0x20, "The parameter text element cannot be changed" },
    {0x21, "No support service" },
    {0x22, "Too many parameter requests" },
    {0x23, "Only support single parameter access" },
    { 0, NULL }
};
static const range_string pn_io_rs_block_type[] = {
    /* Following ranges are used for events */
    { 0x0000, 0x0000, "reserved" },
    { 0x0001, 0x3FFF, "Manufacturer specific" },
    { 0x4000, 0x4000, "Stop observer - Observer Status Observer" },
    { 0x4001, 0x4001, "Buffer observer - RS_BufferObserver" },
    { 0x4002, 0x4002, "Time status observer - RS_TimeStatus" },
    { 0x4003, 0x4003, "System redundancy layer observer - RS_SRLObserver" },
    { 0x4004, 0x4004, "Source identification observer - RS_SourceIdentification" },
    { 0x4005, 0x400F, "reserved" },
    { 0x4010, 0x4010, "Digital input observer - SoE_DigitalInputObserver" },
    { 0x4011, 0x6FFF, "Reserved for normative usage" },
    { 0x7000, 0x7FFF, "Reserved for profile usage" },
    /* Following ranges are used for adjust */
    { 0x8000, 0x8000, "reserved" },
    { 0x8001, 0xBFFF, "Manufacturer specific" },
    { 0xC000, 0xC00F, "Reserved for normative usage" },
    { 0xC010, 0xC010, "Digital input observer - SoE_DigitalInputObserver" },
    { 0xC011, 0xEFFF, "Reserved for normative usage"},
    { 0xF000, 0xFFFF, "Reserved for profile usage"},
    { 0, 0, NULL }
};

static const value_string pn_io_rs_specifier_specifier[] = {
    { 0x0, "Current value" },
    { 0x1, "Appears" },
    { 0x2, "Disappears" },
    { 0x3, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_rs_time_stamp_status[] = {
    { 0x0, "TimeStamp related to global synchronized time" },
    { 0x1, "TimeStamp related to local time" },
    { 0x2, "TimeStamp related to local (arbitrary timescale) time" },
    { 0, NULL }
};

static const value_string pn_io_rs_reason_code_reason[] = {
    { 0x00000000, "Reserved" },
    { 0x00000001, "Observed data status unclear" },
    { 0x00000002, "Buffer overrun" },
    /* 0x0003 - 0xFFFF Reserved */
    { 0, NULL }
};

static const value_string pn_io_rs_reason_code_detail[] = {
    { 0x00000000, "No Detail" },
    /* 0x0001 - 0xFFFF Reserved */
    { 0, NULL }
};

static const value_string pn_io_soe_digital_input_current_value_value[] = {
    { 0x0, "Digital input is zero" },
    { 0x1, "Digital input is one" },
    { 0, NULL }
};

static const value_string pn_io_soe_adjust_specifier_incident[] = {
    { 0x00, "Reserved" },
    { 0x01, "Rising edge" },
    { 0x02, "Falling edge" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_rs_properties_alarm_transport[] = {
    { 0x00000000, "Default Reporting system events need to be read by record " },
    { 0x00000001, "Reporting system events shall be forwarded to the IOC using the alarm transport" },
    { 0, NULL }
};

static const value_string pn_io_am_location_structure_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Twelve level tree format" },
    { 0x02, "Slot - and SubslotNumber format" },
    { 0, NULL }
};

static const range_string pn_io_am_location_level_vals[] = {
    { 0x0000, 0x03FE, "Address information to identify a reported node" },
    { 0x03FF, 0x03FF, "Level not used" },
    { 0, 0, NULL }
};

static const value_string pn_io_am_location_reserved_vals[] = {
    { 0x00, "Reserved" },
    { 0, NULL }
};

static const range_string pn_io_RedundancyDataHoldFactor[] = {
    { 0x0000, 0x0002, "Reserved" },
    { 0x0003, 0x00C7, "Optional - An expiration of the time leads to an AR termination." },
    { 0x00C8, 0xFFFF, "Mandatory - An expiration of the time leads to an AR termination." },
    { 0, 0, NULL }
};

static const value_string pn_io_ar_arnumber[] = {
    { 0x0000, "reserved" },
    { 0x0001, "1st AR of an ARset" },
    { 0x0002, "2nd AR of an ARset" },
    { 0x0003, "3rd AR of an ARset" },
    { 0x0004, "4th AR of an ARset" },
    /*0x0005 - 0xFFFF reserved */
    { 0, NULL }
};

static const value_string pn_io_ar_arresource[] = {
    { 0x0000, "reserved" },
    { 0x0002, "Communication endpoint shall allocate two ARs for the ARset" },
    /*0x0001 and 0x0003 - 0xFFFF reserved */
    { 0, NULL }
};

static const range_string pn_io_line_delay_value[] = {
    { 0x00000000, 0x00000000, "Line delay and cable delay unknown" },
    { 0x00000001, 0x7FFFFFFF, "Line delay in nanoseconds" },
    { 0, 0, NULL }
};

static const range_string pn_io_cable_delay_value[] = {
    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x7FFFFFFF, "Cable delay in nanoseconds" },
    { 0, 0, NULL }
};

static const true_false_string pn_io_pdportstatistic_counter_status_contents = {
    "The contents of the field are invalid. They shall be set to zero.",
    "The contents of the field are valid"
};

static const value_string pn_io_pdportstatistic_counter_status_reserved[] = {
    { 0x00, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_tsn_domain_vid_config_vals[] = {
    { 0x00, "Reserved" },
    { 0x64, "NonStreamVID-Default" },
    { 0x65, "StreamHighVID-Default" },
    { 0x66, "StreamHighRedVID-Default" },
    { 0x67, "StreamLowVID-Default" },
    { 0x68, "StreamLowRedVID-Default" },
    { 0x69, "NonStreamVIDB-Default" },
    { 0x6A, "NonStreamVIDC-Default" },
    { 0x6B, "NonStreamVIDD-Default" },
    { 0, NULL }
};

static const value_string pn_io_tsn_domain_port_config_preemption_enabled_vals[] = {
    { 0x00, "Preemption support is disabled for this port" },
    { 0x01, "Preemption support is enabled for this port" },
    { 0, NULL }
};

static const value_string pn_io_tsn_domain_port_config_boundary_port_config_vals[] = {
    { 0x00, "No boundary port" },
    { 0x01, "Boundary port with Remapping1" },
    { 0x02, "Boundary port with Remapping2" },
    { 0, NULL }
};

static const range_string pn_io_tsn_domain_port_ingress_rate_limiter_cir[] = {
    { 0x0000, 0x0000, "No Boundary Port" },
    { 0x0001, 0xFFFF, "Committed information rate in 0,1 Mbit/s"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_port_ingress_rate_limiter_cbs[] = {
    { 0x0000, 0x0000, "No Boundary Port" },
    { 0x0001, 0xFFFF, "Committed burst size in octets"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_port_ingress_rate_limiter_envelope[] = {
    { 0x0000, 0x0000, "No Boundary Port" },
    { 0x0001, 0x0001, "Best effort envelope"},
    { 0x0002, 0x0002, "RT_CLASS_X, RTA_CLASS_X envelope"},
    { 0x0003, 0xFFFF, "Reserved"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_port_ingress_rate_limiter_rank[] = {
    { 0x0000, 0x0000, "No Boundary Port" },
    { 0x0001, 0x0001, "CF1"},
    { 0x0002, 0x0002, "CF2"},
    { 0x0003, 0x0003, "CF3"},
    { 0x0004, 0x0004, "CF4"},
    { 0x0005, 0x0005, "CF5"},
    { 0x0006, 0xFFFF, "Reserved"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_cir[] = {
    { 0x0000, 0x0000, "Used in case of no rate limiter" },
    { 0x0001, 0xFFFF, "Committed information rate in 0,1 Mbit/s"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_cbs[] = {
    { 0x0000, 0x0000, "Used in case of no rate limiter" },
    { 0x0001, 0xFFFF, "Committed burst size in octets"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_envelope[] = {
    { 0x00, 0x00, "Used in case of no rate limiter" },
    { 0x01, 0x01, "Best effort envelope"},
    { 0x02, 0xFF, "Reserved"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_rank[] = {
    { 0x00, 0x00, "Used in case of no boundary port" },
    { 0x01, 0x01, "CF1"},
    { 0x02, 0x02, "CF2"},
    { 0x03, 0x03, "CF3"},
    { 0x04, 0x04, "CF4"},
    { 0x05, 0x05, "CF5"},
    { 0x06, 0xFF, "Reserved"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_queue_id[] = {
    { 0x00, 0x07, "Identifier of the queue" },
    { 0x08, 0xFF, "Reserved"},
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_rate_limiter_reserved[] = {
    { 0x00, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_io_network_domain[] = {
    { 0x00000000, 0x00000000, "No Deadline" },
    { 0x00000001, 0xFFFFFFFF, "The Deadline in Microseconds"},
    { 0, 0, NULL }
};

static const value_string pn_io_time_domain_number_vals[] = {
    { 0x0000, "Global Time" },
    { 0x0001, "Global Time Redundant" },
    { 0x0020, "Working Clock" },
    { 0x0021, "Working Clock Redundant" },
    { 0, NULL }
};

static const value_string pn_io_time_pll_window_vals[] = {
    { 0x00000000, "Disabled" },
    { 0x000003E8, "Default" },
    { 0x00002710, "Default" },
    { 0x000186A0, "Default" },
    { 0x000F4240, "Default" },
    { 0x00989680, "Default" },
    { 0, NULL }
};

static const value_string pn_io_message_interval_factor_vals[] = {
    { 0x0000, "Reserved" },
    { 0x03E8, "Default" },
    { 0x0FA0, "Default" },
    { 0, NULL }
};

static const range_string pn_io_message_timeout_factor[] = {
    { 0x0000, 0x0000, "Disabled" },
    { 0x0001, 0x0002, "Optional" },
    { 0x0003, 0x0005, "Mandatory" },
    { 0x0006, 0x0006, "Default, mandatory" },
    { 0x0007, 0x000F, "Mandatory" },
    { 0x0010, 0x01FF, "Optional" },
    { 0x0200, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const value_string pn_io_time_sync_properties_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "External Sync" },
    { 0x02, "Internal Sync" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static const range_string pn_io_tsn_domain_queue_config_shaper[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Strict Priority" },
    { 0x02, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_domain_sync_port_role_vals[] = {
    { 0x00,0x00, "The port is not part of the sync tree for this sync domain" },
    { 0x01,0x01, "Sync egress port for this sync domain" },
    { 0x02,0x02, "Sync ingress port for this sync domain" },
    { 0x02,0XFF, "Reserved" },
    { 0, 0, NULL }
};

static const value_string pn_io_tsn_fdb_command[] = {
    { 0x01, "AddStreamEntry" },
    { 0x02, "RemoveStreamEntry" },
    { 0x03, "RemoveAllStreamEntries" },
    /* all others reserved */
    { 0, NULL }
};

static const range_string pn_io_tsn_transfer_time_tx_vals[] = {
    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x05F5E100, "Egress transfer time for the local interface of an endstation" },
    { 0x05F5E101, 0xFFFFFFFF, "Reserved" },
    { 0, 0, NULL }

};

static const range_string pn_io_tsn_transfer_time_rx_vals[] = {

    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x05F5E100, "Ingress transfer time for the local interface of an endstation" },
    { 0x05F5E101, 0xFFFFFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_max_supported_record_size_vals[] = {
    { 0x00000000,0x00000FE3, "Reserved" },
    { 0x00000FE4,0x0000FFFF, "Describes the maximum supported size of RecordDataWrite." },
    {0x00010000,0xFFFFFFFF,"Reserved"},
    { 0, 0, NULL }
};
static const range_string pn_io_tsn_forwarding_group_vals[] = {
    { 0x00,0x00, "Reserved" },
    { 0x01,0xFF, "Identifier of logical port grouping. Identifies ports with equal forwarding delay values." },
    { 0, 0, NULL }
};

static const value_string pn_io_tsn_stream_class_vals[] = {

    /*other reserved */
    { 0x01, "High" },
    { 0x02, "High Redundant" },
    { 0x03, "Low" },
    { 0x04, "Low Redundant" },
    { 0, NULL }
};

static const range_string pn_io_tsn_independent_forwarding_delay_vals[] = {

    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x000F4240, "Independent bridge delay value used for calculation" },
    { 0, 0, NULL }
};

static const range_string pn_io_tsn_dependent_forwarding_delay_vals[] = {

    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x000C3500, "Octet size dependent bridge delay value used for calculation" },
    { 0, 0, NULL }
};

static const value_string pn_io_tsn_number_of_queues_vals[] = {

    { 0x06, "The bridge supports six transmit queues at the port" },
    { 0x08, "The bridge supports eight transmit queues at the port" },
    { 0, NULL }
};

static const value_string pn_io_tsn_port_capabilities_time_aware_vals[] = {
    { 0x00, "This port is not usable within a Time Aware System"},
    { 0x01, "This port is usable within a Time Aware System" },
    { 0, NULL }
};
static const value_string pn_io_tsn_port_capabilities_preemption_vals[] = {
    { 0x00, "Preemption is not supported at this port" },
    { 0x01, "Preemption is supported at this port"},
    { 0, NULL }
};

static const value_string pn_io_tsn_port_capabilities_queue_masking_vals[] = {
    { 0x00, "Queue Masking is not supported at this port"},
    { 0x01, "Queue Masking is supported at this port" },
    { 0, NULL }
};

/* Format of submodule ident number as per PA Profile 4.02 specification:
   [VariantOfSubmodule, Block_object, Parent_Class, Class] */
static const value_string pn_io_pa_profile_block_object_vals[] = {
    { 0, "DAP" },
    { 1, "PB" },
    { 2, "FB" },
    { 3, "TB" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_dap_submodule_vals[] = {
    { 1, "DAP" },
    { 2, "Device Management" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_physical_block_parent_class_vals[] = {
    { 1, "Transmitter" },
    { 2, "Actuator" },
    { 3, "Discrete I/O" },
    { 4, "Controller" },
    { 5, "Analyzer" },
    { 6, "Lab Device" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_function_block_class_vals[] = {
    { 1, "Input" },
    { 2, "Output" },
    { 3, "Further Input" },
    { 4, "Further Output" },
    { 128, "Manuf. specific Input" },
    { 129, "Manuf. specific Output" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_function_block_parent_class_vals[] = {
    {0, "Analog Temperature" },
    {1, "Analog Temperature Difference"},
    {2, "Analog Average Temperature"},
    {3, "Analog Electronics Temperature"},
    {4, "Analog Transmitter Temperature"},
    {5, "Analog Sensor Temperature"},
    {6, "Analog Frame Temperature"},
    {7, "Analog Auxiliary Temperature"},
    {8, "Analog Energy Supply Temperature"},
    {9, "Analog Energy Return Temperature"},
    {20, "Analog Pressure"},
    {21, "Analog Absolute Pressure"},
    {22, "Analog Gauge Pressure"},
    {23, "Analog Differential Pressure"},
    {30, "Analog Level"},
    {31, "Analog Distance"},
    {32, "Analog Interface Level"},
    {33, "Analog Interface Distance"},
    {40, "Analog Volume"},
    {41, "Analog Ullage"},
    {42, "Analog Interface Volume"},
    {43, "Analog Standard Volume"},
    {44, "Analog Fraction Substance 1 Volume"},
    {45, "Analog Fraction Substance 2 Volume"},
    {46, "Analog Fraction Substance 1 Std Volume"},
    {47, "Analog Fraction Substance 2 Std Volume"},
    {50, "Analog Mass"},
    {51, "Analog Net Mass"},
    {52, "Analog Fraction Substance 1 Mass"},
    {53, "Analog Fraction Substance 2 Mass"},
    {60, "Analog Volume Flow"},
    {61, "Analog Standard Volume Flow"},
    {62, "Analog Fraction Substance 1 Volume Flow"},
    {63, "Analog Fraction Substance 2 Volume Flow"},
    {70, "Analog Mass Flow"},
    {71, "Analog Fraction Substance 1 Mass Flow"},
    {72, "Analog Fraction Substance 2 Mass Flow"},
    {80, "Analog Density"},
    {81, "Analog Standard Density"},
    {82, "Analog Analog Api Gravity"},
    {83, "Analog Standard Api Gravity"},
    {84, "Analog Specific Gravity"},
    {85, "Analog Standard Specific Gravity"},
    {90, "Analog Flow Velocity"},
    {91, "Analog Sound Velocity"},
    {92, "Analog Rate Of Change"},
    {100, "Analog Kinematic Viscosity"},
    {101, "Analog Dynamic Viscosity"},
    {110, "Analog Energy"},
    {111, "Analog Power"},
    {120, "Analog Vortex Frequency"},
    {130, "Analog Concentration"},
    {131, "Analog Energy Efficiency Rating"},
    {132, "Analog Coefficient Of Performance"},
    {133, "Analog Fraction Substance 1%"},
    {134, "Analog Fraction Substance 2%"},
    {140, "Analog pH"},
    {141, "Analog Conductivity"},
    {142, "Analog Resistivity"},
    {143, "Analog Gas Concentration"},
    {149, "Flexible AI"},
    {150, "Totalizer"},
    {160, "Actuator"},
    {170, "Discrete"},
    {180, "Enumerated"},
    {190, "Binary(8 Bit)"},
    {191, "Binary(16 Bit)"},
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_parent_class_vals[] = {
    { 1, "Pressure" },
    { 2, "Temperature" },
    { 3, "Flow" },
    { 4, "Level" },
    { 5, "Actuator" },
    { 6, "Discrete I/O" },
    { 7, "Liquid analyzer" },
    { 8, "Gas analyzer" },
    { 10, "Enumerated I/O" },
    { 11, "Binary I/O" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_pressure_class_vals[] = {
    { 1, "Pressure" },
    { 2, "Pressure + level" },
    { 3, "Pressure + flow" },
    { 4, "Pressure + level + flow" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_temperature_class_vals[] = {
    { 1, "Thermocouple (TC)" },
    { 2, "Resistance thermometer (RTD)" },
    { 3, "Pyrometer" },
    { 16, "TC + DC U (DC Voltage)" },
    { 17, "RTD + R (R-Resistance)" },
    { 18, "TC+RTD+r+DC U" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_flow_class_vals[] = {
    { 1, "Electromagnetic" },
    { 2, "Vortex" },
    { 3, "Coriolis" },
    { 4, "Thermal mass" },
    { 5, "Ultrasonic" },
    { 6, "Variable area" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_level_class_vals[] = {
    { 1, "Hydrostatic" },
    { 2, "Ultrasonic" },
    { 3, "Radiometric" },
    { 4, "Capacitance" },
    { 5, "Displacer" },
    { 6, "Float" },
    { 7, "Radar" },
    { 8, "Buoyancy" },
    { 9, "Air bubble system" },
    { 10, "Gravimetric" },
    { 11, "Optical" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_actuator_class_vals[] = {
    { 1, "Electric" },
    { 2, "Electro-pneumatic" },
    { 3, "Electro-hydraulic" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_discrete_io_class_vals[] = {
    { 1, "Input" },
    { 2, "Output" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_liquid_analyzer_class_vals[] = {
    { 1, "pH" },
    { 2, "Conductivity" },
    { 3, "Oxygen" },
    { 4, "Chlorine" },
    { 5, "Resistivity" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_gas_analyzer_class_vals[] = {
    { 1, "Standard" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_enumerated_io_class_vals[] = {
    { 1, "Input" },
    { 2, "Output" },
    { 0, NULL }
};

static const value_string pn_io_pa_profile_transducer_block_binary_io_class_vals[] = {
    { 2, "8 Bit output" },
    { 3, "8 Bit input" },
    { 4, "16 Bit output" },
    { 5, "16 Bit input" },
    { 0, NULL }
};

static const value_string* pn_io_pa_profile_transducer_block_class_vals[] = {
    NULL,
    pn_io_pa_profile_transducer_block_pressure_class_vals,
    pn_io_pa_profile_transducer_block_temperature_class_vals,
    pn_io_pa_profile_transducer_block_flow_class_vals,
    pn_io_pa_profile_transducer_block_level_class_vals,
    pn_io_pa_profile_transducer_block_actuator_class_vals,
    pn_io_pa_profile_transducer_block_discrete_io_class_vals,
    pn_io_pa_profile_transducer_block_liquid_analyzer_class_vals,
    pn_io_pa_profile_transducer_block_gas_analyzer_class_vals,
    NULL,
    pn_io_pa_profile_transducer_block_enumerated_io_class_vals,
    pn_io_pa_profile_transducer_block_binary_io_class_vals
};


static int
dissect_profidrive_value(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                         proto_tree *tree, guint8 *drep, guint8 format_val)
{
    guint32 value32;
    guint16 value16;
    guint8  value8;

    switch(format_val)
    {
    case 1:
    case 2:
    case 5:
    case 0x0A:
    case 0x41:
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_profidrive_param_value_byte, &value8);
        break;
    case 3:
    case 6:
    case 0x42:
    case 0x73:
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_profidrive_param_value_word, &value16);
        break;
    case 4:
    case 7:
    case 0x43:
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_profidrive_param_value_dword, &value32);
        break;
    case 8:
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_profidrive_param_value_float, &value32);
        break;
    case 9:
        {
            gint sLen;
            sLen = (gint)tvb_strnlen( tvb, offset, -1);
            proto_tree_add_item(tree, hf_pn_io_profidrive_param_value_string, tvb, offset, sLen, ENC_ASCII);
            offset = (offset + sLen);
            break;
        }
    default:
        offset = offset + 1;
        expert_add_info_format(pinfo, tree, &ei_pn_io_unsupported, "Not supported or invalid format %u!", format_val);
        break;
    }
    return(offset);
}

static GList *pnio_ars;

typedef struct pnio_ar_s {
    /* generic */
    e_guid_t     aruuid;
    guint16      inputframeid;
    guint16      outputframeid;

    /* controller only */
    /*const char      controllername[33];*/
    guint8       controllermac[6];
    guint16      controlleralarmref;

    /* device only */
    guint8       devicemac[6];
    guint16      devicealarmref;
    guint16      arType;
} pnio_ar_t;



static void
pnio_ar_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, pnio_ar_t *ar)
{
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pn_io, 0, ar );
    p_add_proto_data(pinfo->pool, pinfo, proto_pn_io, 0, GUINT_TO_POINTER(10));

    if (tree) {
        proto_item *item;
        proto_item *sub_item;
        proto_tree *sub_tree;
        address   controllermac_addr, devicemac_addr;

        set_address(&controllermac_addr, AT_ETHER, 6, ar->controllermac);
        set_address(&devicemac_addr, AT_ETHER, 6, ar->devicemac);

        sub_tree = proto_tree_add_subtree_format(tree, tvb, 0, 0, ett_pn_io_ar_info, &sub_item,
            "ARUUID:%s ContrMAC:%s ContrAlRef:0x%x DevMAC:%s DevAlRef:0x%x InCR:0x%x OutCR=0x%x",
            guid_to_str(pinfo->pool, (const e_guid_t*) &ar->aruuid),
            address_to_str(pinfo->pool, &controllermac_addr), ar->controlleralarmref,
            address_to_str(pinfo->pool, &devicemac_addr), ar->devicealarmref,
            ar->inputframeid, ar->outputframeid);
        proto_item_set_generated(sub_item);

        item = proto_tree_add_guid(sub_tree, hf_pn_io_ar_uuid, tvb, 0, 0, (e_guid_t *) &ar->aruuid);
        proto_item_set_generated(item);

        item = proto_tree_add_ether(sub_tree, hf_pn_io_cminitiator_macadd, tvb, 0, 0, ar->controllermac);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_localalarmref, tvb, 0, 0, ar->controlleralarmref);
        proto_item_set_generated(item);

        item = proto_tree_add_ether(sub_tree, hf_pn_io_cmresponder_macadd, tvb, 0, 0, ar->devicemac);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_localalarmref, tvb, 0, 0, ar->devicealarmref);
        proto_item_set_generated(item);

        item = proto_tree_add_uint(sub_tree, hf_pn_io_frame_id, tvb, 0, 0, ar->inputframeid);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(sub_tree, hf_pn_io_frame_id, tvb, 0, 0, ar->outputframeid);
        proto_item_set_generated(item);
    }
}




static int dissect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar);

static int dissect_a_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep);

static int dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, int hfindex);





static pnio_ar_t *
pnio_ar_find_by_aruuid(packet_info *pinfo _U_, e_guid_t *aruuid)
{
    GList     *ars;
    pnio_ar_t *ar;


    /* find pdev */
    for(ars = pnio_ars; ars != NULL; ars = g_list_next(ars)) {
        ar = (pnio_ar_t *)ars->data;

        if (memcmp(&ar->aruuid, aruuid, sizeof(e_guid_t)) == 0) {
            return ar;
        }
    }

    return NULL;
}


static pnio_ar_t *
pnio_ar_new(e_guid_t *aruuid)
{
    pnio_ar_t *ar;


    ar = wmem_new0(wmem_file_scope(), pnio_ar_t);

    memcpy(&ar->aruuid, aruuid, sizeof(e_guid_t));

    ar->controlleralarmref  = 0xffff;
    ar->devicealarmref      = 0xffff;

    pnio_ars = g_list_append(pnio_ars, ar);

    return ar;
}

/* dissect the alarm specifier */
static int
dissect_Alarm_specifier(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16     u16AlarmSpecifierSequence;
    guint16     u16AlarmSpecifierChannel;
    guint16     u16AlarmSpecifierManufacturer;
    guint16     u16AlarmSpecifierSubmodule;
    guint16     u16AlarmSpecifierAR;
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
    guint16     u16ChannelProperties;


    sub_item = proto_tree_add_item(tree, hf_pn_io_channel_properties, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_channel_properties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_direction, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_specifier, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_maintenance, &u16ChannelProperties);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_accumulative, &u16ChannelProperties);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_channel_properties_type, &u16ChannelProperties);

    return offset;
}

/* dissect the RS_BlockHeader */
static int
dissect_RS_BlockHeader(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep,
    guint16 *u16RSBodyLength, guint16 *u16RSBlockType)
{
    guint16 u16RSBlockLength;
    guint8  u8BlockVersionHigh;
    guint8  u8BlockVersionLow;

    /* u16RSBlockType is needed for further dissection */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_block_type, u16RSBlockType);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_block_length, &u16RSBlockLength);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_block_version_high, &u8BlockVersionHigh);
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_block_version_low, &u8BlockVersionLow);

    proto_item_append_text(item, ": Type=%s, Length=%u(+4), Version=%u.%u",
        rval_to_str(*u16RSBlockType, pn_io_rs_block_type, "Unknown (0x%04x)"),
        u16RSBlockLength, u8BlockVersionHigh, u8BlockVersionLow);

    /* Block length is without type and length fields, but with version field */
    /* as it's already dissected, remove it */
    *u16RSBodyLength = u16RSBlockLength - 2;

    /* Padding 2 + 2 + 1 + 1 = 6 */
    /* Therefore we need 2 byte padding to make the block u32 aligned */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* remove padding */
    *u16RSBodyLength -= 2;
    return offset;
}

static int
dissect_RS_AddressInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep, guint16 *u16RSBodyLength)
{
    e_guid_t IM_UniqueIdentifier;
    guint32  u32Api;
    guint16  u16SlotNr;
    guint16  u16SubslotNr;
    guint16  u16ChannelNumber;

    /* IM_UniqueIdentifier */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_ar_uuid, &IM_UniqueIdentifier);
    *u16RSBodyLength -= 16;

    /* API */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
        hf_pn_io_api, &u32Api);
    *u16RSBodyLength -= 4;

    /* SlotNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_slot_nr, &u16SlotNr);
    *u16RSBodyLength -= 2;

    /* SubSlotNumber*/
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_subslot_nr, &u16SubslotNr);
    *u16RSBodyLength -= 2;

    /* Channel Number*/
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_channel_number, &u16ChannelNumber);
    *u16RSBodyLength -= 2;

    return offset;
}

/* dissect the RS_EventDataCommon */
static int
dissect_RS_EventDataCommon(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep, guint16 *u16RSBodyLength)
{
    guint16     u16RSSpecifierSequenceNumber;
    guint16     u16RSSpecifierReserved;
    guint16     u16RSSpecifierSpecifier;
    guint16     u16RSMinorError;
    guint16     u16RSPlusError;
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    proto_item  *sub_item_time_stamp;
    proto_tree  *sub_tree_time_stamp;
    nstime_t    timestamp;
    guint16     u16RSTimeStampStatus;

    /* RS_AddressInfo */
    offset = dissect_RS_AddressInfo(tvb, offset, pinfo, tree, drep, u16RSBodyLength);

    /* RS_Specifier */
    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_specifier, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_specifier);

    /* RS_Specifier.SequenceNumber */
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_rs_specifier_sequence, &u16RSSpecifierSequenceNumber);

    /* RS_Specifier.Reserved */
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_rs_specifier_reserved, &u16RSSpecifierReserved);

    /* RS_Specifier.Specifier */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_rs_specifier_specifier, &u16RSSpecifierSpecifier);
    *u16RSBodyLength -= 2;

    /* RS_TimeStamp */
    sub_item_time_stamp = proto_tree_add_item(tree, hf_pn_io_rs_time_stamp, tvb, offset, 12, ENC_NA);
    sub_tree_time_stamp = proto_item_add_subtree(sub_item_time_stamp, ett_pn_io_rs_time_stamp);

    /* RS_TimeStamp.Status */
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree_time_stamp, drep,
        hf_pn_io_rs_time_stamp_status, &u16RSTimeStampStatus);

    /* RS_TimeStamp.TimeStamp */

    /* Start after from 2 bytes Status */
    timestamp.secs = (time_t)tvb_get_ntoh48(tvb, offset + 2);

    /* Start after from 4 bytes timestamp.secs */
    timestamp.nsecs = (int)tvb_get_ntohl(tvb, offset + 8);

    /* Start after from 2 bytes Status and get all 10 bytes */
    proto_tree_add_time(sub_tree_time_stamp, hf_pn_io_rs_time_stamp_value, tvb, offset + 2, 10, &timestamp);
    *u16RSBodyLength -= 12;
    offset += 12;

    /* RS_MinusError */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_minus_error, &u16RSMinorError);
    *u16RSBodyLength -= 2;

    /* RS_PlusError */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_plus_error, &u16RSPlusError);
    *u16RSBodyLength -= 2;

    return offset;
}

/* dissect the RS_IdentificationInfo */
static int
dissect_RS_IdentificationInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    dcerpc_info di; /* fake dcerpc_info struct */
    dcerpc_call_value dcv; /* fake dcerpc_call_value struct */
    guint64     u64AMDeviceIdentificationDeviceSubID;
    guint64     u64AMDeviceIdentificationDeviceID;
    guint64     u64AMDeviceIdentificationVendorID;
    guint64     u64AM_DeviceIdentificationOrganization;

    proto_item *sub_item;
    proto_tree *sub_tree;

    di.call_data = &dcv;

    sub_item = proto_tree_add_item(tree, hf_pn_io_am_device_identification, tvb, offset, 8, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_am_device_identification);

    /* AM_DeviceIdentification */
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_device_sub_id, &u64AMDeviceIdentificationDeviceSubID);
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_device_id, &u64AMDeviceIdentificationDeviceID);
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_vendor_id, &u64AMDeviceIdentificationVendorID);
    offset = dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_organization, &u64AM_DeviceIdentificationOrganization);

    /* IM_Tag_Function [32] */
    proto_tree_add_item(tree, hf_pn_io_im_tag_function, tvb, offset, 32, ENC_ASCII);
    offset += 32;

    /* IM_Tag_Location [22] */
    proto_tree_add_item(tree, hf_pn_io_im_tag_location, tvb, offset, 22, ENC_ASCII);
    offset += 22;

    return offset;
}

/* dissect the RS_EventDataExtension_Data */
static int
dissect_RS_EventDataExtension_Data(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep,
    guint8 *u8RSExtensionBlockLength, guint16 *u16RSBlockType)
{
    guint32     u32RSReasonCodeReason;
    guint32     u32RSReasonCodeDetail;
    guint8      u8LengthRSDomainIdentification = 16;
    guint8      u8LengthRSMasterIdentification = 8;
    guint16     u16SoE_DigitalInputCurrentValueValue;
    guint16     u16SoE_DigitalInputCurrentValueReserved;

    proto_item *sub_item;
    proto_tree *sub_tree;
    nstime_t timestamp;
    guint16 u16RSTimeStampStatus;
    proto_item *sub_item_time_stamp;
    proto_tree *sub_tree_time_stamp;

    switch (*u16RSBlockType) {
    case(0x4000): /* RS_StopObserver */

        /* RS_BlockType */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_block_type, u16RSBlockType);

        /* RS_ReasonCode */
        sub_item = proto_tree_add_item(tree, hf_pn_io_rs_reason_code, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_reason_code);
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_rs_reason_code_reason, &u32RSReasonCodeReason);
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_rs_reason_code_detail, &u32RSReasonCodeDetail);
        *u8RSExtensionBlockLength -= 6;
        break;
    case(0x4001): /* RS_BufferObserver */
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, *u8RSExtensionBlockLength, "UserData");
        *u8RSExtensionBlockLength = 0;
        break;
    case(0x4002): /* RS_TimeStatus */

        /* Padding 1 + 1 + 16 + 8 = 26  or 1 + 1 + 16 + 8 + 12 = 38 */
        /* Therefore we need 2 byte padding to make the block u32 aligned */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);
        *u8RSExtensionBlockLength -= 2;

        /* RS_DomainIdentification */
        proto_tree_add_item(tree, hf_pn_io_rs_domain_identification, tvb, offset, u8LengthRSDomainIdentification, ENC_NA);
        offset += u8LengthRSDomainIdentification;
        *u8RSExtensionBlockLength -= 16;

        /* RS_MasterIdentification */
        proto_tree_add_item(tree, hf_pn_io_rs_master_identification, tvb, offset, u8LengthRSMasterIdentification, ENC_NA);
        offset += u8LengthRSMasterIdentification;
        *u8RSExtensionBlockLength -= 8;

        if (*u8RSExtensionBlockLength > 2)
        {
            /* RS_TimeStamp */
            sub_item_time_stamp = proto_tree_add_item(tree, hf_pn_io_rs_time_stamp, tvb, offset, 12, ENC_NA);
            sub_tree_time_stamp = proto_item_add_subtree(sub_item_time_stamp, ett_pn_io_rs_time_stamp);

            /* RS_TimeStamp.Status */
            dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree_time_stamp, drep,
                hf_pn_io_rs_time_stamp_status, &u16RSTimeStampStatus);

            /* RS_TimeStamp.TimeStamp */
            timestamp.secs = (time_t)tvb_get_ntoh48(tvb, offset + 2); // Start after from 2 bytes Status
            timestamp.nsecs = (int)tvb_get_ntohl(tvb, offset + 8);  // Start after from 4 bytes timestamp.secs
            // Start after from 2 bytes Status and get all 10 bytes
            proto_tree_add_time(sub_tree_time_stamp, hf_pn_io_rs_time_stamp_value, tvb, offset + 2, 10, &timestamp);
            offset += 12;
        }
        break;
    case(0x4003): /* RS_SRLObserver */
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, *u8RSExtensionBlockLength, "UserData");
        *u8RSExtensionBlockLength = 0;
        break;
    case(0x4004): /* RS_SourceIdentification */
        offset = dissect_RS_IdentificationInfo(tvb, offset, pinfo, tree, drep);
        *u8RSExtensionBlockLength = 0;
        break;
    case(0x4010): /* SoE_DigitalInputObserver */
        /* SoE_DigitalInputCurrentValue */
        sub_item = proto_tree_add_item(tree, hf_pn_io_soe_digital_input_current_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_soe_digital_input_current_value);

        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_soe_digital_input_current_value_value, &u16SoE_DigitalInputCurrentValueValue);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_soe_digital_input_current_value_reserved, &u16SoE_DigitalInputCurrentValueReserved);
        *u8RSExtensionBlockLength -= 2;
        break;
    default:
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, *u8RSExtensionBlockLength, "UserData");
        *u8RSExtensionBlockLength = 0;
        break;
    }
    return offset;
}

/* dissect the RS_EventDataExtension */
static int
dissect_RS_EventDataExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
    proto_tree *tree, guint8 *drep, guint16 *u16RSBlockLength, guint16 *u16RSBlockType)
{
    guint8 u8RSExtensionBlockType;
    guint8 u8RSExtensionBlockLength;

    /* RS_ExtensionBlockType */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_extension_block_type, &u8RSExtensionBlockType);
    *u16RSBlockLength -= 1;

    /* RS_ExtensionBlockLength */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_extension_block_length, &u8RSExtensionBlockLength);
    *u16RSBlockLength -= 1;

    /* Data*[Padding] * a*/
    while (u8RSExtensionBlockLength) {
        *u16RSBlockLength -= u8RSExtensionBlockLength;
        offset = dissect_RS_EventDataExtension_Data(tvb, offset, pinfo, tree, drep,
            &u8RSExtensionBlockLength, u16RSBlockType);
    }

    return offset;
}

/* dissect the RS_EventData */
static int
dissect_RS_EventData(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep,
    guint16 *u16RSBodyLength, guint16 *u16RSBlockType)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    /* RS_EventDataCommon */
    offset = dissect_RS_EventDataCommon(tvb, offset, pinfo, tree, drep, u16RSBodyLength);

    /* optional: RS_EventDataExtension */
    while (*u16RSBodyLength > 0) {
        sub_item = proto_tree_add_item(tree, hf_pn_io_rs_event_data_extension, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_event_data_extension);
        offset = dissect_RS_EventDataExtension(tvb, offset, pinfo, sub_tree, drep,
            u16RSBodyLength, u16RSBlockType);
    }

    return offset;
}

/* dissect the RS_EventBlock */
static int
dissect_RS_EventBlock(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    guint16 u16RSBodyLength;
    guint16 u16RSBlockType;

    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_event_block, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_event_block);

    /* RS_BlockHeader */
    offset = dissect_RS_BlockHeader(tvb, offset, pinfo, sub_tree, sub_item, drep,
        &u16RSBodyLength, &u16RSBlockType);

    /* RS_EventData */
    offset = dissect_RS_EventData(tvb, offset, pinfo, sub_tree, drep,
        &u16RSBodyLength, &u16RSBlockType);
    return offset;
}

/* dissect the RS_AlarmInfo */
static int
dissect_RS_AlarmInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16    u16RSAlarmInfo;

    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_alarm_info, tvb, offset, 2, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_alarm_info);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_rs_alarm_info_reserved_0_7, &u16RSAlarmInfo);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_rs_alarm_info_reserved_8_15, &u16RSAlarmInfo);

    return offset;
}

/* dissect the RS_EventInfo */
static int
dissect_RS_EventInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16    u16NumberofEntries;

    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_event_info, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_event_info);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_number_of_rs_event_info, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;
        offset = dissect_RS_EventBlock(tvb, offset, pinfo, sub_tree, drep);
    }
    return offset;
}

static int
dissect_Diagnosis(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
        proto_tree *tree, proto_item *item, guint8 *drep, guint16 u16UserStructureIdentifier)
{
    guint16    u16ChannelNumber;
    guint16    u16ChannelErrorType;
    guint16    u16ExtChannelErrorType;
    guint32    u32ExtChannelAddValue;
    guint32    u32QualifiedChannelQualifier;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_channel_number, &u16ChannelNumber);

    offset = dissect_ChannelProperties(tvb, offset, pinfo, tree, item, drep);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_channel_error_type, &u16ChannelErrorType);

    if (u16UserStructureIdentifier == 0x8000) /* ChannelDiagnosisData */
    {
        return offset;
    }

    if (u16ChannelErrorType < 0x7fff)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8000)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8000, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8001)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8001, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8002)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8002, &u16ExtChannelErrorType);
    }
    else if ((u16ChannelErrorType == 0x8003)||(u16ChannelErrorType == 0x8009))
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8003, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8004)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8004, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8005)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8005, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8007)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8007, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8008)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8008, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x800A)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x800A, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x800B)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x800B, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x800C)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x800C, &u16ExtChannelErrorType);
    }
    else if (u16ChannelErrorType == 0x8010)
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type0x8010, &u16ExtChannelErrorType);
    }
    else
    {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_error_type, &u16ExtChannelErrorType);
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_ext_channel_add_value, &u32ExtChannelAddValue);

    if (u16UserStructureIdentifier == 0x8002) /* ExtChannelDiagnosisData */
    {
        return offset;
    }

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_qualified_channel_qualifier, &u32QualifiedChannelQualifier);

    /* QualifiedChannelDiagnosisData */
    return offset;
}

static int
dissect_AlarmUserStructure(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
        guint16 *body_length, guint16 u16UserStructureIdentifier)
{
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;

    switch (u16UserStructureIdentifier) {
    case(0x8000):   /* ChannelDiagnosisData */
        offset = dissect_Diagnosis(tvb, offset, pinfo, tree, item, drep,
                        u16UserStructureIdentifier);
        *body_length -= 6;
        break;
    case(0x8002):   /* ExtChannelDiagnosisData */
        offset = dissect_Diagnosis(tvb, offset, pinfo, tree, item, drep,
                        u16UserStructureIdentifier);
        *body_length -= 12;
        break;
  case (0x8003):    /* QualifiedChannelDiagnosisData */
        offset = dissect_Diagnosis(tvb, offset, pinfo, tree, item, drep,
                        u16UserStructureIdentifier);
        *body_length -= 16;
        break;
    case(0x8100):   /* MaintenanceItem */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        *body_length -= 12;
        break;
    case(0x8300): /* RS_AlarmInfo (Reporting System Alarm Information) */
    case(0x8301): /* RS_AlarmInfo */
    case(0x8302): /* RS_AlarmInfo */
        offset = dissect_RS_AlarmInfo(tvb, offset, pinfo, tree, drep);
        *body_length = 0;
        break;
    case(0x8303): /* RS_EventInfo (Reporting System Event Information) */
        offset = dissect_RS_EventInfo(tvb, offset, pinfo, tree, drep);
        *body_length = 0;
        break;
    case(0x8310): /* PE_EnergySavingStatus */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        *body_length = 0;
        break;
    /* XXX - dissect remaining user structures of [AlarmItem] */
    case(0x8001):   /* DiagnosisData */
     default:
        if (u16UserStructureIdentifier >= 0x8000) {
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    while (body_length) {
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
    guint8   u8VendorIDHigh;
    guint8   u8VendorIDLow;
    guint16  u16IMHardwareRevision;
    guint8   u8SWRevisionPrefix;
    guint8   u8IMSWRevisionFunctionalEnhancement;
    guint8   u8IMSWRevisionBugFix;
    guint8   u8IMSWRevisionInternalChange;
    guint16  u16IMRevisionCounter;
    guint16  u16IMProfileID;
    guint16  u16IMProfileSpecificType;
    guint8   u8IMVersionMajor;
    guint8   u8IMVersionMinor;
    guint16  u16IMSupported;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    proto_tree_add_item (tree, hf_pn_io_order_id, tvb, offset, 20, ENC_ASCII);
    offset += 20;

    /* c8[16] IM_Serial_Number */
    proto_tree_add_item (tree, hf_pn_io_im_serial_number, tvb, offset, 16, ENC_ASCII);
    offset += 16;

    /* x16 IM_Hardware_Revision */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_im_hardware_revision, &u16IMHardwareRevision);
    /* c8 SWRevisionPrefix */
    offset = dissect_dcerpc_char(tvb, offset, pinfo, tree, drep,
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

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Tag_Function [32] */
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_im_tag_function, tvb, offset, 32, ENC_ASCII, pinfo->pool, &pTagFunction);
    offset += 32;

    /* IM_Tag_Location [22] */
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_im_tag_location, tvb, offset, 22, ENC_ASCII, pinfo->pool, &pTagLocation);
    offset += 22;

    proto_item_append_text(item, ": TagFunction:\"%s\", TagLocation:\"%s\"", pTagFunction, pTagLocation);

    return offset;
}


static int
dissect_IandM2_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pDate;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Date [16] */
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_im_date, tvb, offset, 16, ENC_ASCII, pinfo->pool, &pDate);
    offset += 16;

    proto_item_append_text(item, ": Date:\"%s\"", pDate);

    return offset;
}


static int
dissect_IandM3_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    char *pDescriptor;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* IM_Descriptor [54] */
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_im_descriptor, tvb, offset, 54, ENC_ASCII, pinfo->pool, &pDescriptor);
    offset += 54;

    proto_item_append_text(item, ": Descriptor:\"%s\"", pDescriptor);

    return offset;
}


static int
dissect_IandM4_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    dissect_pn_user_data(tvb, offset, pinfo, tree, 54, "IM Signature");

    return offset;
}

static int
dissect_IandM5_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_im_numberofentries, &u16NumberofEntries);

    while(u16NumberofEntries > 0) {
        offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
        u16NumberofEntries--;
    }
    return offset;
}

static int
dissect_IandM0FilterData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16NumberOfModules;
    guint16     u16SlotNr;
    guint32     u32ModuleIdentNumber;
    guint16     u16NumberOfSubmodules;
    guint16     u16SubslotNr;
    guint32     u32SubmoduleIdentNumber;
    proto_item *subslot_item;
    proto_tree *subslot_tree;
    proto_item *module_item;
    proto_tree *module_tree;
    guint32     u32ModuleStart;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_api, &u32Api);
        /* NumberOfModules */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_modules, &u16NumberOfModules);

        while (u16NumberOfModules--) {
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

            while (u16NumberOfSubmodules--) {
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


static int
dissect_IandM5Data_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep)
{
    guint8     u8VendorIDHigh;
    guint8     u8VendorIDLow;
    guint16    u16IMHardwareRevision;
    guint8     u8SWRevisionPrefix;
    guint8     u8IMSWRevisionFunctionalEnhancement;
    guint8     u8IMSWRevisionBugFix;
    guint8     u8IMSWRevisionInternalChange;

    /* c8[64] IM Annotation */
    proto_tree_add_item(tree, hf_pn_io_im_annotation, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* c8[64] IM Order ID */
    proto_tree_add_item(tree, hf_pn_io_im_order_id, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* x8 VendorIDHigh */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_high, &u8VendorIDHigh);
    /* x8 VendorIDLow */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_vendor_id_low, &u8VendorIDLow);

    /* c8[16] IM Serial Number */
    proto_tree_add_item(tree, hf_pn_io_im_serial_number, tvb, offset, 16, ENC_ASCII);
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

    return offset;
}

static int
dissect_AM_Location(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item          *sub_item;
    proto_tree          *sub_tree;
    guint8              am_location_structtype;
    int bit_offset;
    guint8 am_location_reserved1;
    guint16 am_location_begin_slot_number;
    guint16 am_location_begin_subslot_number;
    guint16 am_location_end_slot_number;
    guint16 am_location_end_subslot_number;
    guint16 am_location_reserved2;
    guint16 am_location_reserved3;
    guint16 am_location_reserved4;

    sub_item = proto_tree_add_item(tree, hf_pn_io_am_location, tvb, offset, 16, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_am_location);

    am_location_structtype = tvb_get_guint8(tvb, offset+15);
    bit_offset = offset << 3;

    switch (am_location_structtype)
    {
    case (0x01):

        /* level 11 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_11, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 10 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_10, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 9 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_9, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 8 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_8, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 7 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_7, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 6 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_6, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 5 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_5, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 4 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_4, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 3 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_3, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 2 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_2, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 1 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_1, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 0 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_level_0, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        /* level 0 */
        proto_tree_add_bits_item(sub_tree, hf_pn_io_am_location_structure, tvb, bit_offset, 8, ENC_BIG_ENDIAN);

        offset += 16;

        break;
    case (0x02):
        /* Reserved 4 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_reserved4, &am_location_reserved4);

        /* Reserved 3 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_reserved3, &am_location_reserved3);

        /* Reserved 2 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_reserved2, &am_location_reserved2);

        /* EndSubSlotNumber*/
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_endsubslotnum, &am_location_end_subslot_number);

        /* EndSlotNumber*/
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_endslotnum, &am_location_end_slot_number);

        /* BeginSubslotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_beginsubslotnum, &am_location_begin_subslot_number);

        /* BeginSlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_beginslotnum, &am_location_begin_slot_number);

        /* Reserved1 */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_reserved1, &am_location_reserved1);

        /* Structure */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_am_location_structure, &am_location_structtype);

        break;
    default: /* will not execute because of the line preceding the switch */
        offset += 16;
        break;
    }

    return offset;
}

static int
dissect_IM_software_revision(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8   u8SWRevisionPrefix;
    guint8   u8IMSWRevisionFunctionalEnhancement;
    guint8   u8IMSWRevisionBugFix;
    guint8   u8IMSWRevisionInternalChange;

    /* SWRevisionPrefix */
    offset = dissect_dcerpc_char(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_revision_prefix, &u8SWRevisionPrefix);

    /* IM_SWRevision_Functional_Enhancement */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_sw_revision_functional_enhancement, &u8IMSWRevisionFunctionalEnhancement);

    /* IM_SWRevision_Bug_Fix */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_revision_bugfix, &u8IMSWRevisionBugFix);

    /* IM_SWRevision_Internal_Change */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_sw_revision_internal_change, &u8IMSWRevisionInternalChange);

    return offset;
}

static int
dissect_AM_device_identification(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    dcerpc_info di; /* fake dcerpc_info struct */
    dcerpc_call_value dcv; /* fake dcerpc_call_value struct */
    guint64     u64AMDeviceIdentificationDeviceSubID;
    guint64     u64AMDeviceIdentificationDeviceID;
    guint64     u64AMDeviceIdentificationVendorID;
    guint64     u64AM_DeviceIdentificationOrganization;

    proto_item *sub_item;
    proto_tree *sub_tree;

    di.call_data = &dcv;

    sub_item = proto_tree_add_item(tree, hf_pn_io_am_device_identification, tvb, offset, 8, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_am_device_identification);
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_device_sub_id, &u64AMDeviceIdentificationDeviceSubID);
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_device_id, &u64AMDeviceIdentificationDeviceID);
    dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_vendor_id, &u64AMDeviceIdentificationVendorID);
    offset = dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
        hf_pn_io_am_device_identification_organization, &u64AM_DeviceIdentificationOrganization);

    return offset;
}

static int
dissect_AM_FullInformation_block(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_guid_t IM_UniqueIdentifier;
    guint16  u16AM_TypeIdentification;
    guint16  u16IMHardwareRevision;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* align padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* IM_UniqueIdentifier */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_uniqueidentifier, &IM_UniqueIdentifier);

    /* AM_Location */
    offset = dissect_AM_Location(tvb, offset, pinfo, tree, drep);

    /* IM_Annotation */
    proto_tree_add_item(tree, hf_pn_io_im_annotation, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* IM_OrderID */
    proto_tree_add_item(tree, hf_pn_io_im_order_id, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* AM_SoftwareRevision */
    proto_tree_add_item(tree, hf_pn_io_am_software_revision, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* AM_HardwareRevision */
    proto_tree_add_item(tree, hf_pn_io_am_hardware_revision, tvb, offset, 64, ENC_ASCII);
    offset += 64;

    /* IM_Serial_Number */
    proto_tree_add_item(tree, hf_pn_io_im_serial_number, tvb, offset, 16, ENC_ASCII);
    offset += 16;

    /* IM_Software_Revision */
    offset = dissect_IM_software_revision(tvb, offset, pinfo, tree, drep);

    /* AM_DeviceIdentification */
    offset = dissect_AM_device_identification(tvb, offset, pinfo, tree, drep);

    /* AM_TypeIdentification */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_am_type_identification, &u16AM_TypeIdentification);

    /* IM_Hardware_Revision */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_hardware_revision, &u16IMHardwareRevision);

    return offset;
}

static int
dissect_AM_HardwareOnlyInformation_block(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_guid_t IM_UniqueIdentifier;
    guint16  u16AM_TypeIdentification;
    guint16  u16IMHardwareRevision;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* align padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* IM_UniqueIdentifier */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_uniqueidentifier, &IM_UniqueIdentifier);

    /* AM_Location */
    offset = dissect_AM_Location(tvb, offset, pinfo, tree, drep);

    /* IM_Annotation */
    proto_tree_add_item(tree, hf_pn_io_im_annotation, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* IM_OrderID */
    proto_tree_add_item(tree, hf_pn_io_im_order_id, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* AM_HardwareRevision */
    proto_tree_add_item(tree, hf_pn_io_am_hardware_revision, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* IM_Serial_Number */
    proto_tree_add_item(tree, hf_pn_io_im_serial_number, tvb, offset, 16, ENC_ASCII | ENC_NA);
    offset += 16;

    /* AM_DeviceIdentification */
    offset = dissect_AM_device_identification(tvb, offset, pinfo, tree, drep);

    /* AM_TypeIdentification */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_am_type_identification, &u16AM_TypeIdentification);

    /* IM_Hardware_Revision */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_hardware_revision, &u16IMHardwareRevision);

    return offset;
}

static int
dissect_AM_FirmwareOnlyInformation_block(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_guid_t IM_UniqueIdentifier;
    guint16  u16AM_TypeIdentification;
    guint16  u16AM_Reserved;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* IM_UniqueIdentifier */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_im_uniqueidentifier, &IM_UniqueIdentifier);

    /* AM_Location */
    offset = dissect_AM_Location(tvb, offset, pinfo, tree, drep);

    /* IM_Annotation */
    proto_tree_add_item(tree, hf_pn_io_im_annotation, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* IM_OrderID */
    proto_tree_add_item(tree, hf_pn_io_im_order_id, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* AM_SoftwareRevision */
    proto_tree_add_item(tree, hf_pn_io_am_software_revision, tvb, offset, 64, ENC_ASCII | ENC_NA);
    offset += 64;

    /* IM_Serial_Number */
    proto_tree_add_item(tree, hf_pn_io_im_serial_number, tvb, offset, 16, ENC_ASCII | ENC_NA);
    offset += 16;

    /* IM_Software_Revision */
    offset = dissect_IM_software_revision(tvb, offset, pinfo, tree, drep);

    /* AM_DeviceIdentification */
    offset = dissect_AM_device_identification(tvb, offset, pinfo, tree, drep);

    /* AM_TypeIdentification */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_am_type_identification, &u16AM_TypeIdentification);

    /* AM_Reserved */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_am_reserved, &u16AM_Reserved);

    return offset;
}

/* dissect the AssetManagementInfo */
static int
dissect_AssetManagementInfo(tvbuff_t *tvb, int offset,
packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16    u16NumberofEntries;

    sub_item = proto_tree_add_item(tree, hf_pn_io_asset_management_info, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_asset_management_info);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_number_of_asset_management_info, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;
        offset = dissect_a_block(tvb, offset, pinfo, sub_tree, drep);
    }
    return offset;
}

/* dissect the AssetManagementData block */
static int
dissect_AssetManagementData_block(tvbuff_t *tvb, int offset,
packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_AssetManagementInfo(tvb, offset, pinfo, tree, drep);
    return offset;
}

/* dissect the IdentificationData block */
static int
dissect_IdentificationData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfAPIs = 1;
    guint32     u32Api;
    guint16     u16NumberOfSlots;
    guint16     u16SlotNr;
    guint32     u32ModuleIdentNumber;
    guint16     u16NumberOfSubslots;
    guint32     u32SubmoduleIdentNumber;
    guint16     u16SubslotNr;
    proto_item *slot_item;
    proto_tree *slot_tree;
    guint32     u32SlotStart;
    proto_item *subslot_item;
    proto_tree *subslot_tree;


    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if (u8BlockVersionLow == 1) {
        /* NumberOfAPIs */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_number_of_apis, &u16NumberOfAPIs);
    }

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
        if (u8BlockVersionLow == 1) {
            /* API */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_api, &u32Api);
        }

        /* NumberOfSlots */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_number_of_slots, &u16NumberOfSlots);

        proto_item_append_text(item, ", Slots:%u", u16NumberOfSlots);

        while (u16NumberOfSlots--) {
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

            while (u16NumberOfSubslots--) {
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

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    dissect_pn_user_data_bytes(tvb, offset, pinfo, tree, u16BodyLength, SUBST_DATA);

    return offset;
}


/* dissect the RecordInputDataObjectElement block */
static int
dissect_RecordInputDataObjectElement_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8  u8LengthIOCS;
    guint8  u8LengthIOPS;
    guint16 u16LengthData;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint16    u16SubstituteActiveFlag;
    guint8     u8LengthIOCS;
    guint8     u8LengthIOPS;
    guint16    u16LengthData;
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint32     u32MaintenanceStatus;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (u32MaintenanceStatus & 0x0002) {
        proto_item_append_text(item, ", Demanded");
        proto_item_append_text(sub_item, ", Demanded");
    }

    if (u32MaintenanceStatus & 0x0001) {
        proto_item_append_text(item, ", Required");
        proto_item_append_text(sub_item, ", Required");
    }

    return offset;
}

/* dissect the pe_alarm block */
static int
dissect_PE_Alarm_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8     u8PEOperationalMode;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    sub_item = proto_tree_add_item(tree, hf_pn_io_pe_operational_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pe_operational_mode);

    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_pe_operational_mode, &u8PEOperationalMode);

    return offset;

}

/* dissect the read/write header */
static int
dissect_ReadWrite_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint16 *u16Index, e_guid_t *aruuid)
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
    e_guid_t aruuid;
    e_guid_t null_uuid;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_guid_t));
    if (memcmp(&aruuid, &null_uuid, sizeof (e_guid_t)) == 0) {
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
    e_guid_t aruuid;
    e_guid_t null_uuid;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_guid_t));
    if (memcmp(&aruuid, &null_uuid, sizeof (e_guid_t)) == 0) {
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
    e_guid_t aruuid;
    guint16  u16AddVal1;
    guint16  u16AddVal2;
    guint32  u32Status;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);

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
    e_guid_t aruuid;
    guint16  u16AddVal1;
    guint16  u16AddVal2;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &aruuid);

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


/* dissect the control/connect and control/connect block */
static int
dissect_ControlPlugOrConnect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t **ar, guint16 blocktype)
{
    e_guid_t    ar_uuid;
    guint16     u16SessionKey;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16     u16Command;
    guint16     u16Properties;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &ar_uuid);

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &ar_uuid);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, &u16SessionKey);

    if (((blocktype & 0x7FFF) == 0x0111) || ((blocktype & 0x7FFF) == 0x0113)) {
        /* control/plug */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_control_alarm_sequence_number, NULL);
    } else {
        /* control/connect */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_reserved16, NULL);
    }

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

    if (u16Command & 0x0002) {
        /* ApplicationReady: special decode */
        sub_item = proto_tree_add_item(tree, hf_pn_io_control_block_properties_applready, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_block_properties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_control_block_properties_applready_bit0, &u16Properties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_control_block_properties_applready_bit1, &u16Properties);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_control_block_properties_applready_otherbits, &u16Properties);
    } else {
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_control_block_properties, &u16Properties);
    }

    proto_item_append_text(item, ": Session:%u, Command:", u16SessionKey);

    if (u16Command & 0x0001) {
        proto_item_append_text(sub_item, ", ParameterEnd");
        proto_item_append_text(item, " ParameterEnd");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: ParameterEnd");
    }
    if (u16Command & 0x0002) {
        proto_item_append_text(sub_item, ", ApplicationReady");
        proto_item_append_text(item, " ApplicationReady");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: ApplicationReady");
    }
    if (u16Command & 0x0004) {
        proto_item_append_text(sub_item, ", Release");
        proto_item_append_text(item, " Release");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: Release");
    }
    if (u16Command & 0x0008) {
        proto_item_append_text(sub_item, ", Done");
        proto_item_append_text(item, ", Done");
        col_append_str(pinfo->cinfo, COL_INFO, ", Command: Done");

        /* When Release Command Done, keep the release frame of corresponding ar & ar uuid */
        if (!PINFO_FD_VISITED(pinfo) && blocktype == 0x8114) {

            wmem_list_frame_t* aruuid_frame;
            ARUUIDFrame* current_aruuid_frame = NULL;

            if (aruuid_frame_setup_list != NULL) {
                for (aruuid_frame = wmem_list_head(aruuid_frame_setup_list); aruuid_frame != NULL; aruuid_frame = wmem_list_frame_next(aruuid_frame)) {
                    current_aruuid_frame = (ARUUIDFrame*)wmem_list_frame_data(aruuid_frame);
                    if (current_aruuid_frame->aruuid.data1 == ar_uuid.data1) {
                        current_aruuid_frame->releaseframe = pinfo->num;
                    }
                }
            }
        }
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
    e_guid_t    ar_uuid;
    guint16     u16SessionKey;
    guint16     u16Command;
    proto_item *sub_item;
    proto_tree *sub_tree;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    if (u32RecDataLen != 28-2) /* must be 28 see specification (version already dissected) */
    {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_length, "Block length of %u is invalid!", u32RecDataLen);
        return offset;
    }
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* ARUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, hf_pn_io_ar_uuid, &ar_uuid);

    if (!PINFO_FD_VISITED(pinfo)) {
        pn_init_append_aruuid_frame_setup_list(ar_uuid, pinfo->num);
    }

    /* The value NIL indicates the usage of the implicit AR*/
    *ar = pnio_ar_find_by_aruuid(pinfo, &ar_uuid);

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
    guint16 u16Entries;
    guint32 u32API;
    guint16 u16SlotNumber;
    guint16 u16SubSlotNumber;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint16 u16PreambleLength;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

/* dissect the dissect_CheckMAUTypeExtension_block block */
static int
dissect_CheckMAUTypeExtension_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MauTypeExtension;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* MauTypeExtension */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_mau_type_extension, &u16MauTypeExtension);

    return offset;
}

/* dissect the PDPortDataAdjust block */
static int
dissect_PDPortData_Adjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint16   u16SlotNr;
    guint16   u16SubslotNr;
    tvbuff_t *new_tvb;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    new_tvb = tvb_new_subset_length(tvb, offset, u16BodyLength);
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
    guint16   u16SlotNr;
    guint16   u16SubslotNr;
    tvbuff_t *new_tvb;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    new_tvb = tvb_new_subset_length(tvb, offset, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    /* XXX - do we have to free the new_tvb somehow? */

    return offset;
}

/* dissect the Line Delay */
static int
dissect_Line_Delay(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep,
    guint32  *u32LineDelayValue)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32  u32FormatIndicator;
    guint8   isFormatIndicatorEnabled;

    sub_item = proto_tree_add_item(tree, hf_pn_io_line_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_line_delay);

    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_line_delay_format_indicator, &u32FormatIndicator);

    isFormatIndicatorEnabled = (guint8)((u32FormatIndicator >> 31) & 0x01);
    if (isFormatIndicatorEnabled)
    {
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_cable_delay_value, u32LineDelayValue);
    }
    else
    {
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_line_delay_value, u32LineDelayValue);
    }

    return offset;
}

/* dissect the PDPortDataReal blocks */
static int
dissect_PDPortDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16  u16SlotNr;
    guint16  u16SubslotNr;
    guint8   u8LengthOwnPortID;
    char    *pOwnPortID;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8   u8NumberOfPeers;
    guint8   u8I;
    guint8   u8LengthPeerPortID;
    guint8   u8LengthPeerChassisID;
    guint8   mac[6];
    char    *pPeerChassisId;
    char    *pPeerPortId;
    guint16  u16MAUType;
    guint32  u32DomainBoundary;
    guint32  u32MulticastBoundary;
    guint8   u8LinkStatePort;
    guint8   u8LinkStateLink;
    guint32  u32MediaType;
    guint32  u32LineDelayValue;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_own_port_id, tvb, offset, u8LengthOwnPortID, ENC_ASCII, pinfo->pool, &pOwnPortID);
    offset += u8LengthOwnPortID;

    /* NumberOfPeers */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    u8I = u8NumberOfPeers;
    while (u8I--) {
        sub_item = proto_tree_add_item(tree, hf_pn_io_neighbor, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_neighbor);

        /* LengthPeerPortID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_length_peer_port_id, &u8LengthPeerPortID);
        /* PeerPortID */
        proto_tree_add_item_ret_display_string (sub_tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID,
                            ENC_ASCII, pinfo->pool, &pPeerPortId);

        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        proto_tree_add_item_ret_display_string (sub_tree, hf_pn_io_peer_chassis_id, tvb, offset, u8LengthPeerChassisID,
                            ENC_ASCII, pinfo->pool, &pPeerChassisId);

        offset += u8LengthPeerChassisID;

        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, sub_tree);

        /* LineDelay */
        offset = dissect_Line_Delay(tvb, offset, pinfo, sub_tree, drep, &u32LineDelayValue);

        /* PeerMACAddress */
        offset = dissect_pn_mac(tvb, offset, pinfo, sub_tree,
                            hf_pn_io_peer_macadd, mac);
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, sub_tree);

        proto_item_append_text(sub_item, ": %s (%s)", pPeerChassisId, pPeerPortId);
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
    /* LinkState.Port */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_link_state_port, &u8LinkStatePort);
    /* LinkState.Link */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_link_state_link, &u8LinkStateLink);
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MediaType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_media_type, &u32MediaType);

    proto_item_append_text(item, ": Slot:0x%x/0x%x, OwnPortID:%s, Peers:%u LinkState.Port:%s LinkState.Link:%s MediaType:%s",
        u16SlotNr, u16SubslotNr, pOwnPortID, u8NumberOfPeers,
        val_to_str(u8LinkStatePort, pn_io_link_state_port, "0x%x"),
        val_to_str(u8LinkStateLink, pn_io_link_state_link, "0x%x"),
        val_to_str(u32MediaType, pn_io_media_type, "0x%x"));

    return offset;
}


/* dissect the PDPortDataRealExtended blocks */
static int
dissect_PDPortDataRealExtended_block(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    guint16   u16SlotNr;
    guint16   u16SubslotNr;
    guint16   u16Index = 0;
    guint32   u32RecDataLen;
    pnio_ar_t *ar       = NULL;
    int       endoffset = offset + u16BodyLength;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    while (endoffset > offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        u16Index++;
    }

    return offset;
}

static int
dissect_PDInterfaceMrpDataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    e_guid_t  uuid;
    guint16   u16Role;
    guint8    u8LengthDomainName;
    guint8    u8NumberOfMrpInstances;
    int       endoffset = offset + u16BodyLength;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) { /* added low version == 1 */
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if (u8BlockVersionLow == 0) /*dissect LowVersion == 0 */
    {
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
        /* XXX - IEC 61158-6-10 Edition 4.0 says, in section 5.2.17.2.4 "Coding
           of the field MRP_DomainName", that "This field shall be coded as
           data type OctetString with 1 to 240 octets according to Table 702
           and 4.3.1.4.15.2."

           It then says, in subsection 4.3.1.4.15.2 "Encoding" of section
           4.3.1.4.15 "Coding of the field NameOfStationValue", that "This
           field shall be coded as data type OctetString with 1 to 240
           octets. The definition of IETF RFC 5890 and the following syntax
           applies: ..."

           RFC 5890 means Punycode; should we translate the domain name to
           UTF-8 and show both the untranslated and translated domain name?

           They don't mention anything about the RFC 1035 encoding of
           domain names as mentioned in section 3.1 "Name space definitions",
           with the labels being counted strings; does that mean that this
           is just an ASCII string to be interpreted as a Punycode Unicode
           domain name? */
        proto_tree_add_item (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, ENC_ASCII);
        offset += u8LengthDomainName;

        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);
        while (endoffset > offset)
        {
            offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
        }
    }
    else if (u8BlockVersionLow == 1) /*dissect LowVersion == 1 */
    {
        /* Padding one byte */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
        /* Number of Mrp Instances */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_instances, &u8NumberOfMrpInstances);
        if (u8NumberOfMrpInstances > 0xf) {
             expert_add_info_format(pinfo, item, &ei_pn_io_mrp_instances, "Number of MrpInstances greater 0x0f is (0x%x)", u8NumberOfMrpInstances);
            return offset;
        }
        while(u8NumberOfMrpInstances > 0)
        {
            offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
            u8NumberOfMrpInstances--;
        }
    }
    return offset;
}


static int
dissect_PDInterfaceMrpDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    e_guid_t  uuid;
    guint16   u16Role;
    guint16   u16Version;
    guint8    u8LengthDomainName;
    guint8    u8NumberOfMrpInstances;
    int       endoffset = offset + u16BodyLength;

    /* added blockversion 1 */
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 2) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if (u8BlockVersionLow < 2) /* dissect low versions 0 and 1 */
    {
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        /* MRP_DomainUUID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                hf_pn_io_mrp_domain_uuid, &uuid);
        /* MRP_Role */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                hf_pn_io_mrp_role, &u16Role);

        if (u8BlockVersionLow == 1) {
            /* MRP_Version */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_version, &u16Version);
        }
        /* MRP_LengthDomainName */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_mrp_length_domain_name, &u8LengthDomainName);
        /* MRP_DomainName */
        /* XXX - see comment earlier about MRP_DomainName */
        proto_tree_add_item (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, ENC_ASCII);
        offset += u8LengthDomainName;

        if (u8BlockVersionLow == 0) {
            /* MRP_Version */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_version, &u16Version);
        }
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        while(endoffset > offset)
        {
            offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
        }
    }
    else if (u8BlockVersionLow == 2)
    {
        /* Padding one byte */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
        /* Number of Mrp Instances */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_mrp_instances, &u8NumberOfMrpInstances);
        if (u8NumberOfMrpInstances > 0xf) {
            expert_add_info_format(pinfo, item, &ei_pn_io_mrp_instances, "Number of MrpInstances greater 0x0f is (0x%x)", u8NumberOfMrpInstances);
            return offset;
        }
        while(u8NumberOfMrpInstances > 0)
        {
            offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
            u8NumberOfMrpInstances--;
        }
    }
    return offset;
}


static int
dissect_PDInterfaceMrpDataCheck_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_guid_t uuid;
    guint32 u32Check;
    guint8 u8NumberOfMrpInstances;

    /* BlockVersionLow == 1 added */
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    if (u8BlockVersionLow == 0)
    {
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mrp_domain_uuid, &uuid);

    /* MRP_Check */
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_check, &u32Check);
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_check_mrm, &u32Check);
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_check_mrpdomain, &u32Check);
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_check_reserved_1, &u32Check);
        dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_check_reserved_2, &u32Check);
        offset +=4; /* MRP_Check (32 bit) done */
    }
    else if (u8BlockVersionLow == 1)
    {
        /* Padding one byte */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
        /* Number of Mrp Instances */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_instances, &u8NumberOfMrpInstances);
        if (u8NumberOfMrpInstances > 0xf) {
            expert_add_info_format(pinfo, item, &ei_pn_io_mrp_instances, "Number of MrpInstances greater 0x0f is (0x%x)", u8NumberOfMrpInstances);
            return offset;
        }
        while(u8NumberOfMrpInstances > 0)
        {
            offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
            u8NumberOfMrpInstances--;
        }
    }

    return offset;
}


static int
dissect_PDPortMrpData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    e_guid_t uuid;
    guint8  u8MrpInstance;

    /* added BlockVersionLow == 1 */
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    if (u8BlockVersionLow == 0) {
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    }
    else /*if (u8BlockVersionLow == 1) */
    {
        /* Padding one byte */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
        /* Mrp Instance */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mrp_instance, &u8MrpInstance);
    }
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint32     u32RTMode;


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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint16     u16CheckSyncMode;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
        (u16CheckSyncMode >> 1) & 1, u16CheckSyncMode & 1);

    proto_item_append_text(item, " : SyncMaster:%d, CableDelay:%d",
        (u16CheckSyncMode >> 1) & 1, u16CheckSyncMode & 1);

    return offset;
}


static int
dissect_CheckMAUTypeDifference_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MAUTypeMode;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    switch (u8BlockVersionLow) {
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
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* LineDelay */
    offset = dissect_Line_Delay(tvb, offset, pinfo, tree, drep, &u32LineDelay);

    proto_item_append_text(item, ": LineDelay:%uns", u32LineDelay);

    return offset;
}


/* dissect the CheckPeers block */
static int
dissect_CheckPeers_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8  u8NumberOfPeers;
    guint8  u8I;
    guint8  u8LengthPeerPortID;
    guint8  u8LengthPeerChassisID;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfPeers */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);

    u8I = u8NumberOfPeers;
    while (u8I--) {
        /* LengthPeerPortID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_port_id, &u8LengthPeerPortID);
        /* PeerPortID */
        proto_tree_add_item (tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID, ENC_ASCII);
        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        proto_tree_add_item (tree, hf_pn_io_peer_chassis_id, tvb, offset, u8LengthPeerChassisID, ENC_ASCII);
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint32    u32FiberOpticType;
    guint32    u32FiberOpticCableType;
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    if (u16BodyLength != 10) {
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
    guint8  u8VendorIDHigh;
    guint8  u8VendorIDLow;
    guint16 u16VendorBlockType;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


/* dissect the FiberOpticDiagnosisInfo block */
static int
dissect_FiberOpticDiagnosisInfo_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FiberOpticPowerBudget;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* decode the u32FiberOpticPowerBudget better */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_maintenance_required_power_budget, &u32FiberOpticPowerBudget);

    return offset;
}

/* dissect the AdjustMAUTypeExtension block */
static int
dissect_AdjustMAUTypeExtension_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16MauTypeExtension;
    guint16 u16AdjustProperties;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* MauTypeExtension */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_mau_type_extension, &u16MauTypeExtension);

    /* Properties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_adjust_properties, &u16AdjustProperties);

    return offset;
}

/* dissect the PDPortFODataAdjust block */
static int
dissect_PDPortFODataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32FiberOpticType;
    guint32 u32FiberOpticCableType;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

/* dissect the AdjustPeerToPeerBoundary block */
static int
dissect_AdjustPeerToPeerBoundary_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32PeerToPeerBoundary;
    guint16 u16AdjustProperties;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    sub_item = proto_tree_add_item(tree, hf_pn_io_peer_to_peer_boundary_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_peer_to_peer_boundary);

    /* PeerToPeerBoundary.Bit0 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_peer_to_peer_boundary_value_bit0, &u32PeerToPeerBoundary);

    /* PeerToPeerBoundary.Bit1 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_peer_to_peer_boundary_value_bit1, &u32PeerToPeerBoundary);

    /* PeerToPeerBoundary.Bit2 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_peer_to_peer_boundary_value_bit2, &u32PeerToPeerBoundary);

    /* PeerToPeerBoundary.OtherBits */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_peer_to_peer_boundary_value_otherbits, &u32PeerToPeerBoundary);

    /* Properties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_adjust_properties, &u16AdjustProperties);

    return offset;
}


/* dissect the AdjustDCPBoundary block */
static int
dissect_AdjustDCPBoundary_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32DcpBoundary;
    guint16 u16AdjustProperties;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    sub_item = proto_tree_add_item(tree, hf_pn_io_dcp_boundary_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_dcp_boundary);

    /* DcpBoundary.Bit0 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_dcp_boundary_value_bit0, &u32DcpBoundary);

    /* DcpBoundary.Bit1 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_dcp_boundary_value_bit1, &u32DcpBoundary);

    /* DcpBoundary.OtherBits */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_dcp_boundary_value_otherbits, &u32DcpBoundary);

    /* Properties */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_adjust_properties, &u16AdjustProperties);

    return offset;
}

static int
dissect_MrpInstanceDataAdjust_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    guint8  u8MrpInstance;
    e_guid_t uuid;
    guint16 u16Role;
    guint8  u8LengthDomainName;
    int endoffset = offset + u16BodyLength;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* Padding one byte */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    /* Mrp Instance */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_instance, &u8MrpInstance);
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
    /* XXX - see comment earlier about MRP_DomainName */
    proto_tree_add_item (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, ENC_ASCII);
    offset += u8LengthDomainName;
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    while(endoffset > offset)
    {
        offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
    }

    return offset;
}

static int
dissect_MrpInstanceDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    guint8  u8MrpInstance;
    e_guid_t uuid;
    guint16 u16Role;
    guint16 u16Version;
    guint8  u8LengthDomainName;
    int     endoffset = offset + u16BodyLength;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* Padding one byte */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    /* Mrp Instance */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_instance, &u8MrpInstance);
    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_domain_uuid, &uuid);
    /* MRP_Role */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_role, &u16Role);
    /* MRP_Version */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_version, &u16Version);
    /* MRP_LengthDomainName */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_mrp_length_domain_name, &u8LengthDomainName);
    /* MRP_DomainName */
    /* XXX - see comment earlier about MRP_DomainName */
    proto_tree_add_item (tree, hf_pn_io_mrp_domain_name, tvb, offset, u8LengthDomainName, ENC_ASCII);
    offset += u8LengthDomainName;
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    while(endoffset > offset)
    {
        offset = dissect_a_block(tvb, offset, pinfo, tree, drep);
    }
    return offset;
}

static int
dissect_MrpInstanceDataCheck_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength _U_)
{
    guint8  u8MrpInstance;
    guint32 u32Check;
    e_guid_t uuid;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* Padding one byte */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    /* Mrp Instance */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_instance, &u8MrpInstance);
    /* MRP_DomainUUID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
        hf_pn_io_mrp_domain_uuid, &uuid);

    /* MRP_Check */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                          hf_pn_io_mrp_check, &u32Check);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                          hf_pn_io_mrp_check_mrm, &u32Check);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                          hf_pn_io_mrp_check_mrpdomain, &u32Check);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                          hf_pn_io_mrp_check_reserved_1, &u32Check);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                          hf_pn_io_mrp_check_reserved_2, &u32Check);
    offset +=4; /* MRP_Check (32 bit) done */

    return offset;
}

/* PDInterfaceAdjust */
static int
dissect_PDInterfaceAdjust_block(tvbuff_t *tvb, int offset,
 packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32     u32SMultipleInterfaceMode;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
    return offset;
}
    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);
/* MultipleInterfaceMode */
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_MultipleInterfaceMode_NameOfDevice, &u32SMultipleInterfaceMode);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_MultipleInterfaceMode_reserved_1, &u32SMultipleInterfaceMode);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_MultipleInterfaceMode_reserved_2, &u32SMultipleInterfaceMode);
    return offset;
}

/* TSNNetworkControlDataReal */
static int
dissect_TSNNetworkControlDataReal_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item* sub_item;
    proto_tree* sub_tree;

    e_guid_t  nme_parameter_uuid;
    guint32 u32NetworkDeadline;
    guint16 u16SendClockFactor;
    guint16 u16NumberofEntries;
    guint16 u16TSNNMENameLength;
    guint16 u16TSNDomainNameLength;
    e_guid_t  tsn_nme_name_uuid;
    e_guid_t  tsn_domain_uuid;

    int bit_offset;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* NMEParameterUUID*/
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_tsn_nme_parameter_uuid, &nme_parameter_uuid);

    /* TSNDomainVIDConfig*/
    sub_item = proto_tree_add_item(tree, hf_pn_io_tsn_domain_vid_config, tvb, offset, 16, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_tsn_domain_vid_config);
    bit_offset = offset << 3;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_reserved, tvb, bit_offset, 32, ENC_BIG_ENDIAN);
    bit_offset += 32;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_D, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_C, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_B, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_low_red_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_low_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_high_red_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_high_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);

    offset += 16;

    /* TSNDomainPortConfigBlock */
    offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);

    /* Network Deadline */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_network_deadline, &u32NetworkDeadline);

    /* SendClockFactor 16 */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_send_clock_factor, &u16SendClockFactor);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_number_of_tsn_time_data_block_entries, &u16NumberofEntries);

    /* TSNTimeDataBlock */
    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);
    }

    /* TSNNMENameUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_tsn_nme_name_uuid, &tsn_nme_name_uuid);

    /* TSNNMENameLength */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_nme_name_length, &u16TSNNMENameLength);

    /* TSNNMEName */
    proto_tree_add_item(tree, hf_pn_io_tsn_nme_name, tvb, offset, u16TSNNMENameLength, ENC_ASCII | ENC_NA);
    offset += u16TSNNMENameLength;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* TSNDomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_tsn_domain_uuid, &tsn_domain_uuid);

    /* TSNDomainNameLength */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_domain_name_length, &u16TSNDomainNameLength);

    /* TSNDomainName */
    proto_tree_add_item(tree, hf_pn_io_tsn_domain_name, tvb, offset, u16TSNDomainNameLength, ENC_ASCII | ENC_NA);
    offset += u16TSNDomainNameLength;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    return offset;

}

/* TSNNetworkControlDataAdjust */
static int
dissect_TSNNetworkControlDataAdjust_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item* sub_item;
    proto_tree* sub_tree;

    e_guid_t  nme_parameter_uuid;
    guint32 u32NetworkDeadline;
    guint16 u16SendClockFactor;
    guint16 u16NumberofEntries;
    guint16 u16TSNNMENameLength;
    e_guid_t  tsn_nme_name_uuid;

    int bit_offset;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* NMEParameterUUID*/
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_tsn_nme_parameter_uuid, &nme_parameter_uuid);

    /* TSNDomainVIDConfig*/
    sub_item = proto_tree_add_item(tree, hf_pn_io_tsn_domain_vid_config, tvb, offset, 16, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_tsn_domain_vid_config);

    bit_offset = offset << 3;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_reserved, tvb, bit_offset, 32, ENC_BIG_ENDIAN);
    bit_offset += 32;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_D, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_C, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid_B, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_non_stream_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_low_red_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_low_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_high_red_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    bit_offset += 12;

    proto_tree_add_bits_item(sub_tree, hf_pn_io_tsn_domain_vid_config_stream_high_vid, tvb, bit_offset, 12, ENC_BIG_ENDIAN);

    offset += 16;

    /* TSNDomainPortConfigBlock */
    offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);

    /* Network Deadline */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_network_deadline, &u32NetworkDeadline);

    /* SendClockFactor 16 */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_send_clock_factor, &u16SendClockFactor);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_number_of_tsn_time_data_block_entries, &u16NumberofEntries);

    /* TSNTimeDataBlock */
    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);
    }

    /* TSNNMENameUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_tsn_nme_name_uuid, &tsn_nme_name_uuid);

    /* TSNNMENameLength */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_nme_name_length, &u16TSNNMENameLength);

    /* TSNNMEName */
    proto_tree_add_item(tree, hf_pn_io_tsn_nme_name, tvb, offset, u16TSNNMENameLength, ENC_ASCII | ENC_NA);
    offset += u16TSNNMENameLength;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    return offset;
}

/* TSNStreamPathData */
static int
dissect_TSNStreamPathDataReal_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, gboolean real)
{
    guint8  u8FDBCommand;
    guint16 u16NumberofEntries;
    guint8  dstAdd[6];
    guint16 u16StreamClass;
    guint16 u16SlotNumber;
    guint16 u16SubSlotNumber;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);

    if (!real) {
        /* FDBCommand */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_fdb_command, &u8FDBCommand);
    }
    else {
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_sync_tree_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;
        /* DestinationAddress */
        offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_io_tsn_dst_add, dstAdd);

        /* StreamClass */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_stream_class, &u16StreamClass);

        /* IngressPort */
        /* TSNDomainPortID */
        /*SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_slot_nr, &u16SlotNumber);
        /* SubSlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_subslot_nr, &u16SubSlotNumber);

        /* EgressPort */
        /* TSNDomainPortID */
        /*SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_slot_nr, &u16SlotNumber);
        /* SubSlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_subslot_nr, &u16SubSlotNumber);
    }
    return offset;
}

/* TSNSyncTreeData */
static int
dissect_TSNSyncTreeData_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;
    guint16    u16SlotNr;
    guint16    u16SubslotNr;
    guint16    u16TimeDomainNumber;
    guint8     u8SyncPortRole;
    proto_item* sub_item;
    proto_tree* sub_tree;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_sync_tree_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;
        /* TSNDomainPortID */
        sub_item = proto_tree_add_item(tree, hf_pn_io_tsn_domain_port_id, tvb, offset, 4, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_tsn_domain_port_id);
        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_slot_nr, &u16SlotNr);
        /*--*/
        /* Subslotnumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_subslot_nr, &u16SubslotNr);
        /* TimeDomainNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_time_domain_number, &u16TimeDomainNumber);
        /* SyncPortRole */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_domain_sync_port_role, &u8SyncPortRole);

        /* Padding */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    }
    return offset;
}

/* TSNDomainPortConfigBlock */
static int
dissect_TSNDomainPortConfig_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;
    guint16    u16SlotNr;
    guint16    u16SubslotNr;
    proto_item* sub_item_port_config;
    proto_tree* sub_tree_port_config;
    guint8     u8TSNDomainPortConfig;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_port_config_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_slot_nr, &u16SlotNr);
        /* Subslotnumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_subslot_nr, &u16SubslotNr);

        /* TSNDomainPortConfig */
        sub_item_port_config = proto_tree_add_item(tree, hf_pn_io_tsn_domain_port_config, tvb, offset, 1, ENC_NA);
        sub_tree_port_config = proto_item_add_subtree(sub_item_port_config, ett_pn_io_tsn_domain_port_config);

        dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree_port_config, drep,
            hf_pn_io_tsn_domain_port_config_reserved, &u8TSNDomainPortConfig);
        dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree_port_config, drep,
            hf_pn_io_tsn_domain_port_config_boundary_port_config, &u8TSNDomainPortConfig);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree_port_config, drep,
            hf_pn_io_tsn_domain_port_config_preemption_enabled, &u8TSNDomainPortConfig);

        /* Padding */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 3);

        /* TSNDomainPortIngressRateLimiter */
        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);

        /* TSNDomainQueueConfigBlock */
        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);

        /* TSNDomainQueueRateLimiterBlock */
        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);
    }
    return offset;
}

/* TSNDomainQueueConfigBlock */
static int
dissect_TSNDomainQueueConfig_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;
    proto_item* sub_item;
    proto_tree* sub_tree;
    guint64     u64TSNDomainQueueConfig;
    dcerpc_info di; /* fake dcerpc_info struct */
    dcerpc_call_value dcv; /* fake dcerpc_call_value struct */
    di.call_data = &dcv;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_queue_config_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        sub_item = proto_tree_add_item(tree, hf_pn_io_tsn_domain_queue_config, tvb, offset, 8, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_tsn_domain_queue_config);

        /* TSNDomainQueueConfig */
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_mask_time_offset, &u64TSNDomainQueueConfig);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_unmask_time_offset, &u64TSNDomainQueueConfig);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_preemption_mode, &u64TSNDomainQueueConfig);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_shaper, &u64TSNDomainQueueConfig);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_tci_pcp, &u64TSNDomainQueueConfig);
        offset = dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_config_queue_id, &u64TSNDomainQueueConfig);
    }
    return offset;
}

/* TSNTimeDataBlock */
static int
dissect_TSNTimeData_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16 u16TimeDomainNumber;
    guint32 u32TimePLLWindow;
    guint32 u32MessageIntervalFactor;
    guint16 u16MessageTimeoutFactor;
    guint16 u16TimeSyncProperties;
    guint8  u8TimeDomainNameLength;
    e_guid_t  time_domain_uuid;
    proto_item* sub_item;
    proto_tree* sub_tree;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* TimeDomainNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_time_domain_number, &u16TimeDomainNumber);

    /* TimePLLWindow */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_time_pll_window, &u32TimePLLWindow);

    /* MessageIntervalFactor */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_message_interval_factor, &u32MessageIntervalFactor);

    /* MessageTimeoutFactor */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_message_timeout_factor, &u16MessageTimeoutFactor);

    /* TimeSyncProperties */
    sub_item = proto_tree_add_item(tree, hf_pn_io_time_sync_properties, tvb, offset, 2, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_time_sync_properties);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_time_sync_properties_reserved, &u16TimeSyncProperties);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_time_sync_properties_role, &u16TimeSyncProperties);

    /* TimeDomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_io_time_domain_uuid, &time_domain_uuid);

    /* TimeDomainNameLength */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, hf_pn_io_time_domain_name_length, &u8TimeDomainNameLength);

    /* TimeDomainName */
    proto_tree_add_item(tree, hf_pn_io_time_domain_name, tvb, offset, u8TimeDomainNameLength, ENC_ASCII | ENC_NA);
    offset += u8TimeDomainNameLength;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    return offset;
}

/* TSNUploadNetworkAttributesBlock */
static int
dissect_TSNUploadNetworkAttributes_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32     u32TransferTimeTX;
    guint32     u32TransferTimeRX;
    guint32     u32MaxSupportedRecordSize;

    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
        /* Align to the next 32 bit twice */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* TSNPortIDBlock */
    offset = dissect_a_block(tvb, offset, pinfo, tree, drep);

    /*MaxSupportedRecordSize*/
    offset= dissect_dcerpc_uint32(tvb,offset,pinfo,tree,drep,hf_pn_io_tsn_max_supported_record_size,&u32MaxSupportedRecordSize);

    /* TransferTimeTX */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
        hf_pn_io_tsn_transfer_time_tx, &u32TransferTimeTX);

    /* TransferTimeRX */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
        hf_pn_io_tsn_transfer_time_rx, &u32TransferTimeRX);

    /* TSNForwardingDelayBlock */
    offset = dissect_a_block(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* TSNExpectedNeighborBlock */
static int
dissect_TSNExpectedNeighbor_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8      u8NumberOfPeers;
    guint8      u8I;
    guint8      u8LengthPeerPortName;
    guint8      u8LengthPeerStationName;
    guint16     u16NumberOfEntries;
    guint16     u16SlotNr;
    guint16     u16SubslotNr;
    guint32     u32LineDelayValue;

    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_expected_neighbor_block_number_of_entries, &u16NumberOfEntries);

    while (u16NumberOfEntries > 0)
    {
        u16NumberOfEntries--;

        /*TSNDomainPortID*/
        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_slot_nr, &u16SlotNr);
        /*--*/
        /* Subslotnumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_subslot_nr, &u16SubslotNr);

        /* Padding */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 3);

        /* NumberOfPeers */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_number_of_peers, &u8NumberOfPeers);

        u8I = u8NumberOfPeers;
        while (u8I--) {
            /* LengthPeerPortName */
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_peer_port_name, &u8LengthPeerPortName);

            /* PeerPortName */
            proto_tree_add_item(tree, hf_pn_io_peer_port_name, tvb, offset, u8LengthPeerPortName, ENC_ASCII | ENC_NA);
            offset += u8LengthPeerPortName;

            /* LengthPeerStationName */
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                hf_pn_io_length_peer_station_name, &u8LengthPeerStationName);

            /* PeerStationName */
            proto_tree_add_item(tree, hf_pn_io_peer_station_name, tvb, offset, u8LengthPeerStationName, ENC_ASCII | ENC_NA);
            offset += u8LengthPeerStationName;

            /* Padding */
            offset = dissect_pn_align4(tvb, offset, pinfo, tree);

            /* LineDelay */
            offset = dissect_Line_Delay(tvb, offset, pinfo, tree, drep, &u32LineDelayValue);
        }
    }
    return offset;
}

/* TSNExpectedNetworkAttributesBlock */
static int
dissect_TSNExpectedNetworkAttributes_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Align to the next 32 bit twice */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    /* TSNPortIDBlock */
    offset = dissect_a_block(tvb, offset, pinfo, tree, drep);

    /* TSNForwardingDelayBlock */
    offset = dissect_a_block(tvb, offset, pinfo, tree, drep);

    /* TSNExpectedNeighborBlock */
    offset = dissect_a_block(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* TSNDomainPortIngressRateLimiterBlock */
static int
dissect_TSNDomainPortIngressRateLimiter_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;
    proto_item* sub_item_port_ingress;
    proto_tree* sub_tree_port_ingress;
    guint64    u64TSNDomainPortIngressRateLimiter;
    dcerpc_info di; /* fake dcerpc_info struct */
    dcerpc_call_value dcv; /* fake dcerpc_call_value struct */
    di.call_data = &dcv;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_port_ingress_rate_limiter_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        /* TSNDomainPortIngressRateLimiter */
        sub_item_port_ingress = proto_tree_add_item(tree, hf_pn_io_tsn_domain_port_ingress_rate_limiter, tvb, offset, 8, ENC_NA);
        sub_tree_port_ingress = proto_item_add_subtree(sub_item_port_ingress, ett_pn_io_tsn_domain_port_ingress_rate_limiter);

        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree_port_ingress, &di, drep,
            hf_pn_io_tsn_domain_port_ingress_rate_limiter_cir, &u64TSNDomainPortIngressRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree_port_ingress, &di, drep,
            hf_pn_io_tsn_domain_port_ingress_rate_limiter_cbs, &u64TSNDomainPortIngressRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree_port_ingress, &di, drep,
            hf_pn_io_tsn_domain_port_ingress_rate_limiter_envelope, &u64TSNDomainPortIngressRateLimiter);
        offset = dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree_port_ingress, &di, drep,
            hf_pn_io_tsn_domain_port_ingress_rate_limiter_rank, &u64TSNDomainPortIngressRateLimiter);
    }
    return offset;
}

/* TSNDomainQueueRateLimiterBlock */
static int
dissect_TSNDomainQueueRateLimiter_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16NumberofEntries;
    proto_item* sub_item;
    proto_tree* sub_tree;
    guint64    u64TSNDomainQueueRateLimiter;
    dcerpc_info di; /* fake dcerpc_info struct */
    dcerpc_call_value dcv; /* fake dcerpc_call_value struct */
    di.call_data = &dcv;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_tsn_domain_queue_rate_limiter_entries, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;

        /* TSNDomainQueueRateLimiter */
        sub_item = proto_tree_add_item(tree, hf_pn_io_tsn_domain_queue_rate_limiter, tvb, offset, 8, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_tsn_domain_queue_rate_limiter);

        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_cir, &u64TSNDomainQueueRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_cbs, &u64TSNDomainQueueRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_envelope, &u64TSNDomainQueueRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_rank, &u64TSNDomainQueueRateLimiter);
        dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_queue_id, &u64TSNDomainQueueRateLimiter);
        offset = dissect_dcerpc_uint64(tvb, offset, pinfo, sub_tree, &di, drep,
            hf_pn_io_tsn_domain_queue_rate_limiter_reserved, &u64TSNDomainQueueRateLimiter);
    }
    return offset;
}

/* TSNPortIDBlock */
static int
dissect_TSNPortID_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8      u8NumberOfQueues;
    guint8      u8ForwardingGroup;
    guint8      u8TSNPortCapabilities;
    guint16     u16NumberOfEntries;
    guint16     u16SlotNr;
    guint16     u16SubslotNr;
    guint16     u16MAUType;
    guint16     u16MAUTypeExtension;

    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_port_id_block_number_of_entries, &u16NumberOfEntries);

   while (u16NumberOfEntries > 0)
   {
        u16NumberOfEntries--;

        /*TSNDomainPortID*/
        /* SlotNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_slot_nr, &u16SlotNr);
        /*--*/
        /* Subslotnumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_subslot_nr, &u16SubslotNr);

        /*MAUType*/
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mau_type, &u16MAUType);

        /*MAUTypeExtension*/
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_mau_type_extension, &u16MAUTypeExtension);

        /* NumberOfQueues */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_number_of_queues, &u8NumberOfQueues);

        /* TSNPortCapabilities */
        /* bit 0 */
        dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_port_capabilities_time_aware, &u8TSNPortCapabilities);

        /* bit 1 */
        dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_port_capabilities_preemption, &u8TSNPortCapabilities);

        /* bit 2 */
        dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_port_capabilities_queue_masking, &u8TSNPortCapabilities);

        /* bit 3-7 */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_port_capabilities_reserved, &u8TSNPortCapabilities);

        /* ForwardingGroup */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_forwarding_group, &u8ForwardingGroup);

        /* Align to the next 32 bit */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);

    }
    return offset;
}

/* TSNForwardingDelayBlock */
static int
dissect_TSNForwardingDelay_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8      u8ForwardingGroupIngress;
    guint8      u8ForwardingGroupEgress;
    guint16     u16NumberOfEntries;
    guint16     u16StreamClass;
    guint32     u32DependentForwardingDelay;
    guint32     u32IndependentForwardingDelay;

    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_tsn_forwarding_delay_block_number_of_entries, &u16NumberOfEntries);

   while (u16NumberOfEntries > 0)
   {
        u16NumberOfEntries--;

        /*ForwardingGroupIngress*/
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_forwarding_group_ingress, &u8ForwardingGroupIngress);

        /*ForwardingGroupEgress*/
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_forwarding_group_egress, &u8ForwardingGroupEgress);

        /* StreamClass */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_stream_class, &u16StreamClass);

        /* DependentForwardingDelay */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_dependent_forwarding_delay, &u32DependentForwardingDelay);

        /* IndependentForwardingDelay */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
            hf_pn_io_tsn_independent_forwarding_delay, &u32IndependentForwardingDelay);
    }
    return offset;
}

/* PDPortStatistic for one subslot */
static int
dissect_PDPortStatistic_block(tvbuff_t *tvb, int offset,
 packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint32 u32StatValue;
    guint16 u16CounterStatus;
    proto_item *sub_item;
    proto_tree *sub_tree;
    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    switch (u8BlockVersionLow) {
    case(0):
        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    break;
    case(1):
        sub_item = proto_tree_add_item(tree, hf_pn_io_pdportstatistic_counter_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_counter_status);
        /* bit 0 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifInOctets, &u16CounterStatus);
        /* bit 1 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifOutOctets, &u16CounterStatus);
        /* bit 2 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifInDiscards, &u16CounterStatus);
        /* bit 3 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifOutDiscards, &u16CounterStatus);
        /* bit 4 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifInErrors, &u16CounterStatus);
        /* bit 5 */
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_ifOutErrors, &u16CounterStatus);
        /* bit 6-15 */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_pdportstatistic_counter_status_reserved, &u16CounterStatus);
    break;
    default: /* will not execute because of the line preceding the switch */
    break;
    }

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

/* OwnPort */
static int
dissect_OwnPort_block(tvbuff_t *tvb, int offset,
 packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8   u8LengthOwnPortID;
    char    *pOwnPortID;
    guint16  u16MAUType;
    guint16  u16MAUTypeExtension;
    guint32  u32MulticastBoundary;
    guint8   u8LinkStatePort;
    guint8   u8LinkStateLink;
    guint32  u32MediaType;
    guint32  u32LineDelayValue;
    guint16  u16PortStatus;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* LengthOwnPortID */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_length_own_port_id, &u8LengthOwnPortID);
    /* OwnPortName */
    proto_tree_add_item_ret_display_string (tree, hf_pn_io_own_port_id, tvb, offset, u8LengthOwnPortID, ENC_ASCII, pinfo->pool, &pOwnPortID);
    offset += u8LengthOwnPortID;

    /* Padding */
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* LineDelay */
    offset = dissect_Line_Delay(tvb, offset, pinfo, tree, drep, &u32LineDelayValue);

    /* MediaType */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_media_type, &u32MediaType);

    /* MulticastBoundary */
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_multicast_boundary, &u32MulticastBoundary);

    /* MAUType */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mau_type, &u16MAUType);

    /* MAUTypeExtension */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_mau_type_extension, &u16MAUTypeExtension);

    /* LinkState.Port */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_link_state_port, &u8LinkStatePort);
    /* LinkState.Link */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_link_state_link, &u8LinkStateLink);

    /* RTClass3_PortStatus */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_rtclass3_port_status, &u16PortStatus);

    proto_item_append_text(item, ": OwnPortID:%s, LinkState.Port:%s LinkState.Link:%s MediaType:%s MAUType:%s",
        pOwnPortID,
        val_to_str(u8LinkStatePort, pn_io_link_state_port, "0x%x"),
        val_to_str(u8LinkStateLink, pn_io_link_state_link, "0x%x"),
        val_to_str(u32MediaType, pn_io_media_type, "0x%x"),
        val_to_str(u16MAUType, pn_io_mau_type, "0x%x"));

    return offset;
}


/* Neighbors */
static int
dissect_Neighbors_block(tvbuff_t *tvb, int offset,
 packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8   u8NumberOfPeers;
    guint8   u8I;
    guint8   mac[6];
    char    *pPeerStationName;
    char    *pPeerPortName;
    guint8   u8LengthPeerPortName;
    guint8   u8LengthPeerStationName;
    guint16  u16MAUType;
    guint16  u16MAUTypeExtension;
    guint32  u32LineDelayValue;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* NumberOfPeers */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    u8I = u8NumberOfPeers;
    while (u8I--) {
        sub_item = proto_tree_add_item(tree, hf_pn_io_neighbor, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_neighbor);

        /* LineDelay */
        offset = dissect_Line_Delay(tvb, offset, pinfo, sub_tree, drep, &u32LineDelayValue);

        /* MAUType */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_mau_type, &u16MAUType);

        /* MAUTypeExtension */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_mau_type_extension, &u16MAUTypeExtension);

        /* PeerMACAddress */
        offset = dissect_pn_mac(tvb, offset, pinfo, sub_tree,
                            hf_pn_io_peer_macadd, mac);

        /* LengthPeerPortName */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_length_peer_port_name, &u8LengthPeerPortName);
        /* PeerPortName */
        proto_tree_add_item_ret_display_string (sub_tree, hf_pn_io_peer_port_name, tvb, offset, u8LengthPeerPortName,
                            ENC_ASCII, pinfo->pool, &pPeerPortName);
        offset += u8LengthPeerPortName;

        /* LengthPeerStationName */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                            hf_pn_io_length_peer_station_name, &u8LengthPeerStationName);
        /* PeerStationName */
        proto_tree_add_item_ret_display_string (sub_tree, hf_pn_io_peer_station_name, tvb, offset, u8LengthPeerStationName,
                            ENC_ASCII, pinfo->pool, &pPeerStationName);
        offset += u8LengthPeerStationName;

        offset = dissect_pn_align4(tvb, offset, pinfo, sub_tree);

        proto_item_append_text(sub_item, ": %s (%s)", pPeerStationName, pPeerPortName);
    }

    return offset;
}


/* dissect the PDInterfaceDataReal block */
static int
dissect_PDInterfaceDataReal_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint8   u8LengthOwnChassisID;
    guint8   mac[6];
    guint32  ip;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* LengthOwnChassisID */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_length_own_chassis_id, &u8LengthOwnChassisID);
    /* OwnChassisID */
    proto_tree_add_item (tree, hf_pn_io_own_chassis_id, tvb, offset, u8LengthOwnChassisID, ENC_ASCII);
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
    guint16   u16SlotNr;
    guint16   u16SubslotNr;
    e_guid_t  uuid;
    guint32   u32ReservedIntervalBegin;
    guint32   u32ReservedIntervalEnd;
    guint32   u32PLLWindow;
    guint32   u32SyncSendFactor;
    guint16   u16SendClockFactor;
    guint16   u16SyncProperties;
    guint16   u16SyncFrameAddress;
    guint16   u16PTCPTimeoutFactor;
    guint16   u16PTCPTakeoverTimeoutFactor;
    guint16   u16PTCPMasterStartupTime;
    guint8    u8MasterPriority1;
    guint8    u8MasterPriority2;
    guint8    u8LengthSubdomainName;


    if (u8BlockVersionHigh != 1) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    switch (u8BlockVersionLow) {
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
        /* XXX - another Punycode string */
        proto_tree_add_item (tree, hf_pn_io_ptcp_subdomain_name, tvb, offset, u8LengthSubdomainName, ENC_ASCII);
        offset += u8LengthSubdomainName;

        /* Padding */
        offset = dissect_pn_align4(tvb, offset, pinfo, tree);

        proto_item_append_text(item, ": Interval:%u-%u, PLLWin:%u, Send:%u, Clock:%u",
            u32ReservedIntervalBegin, u32ReservedIntervalEnd,
            u32PLLWindow, u32SyncSendFactor, u16SendClockFactor);
        break;
    default:
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
    }

    return offset;
}


/* dissect the PDIRData block */
static int
dissect_PDIRData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16    u16SlotNr;
    guint16    u16SubslotNr;
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;

    /* versions decoded are High: 1 and LOW 0..2 */
    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow > 2 ) ) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    if (u8BlockVersionLow == 0) {
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
    e_guid_t uuid;
    guint32  u32MaxBridgeDelay;
    guint32  u32NumberOfPorts;
    guint32  u32MaxPortTxDelay;
    guint32  u32MaxPortRxDelay;
    guint32  u32MaxLineRxDelay;
    guint32  u32YellowTime;
    guint32  u32Tmp;

    /* added blockversion 2 */
    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow > 2)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    /* IRDataID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ir_data_id, &uuid);

    if (u8BlockVersionLow <= 2) {
        /* MaxBridgeDelay */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                     hf_pn_io_max_bridge_delay, &u32MaxBridgeDelay);
        /* NumberOfPorts */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                     hf_pn_io_number_of_ports, &u32NumberOfPorts);
        u32Tmp = u32NumberOfPorts;

        while (u32Tmp--) {
            /* MaxPortTxDelay */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                         hf_pn_io_max_port_tx_delay, &u32MaxPortTxDelay);
            /* MaxPortRxDelay */
            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                         hf_pn_io_max_port_rx_delay, &u32MaxPortRxDelay);
            if (u8BlockVersionLow >= 2) {
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
    guint32     u32FrameSendOffset;
    guint32     u32FrameDataProperties;
    guint16     u16DataLength;
    guint16     u16ReductionRatio;
    guint16     u16Phase;
    guint16     u16FrameID;
    guint16     u16Ethertype;
    guint8      u8RXPort;
    guint8      u8FrameDetails;
    guint8      u8NumberOfTxPortGroups;
    guint8      u8TxPortGroupArray;
    guint16     u16TxPortGroupArraySize;
    guint16     u16EndOffset;
    guint16     n = 0;
    proto_item *sub_item;
    proto_tree *sub_tree;

    /* added low version 1 */
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_align4(tvb, offset, pinfo, tree);

    u16EndOffset = offset + u16BodyLength -2;
    if (u8BlockVersionLow > 0) {
        /* for low version 1 FrameDataProperties is added */
        sub_item = proto_tree_add_item(tree, hf_pn_io_frame_data_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_FrameDataProperties);
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                              hf_pn_io_frame_data_properties_forwarding_Mode, &u32FrameDataProperties);
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                              hf_pn_io_frame_data_properties_FastForwardingMulticastMACAdd, &u32FrameDataProperties);
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                              hf_pn_io_frame_data_properties_FragmentMode, &u32FrameDataProperties);
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                              hf_pn_io_frame_data_properties_reserved_1, &u32FrameDataProperties);
        offset =
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                              hf_pn_io_frame_data_properties_reserved_2, &u32FrameDataProperties);
    }
    /* dissect all IR frame data */
    while (offset < u16EndOffset)
    {
        proto_item *ir_frame_data_sub_item;
        proto_tree *ir_frame_data_tree;

        n++;

        /* new subtree for each IR frame */
        ir_frame_data_sub_item = proto_tree_add_item(tree, hf_pn_io_ir_frame_data, tvb, offset, 17, ENC_NA);
        ir_frame_data_tree     = proto_item_add_subtree(ir_frame_data_sub_item, ett_pn_io_ir_frame_data);

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
        u8NumberOfTxPortGroups = tvb_get_guint8(tvb, offset);
        sub_item = proto_tree_add_uint(ir_frame_data_tree, hf_pn_io_nr_of_tx_port_groups,
                             tvb, offset, 1, u8NumberOfTxPortGroups);
        offset++;
        if ((u8NumberOfTxPortGroups > 21) || ((u8NumberOfTxPortGroups & 0x1) !=1)) {
            expert_add_info(pinfo, sub_item, &ei_pn_io_nr_of_tx_port_groups);
        }

        /* TxPortArray */
        u16TxPortGroupArraySize =  (u8NumberOfTxPortGroups + 7 / 8);
        sub_item = proto_tree_add_item(ir_frame_data_tree, hf_pn_io_TxPortGroupProperties,
                             tvb, offset, u16TxPortGroupArraySize, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_GroupProperties);
        while (u16TxPortGroupArraySize > 0)
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
    guint32 u32SubStart;
    guint32 u32Tmp;
    guint32 u32Tmp2;
    guint32 u32TxRedOrangePeriodBegin[0x11] = {0};
    guint32 u32TxOrangePeriodBegin [0x11]   = {0};
    guint32 u32TxGreenPeriodBegin [0x11]    = {0};
    guint32 u32RxRedOrangePeriodBegin[0x11] = {0};
    guint32 u32RxOrangePeriodBegin [0x11]   = {0};
    guint32 u32RxGreenPeriodBegin [0x11]    = {0};
    guint32 u32PortIndex;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    while (u32Tmp2--) {
        proto_item *ir_begin_end_port_sub_item;
        proto_tree *ir_begin_end_port_tree;

        /* new subtree for each Port */
        ir_begin_end_port_sub_item = proto_tree_add_item(tree, hf_pn_io_ir_begin_end_port, tvb, offset, 0, ENC_NA);
        ir_begin_end_port_tree = proto_item_add_subtree(ir_begin_end_port_sub_item, ett_pn_io_ir_begin_end_port);
        u32SubStart = offset;

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_number_of_assignments, &u32NumberOfAssignments);
        u32Tmp = u32NumberOfAssignments;
        u32PortIndex = 0;
        if (u32Tmp <= 0x10)
        {
            while (u32Tmp--) {
                /* TXBeginEndAssignment */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_red_orange_period_begin_tx, &u32RedOrangePeriodBegin);
                u32TxRedOrangePeriodBegin[u32PortIndex] = u32RedOrangePeriodBegin;

                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_orange_period_begin_tx, &u32OrangePeriodBegin);
                u32TxOrangePeriodBegin[u32PortIndex]= u32OrangePeriodBegin;

                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_green_period_begin_tx, &u32GreenPeriodBegin);
                u32TxGreenPeriodBegin[u32PortIndex] = u32GreenPeriodBegin;

                /* RXBeginEndAssignment */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_red_orange_period_begin_rx, &u32RedOrangePeriodBegin);
                u32RxRedOrangePeriodBegin[u32PortIndex] = u32RedOrangePeriodBegin;

                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_orange_period_begin_rx, &u32OrangePeriodBegin);
                u32RxOrangePeriodBegin[u32PortIndex]= u32OrangePeriodBegin;

                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                                               hf_pn_io_green_period_begin_rx, &u32GreenPeriodBegin);
                u32RxGreenPeriodBegin[u32PortIndex] = u32GreenPeriodBegin;

                u32PortIndex++;
            }
        }

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ir_begin_end_port_tree, drep,
                            hf_pn_io_number_of_phases, &u32NumberOfPhases);
        u32Tmp = u32NumberOfPhases;
        if (u32Tmp <= 0x10)
        {
            while (u32Tmp--) {
                proto_item *ir_begin_tx_phase_sub_item;
                proto_tree *ir_begin_tx_phase_tree;

                /* new subtree  for TXPhaseAssignment */
                ir_begin_tx_phase_sub_item = proto_tree_add_item(ir_begin_end_port_tree,
                                      hf_pn_ir_tx_phase_assignment, tvb, offset, 0, ENC_NA);
                ir_begin_tx_phase_tree     = proto_item_add_subtree(ir_begin_tx_phase_sub_item, ett_pn_io_ir_tx_phase);
                /* bit 0..3 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_begin_value, &u16TXPhaseAssignment);
                /* bit 4..7 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_orange_begin, &u16TXPhaseAssignment);
                /* bit 8..11 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_end_reserved, &u16TXPhaseAssignment);
                /* bit 12..15 */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_reserved, &u16TXPhaseAssignment);

                proto_item_append_text(ir_begin_tx_phase_sub_item,
                                      ": 0x%x, RedOrangePeriodBegin: %d, OrangePeriodBegin: %d, GreenPeriodBegin: %d",
                                      u16TXPhaseAssignment,
                                      u32TxRedOrangePeriodBegin[u16TXPhaseAssignment & 0x0F],
                                      u32TxOrangePeriodBegin[(u16TXPhaseAssignment & 0x0F0) >> 4],
                                      u32TxGreenPeriodBegin[(u16TXPhaseAssignment & 0x0F00)>> 8]);

                /* new subtree  for RXPhaseAssignment */
                ir_begin_tx_phase_sub_item = proto_tree_add_item(ir_begin_end_port_tree,
                                      hf_pn_ir_rx_phase_assignment, tvb, offset, 0, ENC_NA);
                ir_begin_tx_phase_tree     = proto_item_add_subtree(ir_begin_tx_phase_sub_item, ett_pn_io_ir_rx_phase);
                /* bit 0..3 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_begin_value, &u16RXPhaseAssignment);
                /* bit 4..7 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_orange_begin, &u16RXPhaseAssignment);
                /* bit 8..11 */
                dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_end_reserved, &u16RXPhaseAssignment);
                /* bit 12..15 */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ir_begin_tx_phase_tree, drep,
                                      hf_pn_io_tx_phase_assignment_reserved, &u16RXPhaseAssignment);

                proto_item_append_text(ir_begin_tx_phase_sub_item,
                                      ": 0x%x, RedOrangePeriodBegin: %d, OrangePeriodBegin: %d, GreenPeriodBegin: %d",
                                      u16RXPhaseAssignment,
                                      u32RxRedOrangePeriodBegin[u16RXPhaseAssignment & 0x0F],
                                      u32RxOrangePeriodBegin[(u16RXPhaseAssignment & 0x0F0) >> 4],
                                      u32RxGreenPeriodBegin[(u16RXPhaseAssignment & 0x0F00)>> 8]);
            }
        }
        proto_item_append_text(ir_begin_end_port_sub_item, ": Assignments:%u, Phases:%u",
            u32NumberOfAssignments, u32NumberOfPhases);

        proto_item_set_len(ir_begin_end_port_sub_item, offset - u32SubStart);
    }

    proto_item_append_text(item, ": StartOfRedFrameID: 0x%x, EndOfRedFrameID: 0x%x, Ports: %u",
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
    proto_item *sub_item;


    if (u8BlockVersionHigh != 1 || (u8BlockVersionLow != 0 && u8BlockVersionLow != 1)) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    if (u8BlockVersionLow == 1) {
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
    /* ChannelNumber got new ranges: 0..0x7FFF the source is a channel as specified by the manufacturer */
    /* fetch u16ChannelNumber */
    u16ChannelNumber =  ((drep[0] & DREP_LITTLE_ENDIAN)
                            ? tvb_get_letohs(tvb, offset)
                            : tvb_get_ntohs(tvb, offset));
    if (tree) {
        sub_item = proto_tree_add_item(tree,hf_pn_io_channel_number, tvb, offset, 2, DREP_ENC_INTEGER(drep));
        if (u16ChannelNumber < 0x8000){ /*  0..0x7FFF the source is a channel  as specified by the manufacturer */
             proto_item_append_text(sub_item, " channel number of the diagnosis source");
        }
        else
            if (u16ChannelNumber == 0x8000) /* 0x8000 the whole submodule is the source, */
                proto_item_append_text(sub_item, " (whole) Submodule");
            else
                proto_item_append_text(sub_item, " reserved");
    }
    offset = offset +2; /* Advance behind ChannelNumber */
    /* ChannelProperties */
    offset = dissect_ChannelProperties(tvb, offset, pinfo, tree, item, drep);
    body_length-=8;
    /* UserStructureIdentifier */
    u16UserStructureIdentifier = ((drep[0] & DREP_LITTLE_ENDIAN)
                                        ? tvb_get_letohs(tvb, offset)
                                        : tvb_get_ntohs(tvb, offset));
    if (u16UserStructureIdentifier > 0x7FFF){
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                                       hf_pn_io_user_structure_identifier, &u16UserStructureIdentifier);
    }
    else
    { /* range 0x0 to 0x7fff is manufacturer specific */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                                       hf_pn_io_user_structure_identifier_manf, &u16UserStructureIdentifier);
    }
    proto_item_append_text(item, ", USI:0x%x", u16UserStructureIdentifier);
    body_length-=2;

    /* the rest of the block contains optional: [MaintenanceItem] and/or [AlarmItem] */
    while (body_length) {
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
    guint32     u32ARProperties;
    guint8      startupMode;
    guint8      isTimeAware;

    sub_item = proto_tree_add_item(tree, hf_pn_io_ar_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_ar_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_pull_module_alarm_allowed, &u32ARProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_arproperties_StartupMode, &u32ARProperties);
    startupMode = (guint8)((u32ARProperties >> 30) & 0x01);
    /* Advanced startup mode */
    if (startupMode)
    {
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_ar_properties_combined_object_container_with_advanced_startupmode, &u32ARProperties);
    }
    /* Legacy startup mode */
    else
    {
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_ar_properties_combined_object_container_with_legacy_startupmode, &u32ARProperties);
    }
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_ar_properties_time_aware_system, &u32ARProperties);

    isTimeAware = (guint8)((u32ARProperties >> 28) & 0x01);

    wmem_map_insert(pnio_time_aware_frame_map, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER(isTimeAware));

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
                        hf_pn_io_ar_properties_parameterization_server, &u32ARProperties);
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
    guint32     u32IOCRProperties;

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
    guint16     u16NumberOfARs;
    guint16     u16NumberofEntries;
    e_guid_t    aruuid;
    e_guid_t    uuid;
    guint16     u16ARType;
    guint16     u16NameLength;
    guint16     u16NumberOfIOCRs;
    guint16     u16IOCRType;
    guint16     u16FrameID;
    guint16     u16CycleCounter;
    guint8      u8DataStatus;
    guint8      u8TransferStatus;
    proto_item *ds_item;
    proto_tree *ds_tree;
    guint16     u16UDPRTPort;
    guint16     u16AlarmCRType;
    guint16     u16LocalAlarmReference;
    guint16     u16RemoteAlarmReference;
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    proto_item *iocr_item;
    proto_tree *iocr_tree;
    proto_item *ar_item;
    proto_tree *ar_tree;
    guint32     u32IOCRStart;
    gint32      i32EndOffset;
    guint32     u32ARDataStart;

    /* added BlockversionLow == 1  */
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow > 1) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    i32EndOffset = offset + u16BlockLength;
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_ars, &u16NumberOfARs);
    /* BlockversionLow:  0 */
    if (u8BlockVersionLow == 0) {
        while (u16NumberOfARs--) {
            ar_item = proto_tree_add_item(tree, hf_pn_io_ar_data, tvb, offset, 0, ENC_NA);
            ar_tree = proto_item_add_subtree(ar_item, ett_pn_io_ar_data);
            u32ARDataStart = offset;
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep,
                            hf_pn_io_ar_uuid, &aruuid);

            if (!PINFO_FD_VISITED(pinfo)) {
                pn_init_append_aruuid_frame_setup_list(aruuid, pinfo->num);
            }

            proto_item_append_text(ar_item, "ARUUID:%s", guid_to_str(pinfo->pool, (const e_guid_t*) &aruuid));
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_ar_type, &u16ARType);
            offset = dissect_ARProperties(tvb, offset, pinfo, ar_tree, item, drep);
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep,
                         hf_pn_io_cminitiator_objectuuid, &uuid);
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                         hf_pn_io_station_name_length, &u16NameLength);
            proto_tree_add_item (ar_tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, ENC_ASCII);
            offset += u16NameLength;

            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_number_of_iocrs, &u16NumberOfIOCRs);

            while (u16NumberOfIOCRs--) {
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
            proto_tree_add_item (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, ENC_ASCII);
            offset += u16NameLength;
            /* NumberOfAPIs */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);
            /* API */
            while (u16NumberOfAPIs--) {
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ar_tree, drep,
                    hf_pn_io_api, &u32Api);
            }
            proto_item_set_len(ar_item, offset - u32ARDataStart);
        }
    }
    else
    {    /* BlockversionLow == 1 */
        while (u16NumberOfARs--) {
            ar_item = proto_tree_add_item(tree, hf_pn_io_ar_data, tvb, offset, 0, ENC_NA);
            ar_tree = proto_item_add_subtree(ar_item, ett_pn_io_ar_data);
            u32ARDataStart = offset;
            /*ARUUID */
            offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_ar_uuid, &aruuid);

            if (!PINFO_FD_VISITED(pinfo)) {
                pn_init_append_aruuid_frame_setup_list(aruuid, pinfo->num);
            }

            proto_item_append_text(ar_item, "ARUUID:%s", guid_to_str(pinfo->pool, (const e_guid_t*) &aruuid));
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
            proto_tree_add_item (ar_tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, ENC_ASCII);
            offset += u16NameLength;
            /** align padding! **/
            offset = dissect_pn_align4(tvb, offset, pinfo, ar_tree);

            /* StationNameLength */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_station_name_length, &u16NameLength);
            if (u16NameLength != 0) {
                /* ParameterServerStationName */
                proto_tree_add_item (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, ENC_ASCII);
                offset += u16NameLength;
            }
            else
            { /* display no name present */
                proto_tree_add_string (ar_tree, hf_pn_io_parameter_server_station_name, tvb, offset, u16NameLength, " <no ParameterServerStationName present>");
            }
            /** align padding! **/
            offset = dissect_pn_align4(tvb, offset, pinfo, ar_tree);

            /* NumberOfIOCRs*/
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_number_of_iocrs, &u16NumberOfIOCRs);
            /* align to next 32 bit */
            offset = dissect_pn_padding(tvb, offset, pinfo, ar_tree, 2);

            while (u16NumberOfIOCRs--) {
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
            while (u16NumberOfAPIs--) {
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_api, &u32Api);
            }
            /* get the number of subblocks an dissect them */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, ar_tree, drep, hf_pn_io_number_of_ARDATAInfo, &u16NumberofEntries);

            offset = dissect_pn_padding(tvb, offset, pinfo, ar_tree, 2);

            while ((offset < i32EndOffset) && (u16NumberofEntries > 0)) {
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
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

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* bit 0 ..1  EndPoint1 and EndPoint2*/
    dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_RedundancyInfo, &RedundancyInfo);
    /* bit 2 .. 15 reserved */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_RedundancyInfo_reserved, &RedundancyInfo);
    offset = dissect_pn_align4(tvb, offset, pinfo, tree);
    return offset;
}

/* dissect the LogData block */
static int
dissect_LogData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint64  u64ActualLocaltimeStamp;
    guint16  u16NumberOfLogEntries;
    guint64  u64LocaltimeStamp;
    e_guid_t aruuid;
    guint32  u32EntryDetail;
    dcerpc_info        di; /* fake dcerpc_info struct */
    dcerpc_call_value  call_data;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    di.conformant_run = 0;
    /* we need di->call_data->flags.NDR64 == 0 */
    call_data.flags = 0;
    di.call_data = &call_data;
    di.dcerpc_procedure_name = "";

    /* ActualLocalTimeStamp */
    offset = dissect_dcerpc_uint64(tvb, offset, pinfo, tree, &di, drep,
                    hf_pn_io_actual_local_time_stamp, &u64ActualLocaltimeStamp);
    /* NumberOfLogEntries */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                    hf_pn_io_number_of_log_entries, &u16NumberOfLogEntries);

    while (u16NumberOfLogEntries--) {
        /* LocalTimeStamp */
        offset = dissect_dcerpc_uint64(tvb, offset, pinfo, tree, &di, drep,
                        hf_pn_io_local_time_stamp, &u64LocaltimeStamp);
        /* ARUUID */
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &aruuid);

        if (!PINFO_FD_VISITED(pinfo)) {
            pn_init_append_aruuid_frame_setup_list(aruuid, pinfo->num);
        }

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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    e_guid_t FSParameterUUID;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    u16BodyLength -= 2;

    /* sub blocks */
    new_tvb = tvb_new_subset_length(tvb, offset, u16BodyLength);
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    u16BodyLength -= 2;

    /* sub blocks */
    new_tvb = tvb_new_subset_length(tvb, offset, u16BodyLength);
    dissect_blocks(new_tvb, 0, pinfo, tree, drep);
    offset += u16BodyLength;

    return offset;
}

/* dissect the PE_EntityFilterData block */
static int
dissect_PE_EntityFilterData_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16NumberOfModules;
    guint16     u16SlotNr;
    guint32     u32ModuleIdentNumber;
    guint16     u16NumberOfSubmodules;
    guint16     u16SubslotNr;
    guint32     u32SubmoduleIdentNumber;
    proto_item* api_item;
    proto_tree* api_tree;
    guint32     u32ApiStart;
    proto_item* module_item;
    proto_tree* module_tree;
    guint32     u32ModuleStart;
    proto_item* sub_item;
    proto_tree* sub_tree;
    guint32     u32SubStart;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    // NumberOfAPIs,
    // (API, NumberOfModules, (SlotNumber, ModuleIdentNumber, NumberOfSubmodules, (SubslotNumber, SubmoduleIdentNumber)*)*)*

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
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

        while (u16NumberOfModules--) {
            module_item = proto_tree_add_item(api_tree, hf_pn_io_module_tree, tvb, offset, 0, ENC_NA);
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

            proto_item_append_text(module_item, ": Slot 0x%x, Ident: 0x%x Submodules: %u",
                u16SlotNr, u32ModuleIdentNumber,
                u16NumberOfSubmodules);

            proto_item_append_text(item, ", Submodules:%u", u16NumberOfSubmodules);

            while (u16NumberOfSubmodules--) {
                sub_item = proto_tree_add_item(module_tree, hf_pn_io_submodule_tree, tvb, offset, 0, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
                u32SubStart = offset;

                /* Subslotnumber */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
                offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

                proto_item_append_text(sub_item, ": Subslot 0x%x, IdentNumber: 0x%x",
                    u16SubslotNr, u32SubmoduleIdentNumber);

                proto_item_set_len(sub_item, offset - u32SubStart);
            } /* NumberOfSubmodules */

            proto_item_set_len(module_item, offset - u32ModuleStart);
        }

        proto_item_set_len(api_item, offset - u32ApiStart);
    }


    return offset;
}

/* dissect the PE_EntityStatusData block */
static int
dissect_PE_EntityStatusData_block(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, proto_item* item _U_, guint8* drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16NumberOfModules;
    guint16     u16SlotNr;
    guint16     u16NumberOfSubmodules;
    guint16     u16SubslotNr;
    proto_item* api_item;
    proto_tree* api_tree;
    guint32     u32ApiStart;
    proto_item* module_item;
    proto_tree* module_tree;
    guint32     u32ModuleStart;
    proto_item* sub_item;
    proto_tree* sub_tree;
    guint32     u32SubStart;
    guint8      u8PEOperationalMode;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    // NumberOfAPIs,
    // (API, NumberOfModules, (SlotNumber, NumberOfSubmodules, (SubslotNumber, PE_OperationalMode, [Padding] * a)*)*)*

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
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

        while (u16NumberOfModules--) {
            module_item = proto_tree_add_item(api_tree, hf_pn_io_module_tree, tvb, offset, 0, ENC_NA);
            module_tree = proto_item_add_subtree(module_item, ett_pn_io_module);
            u32ModuleStart = offset;

            /* SlotNumber */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                hf_pn_io_slot_nr, &u16SlotNr);
            /* NumberOfSubmodules */
            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, module_tree, drep,
                hf_pn_io_number_of_submodules, &u16NumberOfSubmodules);

            proto_item_append_text(module_item, ": Slot 0x%x, Submodules: %u",
                u16SlotNr,
                u16NumberOfSubmodules);

            proto_item_append_text(item, ", Submodules:%u", u16NumberOfSubmodules);

            while (u16NumberOfSubmodules--) {
                sub_item = proto_tree_add_item(module_tree, hf_pn_io_submodule_tree, tvb, offset, 0, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
                u32SubStart = offset;

                /* Subslotnumber */
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_subslot_nr, &u16SubslotNr);

                proto_item_append_text(sub_item, ": Subslot 0x%x",
                    u16SubslotNr);

                offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                    hf_pn_io_pe_operational_mode, &u8PEOperationalMode);

                offset = dissect_pn_padding(tvb, offset, pinfo, sub_tree, 1);

                proto_item_set_len(sub_item, offset - u32SubStart);
            } /* NumberOfSubmodules */

            proto_item_set_len(module_item, offset - u32ModuleStart);
        }

        proto_item_set_len(api_item, offset - u32ApiStart);
    }


    return offset;

}

static const char *
decode_ARType_spezial(guint16 ARType, guint16 ARAccess)
{
    if (ARType == 0x0001)
        return ("IO Controller AR");
    else if (ARType == 0x0003)
        return("IO Controller AR");
    else if (ARType == 0x0010)
        return("IO Controller AR (RT_CLASS_3)");
    else if (ARType == 0x0020)
        return("IO Controller AR (sysred/CiR)");
    else if (ARType == 0x0006)
    {
        if (ARAccess) /*TRUE */
            return("DeviceAccess AR");
        else
            return("IO Supervisor AR");
    }
    else
        return("reserved");
}

/* dissect the ARBlockReq */
static int
dissect_ARBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t ** ar)
{
    guint16    u16ARType;
    guint32    u32ARProperties;
    gboolean   have_aruuid = FALSE;
    e_guid_t   aruuid;
    e_guid_t   uuid;
    guint16    u16SessionKey;
    guint8     mac[6];
    guint16    u16TimeoutFactor;
    guint16    u16UDPRTPort;
    guint16    u16NameLength;
    char      *pStationName;
    pnio_ar_t *par;
    proto_item          *sub_item;
    proto_tree          *sub_tree;
    guint16             u16ArNumber;
    guint16             u16ArResource;
    guint16             u16ArReserved;
    proto_item          *sub_item_selector;
    proto_tree          *sub_tree_selector;
    conversation_t      *conversation;
    apduStatusSwitch    *apdu_status_switch = NULL;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    u32ARProperties = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letohl (tvb, offset + 2 + 16 +2 + 6 +12)
            : tvb_get_ntohl (tvb, offset + 2 + 16 +2 + 6 +12));

    u16ARType = ((drep[0] & DREP_LITTLE_ENDIAN)
                ? tvb_get_letohs (tvb, offset)
                : tvb_get_ntohs (tvb, offset));

    if (tree) {
        proto_tree_add_string_format(tree, hf_pn_io_artype_req, tvb, offset, 2,
                        "ARType", "ARType: (0x%04x) %s ",
                        u16ARType, decode_ARType_spezial(u16ARType, u32ARProperties));
    }
    offset = offset + 2;

    if (u16ARType == 0x0020)
    {
        dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, hf_pn_io_ar_uuid, &aruuid);

        sub_item = proto_tree_add_item(tree, hf_pn_io_ar_uuid, tvb, offset, 16, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_ar_info);

        proto_tree_add_item(sub_tree, hf_pn_io_ar_discriminator, tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(sub_tree, hf_pn_io_ar_configid, tvb, offset, 8, ENC_NA);
        offset += 8;

        sub_item_selector = proto_tree_add_item(sub_tree, hf_pn_io_ar_selector, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree_selector = proto_item_add_subtree(sub_item_selector, ett_pn_io_ar_info);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree_selector, drep, hf_pn_io_ar_arnumber, &u16ArNumber);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree_selector, drep, hf_pn_io_ar_arresource, &u16ArResource);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree_selector, drep, hf_pn_io_ar_arreserved, &u16ArReserved);

        /* When ARType==IOCARSR, then find or create conversation for this frame */
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Get current conversation endpoints using MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_UDP, 0, 0, 0);
            if (conversation == NULL) {
                /* Create new conversation, if no "Ident OK" frame as been dissected yet!
                 * Need to switch dl_src & dl_dst, as current packet is sent by controller and not by device.
                 * All conversations are based on Device MAC as addr1 */
                conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_UDP, 0, 0, 0);
            }

            /* Try to get apdu status switch information from the conversation */
            apdu_status_switch = (apduStatusSwitch*)conversation_get_proto_data(conversation, proto_pn_io_apdu_status);

            /* If apdu status switch is null, then fill it*/
            /* If apdu status switch is not null, then update it*/
            if (apdu_status_switch == NULL) {
                /* apdu status switch information is valid for whole file*/
                apdu_status_switch = wmem_new0(wmem_file_scope(), apduStatusSwitch);
                copy_address_shallow(&apdu_status_switch->dl_src, conversation_key_addr1(conversation->key_ptr));
                copy_address_shallow(&apdu_status_switch->dl_dst, conversation_key_addr2(conversation->key_ptr));
                apdu_status_switch->isRedundancyActive = TRUE;
                conversation_add_proto_data(conversation, proto_pn_io_apdu_status, apdu_status_switch);
            }
            else {
                copy_address_shallow(&apdu_status_switch->dl_src, conversation_key_addr1(conversation->key_ptr));
                copy_address_shallow(&apdu_status_switch->dl_dst, conversation_key_addr2(conversation->key_ptr));
                apdu_status_switch->isRedundancyActive = TRUE;
            }
        }
    }
    else
    {
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
            hf_pn_io_ar_uuid, &aruuid);
        have_aruuid = TRUE;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        pn_init_append_aruuid_frame_setup_list(aruuid, pinfo->num);
    }

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

    proto_tree_add_item_ret_display_string (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, ENC_ASCII, pinfo->pool, &pStationName);
    offset += u16NameLength;

    proto_item_append_text(item, ": %s, Session:%u, MAC:%02x:%02x:%02x:%02x:%02x:%02x, Port:0x%x, Station:%s",
        decode_ARType_spezial(u16ARType, u32ARProperties),
        u16SessionKey,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        u16UDPRTPort,
        pStationName);

    if (have_aruuid) {
        par = pnio_ar_find_by_aruuid(pinfo, &aruuid);
        if (par == NULL) {
            par = pnio_ar_new(&aruuid);
            memcpy( (void *) (&par->controllermac), mac, sizeof(par->controllermac));
            par->arType = u16ARType; /* store AR-type for filter generation */
            /*strncpy( (char *) (&par->controllername), pStationName, sizeof(par->controllername));*/
        } else {
            /*expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "ARBlockReq: AR already existing!");*/
        }
        *ar = par;
    } else {
        *ar = NULL;
    }

    return offset;
}


/* dissect the ARBlockRes */
static int
dissect_ARBlockRes_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t **ar)
{
    guint16    u16ARType;
    e_guid_t   uuid;
    guint16    u16SessionKey;
    guint8     mac[6];
    guint16    u16UDPRTPort;
    pnio_ar_t *par;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ar_uuid, &uuid);


    if (!PINFO_FD_VISITED(pinfo)) {
        pn_init_append_aruuid_frame_setup_list(uuid, pinfo->num);
    }

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

    /* The value NIL indicates the usage of the implicit AR*/
    par = pnio_ar_find_by_aruuid(pinfo, &uuid);
    if (par != NULL) {
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
    guint16     u16IOCRType;
    guint16     u16IOCRReference;
    guint16     u16LT;
    guint16     u16DataLength;
    guint16     u16FrameID;
    guint16     u16SendClockFactor;
    guint16     u16ReductionRatio;
    guint16     u16Phase;
    guint16     u16Sequence;
    guint32     u32FrameSendOffset;
    guint16     u16WatchdogFactor;
    guint16     u16DataHoldFactor;
    guint16     u16IOCRTagHeader;
    guint8      mac[6];
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16NumberOfIODataObjectsInAPI;
    guint16     u16NumberOfIODataObjectsInCR = 0U;
    guint16     u16SlotNr;
    guint16     u16SubslotNr;
    guint16     u16IODataObjectFrameOffset;
    guint16     u16NumberOfIOCSInAPI;
    guint16     u16NumberOfIOCSInCR = 0U;
    guint16     u16IOCSFrameOffset;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32     u32ApiStart;
    guint16     u16Tmp;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32     u32SubStart;

    conversation_t    *conversation;
    conversation_t    *conversation_time_aware;
    stationInfo       *station_info = NULL;
    iocsObject        *iocs_object;
    iocsObject        *cmp_iocs_object;
    ioDataObject      *io_data_object;
    ioDataObject      *cmp_io_data_object;
    wmem_list_frame_t *frame;
    wmem_list_t       *iocs_list;

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (wmem_map_contains(pnio_time_aware_frame_map, GUINT_TO_POINTER(pinfo->num)))
    {
        address cyclic_mac_addr;
        address iocr_mac_addr;

        set_address(&cyclic_mac_addr, AT_ETHER, 6, mac);

        iocr_mac_addr = (u16IOCRType == PN_INPUT_CR) ? pinfo->dl_dst : pinfo->dl_src;

         /* Get current conversation endpoints using MAC addresses */
        conversation_time_aware = find_conversation(pinfo->num, &cyclic_mac_addr, &iocr_mac_addr, CONVERSATION_NONE, 0, 0, 0);

        if (conversation_time_aware == NULL) {
            conversation_time_aware = conversation_new(pinfo->num, &iocr_mac_addr, &cyclic_mac_addr, CONVERSATION_NONE, 0, 0, 0);
        }

        conversation_add_proto_data(conversation_time_aware, proto_pn_io_time_aware_status, wmem_map_lookup(pnio_time_aware_frame_map, GUINT_TO_POINTER(pinfo->num)));
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": %s, Ref:0x%x, Len:%u, FrameID:0x%x, Clock:%u, Ratio:%u, Phase:%u APIs:%u",
        val_to_str(u16IOCRType, pn_io_iocr_type, "0x%x"),
        u16IOCRReference, u16DataLength, u16FrameID,
        u16SendClockFactor, u16ReductionRatio, u16Phase, u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, ENC_NA);
        api_tree = proto_item_add_subtree(api_item, ett_pn_io_api);
        u32ApiStart = offset;

        /* API */
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_api, &u32Api);
        /* NumberOfIODataObjects */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_io_data_objects, &u16NumberOfIODataObjectsInAPI);

        /* Set global Variant for Number of IO Data Objects */
        /* Notice: Handle Input & Output seperate!!! */
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Get current conversation endpoints using MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            if (conversation == NULL) {
                /* Create new conversation, if no "Ident OK" frame as been dissected yet!
                 * Need to switch dl_src & dl_dst, as Connect Request is sent by controller and not by device.
                 * All conversations are based on Device MAC as addr1 */
                conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
            }

            current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

            if (current_aruuid_frame != NULL) {
                current_aruuid = current_aruuid_frame->aruuid.data1;
                if (u16IOCRType == PN_INPUT_CR) {
                    current_aruuid_frame->inputframe = u16FrameID;
                }
            }

            station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);
            if (station_info == NULL) {
                station_info = wmem_new0(wmem_file_scope(), stationInfo);
                init_pnio_rtc1_station(station_info);
                conversation_add_proto_data(conversation, current_aruuid, station_info);
            }
            u16NumberOfIODataObjectsInCR += u16NumberOfIODataObjectsInAPI;

            pn_find_dcp_station_info(station_info, conversation);
        }

        u16Tmp = u16NumberOfIODataObjectsInAPI;
        while (u16Tmp--) {
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

            if (!PINFO_FD_VISITED(pinfo) && station_info != NULL) {
                io_data_object = wmem_new0(wmem_file_scope(), ioDataObject);
                io_data_object->slotNr = u16SlotNr;
                io_data_object->subSlotNr = u16SubslotNr;
                io_data_object->frameOffset = u16IODataObjectFrameOffset;
                /* initial - Will be added later with Write Request */
                io_data_object->f_dest_adr = 0;
                io_data_object->f_par_crc1 = 0;
                io_data_object->f_src_adr = 0;
                io_data_object->f_crc_seed = FALSE;
                io_data_object->f_crc_len = 0;
                /* Reset as a PNIO Connect Request of a known module appears */
                io_data_object->last_sb_cb = 0;
                io_data_object->lastToggleBit = 0;

                if (u16IOCRType == PN_INPUT_CR) {
                    iocs_list = station_info->ioobject_data_in;
                }
                else {
                    iocs_list = station_info->ioobject_data_out;
                }

                for (frame = wmem_list_head(iocs_list); frame != NULL; frame = wmem_list_frame_next(frame)) {
                    cmp_io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                    if (cmp_io_data_object->slotNr == u16SlotNr && cmp_io_data_object->subSlotNr == u16SubslotNr) {
                        /* Found identical existing object */
                        break;
                    }
                }

                if (frame == NULL) {
                    /* new io_object data incoming */
                    wmem_list_append(iocs_list, io_data_object);
                }
            }
        }

        /* NumberOfIOCS */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, api_tree, drep,
                            hf_pn_io_number_of_iocs, &u16NumberOfIOCSInAPI);

        /* Set global Vairant for NumberOfIOCS */
        if (!PINFO_FD_VISITED(pinfo)) {
            u16NumberOfIOCSInCR += u16NumberOfIOCSInAPI;
        }

        u16Tmp = u16NumberOfIOCSInAPI;
        while (u16Tmp--) {
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

            if (!PINFO_FD_VISITED(pinfo)) {
                if (station_info != NULL) {
                    if (u16IOCRType == PN_INPUT_CR) {
                        iocs_list = station_info->iocs_data_in;
                    }
                    else {
                        iocs_list = station_info->iocs_data_out;
                    }

                    for (frame = wmem_list_head(iocs_list); frame != NULL; frame = wmem_list_frame_next(frame)) {
                        cmp_iocs_object = (iocsObject*)wmem_list_frame_data(frame);
                        if (cmp_iocs_object->slotNr == u16SlotNr && cmp_iocs_object->subSlotNr == u16SubslotNr) {
                            /* Found identical existing object */
                            break;
                        }
                    }

                    if (frame == NULL) {
                        /* new iocs_object data incoming */
                        iocs_object = wmem_new(wmem_file_scope(), iocsObject);
                        iocs_object->slotNr = u16SlotNr;
                        iocs_object->subSlotNr = u16SubslotNr;
                        iocs_object->frameOffset = u16IOCSFrameOffset;
                        wmem_list_append(iocs_list, iocs_object);
                    }
                }
            }
        }

        proto_item_append_text(api_item, ": 0x%x, NumberOfIODataObjects: %u NumberOfIOCS: %u",
            u32Api, u16NumberOfIODataObjectsInAPI, u16NumberOfIOCSInAPI);

        proto_item_set_len(api_item, offset - u32ApiStart);
    }

    /* Update global object count  */
    if (!PINFO_FD_VISITED(pinfo)) {
        if (station_info != NULL) {
            if (u16IOCRType == PN_INPUT_CR) {
                station_info->iocsNr_in = u16NumberOfIOCSInCR;
                station_info->ioDataObjectNr_in = u16NumberOfIODataObjectsInCR;
            } else {
                station_info->iocsNr_out = u16NumberOfIOCSInCR;
                station_info->ioDataObjectNr_out = u16NumberOfIODataObjectsInCR;
            }
        }
    }

    if (ar != NULL) {
        switch (u16IOCRType) {
        case(1): /* Input CR */
            if (ar->inputframeid != 0 && ar->inputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, &ei_pn_io_frame_id, "IOCRBlockReq: input frameID changed from %u to %u!", ar->inputframeid, u16FrameID);
            }
            ar->inputframeid = u16FrameID;
            break;
        case(2): /* Output CR */
#if 0
            /* will usually contain 0xffff here because the correct framid will be given in the connect.Cnf */
            if (ar->outputframeid != 0 && ar->outputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, &ei_pn_io_frame_id, "IOCRBlockReq: output frameID changed from %u to %u!", ar->outputframeid, u16FrameID);
            }
            ar->outputframeid = u16FrameID;
#endif
            break;
        default:
            expert_add_info_format(pinfo, item, &ei_pn_io_iocr_type, "IOCRBlockReq: IOCRType %u undecoded!", u16IOCRType);
        }
    } else {
        expert_add_info_format(pinfo, item, &ei_pn_io_ar_info_not_found, "IOCRBlockReq: no corresponding AR found!");
    }

    return offset;
}


/* dissect the AlarmCRBlockReq */
static int
dissect_AlarmCRBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    pnio_ar_t *ar)
{
    guint16     u16AlarmCRType;
    guint16     u16LT;
    guint32     u32AlarmCRProperties;
    guint16     u16RTATimeoutFactor;
    guint16     u16RTARetries;
    guint16     u16LocalAlarmReference;
    guint16     u16MaxAlarmDataLength;
    guint16     u16AlarmCRTagHeaderHigh;
    guint16     u16AlarmCRTagHeaderLow;
    proto_item *sub_item;
    proto_tree *sub_tree;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (ar != NULL) {
        if (ar->controlleralarmref != 0xffff && ar->controlleralarmref != u16LocalAlarmReference) {
            expert_add_info_format(pinfo, item, &ei_pn_io_localalarmref, "AlarmCRBlockReq: local alarm ref changed from %u to %u!", ar->controlleralarmref, u16LocalAlarmReference);
        }
        ar->controlleralarmref = u16LocalAlarmReference;
    } else {
        expert_add_info_format(pinfo, item, &ei_pn_io_ar_info_not_found, "AlarmCRBlockReq: no corresponding AR found!");
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (ar != NULL) {
        if (ar->devicealarmref != 0xffff && ar->devicealarmref != u16LocalAlarmReference) {
            expert_add_info_format(pinfo, item, &ei_pn_io_localalarmref, "AlarmCRBlockRes: local alarm ref changed from %u to %u!", ar->devicealarmref, u16LocalAlarmReference);
        }
        ar->devicealarmref = u16LocalAlarmReference;
    } else {
        expert_add_info_format(pinfo, item, &ei_pn_io_ar_info_not_found, "AlarmCRBlockRes: no corresponding AR found!");
    }

    return offset;
}

/* dissect the ARServerBlock */
static int
dissect_ARServerBlock(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength)
{
    guint16  u16NameLength, u16padding;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_station_name_length, &u16NameLength);

    proto_tree_add_item (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, ENC_ASCII);
    offset += u16NameLength;
    /* Padding to next 4 byte alignment in this block */
    u16padding = u16BodyLength - (2 + u16NameLength);
    if (u16padding > 0)
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

    ARUUIDFrame *current_aruuid_frame = NULL;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    if (ar != NULL) {
        switch (u16IOCRType) {
        case(1): /* Input CR */
            if (ar->inputframeid != 0 && ar->inputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, &ei_pn_io_frame_id, "IOCRBlockRes: input frameID changed from %u to %u!", ar->inputframeid, u16FrameID);
            }
            ar->inputframeid = u16FrameID;
            break;
        case(2): /* Output CR */
            if (ar->outputframeid != 0 && ar->outputframeid != u16FrameID) {
                expert_add_info_format(pinfo, item, &ei_pn_io_frame_id, "IOCRBlockRes: output frameID changed from %u to %u!", ar->outputframeid, u16FrameID);
            }
            ar->outputframeid = u16FrameID;
            break;
        default:
            expert_add_info_format(pinfo, item, &ei_pn_io_iocr_type, "IOCRBlockRes: IOCRType %u undecoded!", u16IOCRType);
        }
    } else {
        expert_add_info_format(pinfo, item, &ei_pn_io_ar_info_not_found, "IOCRBlockRes: no corresponding AR found!");
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);
        if (current_aruuid_frame != NULL) {
            if (u16IOCRType == 1) {
                current_aruuid_frame->inputframe = u16FrameID;
            }
            else if (u16IOCRType == 2) {
                current_aruuid_frame->outputframe = u16FrameID;
            }
        }
    }

    return offset;
}



/* dissect the MCRBlockReq */
static int
dissect_MCRBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16  u16IOCRReference;
    guint32  u32AddressResolutionProperties;
    guint16  u16MCITimeoutFactor;
    guint16  u16NameLength;
    char    *pStationName;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    proto_tree_add_item_ret_display_string (tree, hf_pn_io_provider_station_name, tvb, offset, u16NameLength, ENC_ASCII, pinfo->pool, &pStationName);
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
    guint16     u16IOCRReference;
    guint8      mac[6];
    guint32     u32SubFrameData;
    guint16     u16Tmp;
    proto_item *sub_item;
    proto_tree *sub_tree;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    } while (u16Tmp -= 4);

    proto_item_append_text(item, ", CRRef:%u, %u*Data",
        u16IOCRReference, u16BodyLength/4);

    return offset;
}

/* dissect the (PD)SubFrameBlock  0x022B */
static int
dissect_PDSubFrameBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength)
{
    guint32 u32SFIOCRProperties;
    guint32 u32SubFrameData;
    guint16 u16FrameID;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16 u16RemainingLength;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    /* FrameID */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_frame_id, &u16FrameID);
    /* SFIOCRProperties */
    sub_item = proto_tree_add_item(tree, hf_pn_io_SFIOCRProperties, tvb, offset, PD_SUB_FRAME_BLOCK_FIOCR_PROPERTIES_LENGTH, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_SFIOCRProperties);

    /*    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties, &u32SFIOCRProperties); */
    /* Bit 31: SFIOCRProperties.SFCRC16 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_SFCRC16, &u32SFIOCRProperties);

    /* Bit 30: SFIOCRProperties.DFPRedundantPathLayout */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_DFPRedundantPathLayout, &u32SFIOCRProperties);
    /* Bit 29: SFIOCRProperties.DFPRedundantPathLayout */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_DFPType, &u32SFIOCRProperties);
    /* Bit 28 - 29: SFIOCRProperties.reserved_2 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_reserved_2, &u32SFIOCRProperties);
    /* Bit 24 - 27: SFIOCRProperties.reserved_1 */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_reserved_1, &u32SFIOCRProperties);
    /* Bit 16 - 23: SFIOCRProperties.DFPmode */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_SFIOCRProperties_DFPmode, &u32SFIOCRProperties);
    /*  Bit 8 - 15: SFIOCRProperties.RestartFactorForDistributedWD */
    /*      0x00           Mandatory    No restart delay necessary
            0x01 - 0x09    Optional    Less than 1 s restart delay
            0x0A - 0x50    Mandatory    1 s to 8 s restart delay
            0x51 - 0xFF    Optional    More than 8 s restart delay */
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_RestartFactorForDistributedWD, &u32SFIOCRProperties);
    /*  bit 0..7 SFIOCRProperties.DistributedWatchDogFactor */
    offset = /* it is the last one, so advance! */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_DistributedWatchDogFactor, &u32SFIOCRProperties);

    /* SubframeData */
    u16RemainingLength = u16BodyLength - PD_SUB_FRAME_BLOCK_FIOCR_PROPERTIES_LENGTH - PD_SUB_FRAME_BLOCK_FRAME_ID_LENGTH;
    while (u16RemainingLength >= PD_SUB_FRAME_BLOCK_SUB_FRAME_DATA_LENGTH)
    {
        guint8 Position,
               DataLength;
        sub_item = proto_tree_add_item(tree, hf_pn_io_subframe_data, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_subframe_data);

        /* Bit 0 - 6: SubframeData.Position */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_subframe_data_position, &u32SubFrameData);
        /* Bit 7: SubframeData.reserved_1 */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_subframe_reserved1, &u32SubFrameData);
        /* Bit 8 - 15: SubframeData.dataLength */
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_subframe_data_length, &u32SubFrameData);
        /* Bit 16 - 31: SubframeData.reserved_2 */
        offset =
            dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_subframe_reserved2, &u32SubFrameData);
        Position  = (guint8) (u32SubFrameData & 0x7F);       /* the lower 6 bits */
        DataLength =(guint8) ((u32SubFrameData >>8) & 0x0ff); /* bit 8 to 15 */
        proto_item_append_text(sub_item, ", Length:%u (0x%x), Pos:%u",
            DataLength,DataLength, Position);
        u16RemainingLength = u16RemainingLength - 4;
    }
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
    e_guid_t IRDataUUID;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    while (u16NumberOfIOCR--)
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
    guint8 u8SRPropertiesMode;
    proto_item *sub_item;
    proto_tree *sub_tree;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_RedundancyDataHoldFactor, &u16RedundancyDataHoldFactor);

    u32sr_properties = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    sub_item = proto_tree_add_item(tree, hf_pn_io_sr_properties, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_sr_properties);

    u8SRPropertiesMode = (guint8)((u32sr_properties >> 2) & 0x01);

    /* SRProperties.InputValidOnBackupAR with SRProperties.Mode == 1 */
    if (u8SRPropertiesMode)
    {
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_1, &u32sr_properties);
    }
    /* SRProperties.InputValidOnBackupAR with SRProperties.Mode == 0 */
    else
    {
        dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_0, &u32sr_properties);
    }
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_sr_properties_Reserved_1, &u32sr_properties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_sr_properties_Mode, &u32sr_properties);

    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_sr_properties_Reserved_2, &u32sr_properties);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, hf_pn_io_sr_properties_Reserved_3, &u32sr_properties);
    return offset;
}

/* dissect the RSInfoBlock */
static int
dissect_RSInfoBlock_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
    guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow, guint16 u16BodyLength _U_)
{
    guint32 u32RSProperties;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* Padding 2 + 2 + 1 + 1 = 6 */
    /* Therefore we need 2 byte padding to make the block u32 aligned */
    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_rs_properties, &u32RSProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_rs_properties_alarm_transport, &u32RSProperties);
    dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_rs_properties_reserved1, &u32RSProperties);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, hf_pn_io_rs_properties_reserved2, &u32RSProperties);

    return offset;
}

/* dissect the PDIRSubframeData block  0x022a */
static int
dissect_PDIRSubframeData_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfSubframeBlocks;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, hf_pn_io_NumberOfSubframeBlocks, &u16NumberOfSubframeBlocks);

    while (u16NumberOfSubframeBlocks --)
    {   /* dissect the Subframe Block  */
        offset = dissect_a_block(tvb, offset, pinfo, /*sub_*/tree, drep);
    }

    return offset;
}

static int
dissect_ARVendorBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16BodyLength _U_)
{
    guint16 APStructureIdentifier;
    guint32 gu32API;
    guint32 guDataBytes;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    APStructureIdentifier = ((drep[0] & DREP_LITTLE_ENDIAN)
                            ? tvb_get_letohs(tvb, offset)
                            : tvb_get_ntohs(tvb, offset));

    gu32API = ((drep[0] & DREP_LITTLE_ENDIAN)
                ? tvb_get_letohl(tvb, offset + 2)
                : tvb_get_ntohl (tvb, offset + 2));

    if (tree)
    {
        if (gu32API == 0)
        {
            if (APStructureIdentifier <0x8000)
            {
                proto_tree_add_item(tree, hf_pn_io_arvendor_strucidentifier_if0_low, tvb, offset, 2, DREP_ENC_INTEGER(drep));
            }
            else
            {
                if (APStructureIdentifier > 0x8000)
                {
                    proto_tree_add_item(tree, hf_pn_io_arvendor_strucidentifier_if0_high, tvb, offset, 2, DREP_ENC_INTEGER(drep));
                }
                else /* APStructureIdentifier == 0x8000 */
                {
                    proto_tree_add_item(tree, hf_pn_io_arvendor_strucidentifier_if0_is8000, tvb, offset, 2, DREP_ENC_INTEGER(drep));
                }
            }
        }
        else
        {
            proto_tree_add_item(tree, hf_pn_io_arvendor_strucidentifier_not0, tvb, offset, 2, DREP_ENC_INTEGER(drep));
        }
        /* API */
        proto_tree_add_item(tree, hf_pn_io_api, tvb, offset + 2, 4, DREP_ENC_INTEGER(drep));
    }
    offset += 6;
    if (u16BodyLength < 6 )
        return offset; /* there are no user bytes! */
    guDataBytes = u16BodyLength - 6;

    dissect_pn_user_data(tvb, offset, pinfo, tree, guDataBytes, "Data ");
    return offset;
}

/* dissect the DataDescription */
static int
dissect_DataDescription(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, ioDataObject *tmp_io_data_object)
{
    guint16     u16DataDescription;
    guint16     u16SubmoduleDataLength;
    guint8      u8LengthIOCS;
    guint8      u8LengthIOPS;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32     u32SubStart;

    conversation_t    *conversation;
    stationInfo       *station_info = NULL;
    ioDataObject      *io_data_object;
    wmem_list_frame_t *frame;
    wmem_list_t       *ioobject_list;

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

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

    /* Save new data for IO Data Objects */
    if (!PINFO_FD_VISITED(pinfo)) {
        /* Get current conversation endpoints using MAC addresses */
        conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
        if (conversation == NULL) {
            /* Create new conversation, if no "Ident OK" frame as been dissected yet!
             * Need to switch dl_src & dl_dst, as current packet is sent by controller and not by device.
             * All conversations are based on Device MAC as addr1 */
           conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
        }

        current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

        if (current_aruuid_frame != NULL) {
            current_aruuid = current_aruuid_frame->aruuid.data1;
        }

        station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

        if (station_info != NULL) {
            pn_find_dcp_station_info(station_info, conversation);

            if (u16DataDescription == PN_INPUT_DATADESCRITPION) {
                /* INPUT HANDLING */
                ioobject_list = station_info->ioobject_data_in;
            }
            else {
                /* OUTPUT HANDLING */
                ioobject_list = station_info->ioobject_data_out;
            }

            for (frame = wmem_list_head(ioobject_list); frame != NULL; frame = wmem_list_frame_next(frame)) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                if (io_data_object->slotNr == tmp_io_data_object->slotNr && io_data_object->subSlotNr == tmp_io_data_object->subSlotNr) {
                    /* Write additional data from dissect_ExpectedSubmoduleBlockReq_block() to corresponding io_data_object */
                    io_data_object->api = tmp_io_data_object->api;
                    io_data_object->moduleIdentNr = tmp_io_data_object->moduleIdentNr;
                    io_data_object->subModuleIdentNr = tmp_io_data_object->subModuleIdentNr;
                    io_data_object->length = u16SubmoduleDataLength;

                    io_data_object->moduleNameStr = wmem_strdup(wmem_file_scope(), tmp_io_data_object->moduleNameStr);
                    io_data_object->profisafeSupported = tmp_io_data_object->profisafeSupported;
                    io_data_object->discardIOXS = tmp_io_data_object->discardIOXS;
                    io_data_object->amountInGSDML = tmp_io_data_object->amountInGSDML;
                    io_data_object->fParameterIndexNr = tmp_io_data_object->fParameterIndexNr;

                    break;
                }
            }
        }
    }

    return offset;
}


static int
resolve_pa_profile_submodule_name(ioDataObject *io_data_object)
{
    const uint32_t u32SubmoduleIdentNumber = io_data_object->subModuleIdentNr;
    /* split components of submodule ident number */
    const uint8_t variant = (u32SubmoduleIdentNumber >> 24u) & 0xFFu;
    const uint8_t block_object = (u32SubmoduleIdentNumber >> 16u) & 0xFFu;
    const uint8_t parent_class = (u32SubmoduleIdentNumber >> 8u) & 0xFFu;
    const uint8_t class = (u32SubmoduleIdentNumber) & 0xFFu;

    const gchar* parent_class_name = NULL;
    const gchar* class_name        = NULL;

    const gchar* block_object_name = try_val_to_str(block_object, pn_io_pa_profile_block_object_vals);

    if (block_object_name != NULL)
    {
        switch (block_object)
        {
        case PA_PROFILE_BLOCK_DAP:
            if (parent_class == 0u)
            {
                class_name = try_val_to_str(class, pn_io_pa_profile_dap_submodule_vals);
                if (class_name != NULL)
                {
                    (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - %s", block_object_name, class_name);
                }
            }
            else
            {
                /* we have an interface or a port */
                if (class == 0u)
                {
                    (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "Interface %d", parent_class);
                }
                else
                {
                    (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "Port %d Interface %d", class, parent_class);
                }
            }
            break;

        case PA_PROFILE_BLOCK_PB:
            parent_class_name = try_val_to_str(parent_class, pn_io_pa_profile_physical_block_parent_class_vals);
            if (parent_class_name != NULL)
            {
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - %s", block_object_name, parent_class_name);
            }
            else
            {
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - Unknown", block_object_name);
            }
            break;

        case PA_PROFILE_BLOCK_FB:
            class_name = try_val_to_str(class, pn_io_pa_profile_function_block_class_vals);
            if (class <= 2u)
            {
                parent_class_name = try_val_to_str(parent_class, pn_io_pa_profile_function_block_parent_class_vals);
            }
            else
            {
                parent_class_name = (class <= 4u) ? "Analog" : "";
            }

            if ((parent_class_name != NULL) && (class_name != NULL))
            {
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - %s %s", block_object_name, parent_class_name, class_name);
            }
            else
            {
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - Unknown", block_object_name);
            }
            break;

        case PA_PROFILE_BLOCK_TB:
            parent_class_name = try_val_to_str(parent_class, pn_io_pa_profile_transducer_block_parent_class_vals);
            if (parent_class_name != NULL)
            {
                class_name = try_val_to_str(class, pn_io_pa_profile_transducer_block_class_vals[parent_class]);
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - %s (%s)", block_object_name, parent_class_name, class_name);
            }
            else
            {
                (void)snprintf(io_data_object->moduleNameStr, MAX_NAMELENGTH, "%s - Unknown", block_object_name);
            }
            break;
        }

        if (variant != 0u)
        {
            g_strlcat (io_data_object->moduleNameStr, " (VARIANT)", MAX_NAMELENGTH);
        }

        return 1;
    }
    else
    {
        return 0;
    }
}

/* dissect the ExpectedSubmoduleBlockReq */
static int
dissect_ExpectedSubmoduleBlockReq_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16SlotNr;
    guint32     u32ModuleIdentNumber;
    guint16     u16ModuleProperties;
    guint16     u16NumberOfSubmodules;
    guint16     u16SubslotNr;
    guint32     u32SubmoduleIdentNumber;
    guint16     u16SubmoduleProperties;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32     u32ApiStart;
    proto_item *sub_item;
    proto_tree *sub_tree;
    proto_item *submodule_item;
    proto_tree *submodule_tree;
    guint32     u32SubStart;

    /* Variable for the search of gsd file */
    const char vendorIdStr[] = "VendorID=\"";
    const char deviceIdStr[] = "DeviceID=\"";
    const char moduleStr[] = "ModuleIdentNumber=\"";
    const char subModuleStr[] = "SubmoduleIdentNumber=\"";
    const char profisafeStr[] = "PROFIsafeSupported=\"true\"";
    const char fParameterStr[] = "<F_ParameterRecordDataItem";
    const char fParameterIndexStr[] = "Index=";
    const char moduleNameInfo[] = "<Name";
    const char moduleValueInfo[] = "Value=\"";

    guint16  searchVendorID = 0;
    guint16  searchDeviceID = 0;
    gboolean vendorMatch;
    gboolean deviceMatch;
    conversation_t *conversation;
    stationInfo    *station_info = NULL;
    ioDataObject   *io_data_object = NULL; /* Used to transfer data to fct. "dissect_DataDescription()" */

    /* Variable for the search of GSD-file */
    guint32  read_vendor_id;
    guint32  read_device_id;
    guint32  read_module_id;
    guint32  read_submodule_id;
    gboolean gsdmlFoundFlag;
    gchar   tmp_moduletext[MAX_NAMELENGTH];
    gchar   *convertStr;      /* GSD-file search */
    gchar   *pch;             /* helppointer, to save temp. the found Networkpath of GSD-file */
    gchar   *puffer;          /* used for fgets() during GSD-file search */
    gchar   *temp;            /* used for fgets() during GSD-file search */
    gchar   *diropen = NULL;  /* saves the final networkpath to open for GSD-files */
    GDir    *dir;
    FILE    *fp = NULL;       /* filepointer */
    const gchar *filename;    /* saves the found GSD-file name */

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

    /* Helppointer initial */
    convertStr = (gchar*)wmem_alloc(pinfo->pool, MAX_NAMELENGTH);
    convertStr[0] = '\0';
    pch = (gchar*)wmem_alloc(pinfo->pool, MAX_LINE_LENGTH);
    pch[0] = '\0';
    puffer = (gchar*)wmem_alloc(pinfo->pool, MAX_LINE_LENGTH);
    puffer[0] = '\0';
    temp = (gchar*)wmem_alloc(pinfo->pool, MAX_LINE_LENGTH);
    temp[0] = '\0';

    /* Initial */
    io_data_object = wmem_new0(wmem_file_scope(), ioDataObject);
    io_data_object->profisafeSupported = FALSE;
    io_data_object->moduleNameStr = (gchar*)wmem_alloc(wmem_file_scope(), MAX_NAMELENGTH);
    (void) g_strlcpy(io_data_object->moduleNameStr, "Unknown", MAX_NAMELENGTH);
    vendorMatch = FALSE;
    deviceMatch = FALSE;
    gsdmlFoundFlag = FALSE;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);


    /* Get current conversation endpoints using MAC addresses */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
    if (conversation == NULL) {
        /* Create new conversation, if no "Ident OK" frame as been dissected yet!
        * Need to switch dl_src & dl_dst, as current packet is sent by controller and not by device.
        * All conversations are based on Device MAC as addr1 */
        conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
    }

    current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

    if (current_aruuid_frame != NULL) {
        current_aruuid = current_aruuid_frame->aruuid.data1;
    }

    station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

    if (station_info != NULL) {
        pn_find_dcp_station_info(station_info, conversation);

        station_info->gsdFound = FALSE;
        station_info->gsdPathLength = FALSE;

        /* Set searchVendorID and searchDeviceID for GSDfile search */
        searchVendorID = station_info->u16Vendor_id;
        searchDeviceID = station_info->u16Device_id;

        /* Use the given GSD-file networkpath of the PNIO-Preference */
        if(pnio_ps_networkpath[0] != '\0') {   /* check the length of the given networkpath (array overflow protection) */
            station_info->gsdPathLength = TRUE;

            if ((dir = g_dir_open(pnio_ps_networkpath, 0, NULL)) != NULL) {
                /* Find all GSD-files within directory */
                while ((filename = g_dir_read_name(dir)) != NULL) {

                    /* ---- complete the path to open a GSD-file ---- */
                    diropen = wmem_strdup_printf(pinfo->pool, "%s" G_DIR_SEPARATOR_S "%s", pnio_ps_networkpath, filename);

                    /* ---- Open the found GSD-file  ---- */
                    fp = ws_fopen(diropen, "r");

                    if(fp != NULL) {
                        /* ---- Get VendorID & DeviceID ---- */
                        while(pn_fgets(puffer, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL) {
                            /* ----- VendorID ------ */
                            if((strstr(puffer, vendorIdStr)) != NULL) {
                                memset (convertStr, 0, sizeof(*convertStr));
                                pch = strstr(puffer, vendorIdStr);
                                if (pch!= NULL && sscanf(pch, "VendorID=\"%199[^\"]", convertStr) == 1) {
                                    read_vendor_id = (guint32) strtoul (convertStr, NULL, 0);

                                    if(read_vendor_id == searchVendorID) {
                                        vendorMatch = TRUE;        /* found correct VendorID */
                                    }
                                }
                            }

                            /* ----- DeviceID ------ */
                            if((strstr(puffer, deviceIdStr)) != NULL) {
                                memset(convertStr, 0, sizeof(*convertStr));
                                pch = strstr(puffer, deviceIdStr);
                                if (pch != NULL && sscanf(pch, "DeviceID=\"%199[^\"]", convertStr) == 1) {
                                    read_device_id = (guint32)strtoul(convertStr, NULL, 0);

                                    if(read_device_id == searchDeviceID) {
                                        deviceMatch = TRUE;        /* found correct DeviceID */
                                    }
                                }
                            }
                        }

                        fclose(fp);
                        fp = NULL;

                        if(vendorMatch && deviceMatch) {
                            break;        /* Found correct GSD-file! -> Break the searchloop */
                        }
                        else {
                            /* Couldn't find the correct GSD-file to the corresponding device */
                            vendorMatch = FALSE;
                            deviceMatch = FALSE;
                            gsdmlFoundFlag = FALSE;
                            diropen = "";           /* reset array for next search */
                        }
                    }
                }

                g_dir_close(dir);
            }

            /* ---- Found the correct GSD-file -> set Flag and save the completed path ---- */
            if(vendorMatch && deviceMatch) {
                gsdmlFoundFlag = TRUE;
                station_info->gsdFound = TRUE;
                station_info->gsdLocation = wmem_strdup(wmem_file_scope(), diropen);
            }
            else {
                /* Copy searchpath to array for a detailed output message in cyclic data dissection */
                station_info->gsdLocation = wmem_strdup_printf(wmem_file_scope(), "%s" G_DIR_SEPARATOR_S "*.xml", pnio_ps_networkpath);
            }
        }
        else {
            /* will be used later on in cyclic RTC1 data dissection for detailed output message */
            station_info->gsdPathLength = FALSE;
        }
    }

    while (u16NumberOfAPIs--) {
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

        while (u16NumberOfSubmodules--) {
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

            io_data_object->api = u32Api;
            io_data_object->slotNr = u16SlotNr;
            io_data_object->subSlotNr = u16SubslotNr;
            io_data_object->moduleIdentNr = u32ModuleIdentNumber;
            io_data_object->subModuleIdentNr = u32SubmoduleIdentNumber;
            io_data_object->discardIOXS = u16SubmoduleProperties & 0x0020;

            /* Before searching the GSD, check if we have a PA Profile 4.02 submodule. If yes
               then the submodule's name is defined in the specification and can be resolved
               without the GSD.
               We still read the GSD afterwards, in case the user wants to override the specification's
               names with a GSD.
               Most PA Profile submodules are located in API 0x9700, but the DAP and the interfaces/ports
               are located in API 0 per PROFINET specification, so we need to filter also on the DAP module
               ident number.
            */
            if ((io_data_object->api == PA_PROFILE_API) ||
                ((io_data_object->moduleIdentNr & PA_PROFILE_DAP_MASK) == PA_PROFILE_DAP_IDENT))
            {
                resolve_pa_profile_submodule_name(io_data_object);
            }


            /* Search the moduleID and subModuleID, find if PROFIsafe and also search for F-Par. Indexnumber
             * ---------------------------------------------------------------------------------------------
             * Speical case: Module has several ModuleIdentNr. in one GSD-file
             * Also with the given parameters of wireshark, some modules were completely equal. For this
             * special case a compromise for this problem has been made, to set the module name will
             * be more generally displayed.
             * Also this searchloop will find the F-Parameter Indexnumber, so that Wireshark is able to
             * dissect those F-Parameters correctly, as this index can change between the vendors.
             */

            io_data_object->amountInGSDML = 0;
            io_data_object->fParameterIndexNr = 0;
            io_data_object->profisafeSupported = FALSE;

            if (diropen != NULL) {
                fp = ws_fopen(diropen, "r");
            }
            else {
                fp = NULL;
            }
            if(fp != NULL && gsdmlFoundFlag) {
                fseek(fp, 0, SEEK_SET);

                /* Find Indexnumber for fParameter */
                while(pn_fgets(temp, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL) {
                    if((strstr(temp, fParameterStr)) != NULL) {
                        memset (convertStr, 0, sizeof(*convertStr));

                        pch = strstr(temp, fParameterIndexStr);
                        if (pch != NULL && sscanf(pch, "Index=\"%199[^\"]", convertStr) == 1) {
                            io_data_object->fParameterIndexNr = (guint32)strtoul(convertStr, NULL, 0);
                        }
                        break;    /* found Indexnumber -> break search loop */
                    }
                }

                memset (temp, 0, sizeof(*temp));
                fseek(fp, 0, SEEK_SET);                /* Set filepointer to the beginning */

                while(pn_fgets(temp, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL) {
                    if((strstr(temp, moduleStr)) != NULL) {                         /* find the String "ModuleIdentNumber=" */
                        memset (convertStr, 0, sizeof(*convertStr));
                        pch = strstr(temp, moduleStr);                              /* search for "ModuleIdentNumber=\"" within GSD-file */
                        if (pch != NULL && sscanf(pch, "ModuleIdentNumber=\"%199[^\"]", convertStr) == 1) {  /* Change format of Value string-->numeric string */
                            read_module_id = (guint32)strtoul(convertStr, NULL, 0);     /* Change numeric string --> unsigned long; read_module_id contains the Value of the ModuleIdentNumber */

                            /* If the found ModuleID matches with the wanted ModuleID, search for the Submodule and break */
                            if (read_module_id == io_data_object->moduleIdentNr) {
                                ++io_data_object->amountInGSDML;    /* Save the amount of same (!) Module- & SubmoduleIdentNr in one GSD-file */

                                while(pn_fgets(temp, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL) {
                                    if((strstr(temp, moduleNameInfo)) != NULL) {                    /* find the String "<Name" for the TextID */
                                        long filePosRecord;

                                        if (sscanf(temp, "%*s TextId=\"%199[^\"]", tmp_moduletext) != 1)        /* saves the correct TextId for the next searchloop */
                                            break;

                                        filePosRecord = ftell(fp);            /* save the current position of the filepointer (Offset) */
                                        /* ftell() may return -1 for error, don't move fp in this case */
                                        if (filePosRecord >= 0) {
                                            while (pn_fgets(temp, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL && io_data_object->amountInGSDML == 1) {
                                                /* Find a String with the saved TextID and with a fitting value for it in the same line. This value is the name of the Module! */
                                                if(((strstr(temp, tmp_moduletext)) != NULL) && ((strstr(temp, moduleValueInfo)) != NULL)) {
                                                    pch = strstr(temp, moduleValueInfo);
                                                    if (pch != NULL && sscanf(pch, "Value=\"%199[^\"]", io_data_object->moduleNameStr) == 1)
                                                        break;    /* Found the name of the module */
                                                }
                                            }

                                            fseek(fp, filePosRecord, SEEK_SET);    /* set filepointer to the correct TextID */
                                        }
                                    }

                                    /* Search for Submoduleidentnumber in GSD-file */
                                    if((strstr(temp, subModuleStr)) != NULL) {
                                        memset (convertStr, 0, sizeof(*convertStr));
                                        pch = strstr(temp, subModuleStr);
                                        if (pch != NULL && sscanf(pch, "SubmoduleIdentNumber=\"%199[^\"]", convertStr) == 1) {
                                            read_submodule_id = (guint32) strtoul (convertStr, NULL, 0);    /* read_submodule_id contains the Value of the SubModuleIdentNumber */

                                            /* Find "PROFIsafeSupported" flag of the module in GSD-file */
                                            if(read_submodule_id == io_data_object->subModuleIdentNr) {
                                                if((strstr(temp, profisafeStr)) != NULL) {
                                                    io_data_object->profisafeSupported = TRUE;   /* flag is in the same line as SubmoduleIdentNr */
                                                    break;
                                                }
                                                else {    /* flag is not in the same line as Submoduleidentnumber -> search for it */
                                                    while(pn_fgets(temp, MAX_LINE_LENGTH, fp, pinfo->pool) != NULL) {
                                                        if((strstr(temp, profisafeStr)) != NULL) {
                                                            io_data_object->profisafeSupported = TRUE;
                                                            break;    /* Found the PROFIsafeSupported flag of the module */
                                                        }

                                                        else if((strstr(temp, ">")) != NULL) {
                                                            break;
                                                        }
                                                    }
                                                }
                                                break;    /* Found the PROFIsafe Module */
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                fclose(fp);
                fp = NULL;
            }

            if(fp != NULL)
            {
                fclose(fp);
                fp = NULL;
            }

            switch (u16SubmoduleProperties & 0x03) {
            case(0x00): /* no input and no output data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep, io_data_object);
                break;
            case(0x01): /* input data (one Input DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep, io_data_object);
                break;
            case(0x02): /* output data (one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep, io_data_object);
                break;
            case(0x03): /* input and output data (one Input and one Output DataDescription Block follows) */
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep, io_data_object);
                offset = dissect_DataDescription(tvb, offset, pinfo, sub_tree, drep, io_data_object);
                break;
            default: /* will not execute because of the line preceding the switch */
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
    guint16     u16NumberOfAPIs;
    guint32     u32Api;
    guint16     u16NumberOfModules;
    guint16     u16SlotNr;
    guint32     u32ModuleIdentNumber;
    guint16     u16ModuleState;
    guint16     u16NumberOfSubmodules;
    guint16     u16SubslotNr;
    guint32     u32SubmoduleIdentNumber;
    guint16     u16SubmoduleState;
    proto_item *api_item;
    proto_tree *api_tree;
    guint32     u32ApiStart;
    proto_item *module_item;
    proto_tree *module_tree;
    guint32     u32ModuleStart;
    proto_item *sub_item;
    proto_tree *sub_tree;
    proto_item *submodule_item;
    proto_tree *submodule_tree;
    guint32     u32SubStart;

    conversation_t    *conversation;
    stationInfo       *station_info;
    wmem_list_frame_t *frame;
    moduleDiffInfo    *module_diff_info;
    moduleDiffInfo    *cmp_module_diff_info;

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* NumberOfAPIs */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while (u16NumberOfAPIs--) {
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

        while (u16NumberOfModules--) {
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


            if (!PINFO_FD_VISITED(pinfo)) {
                /* Get current conversation endpoints using MAC addresses */
                conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                if (conversation == NULL) {
                    conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                }

                current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

                if (current_aruuid_frame != NULL) {
                    current_aruuid = current_aruuid_frame->aruuid.data1;
                }

                station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

                if (station_info != NULL) {
                    pn_find_dcp_station_info(station_info, conversation);

                    for (frame = wmem_list_head(station_info->diff_module); frame != NULL; frame = wmem_list_frame_next(frame)) {
                        cmp_module_diff_info = (moduleDiffInfo*)wmem_list_frame_data(frame);
                        if (cmp_module_diff_info->slotNr == u16SlotNr) {
                            /* Found identical existing object */
                            break;
                        }
                    }

                    if (frame == NULL) {
                        /* new diffModuleInfo data incoming */
                        module_diff_info = wmem_new(wmem_file_scope(), moduleDiffInfo);
                        module_diff_info->slotNr = u16SlotNr;
                        module_diff_info->modulID = u32ModuleIdentNumber;
                        wmem_list_append(station_info->diff_module, module_diff_info);
                    }
                }
            }

            proto_item_append_text(item, ", Submodules:%u", u16NumberOfSubmodules);

            while (u16NumberOfSubmodules--) {
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
                if (u16SubmoduleState & 0x8000) {
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_ident_info, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_ar_info, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_fault, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_maintenance_demanded, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_maintenance_required, &u16SubmoduleState);
                    dissect_dcerpc_uint16(tvb, offset, pinfo, submodule_tree, drep,
                                    hf_pn_io_submodule_state_advice, &u16SubmoduleState);
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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
    guint32   u32Api;
    guint16   u16SlotNr;
    guint16   u16SubslotNr;
    tvbuff_t *new_tvb;


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
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

    new_tvb = tvb_new_subset_length(tvb, offset, u16BodyLength-10);
    offset = dissect_blocks(new_tvb, 0, pinfo, tree, drep);

    /*offset += u16BodyLength;*/

    return offset;
}

/* dissect Combined Object Container Content block */
static int
dissect_COContainerContent_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow,
    guint16 u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    guint32    u32Api;
    guint16    u16SlotNr;
    guint16    u16SubslotNr;

    if(u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
        hf_pn_io_api, &u32Api);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_slot_nr, &u16SlotNr);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_subslot_nr, &u16SubslotNr);

    offset = dissect_pn_padding(tvb, offset, pinfo, tree, 2);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_index, &u16Index);

    proto_item_append_text(item, ": Api:0x%x Slot:%u Subslot:0x%x Index:0x%x",
        u32Api, u16SlotNr, u16SubslotNr, u16Index);

    if(u16Index != 0x80B0) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, u32RecDataLen, ar);
    }

    return offset;
}


static const gchar *
indexReservedForProfiles(guint16 u16Index)
{
    /* "reserved for profiles" */
    if (u16Index >= 0xb000 && u16Index <= 0xbfff) {
        return "Reserved for Profiles (subslot specific)";
    }
    if (u16Index >= 0xd000 && u16Index <= 0xdfff) {
        return "Reserved for Profiles (slot specific)";
    }
    if (u16Index >= 0xec00 && u16Index <= 0xefff) {
        return "Reserved for Profiles (AR specific)";
    }
    if (u16Index >= 0xf400 && u16Index <= 0xf7ff) {
        return "Reserved for Profiles (API specific)";
    }
    if (u16Index >= 0xfc00 /* up to 0xffff */) {
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


    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    /* user specified format? */
    if (u16Index < 0x8000) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16BodyLength, "User Specified Data");
        return offset;
    }

    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if (userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u16BodyLength, userProfile);
        return offset;
    }

    return dissect_pn_undecoded(tvb, offset, pinfo, tree, u16BodyLength);
}

/* dissect the RS_GetEvent block */
static int
dissect_RS_GetEvent_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
    guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_RS_EventInfo(tvb, offset, pinfo, tree, drep);
    return offset;
}

/* dissect the RS_AdjustControl */
static int
dissect_RS_AdjustControl(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep,
    guint16 *u16RSBodyLength, guint16 *u16RSBlockType)
{
    guint16 u16ChannelNumber;
    guint16 u16SoEMaxScanDelay;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8 u8SoEAdjustSpecifierReserved;
    guint8 u8SoEAdjustSpecifierIndicent;

    switch (*u16RSBlockType) {
    case(0xc010): /* SoE_DigitalInputObserver */

        /* ChannelNumber */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_channel_number, &u16ChannelNumber);

        /* SoE_MaxScanDelay */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
            hf_pn_io_soe_max_scan_delay, &u16SoEMaxScanDelay);

        /* SoE_AdjustSpecifier */
        sub_item = proto_tree_add_item(tree, hf_pn_io_soe_adjust_specifier, tvb, offset, 1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_soe_adjust_specifier);

        dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_soe_adjust_specifier_reserved, &u8SoEAdjustSpecifierReserved);

        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_io_soe_adjust_specifier_incident, &u8SoEAdjustSpecifierIndicent);

        /* Padding 2 + 2 + 1 = 5 */
        /* Therefore we need 3 byte padding to make the block u32 aligned */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 3);
        break;
        default:
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, *u16RSBodyLength, "UserData");
        break;
    }
    return offset;
}

/* dissect the RS_AdjustBlock */
static int
dissect_RS_AdjustBlock(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    guint16 u16RSBodyLength;
    guint16 u16RSBlockType;

    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_adjust_block, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_adjust_block);

    /* RS_BlockHeader */
    offset = dissect_RS_BlockHeader(tvb, offset, pinfo, sub_tree, sub_item, drep,
        &u16RSBodyLength, &u16RSBlockType);

    /* RS_AdjustControl */
    offset = dissect_RS_AdjustControl(tvb, offset, pinfo, sub_tree, drep,
        &u16RSBodyLength, &u16RSBlockType);

    return offset;
}

/* dissect the RS_AdjustInfo */
static int
dissect_RS_AdjustInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16    u16NumberofEntries;

    sub_item = proto_tree_add_item(tree, hf_pn_io_rs_adjust_info, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_rs_adjust_info);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_io_number_of_rs_event_info, &u16NumberofEntries);

    while (u16NumberofEntries > 0) {
        u16NumberofEntries--;
        offset = dissect_RS_AdjustBlock(tvb, offset, pinfo, sub_tree, drep);
    }
    return offset;
}

/* dissect the RS_AdjustObserver block */
static int
dissect_RS_AdjustObserver_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
    guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_RS_AdjustInfo(tvb, offset, pinfo, tree, drep);
    return offset;
}

static int
dissect_RS_AckInfo(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep)
{
    guint16 u16RSSpecifierSequenceNumber;

    /* RS_Specifier.SequenceNumber */
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
        hf_pn_io_rs_specifier_sequence, &u16RSSpecifierSequenceNumber);

    return offset;
}

/* dissect the RS_AckEvent block */
static int
dissect_RS_AckEvent_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep,
    guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_io_block_version,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }
    offset = dissect_RS_AckInfo(tvb, offset, pinfo, tree, drep);
    return offset;
}

/* dissect one PN-IO block (depending on the block type) */
static int
dissect_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen, pnio_ar_t **ar)
{
    guint16     u16BlockType;
    guint16     u16BlockLength;
    guint8      u8BlockVersionHigh;
    guint8      u8BlockVersionLow;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32     u32SubStart;
    guint16     u16BodyLength;
    proto_item *header_item;
    proto_tree *header_tree;
    gint        remainingBytes;

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
    if (remainingBytes < 0)
        remainingBytes = 0;
    if (remainingBytes +2 < u16BodyLength)
    {
        proto_item_append_text(sub_item, " Block_Length: %d greater than remaining Bytes, trying with Blocklen = remaining (%d)", u16BodyLength, remainingBytes);
        u16BodyLength = remainingBytes;
    }
    switch (u16BlockType) {
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
        dissect_ARData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
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
    case(0x0025):
        dissect_IandM5_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh,u8BlockVersionLow);
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
    case(0x0034):
        dissect_IandM5Data_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0035):
        dissect_AssetManagementData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0036):
        dissect_AM_FullInformation_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0037):
        dissect_AM_HardwareOnlyInformation_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0038):
        dissect_AM_FirmwareOnlyInformation_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
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
    case(0x8108):
        dissect_ARVendorBlockReq_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0109):
        dissect_IRInfoBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x010A):
        dissect_SRInfoBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x010C):
        dissect_RSInfoBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0110):
    case(0x0111):
    case(0x0112):
    case(0x0113):
    case(0x0114):
    case(0x0116):
    case(0x0117):
        dissect_ControlPlugOrConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, ar, u16BlockType);
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
        dissect_PDInterfaceMrpDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0212):
        dissect_PDInterfaceMrpDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
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
    case(0x0224):
        dissect_AdjustPeerToPeerBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0225):
        dissect_AdjustDCPBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0226):
        dissect_AdjustPreambleLength_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0227):
        dissect_CheckMAUTypeExtension_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0228):
        dissect_FiberOpticDiagnosisInfo_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0229):
        dissect_AdjustMAUTypeExtension_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x022A):
        dissect_PDIRSubframeData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x022B):
        dissect_PDSubFrameBlock_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x022C):
        dissect_PDPortDataRealExtended_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;

    case(0x0230):
        dissect_PDPortFODataCheck_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0231):
        dissect_MrpInstanceDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
            break;
    case(0x0232):
        dissect_MrpInstanceDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
            break;
    case(0x0233):
        dissect_MrpInstanceDataCheck_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
            break;
    case(0x0240):
        dissect_PDInterfaceDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0241) :
        dissect_PDRsiInstances_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0250):
        dissect_PDInterfaceAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0251):
        dissect_PDPortStatistic_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
	case(0x0260):
        dissect_OwnPort_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0261):
        dissect_Neighbors_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0270):
        dissect_TSNNetworkControlDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0271):
        dissect_TSNNetworkControlDataAdjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0272):
        dissect_TSNDomainPortConfig_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0273):
        dissect_TSNDomainQueueConfig_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0274):
        dissect_TSNTimeData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0275):
        dissect_TSNStreamPathDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, FALSE);
        break;
    case(0x0276):
        dissect_TSNSyncTreeData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0277):
        dissect_TSNUploadNetworkAttributes_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0278):
        dissect_TSNForwardingDelay_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0279):
        dissect_TSNExpectedNetworkAttributes_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x027A):
        dissect_TSNStreamPathDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, TRUE);
	break;
    case(0x027B):
        dissect_TSNDomainPortIngressRateLimiter_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x027C):
        dissect_TSNDomainQueueRateLimiter_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x027D):
        dissect_TSNPortID_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x027E):
        dissect_TSNExpectedNeighbor_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0400):
        dissect_MultipleBlockHeader_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x0401):
        dissect_COContainerContent_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, *u16Index, u32RecDataLen, ar);
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
    case(0x0810):
        dissect_PE_EntityFilterData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0811):
        dissect_PE_EntityStatusData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0900):
        dissect_RS_AdjustObserver_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0901):
        dissect_RS_GetEvent_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0902):
        dissect_RS_AckEvent_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0f00) :
        dissect_Maintenance_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
        break;
    case(0x0f05):
        dissect_PE_Alarm_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow);
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
        dissect_ARServerBlock(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, u16BodyLength);
        break;
    case(0x8110):
    case(0x8111):
    case(0x8112):
    case(0x8113):
    case(0x8114):
    case(0x8116):
    case(0x8117):
    case(0x8118):
        dissect_ControlPlugOrConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionHigh, u8BlockVersionLow, ar, u16BlockType);
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
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;

    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}

/* dissect any number of PN-IO blocks */
int
dissect_blocks(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;


    while (tvb_captured_length(tvb) > (guint) offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        u16Index++;
    }

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}


/* dissect a PN-IO (DCE-RPC) request header */
static int
dissect_IPNIO_rqst_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32     u32ArgsMax;
    guint32     u32ArgsLen;
    guint32     u32MaxCount;
    guint32     u32Offset;
    guint32     u32ArraySize;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32     u32SubStart;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    /* args_max */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                        hf_pn_io_args_max, &u32ArgsMax);
    /* args_len */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_max_count, &u32MaxCount);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_offset, &u32Offset);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_act_count, &u32ArraySize);

    proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u",
        u32MaxCount, u32Offset, u32ArraySize);
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO (DCE-RPC) response header */
static int
dissect_IPNIO_resp_header(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32     u32ArgsLen;
    guint32     u32MaxCount;
    guint32     u32Offset;
    guint32     u32ArraySize;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32     u32SubStart;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    /* args_len */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io);
    u32SubStart = offset;

    /* RPC array header */
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_max_count, &u32MaxCount);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_offset, &u32Offset);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, sub_tree, di, drep,
                        hf_pn_io_array_act_count, &u32ArraySize);

    proto_item_append_text(sub_item, ": Max: %u, Offset: %u, Size: %u",
        u32MaxCount, u32Offset, u32ArraySize);
    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect a PN-IO request */
static int
dissect_IPNIO_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect a PN-IO response */
static int
dissect_IPNIO_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* dissect a PROFIDrive parameter request */
static int
dissect_ProfiDriveParameterRequest(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8      request_reference;
    guint8      request_id;
    guint8      do_id;
    guint8      no_of_parameters;
    guint8      addr_idx;
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

    col_add_fstr(pinfo->cinfo, COL_INFO, "PROFIDrive Write Request, ReqRef:0x%02x, %s DO:%u",
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

            if (no_of_elems>1) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", P%d[%d..%d]", parameter, idx, idx+no_of_elems-1);
            }
            else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", P%d[%d]", parameter, idx);
            }
        }

    /* in case of change request parameter value list */
    if (request_id == 0x02) {
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

            while (no_of_vals--)
            {
                offset = dissect_profidrive_value(tvb, offset, pinfo, sub_tree, drep, format);
            }
        }
    }

    return offset;
}

static int
dissect_ProfiDriveParameterResponse(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint8      request_reference;
    guint8      response_id;
    guint8      do_id;
    guint8      no_of_parameters;
    guint8      addr_idx;
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
    col_add_fstr(pinfo->cinfo, COL_INFO, "PROFIDrive Read Response, ReqRef:0x%02x, RspId:%s",
                           request_reference,
                           val_to_str(response_id, pn_io_profidrive_response_id_vals, "Unknown response"));
    /* in case of  parameter response value list */
    if (response_id == 0x01) {
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

            while (no_of_vals--)
            {
                offset = dissect_profidrive_value(tvb, offset, pinfo, sub_tree, drep, format);
            }
        }
    }

    if(response_id == 0x02){
        // change parameter response ok, no data
    }
    
    if(response_id == 0x81){
         for(addr_idx=0; addr_idx<no_of_parameters; addr_idx++) {
            guint8 format;
            guint8 no_of_vals;
            guint16 value16;
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

            if(format == 0x44){
                
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                   hf_pn_io_profidrive_param_value_error, &value16);    
                if(value16 == 0x23){

                    addr_idx = no_of_parameters;
                }
                while (--no_of_vals)
                {
                    switch(value16)
                    {
                        case 0x1:
                        case 0x2:
                        case 0x3:
                        case 0x6:
                        case 0x7:
                        case 0x14:
                        case 0x20:
                            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                    hf_pn_io_profidrive_param_value_error_sub, &value16);
                            break;
                        default:
                            offset = dissect_profidrive_value(tvb, offset, pinfo, sub_tree, drep, 0x42);
                            break;
                    }
                }
            }else{
                while (no_of_vals--){
                    offset = dissect_profidrive_value(tvb, offset, pinfo, sub_tree, drep, format);
                }
            }
        }
    }
    
    if(response_id == 0x82){

        for(addr_idx=0; addr_idx<no_of_parameters; addr_idx++) {
            guint8 format;
            guint8 no_of_vals;
             guint16 value16;
            proto_item *sub_item;
            proto_tree *sub_tree;

            sub_item = proto_tree_add_item(profidrive_tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_profidrive_parameter_value);
            proto_item_set_text(sub_item, "Parameter Change Result %u: ", addr_idx+1);

            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_profidrive_param_format, &format);
            offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
                                hf_pn_io_profidrive_param_no_of_values, &no_of_vals);

            proto_item_append_text(sub_item, "Format:%s, NoOfVals:%u",
                val_to_str(format, pn_io_profidrive_format_vals, "Unknown"), no_of_vals);

            if(format == 0x44){
                
                offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                   hf_pn_io_profidrive_param_value_error, &value16);    

                if(value16 == 0x23){
                    addr_idx = no_of_parameters;
                }
                
                while (--no_of_vals)
                {
                    switch(value16)
                    {
                        case 0x1:
                        case 0x2:
                        case 0x3:
                        case 0x6:
                        case 0x7:
                        case 0x14:
                        case 0x20:
                            
                            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                                    hf_pn_io_profidrive_param_value_error_sub, &value16);
                            break;
                        default:
                            offset = dissect_profidrive_value(tvb, offset, pinfo, sub_tree, drep, 0x42);
                            break;
                    }

                }

            }
        }
    }
    return offset;
}

static int
dissect_RecordDataRead(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    const gchar *userProfile;
    pnio_ar_t   *ar = NULL;

    /* profidrive parameter access response */
    if (u16Index == 0xb02e || u16Index == 0xb02f || u16Index == 0x002f) {
        return dissect_ProfiDriveParameterResponse(tvb, offset, pinfo, tree, drep);
    }

    /* user specified format? */
    if (u16Index < 0x8000) {
        return dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, "User Specified Data");
    }



    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if (userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, userProfile);
        return offset;
    }

    /* see: pn_io_index */
    /* single block only */
    switch (u16Index) {
    case(0x8010):   /* Maintenance required in channel coding for one subslot */
    case(0x8011):   /* Maintenance demanded in channel coding for one subslot */
    case(0x8012):   /* Maintenance required in all codings for one subslot */
    case(0x8013):   /* Maintenance demanded in all codings for one subslot */
    case(0x801e):   /* SubstituteValues for one subslot */
    case(0x8020):   /* PDIRSubframeData for one subslot */
    case(0x8027):   /* PDPortDataRealExtended for one subslot */
    case(0x8028):   /* RecordInputDataObjectElement for one subslot */
    case(0x8029):   /* RecordOutputDataObjectElement for one subslot */
    case(0x8050):   /* PDInterfaceMrpDataReal for one subslot */
    case(0x8051):   /* PDInterfaceMrpDataCheck for one subslot */
    case(0x8052):   /* PDInterfaceMrpDataAdjust for one subslot */
    case(0x8053):   /* PDPortMrpDataAdjust for one subslot */
    case(0x8054):   /* PDPortMrpDataReal for one subslot */
    case(0x80F0):   /* TSNNetworkControlDataReal */
    case(0x80F2):   /* TSNSyncTreeData */
    case(0x80F3):   /* TSNUploadNetworkAttributes */
    case(0x80F4):   /* TSNExpectedNetworkAttributes */
    case(0x80F5):   /* TSNNetworkControlDataAdjust */
    case(0x8060):   /* PDPortFODataReal for one subslot */
    case(0x8061):   /* PDPortFODataCheck for one subslot */
    case(0x8062):   /* PDPortFODataAdjust for one subslot */
    case(0x8063):   /* PDPortSFPDataCheck for one subslot */
    case(0x8070):   /* PDNCDataCheck for one subslot */
    case(0x8071):   /* PDPortStatistic for one subslot */
    case(0x8080):   /* PDInterfaceDataReal */
    case(0x8090):   /* PDInterfaceFSUDataAdjust */
    case(0x80AF):   /* PE_EntityStatusData for one subslot */
    case(0x80CF):   /* RS_AdjustObserver */

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

    case(0xe030):   /* PE_EntityFilterData for one AR*/
    case(0xe031):   /* PE_EntityStatusData for one AR*/

    case(0xf010):   /* Maintenance required in channel coding for one API */
    case(0xf011):   /* Maintenance demanded in channel coding for one API */
    case(0xf012):   /* Maintenance required in all codings for one API */
    case(0xf013):   /* Maintenance demanded in all codings for one API */
    case(0xf020):   /* ARData for one API */

    case(0xf820):   /* ARData */
    case(0xf821):   /* APIData */
    case(0xf830):   /* LogData */
    case(0xf831):   /* PDevData */
    case(0xf870):   /* PE_EntityFilterData*/
    case(0xf871):   /* PE_EntityStatusData*/
    case(0xf880) : /* AssetManagementData */
    case(0xf8f1):   /* PDRsiInstances */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;

    case(0xf840):   /* I&M0FilterData */
        {
            int end_offset = offset + u32RecDataLen;
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
            if (end_offset > offset)
                offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
            if (end_offset > offset)
                offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        }
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
    case(0x8031):   /* PDTimeData for one subslot */
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
    case(0x8055):   /* PDPortMrpIcDataAdjust for one subslot */
    case(0x8056):   /* PDPortMrpIcDataCheck for one subslot */
    case(0x8057):   /* PDPortMrpIcDataReal for one subslot */
    case(0x8072):   /* PDPortStatistic for one subslot */
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
    case(0xE060):   /* RS_GetEvent (using RecordDataRead service) */
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
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint16    u16Index      = 0;
    guint32    u32RecDataLen = 0;
    pnio_ar_t *ar            = NULL;

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, di, drep);

    /* When PNIOStatus is Error */
    if (!tvb_captured_length_remaining(tvb, offset))
        return offset;

    /* IODReadHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    /* RecordDataRead */
    if (u32RecDataLen != 0) {
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
    }

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}

/* F-Parameter record data object */
static int
dissect_ProfiSafeParameterRequest(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, wmem_list_frame_t *frame)
{
    proto_item *f_item;
    proto_tree *f_tree;
    proto_item *flags1_item;
    proto_tree *flags1_tree;
    proto_item *flags2_item;
    proto_tree *flags2_tree;
    guint16     src_addr;
    guint16     dst_addr;
    guint16     wd_time;
    guint16     par_crc;
    guint32     ipar_crc = 0;
    guint8      prm_flag1;
    guint8      prm_flag1_chck_seq;
    guint8      prm_flag1_chck_ipar;
    guint8      prm_flag1_sil;
    guint8      prm_flag1_crc_len;
    guint8      prm_flag1_crc_seed;
    guint8      prm_flag1_reserved;
    guint8      prm_flag2;
    guint8      prm_flag2_reserved;
    guint8      prm_flag2_f_block_id;
    guint8      prm_flag2_f_par_version;

    conversation_t    *conversation;
    stationInfo       *station_info;
    ioDataObject      *io_data_object;
    wmem_list_frame_t *frame_out;

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

    f_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, ENC_NA);
    f_tree = proto_item_add_subtree(f_item, ett_pn_io_profisafe_f_parameter);
    proto_item_set_text(f_item, "F-Parameter: ");

    flags1_item = proto_tree_add_item(f_tree, hf_pn_io_ps_f_prm_flag1, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags1_tree = proto_item_add_subtree(flags1_item, ett_pn_io_profisafe_f_parameter_prm_flag1);

    /* dissection of F_Prm_Flag1 */
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_chck_seq, &prm_flag1_chck_seq);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_chck_ipar, &prm_flag1_chck_ipar);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_sil, &prm_flag1_sil);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_crc_len, &prm_flag1_crc_len);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_crc_seed, &prm_flag1_crc_seed);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags1_tree, drep,
        hf_pn_io_ps_f_prm_flag1_reserved, &prm_flag1_reserved);
    prm_flag1 = prm_flag1_chck_seq|prm_flag1_chck_ipar|prm_flag1_sil|prm_flag1_crc_len|prm_flag1_crc_seed|prm_flag1_reserved;
    offset++;

    flags2_item = proto_tree_add_item(f_tree, hf_pn_io_ps_f_prm_flag2, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags2_tree = proto_item_add_subtree(flags2_item, ett_pn_io_profisafe_f_parameter_prm_flag2);

    /* dissection of F_Prm_Flag2 */
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_ps_f_prm_flag2_reserved, &prm_flag2_reserved);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_ps_f_prm_flag2_f_block_id, &prm_flag2_f_block_id);
    dissect_dcerpc_uint8(tvb, offset, pinfo, flags2_tree, drep,
        hf_pn_io_ps_f_prm_flag2_f_par_version, &prm_flag2_f_par_version);
    prm_flag2 = prm_flag2_reserved|prm_flag2_f_block_id|prm_flag2_f_par_version;
    offset++;

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_ps_f_src_adr, &src_addr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_ps_f_dest_adr, &dst_addr);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_ps_f_wd_time, &wd_time);

    /* Dissection for F_iPar_CRC: see F_Prm_Flag2 -> F_Block_ID */
    if( (prm_flag2_f_block_id & 0x08) && !(prm_flag2_f_block_id & 0x20) ) {
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, f_item, drep,
                        hf_pn_io_ps_f_ipar_crc, &ipar_crc);
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, f_item, drep,
                    hf_pn_io_ps_f_par_crc, &par_crc);


    /* Differniate between ipar_crc and no_ipar_crc */
    if( (prm_flag2_f_block_id & 0x08) && !(prm_flag2_f_block_id & 0x20) ) {    /* include ipar_crc display */
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        ", F-Parameter record, prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x,"
                         " dst:0x%04x, wd_time:%d, ipar_crc:0x%04x, crc:0x%04x",
                        prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, ipar_crc, par_crc);

        proto_item_append_text(f_item, "prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x, dst:0x%04x, wd_time:%d, ipar_crc:0x%04x, par_crc:0x%04x",
                prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, ipar_crc, par_crc);
    }
    else {    /* exclude ipar_crc display */
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        ", F-Parameter record, prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x,"
                         " dst:0x%04x, wd_time:%d, crc:0x%04x",
                        prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, par_crc);

        proto_item_append_text(f_item, "prm_flag1:0x%02x, prm_flag2:0x%02x, src:0x%04x, dst:0x%04x, wd_time:%d, par_crc:0x%04x",
                prm_flag1, prm_flag2, src_addr, dst_addr, wd_time, par_crc);
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* Get current conversation endpoints using MAC addresses */
        conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
        if (conversation == NULL) {
            /* Create new conversation, if no "Ident OK" frame as been dissected yet!
             * Need to switch dl_src & dl_dst, as current packet is sent by controller and not by device.
             * All conversations are based on Device MAC as addr1 */
            conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
        }

        current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

        if (current_aruuid_frame != NULL) {
            current_aruuid = current_aruuid_frame->aruuid.data1;
        }

        station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

        if (station_info != NULL) {
            pn_find_dcp_station_info(station_info, conversation);

            if (frame != NULL) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame);

                io_data_object->f_par_crc1 = par_crc;
                io_data_object->f_src_adr = src_addr;
                io_data_object->f_dest_adr = dst_addr;
                io_data_object->f_crc_seed = prm_flag1 & 0x40;
                if (!(prm_flag1 & 0x10)) {
                    if (prm_flag1 & 0x20) {
                        io_data_object->f_crc_len = 4;
                    } else {
                        io_data_object->f_crc_len = 3;
                    }
                }
            }

            /* Find same module within output data to saved data */
            for (frame_out = wmem_list_head(station_info->ioobject_data_out); frame_out != NULL; frame_out = wmem_list_frame_next(frame_out)) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame_out);
                if (u16Index == io_data_object->fParameterIndexNr &&    /* Check F-Parameter Indexnumber */
                    io_data_object->profisafeSupported &&               /* Arrayelement has to be PS-Module */
                    io_data_object->f_par_crc1 == 0) {                  /* Find following object with no f_par_crc1 */

                    io_data_object->f_par_crc1 = par_crc;
                    io_data_object->f_src_adr = src_addr;
                    io_data_object->f_dest_adr = dst_addr;
                    io_data_object->f_crc_seed = prm_flag1 & 0x40;
                    if (!(prm_flag1 & 0x10)) {
                        if (prm_flag1 & 0x20) {
                            io_data_object->f_crc_len = 4;
                        } else {
                            io_data_object->f_crc_len = 3;
                        }
                    }

                    break;
                }
            }
        }
    }

    return offset;
}

static int
dissect_RecordDataWrite(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    conversation_t    *conversation;
    stationInfo       *station_info;
    wmem_list_frame_t *frame;
    ioDataObject      *io_data_object;

    const gchar *userProfile;
    pnio_ar_t   *ar = NULL;

    ARUUIDFrame       *current_aruuid_frame = NULL;
    guint32            current_aruuid = 0;

    /* PROFISafe */
    /* Get current conversation endpoints using MAC addresses */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
    if (conversation == NULL) {
        /* Create new conversation, if no "Ident OK" frame as been dissected yet!
        * Need to switch dl_src & dl_dst, as current packet is sent by controller and not by device.
        * All conversations are based on Device MAC as addr1 */
        conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
    }

    current_aruuid_frame = pn_find_aruuid_frame_setup(pinfo);

    if (current_aruuid_frame != NULL) {
        current_aruuid = current_aruuid_frame->aruuid.data1;
    }

    station_info = (stationInfo*)conversation_get_proto_data(conversation, current_aruuid);

    if (station_info != NULL) {
        pn_find_dcp_station_info(station_info, conversation);

        if (!PINFO_FD_VISITED(pinfo)) {
            /* Search within the entire existing list for current input object data */
            for (frame = wmem_list_head(station_info->ioobject_data_in); frame != NULL; frame = wmem_list_frame_next(frame)) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                if (u16Index == io_data_object->fParameterIndexNr &&    /* Check F-Parameter Indexnumber */
                    io_data_object->profisafeSupported &&               /* Arrayelement has to be PS-Module */
                    io_data_object->f_par_crc1 == 0) {                  /* Find following object with no f_par_crc1 */

                    return dissect_ProfiSafeParameterRequest(tvb, offset, pinfo, tree, drep, u16Index, frame);
                }
            }
        }
        else {
            /* User clicked another time the frame to see the data -> PROFIsafe data has already been saved
             * Check whether the device contains an PROFIsafe supported submodule.
             */

            for (frame = wmem_list_head(station_info->ioobject_data_in); frame != NULL; frame = wmem_list_frame_next(frame)) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                if (u16Index == io_data_object->fParameterIndexNr &&    /* Check F-Parameter Indexnumber */
                    io_data_object->profisafeSupported) {               /* Arrayelement has to be PS-Module */

                    return dissect_ProfiSafeParameterRequest(tvb, offset, pinfo, tree, drep, u16Index, frame);
                }
            }

            for (frame = wmem_list_head(station_info->ioobject_data_out); frame != NULL; frame = wmem_list_frame_next(frame)) {
                io_data_object = (ioDataObject*)wmem_list_frame_data(frame);
                if (u16Index == io_data_object->fParameterIndexNr &&    /* Check F-Parameter Indexnumber */
                    io_data_object->profisafeSupported) {               /* Arrayelement has to be PS-Module */

                    return dissect_ProfiSafeParameterRequest(tvb, offset, pinfo, tree, drep, u16Index, frame);
                }
            }
        }
    }
    /* profidrive parameter request */
    if (u16Index == 0xb02e || u16Index == 0xb02f || u16Index == 0x002f) {
        return dissect_ProfiDriveParameterRequest(tvb, offset, pinfo, tree, drep);
    }

    /* user specified format? */
    if (u16Index < 0x8000) {
        return dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, "User Specified Data");
    }



    /* "reserved for profiles"? */
    userProfile = indexReservedForProfiles(u16Index);
    if (userProfile != NULL) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, u32RecDataLen, userProfile);
        return offset;
    }

    /* see: pn_io_index */
    switch (u16Index) {
    case(0x8020):   /* PDIRSubframeData */
    case(0x801e):   /* SubstituteValues for one subslot */
    case(0x802b):   /* PDPortDataCheck for one subslot */
    case(0x802c):   /* PDirData for one subslot */
    case(0x802d):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTA */
    case(0x802e):   /* Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTC */
    case(0x802f):   /* PDPortDataAdjust for one subslot */
    case(0x8030):   /* IsochronousModeData for one subslot */
    case(0x8031):   /* PDTimeData for one subslot */
    case(0x8051):   /* PDInterfaceMrpDataCheck for one subslot */
    case(0x8052):   /* PDInterfaceMrpDataAdjust for one subslot */
    case(0x8053):   /* PDPortMrpDataAdjust for one subslot */
    case(0x8055):   /* PDPortMrpIcDataAdjust for one subslot */
    case(0x8056):   /* PDPortMrpIcDataCheck for one subslot */
    case(0x8061):   /* PDPortFODataCheck for one subslot */
    case(0x8062):   /* PDPortFODataAdjust for one subslot */
    case(0x8063):   /* PDPortSFPDataCheck for one subslot */
    case(0x8070):   /* PDNCDataCheck for one subslot */
    case(0x8071):   /* PDInterfaceAdjust */
    case(0x8090):   /* PDInterfaceFSUDataAdjust */
    case(0x80B0):   /* CombinedObjectContainer*/
    case(0x80CF):   /* RS_AdjustObserver */
    case(0xaff1):   /* I&M1 */
    case(0xaff2):   /* I&M2 */
    case(0xaff3):   /* I&M3 */
    case(0xe050):   /* FastStartUp data for one AR */
    case(0xe061):   /* RS_AckEvent (using RecordDataWrite service) */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, u32RecDataLen);
    }

    return offset;
}

#define PN_IO_MAX_RECURSION_DEPTH 100

static int
dissect_IODWriteReq(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, pnio_ar_t **ar, guint recursion_count)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen = 0;

    if (++recursion_count >= PN_IO_MAX_RECURSION_DEPTH) {
        proto_tree_add_expert(tree, pinfo, &ei_pn_io_max_recursion_depth_reached,
                              tvb, 0, 0);
        return tvb_captured_length(tvb);
    }

    /* IODWriteHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, ar);

    /* IODWriteMultipleReq? */
    if (u16Index == 0xe040) {
        while (tvb_captured_length_remaining(tvb, offset) > 0) {
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, ar, recursion_count++);
        }
    } else {
        tvbuff_t *new_tvb = tvb_new_subset_length(tvb, offset, u32RecDataLen);
        /* RecordDataWrite */
        offset += dissect_RecordDataWrite(new_tvb, 0, pinfo, tree, drep, u16Index, u32RecDataLen);

        /* Padding */
        switch (offset % 4) {
        case(3):
            offset += 1;
            break;
        case(2):
            offset += 2;
            break;
        case(1):
            offset += 3;
            break;
        default: /* will not execute because of the line preceding the switch */
            break;
        }
    }

    return offset;
}

/* dissect a PN-IO write request */
static int
dissect_IPNIO_Write_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    pnio_ar_t *ar = NULL;
    guint recursion_count = 0;

    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, &ar, recursion_count);

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}



static int
dissect_IODWriteRes(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16    u16Index = 0;
    guint32    u32RecDataLen;
    pnio_ar_t *ar       = NULL;


    /* IODWriteResHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);

    /* IODWriteMultipleRes? */
    if (u16Index == 0xe040) {
        while (tvb_captured_length_remaining(tvb, offset) > 0) {
            offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen, &ar);
        }
    }

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}


/* dissect a PN-IO write response */
static int
dissect_IPNIO_Write_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect any number of PN-RSI blocks */
int
dissect_rsi_blocks(tvbuff_t* tvb, int offset,
    packet_info* pinfo, proto_tree* tree, guint8* drep, guint32 u32FOpnumOffsetOpnum, int type)
{
    pnio_ar_t* ar = NULL;
    guint      recursion_count = 0;
    guint16    u16Index = 0;
    guint32    u32RecDataLen = 0;


    switch (u32FOpnumOffsetOpnum) {
    case(0x0): // Connect request or response
        offset = dissect_blocks(tvb, offset, pinfo, tree, drep);
        break;
    case(0x2): // Read request or response
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
        break;
    case(0x3): // Write request or response
        if (type == PDU_TYPE_REQ)
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, &ar, recursion_count);
        else if (type == PDU_TYPE_RSP)
            offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);
        break;
    case(0x4): // Control request or response
        offset = dissect_blocks(tvb, offset, pinfo, tree, drep);
        break;
    case(0x5): // ReadImplicit request or response
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
        break;
    case(0x6): // ReadConnectionless request or response
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
        break;
    case(0x7): // ReadNotification request or response
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
        break;
    case(0x8): // PrmWriteMore request or response
        if (type == PDU_TYPE_REQ)
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, &ar, recursion_count);
        else if (type == PDU_TYPE_RSP)
            offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);
        break;
    case(0x9): // PrmWriteEnd request or response
        if (type == PDU_TYPE_REQ)
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep, &ar, recursion_count);
        else if (type == PDU_TYPE_RSP)
            offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);
        break;
    default:
        col_append_str(pinfo->cinfo, COL_INFO, "Reserved");
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length(tvb));
        break;
    }

    if (ar != NULL) {
        pnio_ar_info(tvb, pinfo, tree, ar);
    }

    return offset;
}


/* dissect the IOxS (IOCS, IOPS) field */
static int
dissect_PNIO_IOxS(tvbuff_t *tvb, int offset,
                  packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_, int hfindex)
{

    if (tree) {
        guint8      u8IOxS;
        proto_item *ioxs_item;
        proto_tree *ioxs_tree;

        u8IOxS = tvb_get_guint8(tvb, offset);

        /* add ioxs subtree */
        ioxs_item = proto_tree_add_uint(tree, hfindex, tvb, offset, 1, u8IOxS);
        proto_item_append_text(ioxs_item,
                               " (%s%s)",
                               (u8IOxS & 0x01) ? "another IOxS follows " : "",
                               (u8IOxS & 0x80) ? "good" : "bad");
        ioxs_tree = proto_item_add_subtree(ioxs_item, ett_pn_io_ioxs);

        proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_datastate, tvb, offset, 1, u8IOxS);
        proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_instance,  tvb, offset, 1, u8IOxS);
        proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_res14,     tvb, offset, 1, u8IOxS);
        proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_extension, tvb, offset, 1, u8IOxS);
    }

    return offset + 1;
}


/* dissect a PN-IO Cyclic Service Data Unit (on top of PN-RT protocol) */
static int
dissect_PNIO_C_SDU(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep _U_)
{
    proto_tree  *data_tree = NULL;
    /* gint iTotalLen    = 0; */
    /* gint iSubFrameLen = 0; */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");

    if (tree) {
        proto_item *data_item;
        data_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_captured_length(tvb),
            "PROFINET IO Cyclic Service Data Unit: %u bytes", tvb_captured_length(tvb));
        data_tree = proto_item_add_subtree(data_item, ett_pn_io_rtc);
    }

    /*dissect_dcerpc_uint16(tvb, offset, pinfo, data_tree, drep, hf_pn_io_packedframe_SFCRC, &u16SFCRC);*/
    if (dissect_CSF_SDU_heur(tvb, pinfo, data_tree, NULL))
        return(tvb_captured_length(tvb));

    /* XXX - dissect the remaining data */
    /* this will be one or more DataItems followed by an optional GAP and RTCPadding */
    /* as we don't have the required context information to dissect the specific DataItems, */
    /* this will be tricky :-( */
    /* actual: there may be an IOxS but most case there isn't so better display a data-stream */
    /* offset = dissect_PNIO_IOxS(tvb, offset, pinfo, data_tree, drep, hf_pn_io_ioxs);        */
    offset = dissect_pn_user_data(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset),
        "User Data (including GAP and RTCPadding)");

    return offset;
}


/* dissect a PN-IO RTA PDU (on top of PN-RT protocol) */
static int
dissect_PNIO_RTA(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16     u16AlarmDstEndpoint;
    guint16     u16AlarmSrcEndpoint;
    guint8      u8PDUType;
    guint8      u8PDUVersion;
    guint8      u8WindowSize;
    guint8      u8Tack;
    guint16     u16SendSeqNum;
    guint16     u16AckSeqNum;
    guint16     u16VarPartLen;
    int         start_offset = offset;
    guint16     u16Index     = 0;
    guint32     u32RecDataLen;
    pnio_ar_t  *ar           = NULL;


    proto_item *rta_item;
    proto_tree *rta_tree;

    proto_item *sub_item;
    proto_tree *sub_tree;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-AL");

    rta_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_captured_length(tvb),
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

    switch ( u8PDUType & 0x0F) {
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
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length(tvb));
    }

    proto_item_set_len(rta_item, offset - start_offset);

    return offset;
}


/* possibly dissect a PN-IO related PN-RT packet */
static gboolean
dissect_PNIO_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data)
{
    guint8   drep_data = 0;
    guint8  *drep      = &drep_data;
    /* the sub tvb will NOT contain the frame_id here! */
    guint16  u16FrameID = GPOINTER_TO_UINT(data);
    heur_dtbl_entry_t *hdtbl_entry;
    conversation_t* conversation;
    guint8 isTimeAware = FALSE;

    /*
     * In case the packet is a protocol encoded in the basic PNIO transport stream,
     * give that protocol a chance to make a heuristic dissection, before we continue
     * to dissect it as a normal PNIO packet.
     */
    if (dissector_try_heuristic(heur_pn_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL))
        return TRUE;

    /* TimeAwareness Information needed for dissecting RTC3 - RTSteam frames  */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);

    if (conversation != NULL) {
        isTimeAware = GPOINTER_TO_UINT(conversation_get_proto_data(conversation, proto_pn_io_time_aware_status));
    }

    /* is this a (none DFP) PNIO class 3 data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=3) */
    if (((u16FrameID >= 0x0100 && u16FrameID <= 0x06FF) || /* RTC3 non redundant */
        (u16FrameID >= 0x0700 && u16FrameID <= 0x0fff)) && /* RTC3 redundant */
        !isTimeAware) {
        dissect_CSF_SDU_heur(tvb, pinfo, tree, data);
        return TRUE;
    }

    /* is this a PNIO class stream data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=Stream) */
    if (((u16FrameID >= 0x1000 && u16FrameID <= 0x2FFF) ||
        (u16FrameID >= 0x3800 && u16FrameID <= 0x3FFF)) &&
        isTimeAware) {
        dissect_CSF_SDU_heur(tvb, pinfo, tree, data);
        return TRUE;
    }

    /* The following range is reserved for following developments */
    /* frame id must be in valid range (Reserved) and
     * first byte (CBA version field) has to be != 0x11 */
    if (u16FrameID >= 0x4000 && u16FrameID <= 0x7fff) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO class 1 data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=1) and
     * first byte (CBA version field) has to be != 0x11 */
    if (u16FrameID >= 0x8000 && u16FrameID < 0xbfff) {
        dissect_PNIO_C_SDU_RTC1(tvb, 0, pinfo, tree, drep, u16FrameID);
        return TRUE;
    }

    /* is this a PNIO class 1 (legacy) data packet? */
    /* frame id must be in valid range (cyclic Real-Time, class=1, legacy) and
     * first byte (CBA version field) has to be != 0x11 */
    if (u16FrameID >= 0xc000 && u16FrameID < 0xfbff) {
        dissect_PNIO_C_SDU_RTC1(tvb, 0, pinfo, tree, drep, u16FrameID);
        return TRUE;
    }

    /* is this a PNIO high priority alarm packet? */
    if (u16FrameID == 0xfc01) {
        col_set_str(pinfo->cinfo, COL_INFO, "Alarm High");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO low priority alarm packet? */
    if (u16FrameID == 0xfe01) {
        col_set_str(pinfo->cinfo, COL_INFO, "Alarm Low");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a Remote Service Interface (RSI) packet*/
    if (u16FrameID == 0xfe02) {
        dissect_PNIO_RSI(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* this PN-RT packet doesn't seem to be PNIO specific */
    return FALSE;
}



static gboolean
pn_io_ar_conv_valid(packet_info *pinfo)
{
    void* profinet_type = p_get_proto_data(pinfo->pool, pinfo, proto_pn_io, 0);

    return ((profinet_type != NULL) && (GPOINTER_TO_UINT(profinet_type) == 10));
}

static gchar *
pn_io_ar_conv_filter(packet_info *pinfo)
{
    pnio_ar_t *ar = (pnio_ar_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pn_io, 0);
    void* profinet_type = p_get_proto_data(pinfo->pool, pinfo, proto_pn_io, 0);
    char      *buf;
    address   controllermac_addr, devicemac_addr;

    if ((profinet_type == NULL) || (GPOINTER_TO_UINT(profinet_type) != 10) || (ar == NULL)) {
        return NULL;
    }

    set_address(&controllermac_addr, AT_ETHER, 6, ar->controllermac);
    set_address(&devicemac_addr, AT_ETHER, 6, ar->devicemac);

    buf = ws_strdup_printf(
        "pn_io.ar_uuid == %s || "                                   /* ARUUID */
        "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "   /* Alarm CR (contr -> dev) */
        "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",      /* Alarm CR (dev -> contr) */
         guid_to_str(pinfo->pool, (const e_guid_t*) &ar->aruuid),
        ar->controlleralarmref, address_to_str(pinfo->pool, &controllermac_addr),
        ar->devicealarmref, address_to_str(pinfo->pool, &devicemac_addr));
    return buf;
}

static gchar *
pn_io_ar_conv_data_filter(packet_info *pinfo)
{
    pnio_ar_t *ar = (pnio_ar_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pn_io, 0);
    void* profinet_type = p_get_proto_data(pinfo->pool, pinfo, proto_pn_io, 0);
    char      *buf, *controllermac_str, *devicemac_str, *guid_str;
    address   controllermac_addr, devicemac_addr;

    if ((profinet_type == NULL) || (GPOINTER_TO_UINT(profinet_type) != 10) || (ar == NULL)) {
        return NULL;
    }

    set_address(&controllermac_addr, AT_ETHER, 6, ar->controllermac);
    set_address(&devicemac_addr, AT_ETHER, 6, ar->devicemac);

    controllermac_str = address_to_str(pinfo->pool, &controllermac_addr);
    devicemac_str = address_to_str(pinfo->pool, &devicemac_addr);
    guid_str = guid_to_str(pinfo->pool, (const e_guid_t*) &ar->aruuid);
    if (ar->arType == 0x0010) /* IOCARSingle using RT_CLASS_3 */
    {
        buf = ws_strdup_printf(
            "pn_io.ar_uuid == %s || "                                           /* ARUUID */
            "(pn_rt.frame_id == 0x%x) || (pn_rt.frame_id == 0x%x) || "
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "           /* Alarm CR (contr -> dev) */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",              /* Alarm CR (dev -> contr) */
            guid_str,
            ar->inputframeid, ar->outputframeid,
            ar->controlleralarmref, controllermac_str,
            ar->devicealarmref, devicemac_str);
    }
    else
    {
        buf = ws_strdup_printf(
            "pn_io.ar_uuid == %s || "                                           /* ARUUID */
            "(pn_rt.frame_id == 0x%x && eth.src == %s && eth.dst == %s) || "    /* Input CR && dev MAC -> contr MAC */
            "(pn_rt.frame_id == 0x%x && eth.src == %s && eth.dst == %s) || "    /* Output CR && contr MAC -> dev MAC */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s) || "           /* Alarm CR (contr -> dev) */
            "(pn_io.alarm_src_endpoint == 0x%x && eth.src == %s)",              /* Alarm CR (dev -> contr) */
            guid_str,
            ar->inputframeid, devicemac_str, controllermac_str,
            ar->outputframeid, controllermac_str, devicemac_str,
            ar->controlleralarmref, controllermac_str,
            ar->devicealarmref, devicemac_str);
    }
    return buf;
}



/* the PNIO dcerpc interface table */
static dcerpc_sub_dissector pn_io_dissectors[] = {
    { 0, "Connect",       dissect_IPNIO_rqst,       dissect_IPNIO_resp },
    { 1, "Release",       dissect_IPNIO_rqst,       dissect_IPNIO_resp },
    { 2, "Read",          dissect_IPNIO_rqst,       dissect_IPNIO_Read_resp },
    { 3, "Write",         dissect_IPNIO_Write_rqst, dissect_IPNIO_Write_resp },
    { 4, "Control",       dissect_IPNIO_rqst,       dissect_IPNIO_resp },
    { 5, "Read Implicit", dissect_IPNIO_rqst,       dissect_IPNIO_Read_resp },
    { 0, NULL, NULL, NULL }
};


static void
pnio_cleanup(void) {
    g_list_free(pnio_ars);
    pnio_ars = NULL;
}


static void
pnio_setup(void) {
    aruuid_frame_setup_list = wmem_list_new(wmem_file_scope());
    pnio_time_aware_frame_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
}


void
proto_register_pn_io (void)
{
    static hf_register_info hf[] = {
    { &hf_pn_io_opnum,
      { "Operation", "pn_io.opnum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_reserved16,
      { "Reserved", "pn_io.reserved16",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_array,
      { "Array", "pn_io.array",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_args_max,
      { "ArgsMaximum", "pn_io.args_max",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_args_len,
      { "ArgsLength", "pn_io.args_len",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_array_max_count,
      { "MaximumCount", "pn_io.array_max_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_array_offset,
      { "Offset", "pn_io.array_offset",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_array_act_count,
      { "ActualCount", "pn_io.array_act_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_ar_data,
      { "ARDATA for AR:", "pn_io.ar_data",
        FT_NONE, BASE_NONE, 0x0, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_type,
      { "ARType", "pn_io.ar_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_ar_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cminitiator_macadd,
      { "CMInitiatorMacAdd", "pn_io.cminitiator_mac_add",
        FT_ETHER, BASE_NONE, 0x0, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cminitiator_objectuuid,
      { "CMInitiatorObjectUUID", "pn_io.cminitiator_uuid",
        FT_GUID, BASE_NONE, 0x0, 0x0,
        NULL, HFILL }
    },
        { &hf_pn_io_parameter_server_objectuuid,
          { "ParameterServerObjectUUID", "pn_io.parameter_server_objectuuid",
            FT_GUID, BASE_NONE, 0x0, 0x0,
            NULL, HFILL }
        },
    { &hf_pn_io_ar_properties,
      { "ARProperties", "pn_io.ar_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_state,
      { "State", "pn_io.ar_properties.state",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_state), 0x00000007,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_supervisor_takeover_allowed,
      { "SupervisorTakeoverAllowed", "pn_io.ar_properties.supervisor_takeover_allowed",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_supervisor_takeover_allowed), 0x00000008,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_parameterization_server,
      { "ParameterizationServer", "pn_io.ar_properties.parameterization_server",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_parameterization_server), 0x00000010,
        NULL, HFILL }
    },
    { &hf_pn_io_artype_req,
        { "ARType", "pn_io.artype_req",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
    { &hf_pn_io_ar_properties_companion_ar,
      { "CompanionAR", "pn_io.ar_properties.companion_ar",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_companion_ar), 0x00000600,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_achnowledge_companion_ar,
      { "AcknowledgeCompanionAR", "pn_io.ar_properties.acknowledge_companion_ar",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_acknowldege_companion_ar), 0x00000800,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_reserved,
      { "Reserved", "pn_io.ar_properties.reserved",
        FT_UINT32, BASE_HEX, NULL, 0x0FFFF000,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_time_aware_system,
      { "TimeAwareSystem", "pn_io.ar_properties.time_aware_system",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_time_aware_system), 0x10000000,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_combined_object_container_with_legacy_startupmode,
      { "CombinedObjectContainer", "pn_io.ar_properties.combined_object_container",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_combined_object_container_with_legacy_startupmode), 0x20000000,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_combined_object_container_with_advanced_startupmode,
    { "CombinedObjectContainer", "pn_io.ar_properties.combined_object_container",
       FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_combined_object_container_with_advanced_startupmode), 0x20000000,
       NULL, HFILL }
    },
    { &hf_pn_io_arproperties_StartupMode,
      { "StartupMode", "pn_io.ar_properties.StartupMode",
        FT_UINT32, BASE_HEX, VALS(pn_io_arpropertiesStartupMode), 0x40000000,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_pull_module_alarm_allowed,
      { "PullModuleAlarmAllowed", "pn_io.ar_properties.pull_module_alarm_allowed",
        FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_pull_module_alarm_allowed), 0x80000000,
        NULL, HFILL }
    },
    { &hf_pn_RedundancyInfo,
      { "RedundancyInfo.EndPoint", "pn_io.srl_data.redundancyInfo",
        FT_UINT16, BASE_HEX, VALS(pn_io_RedundancyInfo), 0x0003,
        NULL, HFILL }
    },
    { &hf_pn_RedundancyInfo_reserved,
      { "RedundancyInfo.reserved", "pn_io.srl_data.redundancyInfoReserved",
        FT_UINT16, BASE_HEX, NULL, 0xFFFFFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_ARDATAInfo,
      { "ARDataInfo.NumberOfEntries", "pn_io.number_of_ARDATAInfo",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_cminitiator_activitytimeoutfactor,
      { "CMInitiatorActivityTimeoutFactor", "pn_io.cminitiator_activitytimeoutfactor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_cminitiator_udprtport,
      { "CMInitiatorUDPRTPort", "pn_io.cminitiator_udprtport",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_station_name_length,
      { "StationNameLength", "pn_io.station_name_length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cminitiator_station_name,
      { "CMInitiatorStationName", "pn_io.cminitiator_station_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_parameter_server_station_name,
      { "ParameterServerStationName", "pn_io.parameter_server_station_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cmresponder_macadd,
      { "CMResponderMacAdd", "pn_io.cmresponder_macadd",
        FT_ETHER, BASE_NONE, 0x0, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cmresponder_udprtport,
      { "CMResponderUDPRTPort", "pn_io.cmresponder_udprtport",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_number_of_iocrs,
      { "NumberOfIOCRs", "pn_io.number_of_iocrs",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_tree,
      { "IOCR", "pn_io.iocr_tree",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_type,
      { "IOCRType", "pn_io.iocr_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_iocr_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_reference,
      { "IOCRReference", "pn_io.iocr_reference",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_SubframeOffset,
      { "-> SubframeOffset", "pn_io.subframe_offset",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_SubframeData,
      { "SubframeData", "pn_io.subframe_data",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_RedundancyDataHoldFactor,
      { "RedundancyDataHoldFactor", "pn_io.RedundancyDataHoldFactor",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_RedundancyDataHoldFactor), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties,
      { "SRProperties", "pn_io.sr_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_0,
      { "InputValidOnBackupAR", "pn_io.sr_properties.InputValidOnBackupAR",
        FT_BOOLEAN, 32, TFS(&tfs_pn_io_sr_properties_BackupAR_with_SRProperties_Mode_0), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_InputValidOnBackupAR_with_SRProperties_Mode_1,
      { "InputValidOnBackupAR", "pn_io.sr_properties.InputValidOnBackupAR",
        FT_BOOLEAN, 32, TFS(&tfs_pn_io_sr_properties_BackupAR_with_SRProperties_Mode_1), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_Reserved_1,
      { "Reserved_1", "pn_io.sr_properties.Reserved_1",
        FT_BOOLEAN, 32, TFS(&tfs_pn_io_sr_properties_Reserved1), 0x00000002,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_Mode,
      { "Mode", "pn_io.sr_properties.Mode",
        FT_BOOLEAN, 32, TFS(&tfs_pn_io_sr_properties_Mode), 0x00000004,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_Reserved_2,
      { "Reserved_2", "pn_io.sr_properties.Reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0x0000FFF8,
        NULL, HFILL }
    },
    { &hf_pn_io_sr_properties_Reserved_3,
      { "Reserved_3", "pn_io.sr_properties.Reserved_3",
        FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_arvendor_strucidentifier_if0_low,
      { "APStructureIdentifier: Vendor specific", "pn_io.structidentifier_api_0_low",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_arvendor_strucidentifier_if0_high,
      { "APStructureIdentifier: Administrative number for common profiles", "pn_io.structidentifier_api_0_high",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_arvendor_strucidentifier_if0_is8000,
      { "APStructureIdentifier: Extended identification rules", "pn_io.tructidentifier_api_0_is8000",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_arvendor_strucidentifier_not0,
    { "APStructureIdentifier: Administrative number for application profiles", "pn_io.tructidentifier_api_not_0",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_lt,
      { "LT", "pn_io.lt",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties,
      { "IOCRProperties", "pn_io.iocr_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_rtclass,
      { "RTClass", "pn_io.iocr_properties.rtclass",
        FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_rtclass), 0x0000000F,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_reserved_1,
      { "Reserved1", "pn_io.iocr_properties.reserved1",
        FT_UINT32, BASE_HEX, NULL, 0x00000FF0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_media_redundancy,
      { "MediaRedundancy", "pn_io.iocr_properties.media_redundancy",
        FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_media_redundancy), 0x00000800,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_reserved_2,
      { "Reserved2", "pn_io.iocr_properties.reserved2",
        FT_UINT32, BASE_HEX, NULL, 0x00FFF000,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_reserved_3,
      { "Reserved3", "pn_io.iocr_properties.reserved3",
        FT_UINT32, BASE_HEX, NULL, 0xF000000,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_fast_forwarding_mac_adr,
      { "FastForwardingMACAdr", "pn_io.iocr_properties.fast_forwarding_mac_adr",
        FT_UINT32, BASE_HEX, NULL, 0x20000000,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_distributed_subframe_watchdog,
      { "DistributedSubFrameWatchDog", "pn_io.iocr_properties.distributed_subframe_watchdog",
        FT_UINT32, BASE_HEX, NULL, 0x40000000,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_properties_full_subframe_structure,
      { "FullSubFrameStructure", "pn_io.iocr_properties.full_subframe_structure",
        FT_UINT32, BASE_HEX, NULL, 0x80000000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties,
      { "SFIOCRProperties", "pn_io.SFIOCRProperties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_DistributedWatchDogFactor,
      { "SFIOCRProperties.DistributedWatchDogFactor", "pn_io.SFIOCRProperties.DistributedWatchDogFactor",
        FT_UINT32, BASE_HEX, NULL, 0x0FF,
        NULL, HFILL }
    },
    { &hf_pn_io_RestartFactorForDistributedWD,
      { "SFIOCRProperties.RestartFactorForDistributedWD", "pn_io.SFIOCRProperties.RestartFactorForDistributedWD",
        FT_UINT32, BASE_HEX, NULL, 0xff00,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_DFPmode,
      { "SFIOCRProperties.DFPmode", "pn_io.SFIOCRProperties.DFPmode",
        FT_UINT32, BASE_HEX, NULL, 0xFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_reserved_1,
      { "SFIOCRProperties.reserved_1", "pn_io.SFIOCRProperties.reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0x0F000000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_reserved_2,
      { "SFIOCRProperties.reserved_2", "pn_io.SFIOCRProperties.reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0x10000000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_DFPType,
      { "SFIOCRProperties.DFPType", "pn_io.SFIOCRProperties.DFPType",
        FT_UINT32, BASE_HEX,  VALS(pn_io_SFIOCRProperties_DFPType_vals), 0x20000000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_DFPRedundantPathLayout,
      { "SFIOCRProperties.DFPRedundantPathLayout", "pn_io.SFIOCRProperties.DFPRedundantPathLayout",
        FT_UINT32, BASE_HEX, VALS(pn_io_DFPRedundantPathLayout_decode), 0x40000000,
        NULL, HFILL }
    },
    { &hf_pn_io_SFIOCRProperties_SFCRC16,
      { "SFIOCRProperties.SFCRC16", "pn_io.SFIOCRProperties.SFCRC16",
        FT_UINT32, BASE_HEX, VALS(pn_io_SFCRC16_Decode), 0x80000000,
        NULL, HFILL }
    },
    { &hf_pn_io_data_length,
      { "DataLength", "pn_io.data_length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ir_frame_data,
      { "Frame data", "pn_io.ir_frame_data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_id,
      { "FrameID", "pn_io.frame_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_send_clock_factor,
      { "SendClockFactor", "pn_io.send_clock_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    }, /* XXX - special values */
    { &hf_pn_io_reduction_ratio,
      { "ReductionRatio", "pn_io.reduction_ratio",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    }, /* XXX - special values */
    { &hf_pn_io_phase,
      { "Phase", "pn_io.phase",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sequence,
      { "Sequence", "pn_io.sequence",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_send_offset,
      { "FrameSendOffset", "pn_io.frame_send_offset",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties,
      { "FrameDataProperties", "pn_io.frame_data_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties_forwarding_Mode,
      { "ForwardingMode", "pn_io.frame_data_properties_forwardingMode",
        FT_UINT32, BASE_HEX, VALS(hf_pn_io_frame_data_properties_forwardingMode), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties_FastForwardingMulticastMACAdd,
      { "FastForwardingMulticastMACAdd", "pn_io.frame_data_properties_MulticastMACAdd",
        FT_UINT32, BASE_HEX, VALS(hf_pn_io_frame_data_properties_FFMulticastMACAdd), 0x06,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties_FragmentMode,
      { "FragmentationMode", "pn_io.frame_data_properties_FragMode",
        FT_UINT32, BASE_HEX, VALS(hf_pn_io_frame_data_properties_FragMode), 0x18,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties_reserved_1,
      { "Reserved_1", "pn_io.frame_data.reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0x0000FFE0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_data_properties_reserved_2,
      { "Reserved_2", "pn_io.frame_data.reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_watchdog_factor,
      { "WatchdogFactor", "pn_io.watchdog_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_data_hold_factor,
      { "DataHoldFactor", "pn_io.data_hold_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_tag_header,
      { "IOCRTagHeader", "pn_io.iocr_tag_header",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocr_multicast_mac_add,
      { "IOCRMulticastMACAdd", "pn_io.iocr_multicast_mac_add",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_apis,
      { "NumberOfAPIs", "pn_io.number_of_apis",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_io_data_objects,
      { "NumberOfIODataObjects", "pn_io.number_of_io_data_objects",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_iocs,
      { "NumberOfIOCS", "pn_io.number_of_iocs",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iocs_frame_offset,
      { "IOCSFrameOffset", "pn_io.iocs_frame_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarmcr_type,
      { "AlarmCRType", "pn_io.alarmcr_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_alarmcr_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarmcr_properties,
      { "AlarmCRProperties", "pn_io.alarmcr_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarmcr_properties_priority,
      { "priority", "pn_io.alarmcr_properties.priority",
        FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_priority), 0x00000001,
        NULL, HFILL }
    },
    { &hf_pn_io_alarmcr_properties_transport,
      { "Transport", "pn_io.alarmcr_properties.transport",
        FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_transport), 0x00000002,
        NULL, HFILL }
    },
    { &hf_pn_io_alarmcr_properties_reserved,
      { "Reserved", "pn_io.alarmcr_properties.reserved",
        FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_rta_timeoutfactor,
      { "RTATimeoutFactor", "pn_io.rta_timeoutfactor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_rta_retries,
      { "RTARetries", "pn_io.rta_retries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - only values 3 - 15 allowed */
    { &hf_pn_io_localalarmref,
      { "LocalAlarmReference", "pn_io.localalarmref",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_remotealarmref,
      { "RemoteAlarmReference", "pn_io.remotealarmref",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - special values */
    { &hf_pn_io_maxalarmdatalength,
      { "MaxAlarmDataLength", "pn_io.maxalarmdatalength",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - only values 200 - 1432 allowed */
    { &hf_pn_io_alarmcr_tagheaderhigh,
      { "AlarmCRTagHeaderHigh", "pn_io.alarmcr_tagheaderhigh",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - 16 bitfield! */
    { &hf_pn_io_alarmcr_tagheaderlow,
      { "AlarmCRTagHeaderLow", "pn_io.alarmcr_tagheaderlow",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },  /* XXX - 16 bitfield!*/
    { &hf_pn_io_api_tree,
      { "API", "pn_io.api_tree",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_module_tree,
      { "Module", "pn_io.module_tree",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_tree,
      { "Submodule", "pn_io.submodule_tree",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_io_data_object,
      { "IODataObject", "pn_io.io_data_object",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_io_data_object_frame_offset,
        { "IODataObjectFrameOffset", "pn_io.io_data_object.frame_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_io_cs,
      { "IOCS", "pn_io.io_cs",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_substitutionmode,
      { "Substitutionmode", "pn_io.substitutionmode",
        FT_UINT16, BASE_HEX, VALS(pn_io_substitutionmode), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_IRData_uuid,
      { "IRDataUUID", "pn_io.IRData_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_uuid,
      { "ARUUID", "pn_io.ar_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_target_ar_uuid,
      { "TargetARUUID", "pn_io.target_ar_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_discriminator,
      { "Discriminator", "pn_io.ar_discriminator",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_configid,
      { "ConfigID", "pn_io.ar_configid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_arnumber,
      { "ARnumber", "pn_io.ar_arnumber",
        FT_UINT16, BASE_HEX, VALS(pn_io_ar_arnumber), 0x0007,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_arresource,
      { "ARresource", "pn_io.ar_arresource",
        FT_UINT16, BASE_HEX, VALS(pn_io_ar_arresource), 0x0018,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_arreserved,
      { "ARreserved", "pn_io.ar_arreserved",
        FT_UINT16, BASE_HEX, NULL, 0xFFE0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_selector,
      { "Selector", "pn_io.ar_selector",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_api,
      { "API", "pn_io.api",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_slot_nr,
      { "SlotNumber", "pn_io.slot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_subslot_nr,
      { "SubslotNumber", "pn_io.subslot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_index,
      { "Index", "pn_io.index",
        FT_UINT16, BASE_HEX, VALS(pn_io_index), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_seq_number,
      { "SeqNumber", "pn_io.seq_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_record_data_length,
      { "RecordDataLength", "pn_io.record_data_length",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_add_val1,
      { "AdditionalValue1", "pn_io.add_val1",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_add_val2,
      { "AdditionalValue2", "pn_io.add_val2",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block_header,
      { "BlockHeader", "pn_io.block_header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block_type,
      { "BlockType", "pn_io.block_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_block_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block_length,
      { "BlockLength", "pn_io.block_length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block_version_high,
      { "BlockVersionHigh", "pn_io.block_version_high",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block_version_low,
      { "BlockVersionLow", "pn_io.block_version_low",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sessionkey,
      { "SessionKey", "pn_io.session_key",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_alarm_sequence_number,
      { "AlarmSequenceNumber", "pn_io.control_alarm_sequence_number",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command,
      { "ControlCommand", "pn_io.control_command",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_reserved,
      { "ControlBlockProperties.reserved", "pn_io.control_properties_reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_prmend,
      { "PrmEnd", "pn_io.control_command.prmend",
        FT_UINT16, BASE_DEC, NULL, 0x0001,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_applready,
      { "ApplicationReady", "pn_io.control_command.applready",
        FT_UINT16, BASE_DEC, NULL, 0x0002,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_release,
      { "Release", "pn_io.control_command.release",
        FT_UINT16, BASE_DEC, NULL, 0x0004,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_done,
      { "Done", "pn_io.control_command.done",
        FT_UINT16, BASE_DEC, NULL, 0x0008,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_ready_for_companion,
      { "ReadyForCompanion", "pn_io.control_command.ready_for_companion",
        FT_UINT16, BASE_DEC, NULL, 0x0010,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_ready_for_rt_class3,
      { "ReadyForRT Class 3", "pn_io.control_command.ready_for_rt_class3",
        FT_UINT16, BASE_DEC, NULL, 0x0020,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_prmbegin,
      { "PrmBegin", "pn_io.control_command.prmbegin",
        FT_UINT16, BASE_DEC, VALS(pn_io_control_properties_prmbegin_vals), 0x0040,
        NULL, HFILL }
    },
    { &hf_pn_io_control_command_reserved_7_15,
      { "ControlBlockProperties.reserved", "pn_io.control_properties_reserved_7_15",
        FT_UINT16, BASE_HEX, NULL, 0x0FF80,
        NULL, HFILL }
    },
    { &hf_pn_io_control_block_properties,
      { "ControlBlockProperties", "pn_io.control_block_properties",
        FT_UINT16, BASE_HEX, VALS(pn_io_control_properties_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_block_properties_applready,
      { "ControlBlockProperties", "pn_io.control_block_properties.appl_ready",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_control_block_properties_applready_bit0,
      { "ApplicationReady.Bit0", "pn_io.control_block_properties.appl_ready_bit0",
        FT_UINT16, BASE_HEX, VALS(pn_io_control_properties_application_ready_bit0_vals), 0x0001,
        NULL, HFILL }
    },
    { &hf_pn_io_control_block_properties_applready_bit1,
      { "ApplicationReady.Bit1", "pn_io.control_block_properties.appl_ready_bit1",
      FT_UINT16, BASE_HEX, VALS(pn_io_control_properties_application_ready_bit1_vals), 0x0002,
    NULL, HFILL }
    },
    { &hf_pn_io_control_block_properties_applready_otherbits,
      { "ApplicationReady.Bit2-15(reserved)", "pn_io.control_block_properties.appl_ready_otherbits",
      FT_UINT16, BASE_HEX, NULL, 0xFFFC,
    NULL, HFILL }
    },
    { &hf_pn_io_SubmoduleListEntries,
      { "NumberOfEntries", "pn_io.SubmoduleListEntries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_block,
      { "Block", "pn_io.block",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_type,
      { "AlarmType", "pn_io.alarm_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_alarm_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier,
      { "AlarmSpecifier", "pn_io.alarm_specifier",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier_sequence,
      { "SequenceNumber", "pn_io.alarm_specifier.sequence",
        FT_UINT16, BASE_HEX, NULL, 0x07FF,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier_channel,
      { "ChannelDiagnosis", "pn_io.alarm_specifier.channel",
        FT_UINT16, BASE_HEX, NULL, 0x0800,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier_manufacturer,
      { "ManufacturerSpecificDiagnosis", "pn_io.alarm_specifier.manufacturer",
        FT_UINT16, BASE_HEX, NULL, 0x1000,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier_submodule,
      { "SubmoduleDiagnosisState", "pn_io.alarm_specifier.submodule",
        FT_UINT16, BASE_HEX, NULL, 0x2000,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_specifier_ardiagnosis,
      { "ARDiagnosisState", "pn_io.alarm_specifier.ardiagnosis",
        FT_UINT16, BASE_HEX, NULL, 0x8000,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_dst_endpoint,
      { "AlarmDstEndpoint", "pn_io.alarm_dst_endpoint",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_alarm_src_endpoint,
      { "AlarmSrcEndpoint", "pn_io.alarm_src_endpoint",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdu_type,
      { "PDUType", "pn_io.pdu_type",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdu_type_type,
      { "Type", "pn_io.pdu_type.type",
        FT_UINT8, BASE_HEX, VALS(pn_io_pdu_type), 0x0F,
        NULL, HFILL }
    },
    { &hf_pn_io_pdu_type_version,
      { "Version", "pn_io.pdu_type.version",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        NULL, HFILL }
    },
    { &hf_pn_io_add_flags,
      { "AddFlags", "pn_io.add_flags",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_window_size,
      { "WindowSize", "pn_io.window_size",
        FT_UINT8, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }
    },
    { &hf_pn_io_tack,
      { "TACK", "pn_io.tack",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        NULL, HFILL }
    },
    { &hf_pn_io_send_seq_num,
      { "SendSeqNum", "pn_io.send_seq_num",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ack_seq_num,
      { "AckSeqNum", "pn_io.ack_seq_num",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_var_part_len,
      { "VarPartLen", "pn_io.var_part_len",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_module_ident_number,
      { "ModuleIdentNumber", "pn_io.module_ident_number",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_ident_number,
      { "SubmoduleIdentNumber", "pn_io.submodule_ident_number",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_number_of_modules,
      { "NumberOfModules", "pn_io.number_of_modules",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_module_properties,
      { "ModuleProperties", "pn_io.module_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_module_state,
      { "ModuleState", "pn_io.module_state",
        FT_UINT16, BASE_HEX, VALS(pn_io_module_state), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_submodules,
      { "NumberOfSubmodules", "pn_io.number_of_submodules",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_submodule_properties,
      { "SubmoduleProperties", "pn_io.submodule_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_type,
      { "Type", "pn_io.submodule_properties.type",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_type), 0x0003,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_shared_input,
      { "SharedInput", "pn_io.submodule_properties.shared_input",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_shared_input), 0x0004,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_reduce_input_submodule_data_length,
      { "ReduceInputSubmoduleDataLength", "pn_io.submodule_properties.reduce_input_submodule_data_length",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_input_submodule_data_length), 0x0008,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_reduce_output_submodule_data_length,
      { "ReduceOutputSubmoduleDataLength", "pn_io.submodule_properties.reduce_output_submodule_data_length",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_output_submodule_data_length), 0x0010,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_discard_ioxs,
      { "DiscardIOXS", "pn_io.submodule_properties.discard_ioxs",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_discard_ioxs), 0x0020,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_properties_reserved,
      { "Reserved", "pn_io.submodule_properties.reserved",
        FT_UINT16, BASE_HEX, NULL, 0xFFC0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state,
      { "SubmoduleState", "pn_io.submodule_state",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_format_indicator,
      { "FormatIndicator", "pn_io.submodule_state.format_indicator",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_format_indicator), 0x8000,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_add_info,
      { "AddInfo", "pn_io.submodule_state.add_info",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_add_info), 0x0007,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_advice,
      { "Advice", "pn_io.submodule_state.advice",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_advice), 0x0008,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_maintenance_required,
      { "MaintenanceRequired", "pn_io.submodule_state.maintenance_required",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_required), 0x0010,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_maintenance_demanded,
      { "MaintenanceDemanded", "pn_io.submodule_state.maintenance_demanded",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_demanded), 0x0020,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_fault,
      { "Fault", "pn_io.submodule_state.fault",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_fault), 0x0040,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_ar_info,
      { "ARInfo", "pn_io.submodule_state.ar_info",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ar_info), 0x0780,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_ident_info,
      { "IdentInfo", "pn_io.submodule_state.ident_info",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ident_info), 0x7800,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_state_detail,
      { "Detail", "pn_io.submodule_state.detail",
        FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_detail), 0x7FFF,
        NULL, HFILL }
    },
    { &hf_pn_io_data_description_tree,
      { "DataDescription", "pn_io.data_description_tree",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_data_description,
      { "DataDescription", "pn_io.data_description",
        FT_UINT16, BASE_HEX, VALS(pn_io_data_description), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_submodule_data_length,
      { "SubmoduleDataLength", "pn_io.submodule_data_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_iocs,
      { "LengthIOCS", "pn_io.length_iocs",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_iops,
      { "LengthIOPS", "pn_io.length_iops",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_iocs,
      { "IOCS", "pn_io.ioxs",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_iops,
      { "IOPS", "pn_io.iops",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ioxs_extension,
      { "Extension (1:another IOxS follows/0:no IOxS follows)", "pn_io.ioxs.extension",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_ioxs_res14,
      { "Reserved (should be zero)", "pn_io.ioxs.res14",
        FT_UINT8, BASE_HEX, NULL, 0x1E,
        NULL, HFILL }
    },
    { &hf_pn_io_ioxs_instance,
      { "Instance (only valid, if DataState is bad)",
        "pn_io.ioxs.instance", FT_UINT8, BASE_HEX, VALS(pn_io_ioxs),
        0x60, NULL, HFILL }
    },
    { &hf_pn_io_ioxs_datastate,
      { "DataState (1:good/0:bad)", "pn_io.ioxs.datastate",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_pn_io_address_resolution_properties,
      { "AddressResolutionProperties", "pn_io.address_resolution_properties",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mci_timeout_factor,
      { "MCITimeoutFactor", "pn_io.mci_timeout_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_provider_station_name,
      { "ProviderStationName", "pn_io.provider_station_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_user_structure_identifier,
      { "UserStructureIdentifier", "pn_io.user_structure_identifier",
        FT_UINT16, BASE_HEX, VALS(pn_io_user_structure_identifier), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_user_structure_identifier_manf,
      { "UserStructureIdentifier manufacturer specific", "pn_io.user_structure_identifier_manf",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ar_properties_reserved_1,
        { "Reserved_1", "pn_io.ar_properties.reserved_1",
           FT_UINT32, BASE_HEX, NULL, 0x000000E0,
           NULL, HFILL }},
    { &hf_pn_io_ar_properties_device_access,
        { "DeviceAccess", "pn_io.ar_properties.device_access",
          FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_DeviceAccess), 0x00000100,
          NULL, HFILL }},
    { &hf_pn_io_subframe_data,
      { "SubFrameData", "pn_io.subframe_data",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_reserved2,
      { "Reserved1", "pn_io.subframe_data.reserved2",
        FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_data_length,
      { "DataLength", "pn_io.subframe_data.data_length",
        FT_UINT32, BASE_HEX, NULL, 0x0000FF00,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_reserved1,
      { "Reserved1", "pn_io.subframe_data.reserved1",
        FT_UINT32, BASE_HEX, NULL, 0x00000080,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_data_position,
      { "DataPosition", "pn_io.subframe_data.position",
        FT_UINT32, BASE_HEX, NULL, 0x0000007F,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_data_reserved1,
      { "Reserved1", "pn_io.subframe_data.reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0x00000080,
        NULL, HFILL }
    },
    { &hf_pn_io_subframe_data_reserved2,
      { "Reserved1", "pn_io.subframe_data.reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_channel_number,
      { "ChannelNumber", "pn_io.channel_number",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_channel_properties,
      { "ChannelProperties", "pn_io.channel_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_channel_properties_type,
      { "Type", "pn_io.channel_properties.type",
        FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_type), 0x00FF,
        NULL, HFILL }
    },
    { &hf_pn_io_channel_properties_accumulative,
      { "Accumulative", "pn_io.channel_properties.accumulative",
        FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_accumulative_vals), 0x0100,
        NULL, HFILL }
    },
    { &hf_pn_io_NumberOfSubframeBlocks,
      { "NumberOfSubframeBlocks", "pn_io.NumberOfSubframeBlocks",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_channel_properties_maintenance,
      { "Maintenance (Severity)", "pn_io.channel_properties.maintenance",
        FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_maintenance), 0x0600,
        NULL, HFILL }
    },
      { &hf_pn_io_channel_properties_specifier,
        { "Specifier", "pn_io.channel_properties.specifier",
          FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_specifier), 0x1800,
          NULL, HFILL }
      },
    { &hf_pn_io_channel_properties_direction,
      { "Direction", "pn_io.channel_properties.direction",
        FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_direction), 0xE000,
        NULL, HFILL }
    },

    { &hf_pn_io_channel_error_type,
      { "ChannelErrorType", "pn_io.channel_error_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_channel_error_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type0",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8000,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type0800",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8000), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8001,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8001",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8001), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8002,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8002",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8002), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8003,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8003",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8003), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8004,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8004",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8004), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8005,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8005",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8005), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8007,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8007",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8007), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8008,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8008",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8008), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x800A,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800A",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800A), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x800B,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800B",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800B), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x800C,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type800C",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x800C), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type0x8010,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type8010",
        FT_UINT16, BASE_HEX, VALS(pn_io_ext_channel_error_type0x8010), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_error_type,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ext_channel_add_value,
      { "ExtChannelAddValue", "pn_io.ext_channel_add_value",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_qualified_channel_qualifier,
      { "QualifiedChannelQualifier", "pn_io.qualified_channel_qualifier",
        FT_UINT32, BASE_HEX, VALS(pn_io_qualified_channel_qualifier), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_subdomain_id,
      { "PTCPSubdomainID", "pn_io.ptcp_subdomain_id",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ir_data_id,
      { "IRDataID", "pn_io.ir_data_id",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_max_bridge_delay,
      { "MaxBridgeDelay", "pn_io.max_bridge_delay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_ports,
      { "NumberOfPorts", "pn_io.number_of_ports",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_max_port_tx_delay,
      { "MaxPortTxDelay", "pn_io.max_port_tx_delay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_max_port_rx_delay,
      { "MaxPortRxDelay", "pn_io.max_port_rx_delay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
   { &hf_pn_io_max_line_rx_delay,
     { "MaxLineRxDelay", "pn_io.max_line_rx_delay",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }
   },
   { &hf_pn_io_yellowtime,
     { "YellowTime", "pn_io.yellowtime",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }
   },
    { &hf_pn_io_reserved_interval_begin,
      { "ReservedIntervalBegin", "pn_io.reserved_interval_begin",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_reserved_interval_end,
      { "ReservedIntervalEnd", "pn_io.reserved_interval_end",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pllwindow,
      { "PLLWindow", "pn_io.pllwindow",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sync_send_factor,
      { "SyncSendFactor", "pn_io.sync_send_factor",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sync_properties,
      { "SyncProperties", "pn_io.sync_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_sync_frame_address,
      { "SyncFrameAddress", "pn_io.sync_frame_address",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_timeout_factor,
      { "PTCPTimeoutFactor", "pn_io.ptcp_timeout_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_takeover_timeout_factor,
      { "PTCPTakeoverTimeoutFactor", "pn_io.ptcp_takeover_timeout_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_master_startup_time,
      { "PTCPMasterStartupTime", "pn_io.ptcp_master_startup_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_master_priority_1,
      { "PTCP_MasterPriority1", "pn_io.ptcp_master_priority_1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_master_priority_2,
      { "PTCP_MasterPriority2", "pn_io.ptcp_master_priority_2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_length_subdomain_name,
      { "PTCPLengthSubdomainName", "pn_io.ptcp_length_subdomain_name",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ptcp_subdomain_name,
      { "PTCPSubdomainName", "pn_io.ptcp_subdomain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_MultipleInterfaceMode_NameOfDevice,
      { "MultipleInterfaceMode.NameOfDevice", "pn_io.MultipleInterfaceMode_NameOfDevice",
        FT_UINT32, BASE_HEX, VALS(pn_io_MultipleInterfaceMode_NameOfDevice), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_MultipleInterfaceMode_reserved_1,
      { "MultipleInterfaceMode.Reserved_1", "pn_io.MultipleInterfaceMode_reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0xFFFE,
        NULL, HFILL }
    },
    { &hf_pn_io_MultipleInterfaceMode_reserved_2,
      { "MultipleInterfaceMode.Reserved_2", "pn_io.MultipleInterfaceMode_reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status,
      { "CounterStatus", "pn_io.CounterStatus",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifInOctets,
      { "CounterStatus.ifInOctets", "pn_io.CounterStatus.ifInOctets",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0001,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifOutOctets,
      { "CounterStatus.ifOutOctets", "pn_io.CounterStatus.ifOutOctets",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0002,
         NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifInDiscards,
      { "CounterStatus.ifInDiscards", "pn_io.CounterStatus.ifInDiscards",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0004,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifOutDiscards,
      { "CounterStatus.ifOutDiscards", "pn_io.CounterStatus.ifOutDiscards",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0008,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifInErrors,
      { "CounterStatus.ifInErrors", "pn_io.CounterStatus.ifInErrors",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0010,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_ifOutErrors,
      { "CounterStatus.ifOutErrors", "pn_io.CounterStatus.ifOutErrors",
        FT_BOOLEAN, 16, TFS(&pn_io_pdportstatistic_counter_status_contents), 0x0020,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_counter_status_reserved,
      { "CounterStatus.Reserved", "pn_io.CounterStatus.Reserved",
        FT_UINT16, BASE_HEX, VALS(pn_io_pdportstatistic_counter_status_reserved), 0xFFC0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifInOctets,
      { "ifInOctets", "pn_io.ifInOctets",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifOutOctets,
      { "ifOutOctets", "pn_io.ifOutOctets",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifInDiscards,
      { "ifInDiscards", "pn_io.ifInDiscards",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifOutDiscards,
      { "ifOutDiscards", "pn_io.ifOutDiscards",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifInErrors,
      { "ifInErrors", "pn_io.ifInErrors",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pdportstatistic_ifOutErrors,
      { "ifOutErrors", "pn_io.ifOutErrors",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_domain_boundary,
      { "DomainBoundary", "pn_io.domain_boundary",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_domain_boundary_ingress,
      { "DomainBoundaryIngress", "pn_io.domain_boundary.ingress",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_domain_boundary_egress,
      { "DomainBoundaryEgress", "pn_io.domain_boundary.egress",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_multicast_boundary,
      { "MulticastBoundary", "pn_io.multicast_boundary",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_adjust_properties,
      { "AdjustProperties", "pn_io.adjust_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_PreambleLength,
      { "Preamble Length", "pn_io.preamble_length",
        FT_UINT16, BASE_DEC_HEX, VALS(pn_io_preamble_length), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_max_supported_record_size,
     { "MaxSupportedRecordSize", "pn_io.tsn_upload_network_attributes.max_supported_record_size",
       FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_max_supported_record_size_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_transfer_time_tx,
     { "TransferTimeTX", "pn_io.tsn_upload_network_attributes.transfer_time_tx",
       FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_transfer_time_tx_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_transfer_time_rx,
     { "TransferTimeRX", "pn_io.tsn_upload_network_attributes.transfer_time_rx",
       FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_transfer_time_rx_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_number_of_queues,
    { "NumberOfQueues", "pn_io.tsn_port_id_block.number_of_queues",
      FT_UINT8, BASE_HEX, VALS(pn_io_tsn_number_of_queues_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_pn_io_tsn_forwarding_delay_block_number_of_entries,
      { "TSNForwardingDelayBlockNumberOfEntries", "pn_io.tsn_forward_delaying_block.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
  { &hf_pn_io_tsn_port_id_block_number_of_entries,
      { "TSNPortIDBlockNumberOfEntries", "pn_io.tsn_port_id_block.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_expected_neighbor_block_number_of_entries,
      { "TSNExpectedNeighborBlockNumberOfEntries", "pn_io.tsn_expected_neighbor_block.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_port_capabilities_time_aware,
       { "TSNPortCapabilities.TimeAware", "pn_io.tsn_port_capabilities.time_aware",
         FT_UINT8, BASE_HEX, VALS(pn_io_tsn_port_capabilities_time_aware_vals), 0x01,
         NULL, HFILL }
    },
    { &hf_pn_io_tsn_port_capabilities_preemption,
       { "TSNPortCapabilities.Preemption", "pn_io.tsn_port_capabilities.preemption",
         FT_UINT8, BASE_HEX, VALS(pn_io_tsn_port_capabilities_preemption_vals), 0x02,
         NULL, HFILL }
    },
    { &hf_pn_io_tsn_port_capabilities_queue_masking,
       { "TSNPortCapabilities.QueueMasking", "pn_io.tsn_port_capabilities.queue_masking",
         FT_UINT8, BASE_HEX, VALS(pn_io_tsn_port_capabilities_queue_masking_vals), 0x04,
         NULL, HFILL }
    },
    { &hf_pn_io_tsn_port_capabilities_reserved,
      { "TSNPortCapabilities.Reserved", "pn_io.tsn_port_capabilities_reserved",
         FT_UINT8, BASE_HEX, NULL, 0xF8,
         NULL, HFILL }
    },
    { &hf_pn_io_tsn_forwarding_group,
     { "ForwardingGroup", "pn_io.tsn_port_id_block.forwarding_group",
       FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_forwarding_group_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_forwarding_group_ingress,
     { "ForwardingGroupIngress", "pn_io.tsn_port_id_block.forwarding_group_ingress",
       FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_forwarding_group_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_forwarding_group_egress,
     { "ForwardingGroupEgress", "pn_io.tsn_port_id_block.forwarding_group_egress",
       FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_forwarding_group_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_stream_class,
      { "StreamClass", "pn_io.tsn_forwarding_delay_entry.stream_class",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_stream_class_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_dependent_forwarding_delay,
     { "DependentForwardDelay", "pn_io.tsn_forwarding_delay_entry.dependent_forwarding_delay",
       FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_dependent_forwarding_delay_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_independent_forwarding_delay,
     { "IndependentForwardDelay", "pn_io.tsn_forwarding_delay_entry.independent_forwarding_delay",
       FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_independent_forwarding_delay_vals), 0x0,
       NULL, HFILL }
    },
    { &hf_pn_io_tsn_nme_parameter_uuid,
      { "NMEParameterUUID", "pn_io.tsn_nme_parameter_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config,
      { "TSNDomainVIDConfig", "pn_io.tsn_domain_vid_config",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_stream_high_vid,
      { "TSNDomainVIDConfig.StreamHighVID", "pn_io.tsn_domain_vid_config.stream_high_vid",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_stream_high_red_vid,
      { "TSNDomainVIDConfig.StreamHighRedVID", "pn_io.tsn_domain_vid_config.stream_high_red_vid",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_stream_low_vid,
      { "TSNDomainVIDConfig.StreamLowVID", "pn_io.tsn_domain_vid_config.stream_low_vid",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_stream_low_red_vid,
      { "TSNDomainVIDConfig.StreamLowRedVID", "pn_io.tsn_domain_vid_config.stream_low_red_vid",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_non_stream_vid,
      { "TSNDomainVIDConfig.NonStreamVID", "pn_io.tsn_domain_vid_config.non_stream_vid",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_non_stream_vid_B,
      { "TSNDomainVIDConfig.NonStreamVIDB", "pn_io.tsn_domain_vid_config.non_stream_vid_B",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_non_stream_vid_C,
      { "TSNDomainVIDConfig.NonStreamVIDC", "pn_io.tsn_domain_vid_config.non_stream_vid_C",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_non_stream_vid_D,
      { "TSNDomainVIDConfig.NonStreamVIDD", "pn_io.tsn_domain_vid_config.non_stream_vid_D",
        FT_UINT16, BASE_HEX, VALS(pn_io_tsn_domain_vid_config_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_vid_config_reserved,
      { "TSNDomainVIDConfig.Reserved", "pn_io.tsn_domain_vid_config.reserved",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_domain_port_config_entries,
      { "TSNDomainPortConfig.NumberOfEntries", "pn_io.tsn_domain_port_config.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_time_data_block_entries,
      { "TSNTimeDataBlock.NumberOfEntries", "pn_io.tsn_time_data_block.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_domain_queue_rate_limiter_entries,
      { "TSNDomainQueueRateLimiter.NumberOfEntries", "pn_io.tsn_domain_queue_rate_limiter.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_domain_port_ingress_rate_limiter_entries,
      { "TSNDomainPortIngressRateLimiter.NumberOfEntries", "pn_io.tsn_domain_port_ingress_limiter.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_config,
      { "TSNDomainPortConfig", "pn_io.tsn_domain_port_config",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_config_preemption_enabled,
      { "TSNDomainPortConfig.PreemptionEnabled", "pn_io.tsn_domain_port_config.preemption_enabled",
        FT_UINT8, BASE_HEX, VALS(pn_io_tsn_domain_port_config_preemption_enabled_vals), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_config_boundary_port_config,
      { "TSNDomainPortConfig.BoundaryPortConfig", "pn_io.tsn_domain_port_config.boundary_port_config",
        FT_UINT8, BASE_HEX, VALS(pn_io_tsn_domain_port_config_boundary_port_config_vals), 0x0E,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_config_reserved,
      { "TSNDomainPortConfig.Reserved", "pn_io.tsn_domain_port_config.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_ingress_rate_limiter,
      { "TSNDomainPortIngressRateLimiter", "pn_io.tsn_domain_port_ingress_rate_limiter",
         FT_UINT64, BASE_HEX, NULL, 0x0,
         NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_ingress_rate_limiter_cir,
      { "TSNDomainPortIngressRateLimiter.Cir", "pn_io.tsn_domain_port_ingress_rate_limiter.cir",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_port_ingress_rate_limiter_cir), 0x000000000000FFFF,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_ingress_rate_limiter_cbs,
      { "TSNDomainPortIngressRateLimiter.Cbs", "pn_io.tsn_domain_port_ingress_rate_limiter.cbs",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_port_ingress_rate_limiter_cbs), 0x00000000FFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_ingress_rate_limiter_envelope,
      { "TSNDomainPortIngressRateLimiter.Envelope", "pn_io.tsn_domain_port_ingress_rate_limiter.envelope",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_port_ingress_rate_limiter_envelope), 0x0000FFFF00000000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_ingress_rate_limiter_rank,
      { "TSNDomainPortIngressRateLimiter.Rank", "pn_io.tsn_domain_port_ingress_rate_limiter.rank",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_port_ingress_rate_limiter_rank), 0xFFFF000000000000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter,
      { "TSNDomainQueueRateLimiter", "pn_io.tsn_domain_port_queue_rate_limiter",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_cir,
      { "TSNDomainQueueRateLimiter.Cir", "pn_io.tsn_domain_port_queue_rate_limiter.cir",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_cir), 0x000000000000FFFF,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_cbs,
      { "TSNDomainQueueRateLimiter.Cbs", "pn_io.tsn_domain_port_queue_rate_limiter.cbs",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_cbs), 0x00000000FFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_envelope,
      { "TSNDomainQueueRateLimiter.Envelope", "pn_io.tsn_domain_port_queue_rate_limiter.envelope",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_envelope), 0x000000FF00000000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_rank,
      { "TSNDomainQueueRateLimiter.Rank", "pn_io.tsn_domain_port_queue_rate_limiter.rank",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_rank), 0x0000FF0000000000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_queue_id,
      { "TSNDomainQueueRateLimiter.QueueID", "pn_io.tsn_domain_port_queue_rate_limiter.queue_id",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_queue_id), 0x00FF000000000000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_rate_limiter_reserved,
      { "TSNDomainQueueRateLimiter.Reserved", "pn_io.tsn_domain_port_queue_rate_limiter.reserved",
        FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_rate_limiter_reserved), 0xFF00000000000000,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_domain_queue_config_entries,
      { "TSNDomainQueueConfig.NumberOfEntries", "pn_io.tsn_domain_queue_config.number_of_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config,
      { "TSNDomainQueueConfig", "pn_io.tsn_domain_queue_config",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_queue_id,
        { "TSNDomainQueueConfig.QueueID", "pn_io.tsn_domain_queue_config.queue_id",
          FT_UINT64, BASE_HEX, NULL, 0xF,
          NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_tci_pcp,
        { "TSNDomainQueueConfig.TciPcp", "pn_io.tsn_domain_queue_config.tci_pcp",
          FT_UINT64, BASE_HEX, NULL, 0x70,
          NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_shaper,
        { "TSNDomainQueueConfig.Shaper", "pn_io.tsn_domain_queue_config.shaper",
          FT_UINT64, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_queue_config_shaper), 0x3F80,
          NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_preemption_mode,
        { "TSNDomainQueueConfig.PreemptionMode", "pn_io.tsn_domain_queue_config.preemption_mode",
          FT_UINT64, BASE_HEX, NULL, 0xC000,
          NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_unmask_time_offset,
      { "TSNDomainQueueConfig.UnmaskTimeOffset", "pn_io.tsn_domain_queue_config.unmask_time_offset",
        FT_UINT64, BASE_HEX, NULL, 0xFFFFFF0000,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_queue_config_mask_time_offset,
      { "TSNDomainQueueConfig.MaskTimeOffset", "pn_io.tsn_domain_queue_config.mask_time_offset",
        FT_UINT64, BASE_HEX, NULL, 0xFFFFFF0000000000,
        NULL, HFILL }
    },
    { &hf_pn_io_network_deadline,
      { "NetworkDeadline", "pn_io.network_deadline",
        FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(pn_io_network_domain), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_domain_number,
      { "TimeDomainNumber", "pn_io.time_domain_number",
         FT_UINT16, BASE_HEX , VALS(pn_io_time_domain_number_vals), 0x0,
         NULL, HFILL }
    },
    { &hf_pn_io_time_pll_window,
      { "TimePLLWindow", "pn_io.time_pll_window",
        FT_UINT32, BASE_DEC , VALS(pn_io_time_pll_window_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_message_interval_factor,
      { "MessageIntervalFactor", "pn_io.message_interval_factor",
         FT_UINT32, BASE_DEC , VALS(pn_io_message_interval_factor_vals), 0x0,
         NULL, HFILL }
    },
    { &hf_pn_io_message_timeout_factor,
      { "MessageTimeoutFactor", "pn_io.message_timeout_factor",
         FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(pn_io_message_timeout_factor), 0x0,
         NULL, HFILL }
    },
    { &hf_pn_io_time_sync_properties,
      { "TimeSyncProperties", "pn_io.time_sync_properties",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_sync_properties_role,
      { "TimeSyncProperties.Role", "pn_io.time_sync_properties.role",
        FT_UINT16, BASE_HEX, VALS(pn_io_time_sync_properties_vals), 0x3,
        NULL, HFILL }
    },
    { &hf_pn_io_time_sync_properties_reserved,
      { "TimeSyncProperties.Reserved", "pn_io.time_sync_properties.reserved",
        FT_UINT16, BASE_HEX, NULL, 0xFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_time_domain_uuid,
      { "TimeDomainUUID", "pn_io.time_domain_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_domain_name_length,
      { "TimeDomainNameLength", "pn_io.time_domain_name_length",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_domain_name,
      { "TimeDomainName", "pn_io.time_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_nme_name_uuid,
      { "TSNNMENameUUID", "pn_io.tsn_nme_name_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_nme_name_length,
      { "TSNNMENameLength", "pn_io.tsn_nme_name_length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_nme_name,
      { "TSNNMEName", "pn_io.tsn_nme_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_uuid,
      { "TSNDomainUUID", "pn_io.tsn_domain_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_name_length,
      { "TSNDomainNameLength", "pn_io.tsn_domain_name_length",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_name,
      { "TSNDomainName", "pn_io.tsn_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_fdb_command,
      { "FDBCommand", "pn_io.tsn_fdb_command",
        FT_UINT8, BASE_HEX, VALS(pn_io_tsn_fdb_command), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_dst_add,
      { "DestinationAddress", "pn_io.tsn_dst_add",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_tsn_domain_sync_tree_entries,
      { "NumberOfEntries", "pn_io.tsn_domain_sync_tree_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_port_id,
      { "TSNDomainPortID", "pn_io.tsn_domain_port_id",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tsn_domain_sync_port_role,
      { "SyncPortRole", "pn_io.tsn_domain_sync_port_rule",
        FT_UINT8,BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_tsn_domain_sync_port_role_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mau_type,
      { "MAUType", "pn_io.mau_type",
        FT_UINT16, BASE_HEX, VALS(pn_io_mau_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mau_type_mode,
      { "MAUTypeMode", "pn_io.mau_type_mode",
        FT_UINT16, BASE_HEX, VALS(pn_io_mau_type_mode), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_dcp_boundary_value,
    { "DCPBoundary", "pn_io.dcp_boundary_value",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_dcp_boundary_value_bit0,
      { "DCPBoundary", "pn_io.dcp_boundary_value_bit0",
         FT_UINT32, BASE_HEX, VALS(pn_io_dcp_boundary_value_bit0), 0x1,
         NULL, HFILL }
    },
    { &hf_pn_io_dcp_boundary_value_bit1,
      { "DCPBoundary", "pn_io.dcp_boundary_value_bit1",
        FT_UINT32, BASE_HEX, VALS(pn_io_dcp_boundary_value_bit1), 0x2,
        NULL, HFILL }
    },
    { &hf_pn_io_dcp_boundary_value_otherbits,
      { "DCPBoundary", "pn_io.dcp_boundary_value_otherbits",
        FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_to_peer_boundary_value,
      { "AdjustPeerToPeer-Boundary", "pn_io.peer_to_peer_boundary_value",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_to_peer_boundary_value_bit0,
      { "AdjustPeerToPeer-Boundary", "pn_io.peer_to_peer_boundary_value_bit0",
        FT_UINT32, BASE_HEX, VALS(pn_io_peer_to_peer_boundary_value_bit0), 0x1,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_to_peer_boundary_value_bit1,
      { "AdjustPeerToPeer-Boundary", "pn_io.peer_to_peer_boundary_value_bit1",
        FT_UINT32, BASE_HEX, VALS(pn_io_peer_to_peer_boundary_value_bit1), 0x2,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_to_peer_boundary_value_bit2,
      { "AdjustPeerToPeer-Boundary", "pn_io.peer_to_peer_boundary_value_bit2",
        FT_UINT32, BASE_HEX, VALS(pn_io_peer_to_peer_boundary_value_bit2), 0x4,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_to_peer_boundary_value_otherbits,
      { "AdjustPeerToPeer-Boundary", "pn_io.peer_to_peer_boundary_value_otherbits",
        FT_UINT32, BASE_HEX, NULL, 0xFFFFFFF8,
        NULL, HFILL }
    },
    { &hf_pn_io_port_state,
      { "PortState", "pn_io.port_state",
        FT_UINT16, BASE_HEX, VALS(pn_io_port_state), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_link_state_port,
      { "LinkState.Port", "pn_io.link_state_port",
        FT_UINT8, BASE_HEX, VALS(pn_io_link_state_port), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_link_state_link,
      { "LinkState.Link", "pn_io.link_state_link",
        FT_UINT8, BASE_HEX, VALS(pn_io_link_state_link), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_line_delay,
      { "LineDelay", "pn_io.line_delay",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "LineDelay in nanoseconds", HFILL }
    },
    { &hf_pn_io_line_delay_value,
      { "LineDelayValue", "pn_io.line_delay_value",
        FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(pn_io_line_delay_value), 0x7FFFFFFF,
        NULL, HFILL }
    },
    { &hf_pn_io_cable_delay_value,
      { "CableDelayValue", "pn_io.cable_delay_value",
         FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(pn_io_cable_delay_value), 0x7FFFFFFF,
        NULL, HFILL }
    },
    { &hf_pn_io_line_delay_format_indicator,
      { "LineDelayFormatIndicator", "pn_io.line_delay_format_indicator",
        FT_UINT32, BASE_HEX, NULL, 0x80000000,
        "LineDelay FormatIndicator", HFILL }
    },
    { &hf_pn_io_number_of_peers,
      { "NumberOfPeers", "pn_io.number_of_peers",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_peer_port_id,
      { "LengthPeerPortID", "pn_io.length_peer_port_id",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_port_id,
      { "PeerPortID", "pn_io.peer_port_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_peer_chassis_id,
      { "LengthPeerChassisID", "pn_io.length_peer_chassis_id",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_chassis_id,
      { "PeerChassisID", "pn_io.peer_chassis_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_neighbor,
      { "Neighbor", "pn_io.neighbor",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_peer_port_name,
      { "LengthPeerPortName", "pn_io.length_peer_port_name",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_port_name,
      { "PeerPortName", "pn_io.peer_port_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_peer_station_name,
      { "LengthPeerStationName", "pn_io.length_peer_station_name",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_station_name,
      { "PeerStationName", "pn_io.peer_station_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_own_chassis_id,
      { "LengthOwnChassisID", "pn_io.length_own_chassis_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_own_chassis_id,
      { "OwnChassisID", "pn_io.own_chassis_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_rtclass3_port_status,
      { "RTClass3_PortStatus", "pn_io.rtclass3_port_status",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_own_port_id,
      { "LengthOwnPortID", "pn_io.length_own_port_id",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_own_port_id,
      { "OwnPortID", "pn_io.own_port_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_peer_macadd,
      { "PeerMACAddress", "pn_io.peer_macadd",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_macadd,
      { "MACAddress", "pn_io.macadd",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_media_type,
      { "MediaType", "pn_io.media_type",
        FT_UINT32, BASE_HEX, VALS(pn_io_media_type), 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_ethertype,
      { "Ethertype", "pn_io.ethertype",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_rx_port,
      { "RXPort", "pn_io.rx_port",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_details,
      { "FrameDetails", "pn_io.frame_details",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_details_sync_frame,
      { "SyncFrame", "pn_io.frame_details.sync_frame",
        FT_UINT8, BASE_HEX, VALS(pn_io_frame_details_sync_master_vals), 0x03,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_details_meaning_frame_send_offset,
      { "Meaning", "pn_io.frame_details.meaning_frame_send_offset",
        FT_UINT8, BASE_HEX, VALS(pn_io_frame_details_meaning_frame_send_offset_vals), 0x0C,
        NULL, HFILL }
    },
    { &hf_pn_io_frame_details_reserved,
      { "Reserved", "pn_io.frame_details.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        NULL, HFILL }
    },
    { &hf_pn_io_nr_of_tx_port_groups,
      { "NumberOfTxPortGroups", "pn_io.nr_of_tx_port_groups",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties,
      { "TxPortGroupProperties", "pn_io.tx_port_properties",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit0,
      { "TxPortLocal", "pn_io.tx_port_properties_bit_0",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit1,
      { "TxPort_1", "pn_io.tx_port_properties_bit_1",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x02,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit2,
      { "TxPort_2", "pn_io.tx_port_properties_bit_2",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x04,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit3,
      { "TxPort_3", "pn_io.tx_port_properties_bit_3",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x08,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit4,
      { "TxPort_4", "pn_io.tx_port_properties_bit_4",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x10,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit5,
      { "TxPort_5", "pn_io.tx_port_properties_bit_5",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x20,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit6,
      { "TxPort_6", "pn_io.tx_port_properties_bit_6",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x40,
        NULL, HFILL }
    },
    { &hf_pn_io_TxPortGroupProperties_bit7,
      { "TxPort_7", "pn_io.tx_port_properties_bit_7",
        FT_UINT8, BASE_HEX, VALS(pn_io_txgroup_state), 0x80,
        NULL, HFILL }
    },

    { &hf_pn_io_start_of_red_frame_id,
      { "StartOfRedFrameID", "pn_io.start_of_red_frame_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_end_of_red_frame_id,
      { "EndOfRedFrameID", "pn_io.end_of_red_frame_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ir_begin_end_port,
      { "Port", "pn_io.ir_begin_end_port",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_assignments,
      { "NumberOfAssignments", "pn_io.number_of_assignments",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_phases,
      { "NumberOfPhases", "pn_io.number_of_phases",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_red_orange_period_begin_tx,
      { "RedOrangePeriodBegin [TX]", "pn_io.red_orange_period_begin_tx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_orange_period_begin_tx,
      { "OrangePeriodBegin [TX]", "pn_io.orange_period_begin_tx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_green_period_begin_tx,
      { "GreenPeriodBegin [TX]", "pn_io.green_period_begin_tx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_red_orange_period_begin_rx,
      { "RedOrangePeriodBegin [RX]", "pn_io.red_orange_period_begin_rx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_orange_period_begin_rx,
      { "OrangePeriodBegin [RX]", "pn_io.orange_period_begin_rx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_green_period_begin_rx,
      { "GreenPeriodBegin [RX]", "pn_io.green_period_begin_rx",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_ir_tx_phase_assignment,
      { "TXPhaseAssignment", "pn_io.tx_phase_assignment_sub",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_tx_phase_assignment_begin_value,
      { "AssignedValueForReservedBegin", "pn_io.tx_phase_assignment_begin_value",
        FT_UINT16, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }
    },
    { &hf_pn_io_tx_phase_assignment_orange_begin,
      { "AssignedValueForOrangeBegin", "pn_io.tx_phase_assignment_orange_begin",
        FT_UINT16, BASE_DEC, NULL, 0x0F0,
        NULL, HFILL }
    },
    { &hf_pn_io_tx_phase_assignment_end_reserved,
      { "AssignedValueForReservedEnd", "pn_io.tx_phase_assignment_end_reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0F00,
        NULL, HFILL }
    },
    { &hf_pn_io_tx_phase_assignment_reserved,
      { "Reserved should be 0", "pn_io.tx_phase_assignment_reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0F000,
        NULL, HFILL }
    },
    { &hf_pn_ir_rx_phase_assignment,
      { "RXPhaseAssignment", "pn_io.rx_phase_assignment_sub",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_slot,
      { "Slot", "pn_io.slot",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_subslot,
      { "Subslot", "pn_io.subslot",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_slots,
      { "NumberOfSlots", "pn_io.number_of_slots",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_subslots,
      { "NumberOfSubslots", "pn_io.number_of_subslots",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_maintenance_required_power_budget,
      { "MaintenanceRequiredPowerBudget", "pn_io.maintenance_required_power_budget",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_maintenance_demanded_power_budget,
      { "MaintenanceDemandedPowerBudget", "pn_io.maintenance_demanded_power_budget",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_error_power_budget,
      { "ErrorPowerBudget", "pn_io.error_power_budget",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fiber_optic_type,
      { "FiberOpticType", "pn_io.fiber_optic_type",
        FT_UINT32, BASE_HEX, VALS(pn_io_fiber_optic_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fiber_optic_cable_type,
      { "FiberOpticCableType", "pn_io.fiber_optic_cable_type",
        FT_UINT32, BASE_HEX, VALS(pn_io_fiber_optic_cable_type), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_controller_appl_cycle_factor,
      { "ControllerApplicationCycleFactor", "pn_io.controller_appl_cycle_factor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_data_cycle,
      { "TimeDataCycle", "pn_io.time_data_cycle",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_io_input,
      { "TimeIOInput", "pn_io.time_io_input",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_io_output,
      { "TimeIOOutput", "pn_io.time_io_output",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_io_input_valid,
      { "TimeIOInputValid", "pn_io.time_io_input_valid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_time_io_output_valid,
      { "TimeIOOutputValid", "pn_io.time_io_output_valid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_maintenance_status,
      { "MaintenanceStatus", "pn_io.maintenance_status",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_maintenance_status_required,
      { "Required", "pn_io.maintenance_status_required",
        FT_UINT32, BASE_HEX, NULL, 0x0001,
        NULL, HFILL }
    },
    { &hf_pn_io_maintenance_status_demanded,
      { "Demanded", "pn_io.maintenance_status_demanded",
        FT_UINT32, BASE_HEX, NULL, 0x0002,
        NULL, HFILL }
    },
    { &hf_pn_io_vendor_id_high,
      { "VendorIDHigh", "pn_io.vendor_id_high",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_vendor_id_low,
      { "VendorIDLow", "pn_io.vendor_id_low",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_vendor_block_type,
      { "VendorBlockType", "pn_io.vendor_block_type",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_order_id,
      { "OrderID", "pn_io.order_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_serial_number,
      { "IMSerialNumber", "pn_io.im_serial_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_hardware_revision,
      { "IMHardwareRevision", "pn_io.im_hardware_revision",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
      /* XXX - better use a simple char here -> vals */
    { &hf_pn_io_im_revision_prefix,
      { "IMRevisionPrefix", "pn_io.im_revision_prefix",
        FT_CHAR, BASE_HEX, VALS(pn_io_im_revision_prefix_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_sw_revision_functional_enhancement,
      { "IMSWRevisionFunctionalEnhancement", "pn_io.im_sw_revision_functional_enhancement",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_revision_bugfix,
      { "IM_SWRevisionBugFix", "pn_io.im_revision_bugfix",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_sw_revision_internal_change,
      { "IMSWRevisionInternalChange", "pn_io.im_sw_revision_internal_change",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_revision_counter,
      { "IMRevisionCounter", "pn_io.im_revision_counter",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_profile_id,
      { "IMProfileID", "pn_io.im_profile_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_profile_specific_type,
      { "IMProfileSpecificType", "pn_io.im_profile_specific_type",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_version_major,
      { "IMVersionMajor", "pn_io.im_version_major",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_version_minor,
      { "IMVersionMinor", "pn_io.im_version_minor",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_supported,
      { "IM_Supported", "pn_io.im_supported",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_numberofentries,
      { "NumberOfEntries", "pn_io.im_numberofentries",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_annotation,
      { "IM Annotation", "pn_io.im_annotation",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_order_id,
      { "IM Order ID", "pn_io.im_order_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_ars,
      { "NumberOfARs", "pn_io.number_of_ars",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_cycle_counter,
      { "CycleCounter", "pn_io.cycle_counter",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status,
      { "DataStatus", "pn_io.ds",
        FT_UINT8, BASE_HEX, 0, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_res67,
      { "Reserved (should be zero)", "pn_io.ds_res67",
        FT_UINT8, BASE_HEX, 0, 0xc0,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_ok,
      { "StationProblemIndicator (1:Ok/0:Problem)", "pn_io.ds_ok",
        FT_UINT8, BASE_HEX, 0, 0x20,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_operate,
      { "ProviderState (1:Run/0:Stop)", "pn_io.ds_operate",
        FT_UINT8, BASE_HEX, 0, 0x10,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_res3,
      { "Reserved (should be zero)", "pn_io.ds_res3",
        FT_UINT8, BASE_HEX, 0, 0x08,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_valid,
      { "DataValid (1:Valid/0:Invalid)", "pn_io.ds_valid",
        FT_UINT8, BASE_HEX, 0, 0x04,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_res1,
      { "primary AR of a given AR-set is present (0:One/ 1:None)", "pn_io.ds_res1",
        FT_UINT8, BASE_HEX, 0, 0x02,
        NULL, HFILL }
    },
    { &hf_pn_io_data_status_primary,
      { "State (1:Primary/0:Backup)", "pn_io.ds_primary",
        FT_UINT8, BASE_HEX, 0, 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_transfer_status,
      { "TransferStatus", "pn_io.transfer_status",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_actual_local_time_stamp,
      { "ActualLocalTimeStamp", "pn_io.actual_local_time_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_local_time_stamp,
      { "LocalTimeStamp", "pn_io.local_time_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_log_entries,
      { "NumberOfLogEntries", "pn_io.number_of_log_entries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_entry_detail,
      { "EntryDetail", "pn_io.entry_detail",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ip_address,
      { "IPAddress", "pn_io.ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_subnetmask,
      { "Subnetmask", "pn_io.subnetmask",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_standard_gateway,
      { "StandardGateway", "pn_io.standard_gateway",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_mrp_domain_uuid,
      { "MRP_DomainUUID", "pn_io.mrp_domain_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_role,
      { "MRP_Role", "pn_io.mrp_role",
        FT_UINT16, BASE_HEX, VALS(pn_io_mrp_role_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_length_domain_name,
      { "MRP_LengthDomainName", "pn_io.mrp_length_domain_name",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_domain_name,
      { "MRP_DomainName", "pn_io.mrp_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_instances,
      { "NumberOfMrpInstances", "pn_io.mrp_Number_MrpInstances",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_instance,
      { "Mrp_Instance", "pn_io.mrp_MrpInstance",
        FT_UINT8, BASE_DEC,  VALS(pn_io_mrp_instance_no), 0x0,
        NULL, HFILL }
    },

    { &hf_pn_io_mrp_prio,
      { "MRP_Prio", "pn_io.mrp_prio",
        FT_UINT16, BASE_HEX, VALS(pn_io_mrp_prio_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_topchgt,
      { "MRP_TOPchgT", "pn_io.mrp_topchgt",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "time base 10ms", HFILL }
    },
    { &hf_pn_io_mrp_topnrmax,
      { "MRP_TOPNRmax", "pn_io.mrp_topnrmax",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "number of iterations", HFILL }
    },
    { &hf_pn_io_mrp_tstshortt,
      { "MRP_TSTshortT", "pn_io.mrp_tstshortt",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "time base 1 ms", HFILL }
    },
    { &hf_pn_io_mrp_tstdefaultt,
      { "MRP_TSTdefaultT", "pn_io.mrp_tstdefaultt",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "time base 1ms", HFILL }
    },
    { &hf_pn_io_mrp_tstnrmax,
      { "MRP_TSTNRmax", "pn_io.mrp_tstnrmax",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "number of outstanding test indications causes ring failure", HFILL }
    },
    { &hf_pn_io_mrp_check,
      { "MRP_Check", "pn_io.mrp_check",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_check_mrm,
      { "MRP_Check.MediaRedundancyManager", "pn_io.mrp_check.mrm",
        FT_UINT32, BASE_HEX, VALS(pn_io_mrp_mrm_on), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_check_mrpdomain,
      { "MRP_Check.MRP_DomainUUID", "pn_io.mrp_check.domainUUID",
        FT_UINT32, BASE_HEX, VALS(pn_io_mrp_checkUUID), 0x02,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_check_reserved_1,
      { "MRP_Check.reserved_1", "pn_io.mrp_check_reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0x0FFFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_check_reserved_2,
      { "MRP_Check.reserved_2", "pn_io.mrp_check_reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0x0FF000000,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rtmode,
      { "MRP_RTMode", "pn_io.mrp_rtmode",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rtmode_rtclass12,
      { "RTClass1_2", "pn_io.mrp_rtmode.class1_2",
        FT_UINT32, BASE_HEX, VALS(pn_io_mrp_rtmode_rtclass12_vals), 0x00000001,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rtmode_rtclass3,
      { "RTClass1_3", "pn_io.mrp_rtmode.class3",
        FT_UINT32, BASE_HEX, VALS(pn_io_mrp_rtmode_rtclass3_vals), 0x00000002,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rtmode_reserved1,
      { "Reserved_1", "pn_io.mrp_rtmode.reserved_1",
        FT_UINT32, BASE_HEX, NULL, 0x00fffffc,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rtmode_reserved2,
      { "Reserved_2", "pn_io.mrp_rtmode.reserved_2",
        FT_UINT32, BASE_HEX, NULL, 0xff000000,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_lnkdownt,
      { "MRP_LNKdownT", "pn_io.mrp_lnkdownt",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Link down Interval in ms", HFILL }
    },
    { &hf_pn_io_mrp_lnkupt,
      { "MRP_LNKupT", "pn_io.mrp_lnkupt",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Link up Interval in ms", HFILL }
    },
    { &hf_pn_io_mrp_lnknrmax,
      { "MRP_LNKNRmax", "pn_io.mrp_lnknrmax",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "number of iterations", HFILL }
    },
    { &hf_pn_io_mrp_version,
      { "MRP_Version", "pn_io.mrp_version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_substitute_active_flag,
      { "SubstituteActiveFlag", "pn_io.substitute_active_flag",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_length_data,
      { "LengthData", "pn_io.length_data",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_ring_state,
      { "MRP_RingState", "pn_io.mrp_ring_state",
        FT_UINT16, BASE_HEX, VALS(pn_io_mrp_ring_state_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mrp_rt_state,
      { "MRP_RTState", "pn_io.mrp_rt_state",
        FT_UINT16, BASE_HEX, VALS(pn_io_mrp_rt_state_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_tag_function,
      { "IM_Tag_Function", "pn_io.im_tag_function",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_tag_location,
      { "IM_Tag_Location", "pn_io.im_tag_location",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_date,
      { "IM_Date", "pn_io.im_date",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_descriptor,
      { "IM_Descriptor", "pn_io.im_descriptor",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fs_hello_mode,
      { "FSHelloMode", "pn_io.fs_hello_mode",
        FT_UINT32, BASE_HEX, VALS(pn_io_fs_hello_mode_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fs_hello_interval,
      { "FSHelloInterval", "pn_io.fs_hello_interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "ms before conveying a second DCP_Hello.req", HFILL }
    },
    { &hf_pn_io_fs_hello_retry,
      { "FSHelloRetry", "pn_io.fs_hello_retry",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fs_hello_delay,
      { "FSHelloDelay", "pn_io.fs_hello_delay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fs_parameter_mode,
      { "FSParameterMode", "pn_io.fs_parameter_mode",
        FT_UINT32, BASE_HEX, VALS(pn_io_fs_parameter_mode_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_fs_parameter_uuid,
      { "FSParameterUUID", "pn_io.fs_parameter_uuid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_check_sync_mode,
      { "CheckSyncMode", "pn_io.check_sync_mode",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_check_sync_mode_reserved,
      { "Reserved", "pn_io.check_sync_mode.reserved",
        FT_UINT16, BASE_HEX, NULL, 0xFFFC,
        NULL, HFILL }
    },
    { &hf_pn_io_check_sync_mode_sync_master,
      { "SyncMaster", "pn_io.check_sync_mode.sync_master",
        FT_UINT16, BASE_HEX, NULL, 0x0002,
        NULL, HFILL }
    },
    { &hf_pn_io_check_sync_mode_cable_delay,
      { "CableDelay", "pn_io.check_sync_mode.cable_delay",
        FT_UINT16, BASE_HEX, NULL, 0x0001,
        NULL, HFILL }
    },
    /* PROFIsafe F-Parameter */
    { &hf_pn_io_ps_f_prm_flag1,
      { "F_Prm_Flag1", "pn_io.ps.f_prm_flag1",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_chck_seq,
      { "F_Check_SeqNr", "pn_io.ps.f_prm_flag1.f_check_seqnr",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_check_seqnr), 0x01,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_chck_ipar,
      { "F_Check_iPar", "pn_io.ps.f_prm_flag1.f_check_ipar",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_check_ipar), 0x02,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_sil,
      { "F_SIL", "pn_io.ps.f_prm_flag1.f_sil",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_sil), 0xc,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_crc_len,
      { "F_CRC_Length", "pn_io.ps.f_prm_flag1.f_crc_len",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_crc_len), 0x30,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_crc_seed,
        { "F_CRC_Seed", "pn_io.ps.f_prm_flag1.f_crc_seed",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_crc_seed), 0x40,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag1_reserved,
      { "Reserved", "pn_io.ps.f_prm_flag1.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag2,
      { "F_Prm_Flag2", "pn_io.ps.f_prm_flag2",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag2_reserved,
      { "Reserved", "pn_io.ps.f_prm_flag2.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag2_f_block_id,
      { "F_Block_ID", "pn_io.ps.f_prm_flag2.f_block_id",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_block_id), 0x38,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_prm_flag2_f_par_version,
      { "F_Par_Version", "pn_io.ps.f_prm_flag2.f_par_version",
        FT_UINT8, BASE_HEX, VALS(pn_io_f_par_version), 0xC0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_wd_time,
      { "F_WD_Time", "pn_io.ps.f_wd_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_ipar_crc,
        { "F_iPar_CRC", "pn_io.ps.f_ipar_crc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_par_crc,
        { "F_Par_CRC", "pn_io.ps.f_par_crc",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_dest_adr,
        { "F_Dest_Add", "pn_io.ps.f_dest_add",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_ps_f_src_adr,
        { "F_Source_Add", "pn_io.ps.f_source_add",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* profidrive parameter access */
    { &hf_pn_io_profidrive_request_reference,
      { "RequestReference", "pn_io.profidrive.parameter.request_reference",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_request_id,
      { "RequestID", "pn_io.profidrive.parameter.request_id",
        FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_request_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_do_id,
      { "DO", "pn_io.profidrive.parameter.do",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_no_of_parameters,
      { "NoOfParameters", "pn_io.profidrive.parameter.no_of_parameters",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_attribute,
      { "Attribute", "pn_io.profidrive.parameter.attribute",
        FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_attribute_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_no_of_elems,
      { "NoOfElements", "pn_io.profidrive.parameter.no_of_elems",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_number,
      { "Parameter", "pn_io.profidrive.parameter.number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_subindex,
      { "Index", "pn_io.profidrive.parameter.index",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_response_id,
      { "ResponseID", "pn_io.profidrive.parameter.response_id",
        FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_response_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_format,
      { "Format", "pn_io.profidrive.parameter.format",
        FT_UINT8, BASE_HEX, VALS(pn_io_profidrive_format_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_error,
      { "Error Number", "pn_io.profidrive.parameter.error_num",
        FT_UINT16, BASE_HEX, VALS(pn_io_profidrive_parameter_resp_errors), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_error_sub,
      { "Error Subindex", "pn_io.profidrive.parameter.error_subindex",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_no_of_values,
      { "NoOfValues", "pn_io.profidrive.parameter.no_of_values",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_byte,
      { "Value", "pn_io.profidrive.parameter.value_b",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_word,
      { "Value", "pn_io.profidrive.parameter.value_w",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_dword,
      { "Value", "pn_io.profidrive.parameter.value_dw",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_float,
      { "Value", "pn_io.profidrive.parameter.value_float",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_profidrive_param_value_string,
      { "Value", "pn_io.profidrive.parameter.value_str",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_rs_alarm_info_reserved_8_15,
      { "RSAlarmInfo.Reserved2", "pn_io.rs_alarm_info_reserved_8_15",
        FT_UINT16, BASE_HEX, NULL, 0x0FF00,
        NULL, HFILL }
    },
    { &hf_pn_io_rs_alarm_info_reserved_0_7,
      { "RSAlarmInfo.Reserved1", "pn_io.rs_alarm_info_reserved_0_7",
        FT_UINT16, BASE_HEX, NULL, 0x000FF,
        NULL, HFILL }
    },
    { &hf_pn_io_rs_alarm_info,
        { "RS Alarm Info", "pn_io.rs_alarm_info",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_event_info,
        { "RS Event Info", "pn_io.rs_event_info",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_event_block,
        { "RS Event Block", "pn_io.rs_event_block",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_adjust_block,
        { "RS Adjust Block", "pn_io.rs_adjust_block",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_event_data_extension,
        { "RS Event Data Extension", "pn_io.rs_event_data_extension",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_number_of_rs_event_info,
        { "RSEventInfo.NumberOfEntries", "pn_io.number_of_rs_event_info",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_block_type,
        { "RS Block Type", "pn_io.rs_block_type",
          FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_rs_block_type), 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_block_length,
        { "RS Block Length", "pn_io.rs_block_length",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_specifier,
        { "RS_Specifier", "pn_io.rs_specifier",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_specifier_sequence,
        { "RS_Specifier.SequenceNumber", "pn_io.rs_specifier.sequence",
          FT_UINT16, BASE_HEX, NULL, 0x07FF,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_specifier_reserved,
        { "RS_Specifier.Reserved", "pn_io.rs_specifier_reserved",
          FT_UINT16, BASE_HEX, NULL, 0x3800,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_specifier_specifier,
        { "RS_Specifier.Specifier", "pn_io.rs_specifier.specifier",
          FT_UINT16, BASE_HEX, VALS(pn_io_rs_specifier_specifier), 0xC000,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_time_stamp,
      { "RS_TimeStamp", "pn_io.rs_time_stamp",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_rs_time_stamp_status,
        { "RS_TimeStamp.Status", "pn_io.rs_time_stamp.status",
          FT_UINT16, BASE_HEX, VALS(pn_io_rs_time_stamp_status), 0x0003,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_time_stamp_value,
        { "RS_TimeStamp.Value", "pn_io.rs_time_stamp.value",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_minus_error,
        { "RS_MinusError", "pn_io.rs_minus_error",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_plus_error,
        { "RS_PlusError", "pn_io.rs_plus_error",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_extension_block_type,
        { "RS_ExtensionBlockType", "pn_io.rs_extension_block_type",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_extension_block_length,
        { "RS_ExtensionBlockLength", "pn_io.rs_extension_block_length",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_reason_code,
        { "RS_ReasonCode", "pn_io.rs_reason_code",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_reason_code_reason,
        { "RS_ReasonCode.Reason", "pn_io.rs_reason_code.reason",
          FT_UINT32, BASE_HEX, VALS(pn_io_rs_reason_code_reason), 0x0000FFFF,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_reason_code_detail,
        { "RS_ReasonCode.Detail", "pn_io.rs_reason_code.detail",
          FT_UINT32, BASE_HEX, VALS(pn_io_rs_reason_code_detail), 0xFFFF0000,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_domain_identification,
        { "RS_DomainIdentification", "pn_io.rs_domain_identification",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_master_identification,
        { "RS_MasterIdentification", "pn_io.rs_master_identification",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_digital_input_current_value,
        { "SoE_DigitalInputCurrentValue", "pn_io.soe_digital_input_current_value",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_digital_input_current_value_value,
        { "SoE_DigitalInputCurrentValue.Value", "pn_io.soe_digital_input_current_value.value",
          FT_UINT16, BASE_HEX, VALS(pn_io_soe_digital_input_current_value_value), 0x0001,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_digital_input_current_value_reserved,
        { "SoE_DigitalInputCurrentValue.Reserved", "pn_io.soe_digital_input_current_value.reserved",
          FT_UINT16, BASE_HEX, NULL, 0xFFFE,
          NULL, HFILL }
    },
    { &hf_pn_io_am_device_identification,
        { "AM_DeviceIdentification", "pn_io.am_device_identification",
          FT_UINT64, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_am_device_identification_device_sub_id,
        { "AM_DeviceIdentification.DeviceSubID", "pn_io.am_device_identification.device_sub_id",
          FT_UINT64, BASE_HEX, NULL, 0x000000000000FFFF,
          NULL, HFILL }
    },
    { &hf_pn_io_am_device_identification_device_id,
        { "AM_DeviceIdentification.DeviceID", "pn_io.am_device_identification.device_id",
          FT_UINT64, BASE_HEX, NULL, 0x00000000FFFF0000,
          NULL, HFILL }
    },
    { &hf_pn_io_am_device_identification_vendor_id,
        { "AM_DeviceIdentification.VendorID", "pn_io.am_device_identification.vendor_id",
          FT_UINT64, BASE_HEX, NULL, 0x0000FFFF00000000,
          NULL, HFILL }
    },
    { &hf_pn_io_am_device_identification_organization,
        { "AM_DeviceIdentification.Organization", "pn_io.am_device_identification.organization",
          FT_UINT64, BASE_HEX, NULL, 0xFFFF000000000000,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_adjust_info,
        { "RS Adjust Info", "pn_io.rs_adjust_info",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_max_scan_delay,
        { "SoE_MaxScanDelay", "pn_io.soe_max_scan_delay",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_adjust_specifier,
        { "SoE_AdjustSpecifier", "pn_io.soe_adjust_specifier",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_adjust_specifier_reserved,
        { "SoE_AdjustSpecifier.Reserved", "pn_io.soe_adjust_specifier.reserved",
          FT_UINT8, BASE_HEX, NULL, 0x3F,
          NULL, HFILL }
    },
    { &hf_pn_io_soe_adjust_specifier_incident,
        { "SoE_AdjustSpecifier.Incident", "pn_io.soe_adjust_specifier.incident",
          FT_UINT8, BASE_HEX, VALS(pn_io_soe_adjust_specifier_incident), 0xC0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_properties,
        { "RSProperties", "pn_io.rs_properties",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_properties_alarm_transport,
        { "RSProperties", "pn_io.rs_properties",
          FT_UINT32, BASE_HEX, VALS(pn_io_rs_properties_alarm_transport), 0x00000001,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_properties_reserved1,
        { "RSProperties.Reserved1", "pn_io.rs_properties.reserved1",
          FT_UINT32, BASE_HEX, NULL, 0x00FFFFFE,
          NULL, HFILL }
    },
    { &hf_pn_io_rs_properties_reserved2,
        { "RSProperties.Reserved2", "pn_io.rs_properties.reserved2",
          FT_UINT32, BASE_HEX, NULL, 0xFF000000,
          NULL, HFILL }
    },
    { &hf_pn_io_asset_management_info,
      { "Asset Management Info", "pn_io.asset_management_info",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_number_of_asset_management_info,
      { "AssetManagementInfo.NumberOfEntries", "pn_io.number_of_asset_management_info",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_im_uniqueidentifier,
      { "IM_UniqueIdentifier", "pn_io.IM_UniqueIdentifier",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_structure,
      { "AM_Location.Structure", "pn_io.am_location.structure",
         FT_UINT8, BASE_HEX, VALS(pn_io_am_location_structure_vals), 0x0,
         NULL, HFILL }
    },
    { &hf_pn_io_am_location,
      { "AM_Location", "pn_io.am_location",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_0,
      { "AM_Location Level 0", "pn_io.am_location.level_0",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_1,
      { "AM_Location Level 1", "pn_io.am_location.level_1",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_2,
      { "AM_Location Level 2", "pn_io.am_location.level_2",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_3,
      { "AM_Location Level 3", "pn_io.am_location.level_3",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_4,
      { "AM_Location Level 4", "pn_io.am_location.level_4",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_5,
      { "AM_Location Level 5", "pn_io.am_location.level_5",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_6,
      { "AM_Location Level 6", "pn_io.am_location.level_6",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_7,
      { "AM_Location Level 7", "pn_io.am_location.level_7",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_8,
      { "AM_Location Level 8", "pn_io.am_location.level_8",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_9,
      { "AM_Location Level 9", "pn_io.am_location.level_9",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_10,
      { "AM_Location Level 10", "pn_io.am_location.level_10",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_level_11,
      { "AM_Location Level 11", "pn_io.am_location.level_11",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_am_location_level_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_reserved1,
      { "AM_Location.Reserved1", "pn_io.am_location.reserved1",
        FT_UINT8, BASE_HEX, VALS(pn_io_am_location_reserved_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_reserved2,
      { "AM_Location.Reserved2", "pn_io.am_location.reserved2",
        FT_UINT16, BASE_HEX, VALS(pn_io_am_location_reserved_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_reserved3,
      { "AM_Location.Reserved3", "pn_io.am_location.reserved3",
        FT_UINT16, BASE_HEX, VALS(pn_io_am_location_reserved_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_reserved4,
      { "AM_Location.Reserved4", "pn_io.am_location.reserved4",
        FT_UINT16, BASE_HEX, VALS(pn_io_am_location_reserved_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_beginslotnum,
      { "AM_Location.BeginSlotNumber", "pn_io.slot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_beginsubslotnum,
      { "AM_Location.BeginSubSlotNumber", "pn_io.subslot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_endslotnum,
      { "AM_Location.EndSlotNumber", "pn_io.slot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_location_endsubslotnum,
      { "AM_Location.EndSubSlotNumber", "pn_io.subslot_nr",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_software_revision,
      { "AM Software Revision", "pn_io.am_software_revision",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_hardware_revision,
      { "AM Hardware Revision", "pn_io.am_hardware_revision",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_type_identification,
      { "AM Type Identification", "pn_io.am_type_identification",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_am_reserved,
      { "AM Reserved", "pn_io.am_reserved",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_mau_type_extension,
    { "MAUTypeExtension", "pn_io.mau_type_extension",
        FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_mau_type_extension), 0x0,
        NULL, HFILL }
    },
    { &hf_pn_io_pe_operational_mode,
    { "PE_OperationalMode", "pn_io.pe_operationalmode",
       FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(pn_io_pe_operational_mode), 0x0,
       NULL, HFILL }
    },
    };

    static gint *ett[] = {
        &ett_pn_io,
        &ett_pn_io_block,
        &ett_pn_io_block_header,
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
        &ett_pn_FrameDataProperties,
        &ett_pn_io_ar_info,
        &ett_pn_io_ar_data,
        &ett_pn_io_ir_begin_end_port,
        &ett_pn_io_ir_tx_phase,
        &ett_pn_io_ir_rx_phase,
        &ett_pn_io_subframe_data,
        &ett_pn_io_SFIOCRProperties,
        &ett_pn_io_frame_defails,
        &ett_pn_io_profisafe_f_parameter,
        &ett_pn_io_profisafe_f_parameter_prm_flag1,
        &ett_pn_io_profisafe_f_parameter_prm_flag2,
        &ett_pn_io_profidrive_parameter_request,
        &ett_pn_io_profidrive_parameter_response,
        &ett_pn_io_profidrive_parameter_address,
        &ett_pn_io_profidrive_parameter_value,
        &ett_pn_io_GroupProperties,
        &ett_pn_io_rs_alarm_info,
        &ett_pn_io_rs_event_info,
        &ett_pn_io_rs_event_block,
        &ett_pn_io_rs_adjust_block,
        &ett_pn_io_rs_event_data_extension,
        &ett_pn_io_rs_specifier,
        &ett_pn_io_rs_time_stamp,
        &ett_pn_io_am_device_identification,
        &ett_pn_io_rs_reason_code,
        &ett_pn_io_soe_digital_input_current_value,
        &ett_pn_io_rs_adjust_info,
        &ett_pn_io_soe_adjust_specifier,
        &ett_pn_io_asset_management_info,
        &ett_pn_io_asset_management_block,
        &ett_pn_io_am_location,
        &ett_pn_io_sr_properties,
        &ett_pn_io_line_delay,
        &ett_pn_io_counter_status,
        &ett_pn_io_dcp_boundary,
        &ett_pn_io_peer_to_peer_boundary,
        &ett_pn_io_mau_type_extension,
        &ett_pn_io_pe_operational_mode,
		&ett_pn_io_neighbor,
		&ett_pn_io_tsn_domain_vid_config,
        &ett_pn_io_tsn_domain_port_config,
        &ett_pn_io_tsn_domain_queue_config,
        &ett_pn_io_tsn_domain_port_ingress_rate_limiter,
        &ett_pn_io_tsn_domain_queue_rate_limiter,
        &ett_pn_io_time_sync_properties,
		&ett_pn_io_tsn_domain_port_id
    };

    static ei_register_info ei[] = {
        { &ei_pn_io_block_version, { "pn_io.block_version.not_implemented", PI_UNDECODED, PI_WARN, "Block version not implemented yet!", EXPFILL }},
        { &ei_pn_io_ar_info_not_found, { "pn_io.ar_info_not_found", PI_UNDECODED, PI_NOTE, "IODWriteReq: AR information not found!", EXPFILL }},
        { &ei_pn_io_block_length, { "pn_io.block_length.invalid", PI_UNDECODED, PI_WARN, "Block length invalid!", EXPFILL }},
        { &ei_pn_io_unsupported, { "pn_io.profidrive.parameter.format.invalid", PI_UNDECODED, PI_WARN, "Unknown Formatvalue", EXPFILL }},
        { &ei_pn_io_mrp_instances, { "pn_io.mrp_Number_MrpInstances.invalid", PI_UNDECODED, PI_WARN, "Number of MrpInstances invalid", EXPFILL }},
        { &ei_pn_io_frame_id, { "pn_io.frame_id.changed", PI_UNDECODED, PI_WARN, "FrameID changed", EXPFILL }},
        { &ei_pn_io_iocr_type, { "pn_io.iocr_type.unknown", PI_UNDECODED, PI_WARN, "IOCRType undecoded!", EXPFILL }},
        { &ei_pn_io_localalarmref, { "pn_io.localalarmref.changed", PI_UNDECODED, PI_WARN, "AlarmCRBlockReq: local alarm ref changed", EXPFILL }},
        { &ei_pn_io_nr_of_tx_port_groups, { "pn_io.nr_of_tx_port_groups.not_allowed", PI_PROTOCOL, PI_WARN, "Not allowed value of NumberOfTxPortGroups", EXPFILL }},
        { &ei_pn_io_max_recursion_depth_reached, { "pn_io.max_recursion_depth_reached", PI_PROTOCOL, PI_WARN, "Maximum allowed recursion depth reached - stopping dissection", EXPFILL }}
    };

    module_t *pnio_module;
    expert_module_t* expert_pn_io;

    proto_pn_io = proto_register_protocol ("PROFINET IO", "PNIO", "pn_io");

    /* Register by name */
    register_dissector("pnio", dissect_PNIO_heur, proto_pn_io);

    /* Created to remove Decode As confusion */
    proto_pn_io_device = proto_register_protocol_in_name_only("PROFINET IO (Device)", "PNIO (Device Interface)", "pn_io_device", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_controller = proto_register_protocol_in_name_only("PROFINET IO (Controller)", "PNIO (Controller Interface)", "pn_io_controller", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_supervisor = proto_register_protocol_in_name_only("PROFINET IO (Supervisor)", "PNIO (Supervisor Interface)", "pn_io_supervisor", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_parameterserver = proto_register_protocol_in_name_only("PROFINET IO (Parameter Server)", "PNIO (Parameter Server Interface)", "pn_io_parameterserver", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_implicitar = proto_register_protocol_in_name_only("PROFINET IO (Implicit Ar)", "PNIO (Implicit Ar)", "pn_io_implicitar", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_apdu_status = proto_register_protocol_in_name_only("PROFINET IO (Apdu Status)", "PNIO (Apdu Status)", "pn_io_apdu_status", proto_pn_io, FT_PROTOCOL);
    proto_pn_io_time_aware_status = proto_register_protocol_in_name_only("PROFINET IO (Time Aware Status)", "PNIO (Time Aware Status)", "pn_io_time_aware_status", proto_pn_io, FT_PROTOCOL);

    proto_register_field_array (proto_pn_io, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    expert_pn_io = expert_register_protocol(proto_pn_io);
    expert_register_field_array(expert_pn_io, ei, array_length(ei));

    /* Register preferences */
    pnio_module = prefs_register_protocol(proto_pn_io, NULL);
    prefs_register_bool_preference(pnio_module, "pnio_ps_selection",
        "Enable detailed PROFIsafe dissection",
        "Whether the PNIO dissector is allowed to use detailed PROFIsafe dissection of cyclic data frames",
        &pnio_ps_selection);
    prefs_register_directory_preference(pnio_module, "pnio_ps_networkpath",
        "Configuration GSD-File Networkpath",                 /* Title */
        "Select your Networkpath to your GSD-Files.",         /* Descreption */
        &pnio_ps_networkpath);                                /* Variable to save the GSD-File networkpath */

    /* subdissector code */
    register_dissector("pn_io", dissect_PNIO_heur, proto_pn_io);
    heur_pn_subdissector_list = register_heur_dissector_list("pn_io", proto_pn_io);

    /* Initialise RTC1 dissection */
    init_pn_io_rtc1(proto_pn_io);

    /* Initialise RSI dissection */
    init_pn_rsi(proto_pn_io);

    /* Init functions of PNIO protocol */
    register_init_routine(pnio_setup);

    /* Cleanup functions of PNIO protocol */
    register_cleanup_routine(pnio_cleanup);

    register_conversation_filter("pn_io", "PN-IO AR", pn_io_ar_conv_valid, pn_io_ar_conv_filter);
    register_conversation_filter("pn_io", "PN-IO AR (with data)", pn_io_ar_conv_valid, pn_io_ar_conv_data_filter);
}


void
proto_reg_handoff_pn_io (void)
{
    /* Register the protocols as dcerpc */
    dcerpc_init_uuid (proto_pn_io_device, ett_pn_io, &uuid_pn_io_device, ver_pn_io_device, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io_controller, ett_pn_io, &uuid_pn_io_controller, ver_pn_io_controller, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io_supervisor, ett_pn_io, &uuid_pn_io_supervisor, ver_pn_io_supervisor, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io_parameterserver, ett_pn_io, &uuid_pn_io_parameterserver, ver_pn_io_parameterserver, pn_io_dissectors, hf_pn_io_opnum);
    dcerpc_init_uuid (proto_pn_io_implicitar, ett_pn_io, &uuid_pn_io_implicitar, ver_pn_io_implicitar, pn_io_dissectors, hf_pn_io_opnum);

    heur_dissector_add("pn_rt", dissect_PNIO_heur, "PROFINET IO", "pn_io_pn_rt", proto_pn_io, HEURISTIC_ENABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
