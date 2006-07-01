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

static int hf_pn_io_data = -1;

static int hf_pn_io_ar_type = -1;
static int hf_pn_io_cminitiator_macadd = -1;
static int hf_pn_io_cminitiator_objectuuid = -1;
static int hf_pn_io_ar_properties = -1;
static int hf_pn_io_ar_properties_state = -1;
static int hf_pn_io_ar_properties_supervisor_takeover_allowed = -1;
static int hf_pn_io_ar_properties_parametrization_server = -1;
static int hf_pn_io_ar_properties_data_rate = -1;
static int hf_pn_io_ar_properties_reserved_1 = -1;
static int hf_pn_io_ar_properties_device_access = -1;
static int hf_pn_io_ar_properties_companion_ar = -1;
static int hf_pn_io_ar_properties_reserved = -1;
static int hf_pn_io_ar_properties_pull_module_alarm_allowed = -1;

static int hf_pn_io_cminitiator_activitytimeoutfactor = -1;
static int hf_pn_io_cminitiator_udprtport = -1;
static int hf_pn_io_station_name_length = -1;
static int hf_pn_io_cminitiator_station_name = -1;

static int hf_pn_io_cmresponder_macadd = -1;
static int hf_pn_io_cmresponder_udprtport = -1;

static int hf_pn_io_iocr_type = -1;
static int hf_pn_io_iocr_reference = -1;
static int hf_pn_io_lt = -1;
static int hf_pn_io_iocr_properties = -1;
static int hf_pn_io_iocr_properties_rtclass = -1;
static int hf_pn_io_iocr_properties_reserved_1 = -1;
static int hf_pn_io_iocr_properties_media_redundancy = -1;
static int hf_pn_io_iocr_properties_reserved_2 = -1;
static int hf_pn_io_data_length = -1;
static int hf_pn_io_frame_id = -1;
static int hf_pn_io_send_clock_factor = -1;
static int hf_pn_io_reduction_ratio = -1;
static int hf_pn_io_phase = -1;
static int hf_pn_io_sequence = -1;
static int hf_pn_io_frame_send_offset = -1;
static int hf_pn_io_watchdog_factor = -1;
static int hf_pn_io_data_hold_factor = -1;
static int hf_pn_io_iocr_tag_header = -1;
static int hf_pn_io_iocr_multicast_mac_add = -1;
static int hf_pn_io_number_of_apis = -1;
static int hf_pn_io_number_of_io_data_objects = -1;
static int hf_pn_io_io_data_object_frame_offset = -1;
static int hf_pn_io_number_of_iocs = -1;
static int hf_pn_io_iocs_frame_offset = -1;

static int hf_pn_io_alarmcr_type = -1;
static int hf_pn_io_alarmcr_properties = -1;
static int hf_pn_io_alarmcr_properties_priority = -1;
static int hf_pn_io_alarmcr_properties_transport = -1;
static int hf_pn_io_alarmcr_properties_reserved = -1;

static int hf_pn_io_rta_timeoutfactor = -1;
static int hf_pn_io_rta_retries = -1;
static int hf_pn_io_localalarmref = -1;
static int hf_pn_io_maxalarmdatalength = -1;
static int hf_pn_io_alarmcr_tagheaderhigh = -1;
static int hf_pn_io_alarmcr_tagheaderlow = -1;

static int hf_pn_io_ar_uuid = -1;
static int hf_pn_io_target_ar_uuid = -1;
static int hf_pn_io_api_tree = -1;
static int hf_pn_io_module_tree = -1;
static int hf_pn_io_submodule_tree = -1;
static int hf_pn_io_io_data_object = -1;
static int hf_pn_io_io_cs = -1;
static int hf_pn_io_api = -1;
static int hf_pn_io_slot_nr = -1;
static int hf_pn_io_subslot_nr = -1;
static int hf_pn_io_index = -1;
static int hf_pn_io_seq_number = -1;
static int hf_pn_io_record_data_length = -1;
static int hf_pn_io_padding = -1;
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
static int hf_pn_io_control_block_properties = -1;

static int hf_pn_io_error_code = -1;
static int hf_pn_io_error_decode = -1;
static int hf_pn_io_error_code1 = -1;
static int hf_pn_io_error_code2 = -1;
static int hf_pn_io_error_code1_pniorw = -1;
static int hf_pn_io_error_code1_pnio = -1;

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
static int hf_pn_io_channel_properties_maintenance_required = -1;
static int hf_pn_io_channel_properties_maintenance_demanded = -1;
static int hf_pn_io_channel_properties_specifier = -1;
static int hf_pn_io_channel_properties_direction = -1;

static int hf_pn_io_channel_error_type = -1;
static int hf_pn_io_ext_channel_error_type = -1;
static int hf_pn_io_ext_channel_add_value = -1;

static int hf_pn_io_ptcp_subdomain_id = -1;
static int hf_pn_io_ir_data_id = -1;
static int hf_pn_io_reserved_interval_begin = -1;
static int hf_pn_io_reserved_interval_end = -1;
static int hf_pn_io_pllwindow = -1;
static int hf_pn_io_sync_send_factor = -1;
static int hf_pn_io_sync_properties = -1;
static int hf_pn_io_sync_frame_address = -1;
static int hf_pn_io_ptcp_timeout_factor = -1;

static int hf_pn_io_domain_boundary = -1;
static int hf_pn_io_multicast_boundary = -1;
static int hf_pn_io_adjust_properties = -1;
static int hf_pn_io_mau_type = -1;
static int hf_pn_io_port_state = -1;
static int hf_pn_io_propagation_delay_factor = -1;
static int hf_pn_io_number_of_peers = -1;
static int hf_pn_io_length_peer_port_id = -1;
static int hf_pn_io_peer_port_id = -1;
static int hf_pn_io_length_peer_chassis_id = -1;
static int hf_pn_io_peer_chassis_id = -1;
static int hf_pn_io_length_own_port_id = -1;
static int hf_pn_io_own_port_id = -1;
static int hf_pn_io_peer_macadd = -1;
static int hf_pn_io_media_type = -1;

static int hf_pn_io_ethertype = -1;
static int hf_pn_io_rx_port = -1;
static int hf_pn_io_frame_details = -1;
static int hf_pn_io_nr_of_tx_port_groups = -1;

static int hf_pn_io_subslot = -1;
static int hf_pn_io_number_of_slots = -1;
static int hf_pn_io_number_of_subslots = -1;
    
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
static gint ett_pn_io_subslot = -1;

static e_uuid_t uuid_pn_io_device = { 0xDEA00001, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_device = 1;

static e_uuid_t uuid_pn_io_controller = { 0xDEA00002, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_controller = 1;

static e_uuid_t uuid_pn_io_supervisor = { 0xDEA00003, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_supervisor = 1;

static e_uuid_t uuid_pn_io_parameterserver = { 0xDEA00004, 0x6C97, 0x11D1, { 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D } };
static guint16  ver_pn_io_parameterserver = 1;


static const value_string pn_io_block_type[] = {
	{ 0x0000, "Reserved" },
	{ 0x0001, "Alarm Notification High"},
	{ 0x0002, "Alarm Notification Low"},
	{ 0x0008, "WriteRecordReq"},
	{ 0x8008, "WriteRecordRes"},
	{ 0x0009, "ReadRecordReq"},
	{ 0x8009, "ReadRecordRes"},
	{ 0x0010, "DiagnosisBlock"},
	{ 0x0011, "MulticastConsumerInfoBlock"},
	{ 0x0012, "ExpectedIdentificationDataBlock"},
	{ 0x0013, "RealIdentificationData"},
	{ 0x0014, "SubstituteValue"},
	{ 0x0015, "RecordInputDataObjectElement"},
	{ 0x0016, "RecordOutputDataObjectElement"},
	{ 0x0017, "reserved"},
	{ 0x0018, "ARData"},
	{ 0x0019, "LogData"},
	{ 0x001A, "APIData"},
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
	{ 0x0030, "I&M0FilterData"},
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
	{ 0x0110, "IODBlockReq"},
	{ 0x8110, "IODBlockRes"},
	{ 0x0111, "IODBlockReq"},
	{ 0x8111, "IODBlockRes"},
	{ 0x0112, "IOXBlockReq"},
	{ 0x8112, "IOXBlockRes"},
	{ 0x0113, "IOXBlockReq"},
	{ 0x8113, "IOXBlockRes"},
	{ 0x0114, "ReleaseBlockReq"},
	{ 0x8114, "ReleaseBlockRes"},
	{ 0x0115, "ARRPCServerBlockReq"},
	{ 0x8115, "ARRPCServerBlockRes"},
	{ 0x0200, "PDPortDataCheck"},
	{ 0x0201, "PDevData"},
	{ 0x0202, "PDPortDataAdjust"},
	{ 0x0203, "PDSyncData"},
	{ 0x0204, "IsochronousModeData"},
	{ 0x0205, "PDIRData"},
	{ 0x0206, "PDIRGlobalData"},
	{ 0x0207, "PDIRFrameData"},
	{ 0x0209, "AdjustDomainBoundary"},
	{ 0x020A, "CheckPeers"},
	{ 0x020B, "CheckPropagationDelayFactor"},
	{ 0x020C, "Checking MAUType"},
	{ 0x020E, "Adjusting MAUType"},
	{ 0x020F, "PDPortDataReal"},
	{ 0x0210, "AdjustMulticastBoundary"},
	{ 0x0211, "Adjusting MRP interface data"},
	{ 0x0212, "Reading MRP interface data"},
	{ 0x0213, "Checking MRP interface data"},
	{ 0x0214, "Adjusting MRP port data"},
	{ 0x0215, "Reading MRP port data"},
	{ 0x0216, "Media redundancy manager parameters"},
	{ 0x0217, "Media redundancy client parameters"},
	{ 0x0218, "Media redundancy RT mode for manager"},
	{ 0x0219, "Media redundancy ring state data"},
	{ 0x021A, "Media redundancy RT ring state data"},
	{ 0x021B, "AdjustPortState"},
	{ 0x021C, "Checking PortState"},
	{ 0x021D, "Media redundancy RT mode for clients"},
	{ 0x0220, "PDPortFODataReal"},
	{ 0x0221, "Reading real fiber optic manufacturerspecific data"},
	{ 0x0222, "PDPortFODataAdjust"},
	{ 0x0223, "PDPortFODataCheck"},
	{ 0x0230, "PDNCDataCheck"},
	{ 0x0400, "MultipleBlockHeader"},
	{ 0x0F00, "MaintenanceBlock"},
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
    /*0x0013 - 0x001E reserved */
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

/*
XXX: the next 2 are dependant on error_code and error_decode

e.g.: CL-RPC error:
error_code .. see above
error_decode .. 0x81
error_code1 .. 0x69
error_code2 ..
1 RPC_ERR_REJECTED
2 RPC_ERR_FAULTED
3 RPC_ERR_TIMEOUT
4 RPC_ERR_IN_ARGS
5 RPC_ERR_OUT_ARGS
6 RPC_ERR_DECODE
7 RPC_ERR_PNIO_OUT_ARGS
8 Application Timeout
*/

/* XXX: add some more error codes here */
static const value_string pn_io_error_code1[] = {
	{ 0x00, "OK" },
    { 0, NULL }
};

/* XXX: add some more error codes here */
static const value_string pn_io_error_code2[] = {
	{ 0x00, "OK" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pniorw[] = {
	{ 0x0a /* 10*/, "application" },
	{ 0x0b /* 11*/, "access" },
	{ 0x0c /* 12*/, "resource" },
	{ 0x0d /* 13*/, "user specific(13)" },
	{ 0x0e /* 14*/, "user specific(14)" },
	{ 0x0f /* 15*/, "user specific(15)" },
    { 0, NULL }
};

static const value_string pn_io_error_code1_pnio[] = {
	{ 0x00 /*  0*/, "Reserved" },
	{ 0x01 /*  1*/, "Connect: Faulty ARBlockReq" },
	{ 0x02 /*  2*/, "Connect: Faulty IOCRBlockReq" },
	{ 0x03 /*  3*/, "Connect: Faulty ExpectedSubmoduleBlockReq" },
	{ 0x04 /*  4*/, "Connect: Faulty AlarmCRBlockReq" },
	{ 0x05 /*  5*/, "Connect: Faulty PrmServerBlockReq" },

	{ 0x14 /* 20*/, "IODControl: Faulty ControlBlockConnect" },
	{ 0x15 /* 21*/, "IODControl: Faulty ControlBlockPlug" },
	{ 0x16 /* 22*/, "IOXControl: Faulty ControlBlock after a connect est." },
	{ 0x17 /* 23*/, "IOXControl: Faulty ControlBlock a plug alarm" },

    { 0x28 /* 40*/, "Release: Faulty ReleaseBlock" },

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
	{ 0x00000000, "Backup" },
	{ 0x00000001, "Primary" },
    /*0x00000002 - 0x00000007 reserved */
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

static const value_string pn_io_arproperties_data_rate[] = {
	{ 0x00000000, "at least 100 MB/s or more" },
	{ 0x00000001, "100 MB/s" },
	{ 0x00000002, "1 GB/s" },
	{ 0x00000003, "10 GB/s" },
    { 0, NULL }
};

static const value_string pn_io_arproperties_device_access[] = {
	{ 0x00000000, "only submodules from ExtendedSubmoduleBlock" },
	{ 0x00000001, "Submodule is controlled by IO device appl." },
    { 0, NULL }
};

static const value_string pn_io_arproperties_companion_ar[] = {
	{ 0x00000000, "Single AR or second AR of a companion pair" },
	{ 0x00000001, "First AR of a companion pair and a companion AR shall follow" },
	{ 0x00000002, "Companion AR" },
	{ 0x00000003, "Reserved" },
    { 0, NULL }
};

static const value_string pn_io_arproperties_pull_module_alarm_allowed[] = {
	{ 0x00000000, "AlarmType(=Pull) shall signal pulling of submodule and module" },
	{ 0x00000001, "AlarmType(=Pull) shall signal pulling of submodule" },
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
	{ 0x0001, "Wrong (WR)" },
	{ 0x0001, "NoSubmodule (NO)" },
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

static const value_string pn_io_index[] = {
    /*0x0008 - 0x7FFF user specific */
    
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
	{ 0x802D, "Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTA" },
	{ 0x802E, "Expected PDSyncData for one subslot with SyncID value 0 for PTCPoverRTC" },
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
    /*0x8071 - 0xAFEF reserved */
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
    /*0xB000 - 0xBFFF reserved for profiles */

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
    /*0xE041 - 0xEBFF reserved */
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
    /*0xF843 - 0xFBFF reserved */
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
    /*0x800A - 0x8FFF reserved */
    /*0x9000 - 0x9FFF reserved for profile */
    /*0xA000 - 0xFFFF reserved */
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

static const value_string pn_io_channel_properties_specifier[] = {
	{ 0x0000, "All subsequent disappears" },
	{ 0x0001, "Appears" },
	{ 0x0002, "Disappears" },
	{ 0x0003, "disappears but other remain" },
    { 0, NULL }
};

static const value_string pn_io_channel_properties_direction[] = {
	{ 0x0000, "manufacturer specific" },
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
	{ 0x0000, "unknown" },
	{ 0x0001, "Copper cable" },
	{ 0x0002, "Fiber optic cable" },
	{ 0x0003, "Radio communication" },
    /*0x0004 - 0xFFFF reserved */
    { 0, NULL }
};



static int dissect_blocks(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep);




/* dissect a 6 byte MAC address */
static int 
dissect_MAC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint8 *pdata)
{
    guint8 data[6];

    tvb_memcpy(tvb, data, offset, 6);
    if(tree)
        proto_tree_add_ether(tree, hfindex, tvb, offset, 6, data);

    if (pdata)
        memcpy(pdata, data, 6);

    return offset + 6;
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
    int bytemask = (drep[0] & 0x10) ? 3 : 0;
    const value_string *error_code1_vals;



    /* status */
    sub_item = proto_tree_add_item(tree, hf_pn_io_status, tvb, offset, 0, FALSE);
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
        break;
    case(0x81): /* PNIO */
	    dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep, 
                            hf_pn_io_error_code1_pnio, &u8ErrorCode1);
        error_code1_vals = pn_io_error_code1_pnio;
        break;
    default:
	    dissect_dcerpc_uint8(tvb, offset+(2^bytemask), pinfo, sub_tree, drep, 
                            hf_pn_io_error_code1, &u8ErrorCode1);
        /*expert_add_info_format(pinfo, sub_item, PI_UNDECODED, PI_WARN,
			"Unknown ErrorDecode 0x%x", u8ErrorDecode);*/
        error_code1_vals = pn_io_error_code1;
    }

    /* XXX - this has to be decode specific too */
	dissect_dcerpc_uint8(tvb, offset+(3^bytemask), pinfo, sub_tree, drep, 
                        hf_pn_io_error_code2, &u8ErrorCode2);

    offset +=4;

    if(u8ErrorCode == 0 && u8ErrorDecode == 0 && u8ErrorCode1 == 0 && u8ErrorCode2 == 0) {
        proto_item_append_text(sub_item, ": OK");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", OK");
    } else {
        proto_item_append_text(sub_item, ": Error Code: \"%s\", Decode: \"%s\", Code1: \"%s\" Code2: 0x%x", 
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            val_to_str(u8ErrorCode1, error_code1_vals, "(0x%x)"),
            u8ErrorCode2);
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Error Code: %s, Decode: %s, Code1: 0x%x Code2: 0x%x",
            val_to_str(u8ErrorCode, pn_io_error_code, "(0x%x)"),
            val_to_str(u8ErrorDecode, pn_io_error_decode, "(0x%x)"),
            u8ErrorCode1,
            u8ErrorCode2);
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
	sub_item = proto_tree_add_item(tree, hf_pn_io_alarm_specifier, tvb, offset, 2, FALSE);
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

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Slot: 0x%x/0x%x", 
        val_to_str(u16AlarmType, pn_io_alarm_type, "(0x%x)"),
        u16SlotNr, u16SubslotNr);

    return offset;
}


/* dissect the alarm notification block */
static int
dissect_AlarmNotification_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint16 body_length)
{
    guint32 u32ModuleIdentNumber;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16UserStructureIdentifier;
    guint16 u16ChannelNumber;
    guint16 u16ChannelProperties;
    guint16 u16ChannelErrorType;
    guint16 u16ExtChannelErrorType;
    guint32 u32ExtChannelAddValue;
	proto_item *sub_item;
	proto_tree *sub_tree;

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_str(pinfo->cinfo, COL_INFO, ", Alarm Notification");

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, item, drep);
    
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_user_structure_identifier, &u16UserStructureIdentifier);

    proto_item_append_text(item, ", Ident:0x%x, SubIdent:0x%x, USI:0x%x",
        u32ModuleIdentNumber, u32SubmoduleIdentNumber, u16UserStructureIdentifier);

    switch(u16UserStructureIdentifier) {
    case(0x8002):   /* ExtChannelDiagnosisData */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_number, &u16ChannelNumber);

        sub_item = proto_tree_add_item(tree, hf_pn_io_channel_properties, tvb, offset, 2, FALSE);
	    sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_channel_properties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_direction, &u16ChannelProperties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_specifier, &u16ChannelProperties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_maintenance_demanded, &u16ChannelProperties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_maintenance_required, &u16ChannelProperties);
        dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_accumulative, &u16ChannelProperties);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_channel_properties_type, &u16ChannelProperties);

        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_channel_error_type, &u16ChannelErrorType);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_error_type, &u16ExtChannelErrorType);
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_ext_channel_add_value, &u32ExtChannelAddValue);
        break;
    default:
        /* XXX - dissect AlarmItem */
        body_length -= 22;
        sub_item = proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, body_length, "data", 
            "Alarm Item Data: %u bytes", body_length);
        if(u16UserStructureIdentifier >= 0x8000) {
            expert_add_info_format(pinfo, sub_item, PI_UNDECODED, PI_WARN,
			    "Unknown UserStructureIdentifier 0x%x", u16UserStructureIdentifier);
        }

        offset += body_length;
    }

    return offset;
}


/* dissect the RealIdentificationData block */
static int
dissect_RealIdentificationData_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint8 u8BlockVersionLow)
{
    guint16 u16NumberOfAPIs = 1;
    guint32 u32Api;
    guint16 u16NumberOfSlots;
    guint16 u16SlotNr;
    guint32 u32ModuleIdentNumber;
    guint16 u16NumberOfSubslots;
    guint32 u32SubmoduleIdentNumber;
    guint16 u16SubslotNr;
	proto_item *subslot_item;
	proto_tree *subslot_tree;
    
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
            /* SlotNumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                                hf_pn_io_slot_nr, &u16SlotNr);
            /* ModuleIdentNumber */
	        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                                hf_pn_io_module_ident_number, &u32ModuleIdentNumber);
            /* NumberOfSubslots */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                                hf_pn_io_number_of_subslots, &u16NumberOfSubslots);

            proto_item_append_text(item, ", Subslots:%u", u16NumberOfSubslots);

            while(u16NumberOfSubslots--) {
                subslot_item = proto_tree_add_item(tree, hf_pn_io_subslot, tvb, offset, 6, FALSE);
	            subslot_tree = proto_item_add_subtree(subslot_item, ett_pn_io_subslot);

                /* SubslotNumber */
	            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, subslot_tree, drep, 
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
	            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, subslot_tree, drep, 
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);

                proto_item_append_text(subslot_item, ": Number:0x%x, Ident:%u",
                    u16SubslotNr, u32SubmoduleIdentNumber);
            }
        }
    }

    return offset;
}


/* dissect the alarm acknowledge block */
static int
dissect_Alarm_ack_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_str(pinfo->cinfo, COL_INFO, ", Alarm Ack");

    offset = dissect_Alarm_header(tvb, offset, pinfo, tree, item, drep);

    offset = dissect_Alarm_specifier(tvb, offset, pinfo, tree, drep);

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

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
    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_index, u16Index);

    proto_item_append_text(item, ": Seq:%u, Api:0x%x, Slot:0x%x/0x%x",
        u16SeqNr, u32Api, u16SlotNr, u16SubslotNr);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Api:0x%x, Slot:0x%x/0x%x, Index:%s",
            u32Api, u16SlotNr, u16SubslotNr, 
            val_to_str(*u16Index, pn_io_index, "(0x%x)"));

    return offset;
}


/* dissect the read/write request block */
static int
dissect_ReadWrite_rqst_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen)
{
    e_uuid_t aruuid;
    e_uuid_t null_uuid;

    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_record_data_length, u32RecDataLen);

    memset(&null_uuid, 0, sizeof(e_uuid_t));
    if(memcmp(&aruuid, &null_uuid, sizeof (e_uuid_t)) == 0) {
        offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_target_ar_uuid, &aruuid);
    }

    proto_item_append_text(item, ", Len:%u", *u32RecDataLen);

    if (check_col(pinfo->cinfo, COL_INFO) && *u32RecDataLen != 0)
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the read/write response block */
static int
dissect_ReadWrite_resp_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen)
{
    e_uuid_t aruuid;
    guint16 u16AddVal1;
    guint16 u16AddVal2;


    offset = dissect_ReadWrite_header(tvb, offset, pinfo, tree, item, drep, u16Index, &aruuid);

	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_record_data_length, u32RecDataLen);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_add_val1, &u16AddVal1);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_add_val2, &u16AddVal2);

    proto_item_append_text(item, ", Len:%u, AddVal1:%u, AddVal2:%u", 
        *u32RecDataLen, u16AddVal1, u16AddVal2);

    if (check_col(pinfo->cinfo, COL_INFO) && *u32RecDataLen != 0)
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %u bytes",
            *u32RecDataLen);

    return offset;
}


/* dissect the control/connect block */
static int
dissect_ControlConnect_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    e_uuid_t    ar_uuid;
    guint16     u16SessionKey;
	proto_item *sub_item;
	proto_tree *sub_tree;
    guint16     u16Command;
    guint16     u16Properties;


    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &ar_uuid);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_sessionkey, &u16SessionKey);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_reserved16, NULL);

    sub_item = proto_tree_add_item(tree, hf_pn_io_control_command, tvb, offset, 2, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_control_command);

    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_prmend, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_applready, &u16Command);
    dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_release, &u16Command);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
                        hf_pn_io_control_command_done, &u16Command);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep,
                        hf_pn_io_control_block_properties, &u16Properties);

    proto_item_append_text(item, ": Session:%u, Command:", u16SessionKey);

    if(u16Command & 0x0001) {
        proto_item_append_text(sub_item, ", ParameterEnd");
        proto_item_append_text(item, " ParameterEnd");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: ParameterEnd");
    }
    if(u16Command & 0x0002) {
        proto_item_append_text(sub_item, ", ApplicationReady");
        proto_item_append_text(item, " ApplicationReady");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: ApplicationReady");
    }
    if(u16Command & 0x0004) {
        proto_item_append_text(sub_item, ", Release");
        proto_item_append_text(item, " Release");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: Release");
    }
    if(u16Command & 0x0008) {
        proto_item_append_text(sub_item, ", Done");
        proto_item_append_text(item, ", Done");
        if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: Done");
    }

    proto_item_append_text(item, ", Properties:0x%x", u16Properties);

    return offset;
}


/* dissect the PDPortDataCheck/PDPortDataAdjust blocks */
static int
dissect_PDPortData_Check_Adjust_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

    /* SlotNumber */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Slot:0x%x/0x%x", u16SlotNr, u16SubslotNr);

    dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}



/* dissect the PDPortDataReal blocks */
static int
dissect_PDPortDataReal_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;
    guint8 u8LengthOwnPortID;
    char *pOwnPortID;
    guint8 u8NumberOfPeers;
    guint8 u8I;
    guint8 u8LengthPeerPortID;
    guint8 *pPeerPortID;
    guint8 u8LengthPeerChassisID;
    char *pPeerChassisID;
    guint32 u32PropagationDelayFactor;
    guint8 mac[6];
    guint16 u16MAUType;
    guint32 u32DomainBoundary;
    guint32 u32MulticastBoundary;
    guint16 u16PortState;
    guint32 u32MediaType;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

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
    tvb_memcpy(tvb, pOwnPortID, offset, u8LengthOwnPortID);
    pOwnPortID[u8LengthOwnPortID] = '\0';
    proto_tree_add_string (tree, hf_pn_io_own_port_id, tvb, offset, u8LengthOwnPortID, pOwnPortID);
    offset += u8LengthOwnPortID;

    /* NumberOfPeers */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_peers, &u8NumberOfPeers);
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
    u8I = u8NumberOfPeers;
    while(u8I--) {
        /* LengthPeerPortID */
	    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                            hf_pn_io_length_peer_port_id, &u8LengthPeerPortID);
        /* PeerPortID */
        pPeerPortID = ep_alloc(u8LengthPeerPortID+1);
        tvb_memcpy(tvb, pPeerPortID, offset, u8LengthPeerPortID);
        pPeerPortID[u8LengthPeerPortID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID, pPeerPortID);
        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
	    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        pPeerChassisID = ep_alloc(u8LengthPeerChassisID+1);
        tvb_memcpy(tvb, pPeerChassisID, offset, u8LengthPeerChassisID);
        pPeerChassisID[u8LengthPeerChassisID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_chassis_id, tvb, offset, u8LengthPeerChassisID, pPeerChassisID);
        offset += u8LengthPeerChassisID;

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

        /* PropagationDelayFactor */
	    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                            hf_pn_io_propagation_delay_factor, &u32PropagationDelayFactor);

        /* PeerMACAddress */
        offset = dissect_MAC(tvb, offset, pinfo, tree, 
                            hf_pn_io_peer_macadd, mac);
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

    /* MAUType */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_mau_type, &u16MAUType);
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
    /* MediaType */
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_media_type, &u32MediaType);

    proto_item_append_text(item, ": Slot:0x%x/0x%x, OwnPortID:%s, Peers:%u PortState:%s MediaType:%s", 
        u16SlotNr, u16SubslotNr, pOwnPortID, u8NumberOfPeers,
        val_to_str(u16PortState, pn_io_port_state, "0x%x"),
        val_to_str(u32MediaType, pn_io_media_type, "0x%x"));

    return offset;
}


/* dissect the AdjustDomainBoundary blocks */
static int
dissect_AdjustDomainBoundary_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint32 u32DomainBoundary;
    guint16 u16AdjustProperties;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

    /* Boundary */
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_domain_boundary, &u32DomainBoundary);
    /* AdjustProperties */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_adjust_properties, &u16AdjustProperties);

    proto_item_append_text(item, ": Boundary:0x%x, Properties:0x%x", 
        u32DomainBoundary, u16AdjustProperties);

    return offset;
}


/* dissect the AdjustMulticastBoundary blocks */
static int
dissect_AdjustMulticastBoundary_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint32 u32MulticastBoundary;
    guint16 u16AdjustProperties;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

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
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16MAUType;
    guint16 u16AdjustProperties;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

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
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16MAUType;


    /* MAUType */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_mau_type, &u16MAUType);

    proto_item_append_text(item, ": MAUType:%s", 
        val_to_str(u16MAUType, pn_io_mau_type, "0x%x"));

    return offset;
}


/* dissect the CheckPropagationDelayFactor block */
static int
dissect_CheckPropagationDelayFactor_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint32 u32PropagationDelayFactor;


    /* PropagationDelayFactor */
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_propagation_delay_factor, &u32PropagationDelayFactor);

    proto_item_append_text(item, ": PropagationDelayFactor:%uns", u32PropagationDelayFactor);

    return offset;
}


/* dissect the CheckPeers block */
static int
dissect_CheckPeers_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint8 u8NumberOfPeers;
    guint8 u8I;
    guint8 u8LengthPeerPortID;
    char *pPeerPortID;
    guint8 u8LengthPeerChassisID;
    char *pPeerChassisID;


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
        tvb_memcpy(tvb, pPeerPortID, offset, u8LengthPeerPortID);
        pPeerPortID[u8LengthPeerPortID] = '\0';
        proto_tree_add_string (tree, hf_pn_io_peer_port_id, tvb, offset, u8LengthPeerPortID, pPeerPortID);
        offset += u8LengthPeerPortID;

        /* LengthPeerChassisID */
	    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                            hf_pn_io_length_peer_chassis_id, &u8LengthPeerChassisID);
        /* PeerChassisID */
        pPeerChassisID = ep_alloc(u8LengthPeerChassisID+1);
        tvb_memcpy(tvb, pPeerChassisID, offset, u8LengthPeerChassisID);
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
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16PortState;
    guint16 u16AdjustProperties;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

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


/* dissect the PDSyncData block */
static int
dissect_PDSyncData_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
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


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

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

    return offset;
}


/* dissect the PDIRData block */
static int
dissect_PDIRData_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16SlotNr;
    guint16 u16SubslotNr;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

    /* SlotNumber */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_slot_nr, &u16SlotNr);
    /* Subslotnumber */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_subslot_nr, &u16SubslotNr);

    proto_item_append_text(item, ": Slot:0x%x/0x%x",
        u16SlotNr, u16SubslotNr);

    dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}


/* dissect the PDIRGlobalData block */
static int
dissect_PDIRGlobalData_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep)
{
    e_uuid_t uuid;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

    /* IRDataID */
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ir_data_id, &uuid);

    return offset;
}


/* dissect the PDIRFrameData block */
static int
dissect_PDIRFrameData_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint32 u32FrameSendOffset;
    guint16 u16DataLength;
    guint16 u16ReductionRatio;
    guint16 u16Phase;
    guint16 u16FrameID;
    guint16 u16Ethertype;
    guint8 u8RXPort;
    guint8 u8FrameDetails;
    guint8 u8NumberOfTxPortGroups;


    proto_tree_add_string_format(tree, hf_pn_io_padding, tvb, offset, 2, "padding", "Padding: 2 bytes");
    offset += 2;

    /* FrameSendOffset */
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_send_offset, &u32FrameSendOffset);
    /* DataLength */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_data_length, &u16DataLength);
    /* ReductionRatio */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_reduction_ratio, &u16ReductionRatio);
    /* Phase */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_phase, &u16Phase);
    /* FrameID */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_id, &u16FrameID);

    /* Ethertype */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ethertype, &u16Ethertype);
    /* RxPort */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_rx_port, &u8RXPort);
    /* FrameDetails */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_details, &u8FrameDetails);
    /* TxPortGroup */
	offset = dissect_dcerpc_uint8(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_nr_of_tx_port_groups, &u8NumberOfTxPortGroups);


    proto_item_append_text(item, ": Offset:%u, Len:%u, Ratio:%u, Phase:%u, FrameID:%u",
        u32FrameSendOffset, u16DataLength, u16ReductionRatio, u16Phase, u16FrameID);

    return offset;
}


/* dissect the DiagnosisBlock */
static int
dissect_DiagnosisBlock(tvbuff_t *tvb, int offset,
	packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint8 *drep _U_, guint16 length)
{

    /* XXX - how to decode this? */
    proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, length, "undecoded", "Undecoded Diagnosis Data: %d bytes", length);

    return offset;
}


/* dissect the ARBlockReq */
static int
dissect_ARBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16ARType;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint32 u32ARProperties;
    guint16 u16TimeoutFactor;
    guint16 u16UDPRTPort;
    guint16 u16NameLength;
    char *pStationName;
	proto_item *sub_item;
	proto_tree *sub_tree;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &uuid);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_cminitiator_macadd, mac);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_objectuuid, &uuid);

	sub_item = proto_tree_add_item(tree, hf_pn_io_ar_properties, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_ar_properties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_pull_module_alarm_allowed, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_reserved, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_companion_ar, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_device_access, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_reserved_1, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_data_rate, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_parametrization_server, &u32ARProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_supervisor_takeover_allowed, &u32ARProperties);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_ar_properties_state, &u32ARProperties);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_activitytimeoutfactor, &u16TimeoutFactor);   /* XXX - special values */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cminitiator_udprtport, &u16UDPRTPort);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_station_name_length, &u16NameLength);

    pStationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, pStationName, offset, u16NameLength);
    pStationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_cminitiator_station_name, tvb, offset, u16NameLength, pStationName);
    offset += u16NameLength;

    proto_item_append_text(item, ": %s, Session:%u, MAC:%02x:%02x:%02x:%02x:%02x:%02x, Port:0x%x, Station:%s",
        val_to_str(u16ARType, pn_io_ar_type, "0x%x"),
        u16SessionKey,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        u16UDPRTPort,
        pStationName);

    return offset;
}


/* dissect the ARBlockRes */
static int
dissect_ARBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16ARType;
    e_uuid_t uuid;
    guint16 u16SessionKey;
    guint8 mac[6];
    guint16 u16UDPRTPort;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_type, &u16ARType);
    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_ar_uuid, &uuid);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_sessionkey, &u16SessionKey);
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_cmresponder_macadd, mac);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_cmresponder_udprtport, &u16UDPRTPort);

    proto_item_append_text(item, ": %s, Session:%u, MAC:%02x:%02x:%02x:%02x:%02x:%02x, Port:0x%x",
        val_to_str(u16ARType, pn_io_ar_type, "0x%x"),
        u16SessionKey, 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        u16UDPRTPort);

    return offset;
}


/* dissect the IOCRBlockReq */
static int
dissect_IOCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16LT;
    guint32 u32IOCRProperties;
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


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_type, &u16IOCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_lt, &u16LT);

	sub_item = proto_tree_add_item(tree, hf_pn_io_iocr_properties, tvb, offset, 4, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_iocr_properties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_iocr_properties_reserved_2, &u32IOCRProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_iocr_properties_media_redundancy, &u32IOCRProperties);
	dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_iocr_properties_reserved_1, &u32IOCRProperties);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                        hf_pn_io_iocr_properties_rtclass, &u32IOCRProperties);

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
    offset = dissect_MAC(tvb, offset, pinfo, tree, 
                        hf_pn_io_iocr_multicast_mac_add, mac);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": %s, Ref:0x%x, Len:%u, FrameID:0x%x, Clock:%u, Ratio:%u, Phase:%u APIs:%u",
        val_to_str(u16IOCRType, pn_io_iocr_type, "0x%x"),
        u16IOCRReference, u16DataLength, u16FrameID, 
        u16SendClockFactor, u16ReductionRatio, u16Phase, u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
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
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_data_object, tvb, offset, 0, FALSE);
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
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_io_cs, tvb, offset, 0, FALSE);
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

        proto_item_append_text(api_item, ": %u, NumberOfIODataObjects: %u NumberOfIOCS: %u", 
            u32Api, u16NumberOfIODataObjects, u16NumberOfIOCS);

	    proto_item_set_len(api_item, offset - u32ApiStart);
    }

    return offset;
}


/* dissect the AlarmCRBlockReq */
static int
dissect_AlarmCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
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


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_lt, &u16LT);
	
    sub_item = proto_tree_add_item(tree, hf_pn_io_alarmcr_properties, tvb, offset, 4, FALSE);
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

    return offset;
}


/* dissect the AlarmCRBlockRes */
static int
dissect_AlarmCRBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16AlarmCRType;
    guint16 u16LocalAlarmReference;
    guint16 u16MaxAlarmDataLength;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_alarmcr_type, &u16AlarmCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_localalarmref, &u16LocalAlarmReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_maxalarmdatalength, &u16MaxAlarmDataLength);

    proto_item_append_text(item, ": %s, Ref:0x%04x, MaxDataLen:%u",
        val_to_str(u16AlarmCRType, pn_io_alarmcr_type, "0x%x"),
        u16LocalAlarmReference, u16MaxAlarmDataLength);

    return offset;
}



/* dissect the IOCRBlockRes */
static int
dissect_IOCRBlockRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16IOCRType;
    guint16 u16IOCRReference;
    guint16 u16FrameID;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_type, &u16IOCRType);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_frame_id, &u16FrameID);

    proto_item_append_text(item, ": %s, Ref:0x%04x, FrameID:0x%04x",
        val_to_str(u16IOCRType, pn_io_iocr_type, "0x%x"),
        u16IOCRReference, u16FrameID);

    return offset;
}



/* dissect the MCRBlockReq */
static int
dissect_MCRBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
{
    guint16 u16IOCRReference;
    guint32 u32AddressResolutionProperties;
    guint16 u16MCITimeoutFactor;
    guint16 u16NameLength;
    char *pStationName;


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_iocr_reference, &u16IOCRReference);
	offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_address_resolution_properties, &u32AddressResolutionProperties);
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_mci_timeout_factor, &u16MCITimeoutFactor);

	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_station_name_length, &u16NameLength);

    pStationName = ep_alloc(u16NameLength+1);
    tvb_memcpy(tvb, pStationName, offset, u16NameLength);
    pStationName[u16NameLength] = '\0';
    proto_tree_add_string (tree, hf_pn_io_provider_station_name, tvb, offset, u16NameLength, pStationName);
    offset += u16NameLength;    

    proto_item_append_text(item, ", CRRef:%u, Properties:0x%x, TFactor:%u, Station:%s",
        u16IOCRReference, u32AddressResolutionProperties, u16MCITimeoutFactor, pStationName);

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


    sub_item = proto_tree_add_item(tree, hf_pn_io_data_description_tree, tvb, offset, 0, FALSE);
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
dissect_ExpectedSubmoduleBlockReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
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


	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);

    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
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
            sub_item = proto_tree_add_item(api_tree, hf_pn_io_submodule_tree, tvb, offset, 0, FALSE);
	        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
            u32SubStart = offset;

            /* Subslotnumber */
	        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_subslot_nr, &u16SubslotNr);
            /* SubmoduleIdentNumber */
	        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                            hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
            /* SubmoduleProperties */
            submodule_item = proto_tree_add_item(sub_tree, hf_pn_io_submodule_properties, tvb, offset, 2, FALSE);
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
dissect_ModuleDiffBlock(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint8 *drep)
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


    /* NumberOfAPIs */
	offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_number_of_apis, &u16NumberOfAPIs);

    proto_item_append_text(item, ": APIs:%u", u16NumberOfAPIs);
    
    while(u16NumberOfAPIs--) {
        api_item = proto_tree_add_item(tree, hf_pn_io_api_tree, tvb, offset, 0, FALSE);
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
            module_item = proto_tree_add_item(api_tree, hf_pn_io_module_tree, tvb, offset, 0, FALSE);
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
                sub_item = proto_tree_add_item(module_tree, hf_pn_io_submodule_tree, tvb, offset, 0, FALSE);
	            sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_submodule);
                u32SubStart = offset;

                /* Subslotnumber */
	            offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep, 
                                    hf_pn_io_subslot_nr, &u16SubslotNr);
                /* SubmoduleIdentNumber */
	            offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep, 
                                hf_pn_io_submodule_ident_number, &u32SubmoduleIdentNumber);
                /* SubmoduleState */
                submodule_item = proto_tree_add_item(sub_tree, hf_pn_io_submodule_state, tvb, offset, 2, FALSE);
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


/* dissect one PN-IO block (depending on the block type) */
static int
dissect_block(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 *u16Index, guint32 *u32RecDataLen)
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


    /* from here, we only have big endian (network byte ordering)!!! */
    drep[0] &= ~0x10;

    sub_item = proto_tree_add_item(tree, hf_pn_io_block, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_block);
    u32SubStart = offset;

    header_item = proto_tree_add_item(sub_tree, hf_pn_io_block_header, tvb, offset, 6, FALSE);
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

	proto_item_append_text(sub_item, "%s", 
		val_to_str(u16BlockType, pn_io_block_type, "Unknown (0x%04x)"));

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
        val_to_str(u16BlockType, pn_io_block_type, "Unknown"));

    /* block length is without type and length fields, but with version field */
    /* as it's already dissected, remove it */
    u16BodyLength = u16BlockLength - 2;
    tvb_ensure_bytes_exist(tvb, offset, u16BodyLength);

    switch(u16BlockType) {
    case(0x0001):
    case(0x0002):
        dissect_AlarmNotification_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u16BodyLength);
        break;
    case(0x0010):
        dissect_DiagnosisBlock(tvb, offset, pinfo, sub_tree, sub_item, drep, u16BodyLength);
        break;
    case(0x0013):
        dissect_RealIdentificationData_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u8BlockVersionLow);
        break;
    case(0x0101):
        dissect_ARBlockReq(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0102):
        dissect_IOCRBlockReq(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0103):
        dissect_AlarmCRBlockReq(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0104):
        dissect_ExpectedSubmoduleBlockReq(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0106):
        dissect_MCRBlockReq(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0110):
    case(0x0112):
    case(0x0114):
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0008):
    case(0x0009):
        dissect_ReadWrite_rqst_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u16Index, u32RecDataLen);
        break;
    case(0x8001):
    case(0x8002):
        dissect_Alarm_ack_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x8008):
    case(0x8009):
        dissect_ReadWrite_resp_block(tvb, offset, pinfo, sub_tree, sub_item, drep, u16Index, u32RecDataLen);
        break;
    case(0x8101):
        dissect_ARBlockRes(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x8102):
        dissect_IOCRBlockRes(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x8103):
        dissect_AlarmCRBlockRes(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x8104):
        dissect_ModuleDiffBlock(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x8110):
    case(0x8112):
    case(0x8114):
        dissect_ControlConnect_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0200):
    case(0x0202):
        dissect_PDPortData_Check_Adjust_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0203):
        dissect_PDSyncData_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0205):
        dissect_PDIRData_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0206):
        dissect_PDIRGlobalData_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0207):
        dissect_PDIRFrameData_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;        
    case(0x0209):
        dissect_AdjustDomainBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x20A):
        dissect_CheckPeers_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x20B):
        dissect_CheckPropagationDelayFactor_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x20C):
        dissect_CheckMAUType_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x20E):
        dissect_AdjustMAUType_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x20F):
        dissect_PDPortDataReal_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x0210):
        dissect_AdjustMulticastBoundary_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    case(0x21B):
        dissect_AdjustPortState_block(tvb, offset, pinfo, sub_tree, sub_item, drep);
        break;
    default:
    	header_item = proto_tree_add_string_format(sub_tree, hf_pn_io_data, tvb, offset, u16BodyLength, "undecoded", "Undecoded Block Data: %d bytes", u16BodyLength);
        expert_add_info_format(pinfo, header_item, PI_UNDECODED, PI_WARN,
			"Undecoded block type %s (0x%x), %u bytes",
   			val_to_str(u16BlockType, pn_io_block_type, ""),
			u16BlockType, u16BodyLength);
    }
    offset += u16BodyLength;

	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


/* dissect any number of PN-IO blocks */
static int
dissect_blocks(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16Index = 0;
    guint32 u32RecDataLen;
    

    while(tvb_length(tvb) > (guint) offset) {
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);
        u16Index++;
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


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    /* args_max */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_max, &u32ArgsMax);
    /* args_len */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, FALSE);
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


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-CM");

    offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);

    /* args_len */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
                        hf_pn_io_args_len, &u32ArgsLen);

    sub_item = proto_tree_add_item(tree, hf_pn_io_array, tvb, offset, 0, FALSE);
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


static int
dissect_RecordDataRead(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    proto_item *item;

    /* user specified format? */
    if(u16Index < 0x8000) {
        item = proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, u32RecDataLen, "data", 
            "RecordDataRead: %d bytes", u32RecDataLen);
        offset += u32RecDataLen;
        return offset;
    }

    /* see: pn_io_index */
    switch(u16Index) {
    case(0x8001):   /* RealIdentificationData */
    case(0x802a):   /* PDPortDataReal */
    case(0x802b):   /* PDPortDataCheck */
    case(0x802d):   /* PDSyncData */
    case(0x802e):   /* PDSyncData */
    case(0x802f):   /* PDPortDataAdjust */
    case(0xe00c):
    case(0xe010):
    case(0xe012):
    case(0xf000):   /* RealIdentificationData */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);
        break;
    default:
        item = proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, u32RecDataLen, "data", 
            "RecordDataRead: %d bytes", u32RecDataLen);
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
			"Undecoded index %s (0x%x), %u bytes",
			val_to_str(u16Index, pn_io_index, ""),
            u16Index, u32RecDataLen);
        offset += u32RecDataLen;
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

    offset = dissect_IPNIO_resp_header(tvb, offset, pinfo, tree, drep);

    /* IODReadHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

    /* RecordDataRead */
    if(u32RecDataLen != 0) {
        offset = dissect_RecordDataRead(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);
    }

	return offset;
}


static int
dissect_RecordDataWrite(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16Index, guint32 u32RecDataLen)
{
    proto_item *item;

    /* user specified format? */
    if(u16Index < 0x8000) {
        item = proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, u32RecDataLen, "data", 
            "RecordDataWrite: %d bytes", u32RecDataLen);
        offset += u32RecDataLen;
        return offset;
    }

    /* see: pn_io_index */
    switch(u16Index) {
    case(0x802b):   /* PDPortDataCheck */
    case(0x802c):   /* PDirData */
    case(0x802d):   /* PDSyncData */
    case(0x802e):   /* PDSyncData */
    case(0x802f):   /* PDPortDataAdjust */
        offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);
        break;
    default:
        item = proto_tree_add_string_format(tree, hf_pn_io_data, tvb, offset, u32RecDataLen, "data", 
            "RecordDataWrite: %d bytes", u32RecDataLen);
        expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN,
			"Undecoded index %s (0x%x), %u bytes",
			val_to_str(u16Index, pn_io_index, ""),
            u16Index, u32RecDataLen);
        offset += u32RecDataLen;
    }

    return offset;
}


static int
dissect_IODWriteReq(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    /* IODWriteHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

    /* IODWriteMultipleReq? */
    if(u16Index == 0xe040) {
        while((remain = tvb_length_remaining(tvb, offset)) > 0) {
            offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep);
        }
    } else {
        /* RecordDataWrite */
        offset = dissect_RecordDataWrite(tvb, offset, pinfo, tree, drep, u16Index, u32RecDataLen);

        /* add padding (required with IODWriteMultipleReq) */
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
    offset = dissect_IPNIO_rqst_header(tvb, offset, pinfo, tree, drep);

    offset = dissect_IODWriteReq(tvb, offset, pinfo, tree, drep);

	return offset;
}



static int
dissect_IODWriteRes(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    gint remain;
    guint16 u16Index = 0;
    guint32 u32RecDataLen;


    /* IODWriteResHeader */
    offset = dissect_block(tvb, offset, pinfo, tree, drep, &u16Index, &u32RecDataLen);

    /* IODWriteMultipleRes? */
    if(u16Index == 0xe040) {
        while((remain = tvb_length_remaining(tvb, offset)) > 0) {
            offset = dissect_IODWriteRes(tvb, offset, pinfo, tree, drep);
        }
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
	packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_)
{
    guint8 u8IOxS;
    proto_item *ioxs_item = NULL;
    proto_tree *ioxs_tree = NULL;


    u8IOxS = tvb_get_guint8(tvb, offset);

    /* add ioxs subtree */
	ioxs_item = proto_tree_add_uint_format(tree, hf_pn_io_ioxs, 
		tvb, offset, 1, u8IOxS,
		"IOxS: 0x%02x (%s%s)", 
		u8IOxS, 
		(u8IOxS & 0x01) ? "another IOxS follows " : "",
		(u8IOxS & 0x80) ? "good" : "bad");
	ioxs_tree = proto_item_add_subtree(ioxs_item, ett_pn_io_ioxs);

	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_extension, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_res14, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_instance, tvb, offset, 1, u8IOxS);
	proto_tree_add_uint(ioxs_tree, hf_pn_io_ioxs_datastate, tvb, offset, 1, u8IOxS);

    return offset + 1;
}


/* dissect a PN-IO Cyclic Service Data Unit (on top of PN-RT protocol) */
static int
dissect_PNIO_C_SDU(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    proto_item *data_item;
	proto_tree *data_tree;


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO");

    if(tree) {
	    data_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb),
				    "PROFINET IO Cyclic Service Data Unit: %u bytes", tvb_length(tvb));
        data_tree = proto_item_add_subtree(data_item, ett_pn_io_rtc);

        offset = dissect_PNIO_IOxS(tvb, offset, pinfo, data_tree, drep);

        /* XXX - dissect the remaining data */
        /* this will be one or more DataItems followed by an optional GAP and RTCPadding */
        /* as we don't have the required context information to dissect the specific DataItems, this will be tricky :-( */
	    data_item = proto_tree_add_protocol_format(data_tree, proto_pn_io, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Data: %u bytes (including GAP and RTCPadding)", tvb_length_remaining(tvb, offset));
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


    proto_item *rta_item;
	proto_tree *rta_tree;

    proto_item *sub_item;
	proto_tree *sub_tree;


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-AL");

	rta_item = proto_tree_add_protocol_format(tree, proto_pn_io, tvb, offset, tvb_length(tvb), 
        "PROFINET IO Alarm");
	rta_tree = proto_item_add_subtree(rta_item, ett_pn_io_rta);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_alarm_dst_endpoint, &u16AlarmDstEndpoint);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep, 
                    hf_pn_io_alarm_src_endpoint, &u16AlarmSrcEndpoint);

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: 0x%x, Dst: 0x%x",
        u16AlarmSrcEndpoint, u16AlarmDstEndpoint);

    /* PDU type */
	sub_item = proto_tree_add_item(rta_tree, hf_pn_io_pdu_type, tvb, offset, 1, FALSE);
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
	sub_item = proto_tree_add_item(rta_tree, hf_pn_io_add_flags, tvb, offset, 1, FALSE);
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
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", Data-RTA");
        offset = dissect_block(tvb, offset, pinfo, rta_tree, drep, &u16Index, &u32RecDataLen);
        break;
    case(2):    /* NACK-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", NACK-RTA");
        /* no additional data */
        break;
    case(3):    /* ACK-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", ACK-RTA");
        /* no additional data */
        break;
    case(4):    /* ERR-RTA */
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_str(pinfo->cinfo, COL_INFO, ", ERR-RTA");
        offset = dissect_PNIO_status(tvb, offset, pinfo, rta_tree, drep);
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_io_data, tvb, 0, tvb_length(tvb), "data", 
            "PN-IO Alarm: unknown PDU type 0x%x", u8PDUType);    
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


    /* the sub tvb will NOT contain the frame_id here! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

    u8CBAVersion = tvb_get_guint8 (tvb, 0);

    /* is this a PNIO class 2 data packet? */
	/* frame id must be in valid range (cyclic Real-Time, class=2) */
	if (u16FrameID >= 0x8000 && u16FrameID < 0xbf00) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO class 1 data packet? */
	/* frame id must be in valid range (cyclic Real-Time, class=1) and
     * first byte (CBA version field) has to be != 0x11 */
	if (u16FrameID >= 0xc000 && u16FrameID < 0xfb00 && u8CBAVersion != 0x11) {
        dissect_PNIO_C_SDU(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO high priority alarm packet? */
    if(u16FrameID == 0xfc01) {
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_add_str(pinfo->cinfo, COL_INFO, "Alarm High");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* is this a PNIO low priority alarm packet? */
    if(u16FrameID == 0xfe01) {
    	if (check_col(pinfo->cinfo, COL_INFO))
	        col_add_str(pinfo->cinfo, COL_INFO, "Alarm Low");

        dissect_PNIO_RTA(tvb, 0, pinfo, tree, drep);
        return TRUE;
    }

    /* this PN-RT packet doesn't seem to be PNIO specific */
    return FALSE;
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


void
proto_register_pn_io (void)
{
	static hf_register_info hf[] = {
	{ &hf_pn_io_opnum,
		{ "Operation", "pn_io.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_reserved16,
		{ "Reserved", "pn_io.reserved16", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array,
        { "Array", "pn_io.array", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_status,
		{ "Status", "pn_io.status", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_args_max,
		{ "ArgsMaximum", "pn_io.args_max", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_args_len,
		{ "ArgsLength", "pn_io.args_len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_max_count,
		{ "MaximumCount", "pn_io.array_max_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_offset,
		{ "Offset", "pn_io.array_offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_array_act_count,
		{ "ActualCount", "pn_io.array_act_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ar_type,
    { "ARType", "pn_io.ar_type", FT_UINT16, BASE_HEX, VALS(pn_io_ar_type), 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_macadd,
      { "CMInitiatorMacAdd", "pn_io.cminitiator_mac_add", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_objectuuid,
      { "CMInitiatorObjectUUID", "pn_io.cminitiator_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_ar_properties,
		{ "ARProperties", "pn_io.ar_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_ar_properties_state,
		{ "State", "pn_io.ar_properties.state", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_state), 0x00000007, "", HFILL }},
	{ &hf_pn_io_ar_properties_supervisor_takeover_allowed,
		{ "SupervisorTakeoverAllowed", "pn_io.ar_properties.supervisor_takeover_allowed", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_supervisor_takeover_allowed), 0x00000008, "", HFILL }},
	{ &hf_pn_io_ar_properties_parametrization_server,
		{ "ParametrizationServer", "pn_io.ar_properties.parametrization_server", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_parametrization_server), 0x00000010, "", HFILL }},
	{ &hf_pn_io_ar_properties_data_rate,
		{ "DataRate", "pn_io.ar_properties.data_rate", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_data_rate), 0x00000060, "", HFILL }},
	{ &hf_pn_io_ar_properties_reserved_1,
		{ "Reserved_1", "pn_io.ar_properties.reserved_1", FT_UINT32, BASE_HEX, NULL, 0x00000080, "", HFILL }},
	{ &hf_pn_io_ar_properties_device_access,
		{ "DeviceAccess", "pn_io.ar_properties.device_access", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_device_access), 0x00000100, "", HFILL }},
	{ &hf_pn_io_ar_properties_companion_ar,
		{ "CompanionAR", "pn_io.ar_properties.companion_ar", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_companion_ar), 0x00000600, "", HFILL }},
	{ &hf_pn_io_ar_properties_reserved,
		{ "Reserved", "pn_io.ar_properties.reserved", FT_UINT32, BASE_HEX, NULL, 0x7FFFF800, "", HFILL }},
	{ &hf_pn_io_ar_properties_pull_module_alarm_allowed,
		{ "PullModuleAlarmAllowed", "pn_io.ar_properties.pull_module_alarm_allowed", FT_UINT32, BASE_HEX, VALS(pn_io_arproperties_pull_module_alarm_allowed), 0x80000000, "", HFILL }},

	{ &hf_pn_io_cminitiator_activitytimeoutfactor,
		{ "CMInitiatorActivityTimeoutFactor", "pn_io.cminitiator_activitytimeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_cminitiator_udprtport,
		{ "CMInitiatorUDPRTPort", "pn_io.cminitiator_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_station_name_length,
		{ "StationNameLength", "pn_io.station_name_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_cminitiator_station_name,
		{ "CMInitiatorStationName", "pn_io.cminitiator_station_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_pn_io_cmresponder_macadd,
      { "CMResponderMacAdd", "pn_io.cmresponder_macadd", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_io_cmresponder_udprtport,
		{ "CMResponderUDPRTPort", "pn_io.cmresponder_udprtport", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */

    { &hf_pn_io_iocr_type,
    { "IOCRType", "pn_io.iocr_type", FT_UINT16, BASE_HEX, VALS(pn_io_iocr_type), 0x0, "", HFILL }},
    { &hf_pn_io_iocr_reference,
    { "IOCRReference", "pn_io.iocr_reference", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_lt,
    { "LT", "pn_io.lt", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	
    { &hf_pn_io_iocr_properties,
    { "IOCRProperties", "pn_io.iocr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocr_properties_rtclass,
    { "RTClass", "pn_io.iocr_properties.rtclass", FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_rtclass), 0x0000000F, "", HFILL }},
	{ &hf_pn_io_iocr_properties_reserved_1,
    { "Reserved1", "pn_io.iocr_properties.reserved1", FT_UINT32, BASE_HEX, NULL, 0x000007F0, "", HFILL }},
	{ &hf_pn_io_iocr_properties_media_redundancy,
    { "MediaRedundancy", "pn_io.iocr_properties.media_redundancy", FT_UINT32, BASE_HEX, VALS(pn_io_iocr_properties_media_redundancy), 0x00000800, "", HFILL }},
	{ &hf_pn_io_iocr_properties_reserved_2,
    { "Reserved2", "pn_io.iocr_properties.reserved2", FT_UINT32, BASE_HEX, NULL, 0xFFFFF000, "", HFILL }},

    { &hf_pn_io_data_length,
      { "DataLength", "pn_io.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_frame_id,
      { "FrameID", "pn_io.frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_send_clock_factor,
      { "SendClockFactor", "pn_io.send_clock_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }}, /* XXX - special values */
    { &hf_pn_io_reduction_ratio,
      { "ReductionRatio", "pn_io.reduction_ratio", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }}, /* XXX - special values */
    { &hf_pn_io_phase,
      { "Phase", "pn_io.phase", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sequence,
      { "Sequence", "pn_io.sequence", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_frame_send_offset,
      { "FrameSendOffset", "pn_io.frame_send_offset", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_watchdog_factor,
      { "WatchdogFactor", "pn_io.watchdog_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data_hold_factor,
      { "DataHoldFactor", "pn_io.data_hold_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocr_tag_header,
      { "IOCRTagHeader", "pn_io.iocr_tag_header", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocr_multicast_mac_add,
      { "IOCRMulticastMACAdd", "pn_io.iocr_multicast_mac_add", FT_ETHER, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_apis,
      { "NumberOfAPIs", "pn_io.number_of_apis", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_io_data_objects,
      { "NumberOfIODataObjects", "pn_io.number_of_io_data_objects", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_data_object_frame_offset,
      { "IODataObjectFrameOffset", "pn_io.io_data_object_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_iocs,
      { "NumberOfIOCS", "pn_io.number_of_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_iocs_frame_offset,
      { "IOCSFrameOffset", "pn_io.iocs_frame_offset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_alarmcr_type,
    { "AlarmCRType", "pn_io.alarmcr_type", FT_UINT16, BASE_HEX, VALS(pn_io_alarmcr_type), 0x0, "", HFILL }},

    { &hf_pn_io_alarmcr_properties,
    { "AlarmCRProperties", "pn_io.alarmcr_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_alarmcr_properties_priority,
    { "priority", "pn_io.alarmcr_properties.priority", FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_priority), 0x00000001, "", HFILL }},
    { &hf_pn_io_alarmcr_properties_transport,
    { "Transport", "pn_io.alarmcr_properties.transport", FT_UINT32, BASE_HEX, VALS(pn_io_alarmcr_properties_transport), 0x00000002, "", HFILL }},
    { &hf_pn_io_alarmcr_properties_reserved,
    { "Reserved", "pn_io.alarmcr_properties.reserved", FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC, "", HFILL }},

	{ &hf_pn_io_rta_timeoutfactor,
		{ "RTATimeoutFactor", "pn_io.rta_timeoutfactor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_rta_retries,
		{ "RTARetries", "pn_io.rta_retries", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - only values 3 - 15 allowed */
	{ &hf_pn_io_localalarmref,
		{ "LocalAlarmReference", "pn_io.localalarmref", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - special values */
	{ &hf_pn_io_maxalarmdatalength,
		{ "MaxAlarmDataLength", "pn_io.maxalarmdatalength", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},  /* XXX - only values 200 - 1432 allowed */
	{ &hf_pn_io_alarmcr_tagheaderhigh,
		{ "AlarmCRTagHeaderHigh", "pn_io.alarmcr_tagheaderhigh", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 16 bitfield! */
	{ &hf_pn_io_alarmcr_tagheaderlow,
		{ "AlarmCRTagHeaderLow", "pn_io.alarmcr_tagheaderlow", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},  /* XXX - 16 bitfield!*/

    { &hf_pn_io_api_tree,
      { "API", "pn_io.api", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_tree,
      { "Module", "pn_io.module", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_tree,
      { "Submodule", "pn_io.submodule", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_data_object,
      { "IODataObject", "pn_io.io_data_object", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_io_cs,
      { "IOCS", "pn_io.io_cs", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ar_uuid,
      { "ARUUID", "pn_io.ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_target_ar_uuid,
      { "TargetARUUID", "pn_io.target_ar_uuid", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_api,
      { "API", "pn_io.api", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_slot_nr,
      { "SlotNumber", "pn_io.slot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_subslot_nr,
      { "SubslotNumber", "pn_io.subslot_nr", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_index,
      { "Index", "pn_io.index", FT_UINT16, BASE_HEX, VALS(pn_io_index), 0x0, "", HFILL }},
    { &hf_pn_io_seq_number,
      { "SeqNumber", "pn_io.seq_number", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_record_data_length,
      { "RecordDataLength", "pn_io.record_data_length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_padding,
      { "Padding", "pn_io.padding", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_add_val1,
      { "AdditionalValue1", "pn_io.add_val1", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_add_val2,
      { "AdditionalValue2", "pn_io.add_val2", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_header,
      { "BlockHeader", "pn_io.block_header", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_type,
      { "BlockType", "pn_io.block_type", FT_UINT16, BASE_HEX, VALS(pn_io_block_type), 0x0, "", HFILL }},
    { &hf_pn_io_block_length,
      { "BlockLength", "pn_io.block_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_version_high,
      { "BlockVersionHigh", "pn_io.block_version_high", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_block_version_low,
      { "BlockVersionLow", "pn_io.block_version_low", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sessionkey,
      { "SessionKey", "pn_io.session_key", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_control_command,
      { "ControlCommand", "pn_io.control_command", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_control_command_prmend,
      { "PrmEnd", "pn_io.control_command.prmend", FT_UINT16, BASE_DEC, NULL, 0x0001, "", HFILL }},
    { &hf_pn_io_control_command_applready,
      { "ApplicationReady", "pn_io.control_command.applready", FT_UINT16, BASE_DEC, NULL, 0x0002, "", HFILL }},
    { &hf_pn_io_control_command_release,
      { "Release", "pn_io.control_command.release", FT_UINT16, BASE_DEC, NULL, 0x0004, "", HFILL }},
    { &hf_pn_io_control_command_done,
      { "Done", "pn_io.control_command.done", FT_UINT16, BASE_DEC, NULL, 0x0008, "", HFILL }},
    { &hf_pn_io_control_block_properties,
      { "ControlBlockProperties", "pn_io.control_block_properties", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_error_code,
      { "ErrorCode", "pn_io.error_code", FT_UINT8, BASE_HEX, VALS(pn_io_error_code), 0x0, "", HFILL }},
    { &hf_pn_io_error_decode,
      { "ErrorDecode", "pn_io.error_decode", FT_UINT8, BASE_HEX, VALS(pn_io_error_decode), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1,
      { "ErrorCode1", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1), 0x0, "", HFILL }},
    { &hf_pn_io_error_code2,
      { "ErrorCode2", "pn_io.error_code2", FT_UINT8, BASE_HEX, VALS(pn_io_error_code2), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1_pniorw,
      { "ErrorCode1 (PNIORW)", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1_pniorw), 0x0, "", HFILL }},
    { &hf_pn_io_error_code1_pnio,
      { "ErrorCode1 (PNIO)", "pn_io.error_code1", FT_UINT8, BASE_HEX, VALS(pn_io_error_code1_pnio), 0x0, "", HFILL }},
	{ &hf_pn_io_block,
    { "", "pn_io.block", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data,
      { "Undecoded Data", "pn_io.data", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_alarm_type,
      { "AlarmType", "pn_io.alarm_type", FT_UINT16, BASE_HEX, VALS(pn_io_alarm_type), 0x0, "", HFILL }},

    { &hf_pn_io_alarm_specifier,
      { "AlarmSpecifier", "pn_io.alarm_specifier", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_alarm_specifier_sequence,
      { "SequenceNumber", "pn_io.alarm_specifier.sequence", FT_UINT16, BASE_HEX, NULL, 0x07FF, "", HFILL }},
    { &hf_pn_io_alarm_specifier_channel,
      { "ChannelDiagnosis", "pn_io.alarm_specifier.channel", FT_UINT16, BASE_HEX, NULL, 0x0800, "", HFILL }},
    { &hf_pn_io_alarm_specifier_manufacturer,
      { "ManufacturerSpecificDiagnosis", "pn_io.alarm_specifier.manufacturer", FT_UINT16, BASE_HEX, NULL, 0x1000, "", HFILL }},
    { &hf_pn_io_alarm_specifier_submodule,
      { "SubmoduleDiagnosisState", "pn_io.alarm_specifier.submodule", FT_UINT16, BASE_HEX, NULL, 0x2000, "", HFILL }},
    { &hf_pn_io_alarm_specifier_ardiagnosis,
      { "ARDiagnosisState", "pn_io.alarm_specifier.ardiagnosis", FT_UINT16, BASE_HEX, NULL, 0x8000, "", HFILL }},

    { &hf_pn_io_alarm_dst_endpoint,
      { "AlarmDstEndpoint", "pn_io.alarm_dst_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_alarm_src_endpoint,
      { "AlarmSrcEndpoint", "pn_io.alarm_src_endpoint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_pdu_type,
      { "PDUType", "pn_io.pdu_type", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_pdu_type_type,
      { "Type", "pn_io.pdu_type.type", FT_UINT8, BASE_HEX, VALS(pn_io_pdu_type), 0x0F, "", HFILL }},
    { &hf_pn_io_pdu_type_version,
      { "Version", "pn_io.pdu_type.version", FT_UINT8, BASE_HEX, NULL, 0xF0, "", HFILL }},
    { &hf_pn_io_add_flags,
      { "AddFlags", "pn_io.add_flags", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_window_size,
      { "WindowSize", "pn_io.window_size", FT_UINT8, BASE_DEC, NULL, 0x0F, "", HFILL }},
    { &hf_pn_io_tack,
      { "TACK", "pn_io.tack", FT_UINT8, BASE_HEX, NULL, 0xF0, "", HFILL }},
    { &hf_pn_io_send_seq_num,
      { "SendSeqNum", "pn_io.send_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ack_seq_num,
      { "AckSeqNum", "pn_io.ack_seq_num", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_var_part_len,
      { "VarPartLen", "pn_io.var_part_len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_ident_number,
      { "ModuleIdentNumber", "pn_io.module_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_ident_number,
      { "SubmoduleIdentNumber", "pn_io.submodule_ident_number", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_number_of_modules,
      { "NumberOfModules", "pn_io.number_of_modules", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_properties,
      { "ModuleProperties", "pn_io.module_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_module_state,
      { "ModuleState", "pn_io.module_state", FT_UINT16, BASE_HEX, VALS(pn_io_module_state), 0x0, "", HFILL }},
    { &hf_pn_io_number_of_submodules,
      { "NumberOfSubmodules", "pn_io.number_of_submodules", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_submodule_properties,
      { "SubmoduleProperties", "pn_io.submodule_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_properties_type,
      { "Type", "pn_io.submodule_properties.type", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_type), 0x0003, "", HFILL }},
    { &hf_pn_io_submodule_properties_shared_input,
      { "SharedInput", "pn_io.submodule_properties.shared_input", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_shared_input), 0x0004, "", HFILL }},
    { &hf_pn_io_submodule_properties_reduce_input_submodule_data_length,
      { "ReduceInputSubmoduleDataLength", "pn_io.submodule_properties.reduce_input_submodule_data_length", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_input_submodule_data_length), 0x0008, "", HFILL }},
    { &hf_pn_io_submodule_properties_reduce_output_submodule_data_length,
      { "ReduceOutputSubmoduleDataLength", "pn_io.submodule_properties.reduce_output_submodule_data_length", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_reduce_output_submodule_data_length), 0x0010, "", HFILL }},
    { &hf_pn_io_submodule_properties_discard_ioxs,
      { "DiscardIOXS", "pn_io.submodule_properties.discard_ioxs", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_properties_discard_ioxs), 0x0020, "", HFILL }},
    { &hf_pn_io_submodule_properties_reserved,
      { "Reserved", "pn_io.submodule_properties.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFC0, "", HFILL }},

    { &hf_pn_io_submodule_state,
      { "SubmoduleState", "pn_io.submodule_state", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_submodule_state_format_indicator,
      { "FormatIndicator", "pn_io.submodule_state.format_indicator", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_format_indicator), 0x8000, "", HFILL }},
    { &hf_pn_io_submodule_state_add_info,
      { "AddInfo", "pn_io.submodule_state.add_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_add_info), 0x0007, "", HFILL }},
    { &hf_pn_io_submodule_state_qualified_info,
      { "QualifiedInfo", "pn_io.submodule_state.qualified_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_qualified_info), 0x0008, "", HFILL }},
    { &hf_pn_io_submodule_state_maintenance_required,
      { "MaintenanceRequired", "pn_io.submodule_state.maintenance_required", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_required), 0x0010, "", HFILL }},
    { &hf_pn_io_submodule_state_maintenance_demanded,
      { "MaintenanceDemanded", "pn_io.submodule_state.maintenance_demanded", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_maintenance_demanded), 0x0020, "", HFILL }},
    { &hf_pn_io_submodule_state_diag_info,
      { "DiagInfo", "pn_io.submodule_state.diag_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_diag_info), 0x0040, "", HFILL }},
    { &hf_pn_io_submodule_state_ar_info,
      { "ARInfo", "pn_io.submodule_state.ar_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ar_info), 0x0780, "", HFILL }},
    { &hf_pn_io_submodule_state_ident_info,
      { "IdentInfo", "pn_io.submodule_state.ident_info", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_ident_info), 0x7800, "", HFILL }},
    { &hf_pn_io_submodule_state_detail,
      { "Detail", "pn_io.submodule_state.detail", FT_UINT16, BASE_HEX, VALS(pn_io_submodule_state_detail), 0x7FFF, "", HFILL }},

    { &hf_pn_io_data_description_tree,
      { "DataDescription", "pn_io.data_description", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_data_description,
      { "DataDescription", "pn_io.data_description", FT_UINT16, BASE_HEX, VALS(pn_io_data_description), 0x0, "", HFILL }},
    { &hf_pn_io_submodule_data_length,
      { "SubmoduleDataLength", "pn_io.submodule_data_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_iocs,
      { "LengthIOCS", "pn_io.length_iocs", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_iops,
      { "LengthIOPS", "pn_io.length_iops", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ioxs,
      { "IOxS", "pn_io.ioxs", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ioxs_extension,
      { "Extension (1:another IOxS follows/0:no IOxS follows)", "pn_io.ioxs.extension", FT_UINT8, BASE_HEX, NULL, 0x01, "", HFILL }},
    { &hf_pn_io_ioxs_res14,
      { "Reserved (should be zero)", "pn_io.ioxs.res14", FT_UINT8, BASE_HEX, NULL, 0x1E, "", HFILL }},
    { &hf_pn_io_ioxs_instance,
      { "Instance (only valid, if DataState is bad)", "pn_io.ioxs.instance", FT_UINT8, BASE_HEX, VALS(pn_io_ioxs), 0x60, "", HFILL }},
    { &hf_pn_io_ioxs_datastate,
      { "DataState (1:good/0:bad)", "pn_io.ioxs.datastate", FT_UINT8, BASE_HEX, NULL, 0x80, "", HFILL }},

    { &hf_pn_io_address_resolution_properties,
      { "AddressResolutionProperties", "pn_io.address_resolution_properties", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_mci_timeout_factor,
      { "MCITimeoutFactor", "pn_io.mci_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_provider_station_name,
		{ "ProviderStationName", "pn_io.provider_station_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_io_user_structure_identifier,
		{ "UserStructureIdentifier", "pn_io.user_structure_identifier", FT_UINT16, BASE_HEX, VALS(pn_io_user_structure_identifier), 0x0, "", HFILL }},

    { &hf_pn_io_channel_number,
      { "ChannelNumber", "pn_io.channel_number", FT_UINT16, BASE_HEX, VALS(pn_io_channel_number), 0x0, "", HFILL }},

    { &hf_pn_io_channel_properties,
      { "ChannelProperties", "pn_io.channel_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_channel_properties_type,
      { "Type", "pn_io.channel_properties.type", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_type), 0x00FF, "", HFILL }},
    { &hf_pn_io_channel_properties_accumulative,
      { "Accumulative", "pn_io.channel_properties.accumulative", FT_UINT16, BASE_HEX, NULL, 0x0100, "", HFILL }},
    { &hf_pn_io_channel_properties_maintenance_required,
      { "MaintenanceRequired", "pn_io.channel_properties.maintenance_required", FT_UINT16, BASE_HEX, NULL, 0x0200, "", HFILL }},
    { &hf_pn_io_channel_properties_maintenance_demanded,
      { "MaintenanceDemanded", "pn_io.channel_properties.maintenance_demanded", FT_UINT16, BASE_HEX, NULL, 0x0400, "", HFILL }},
    { &hf_pn_io_channel_properties_specifier,
      { "Specifier", "pn_io.channel_properties.specifier", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_specifier), 0x1800, "", HFILL }},
    { &hf_pn_io_channel_properties_direction,
      { "Direction", "pn_io.channel_properties.direction", FT_UINT16, BASE_HEX, VALS(pn_io_channel_properties_direction), 0xE000, "", HFILL }},

    { &hf_pn_io_channel_error_type,
      { "ChannelErrorType", "pn_io.channel_error_type", FT_UINT16, BASE_HEX, VALS(pn_io_channel_error_type), 0x0, "", HFILL }},
    { &hf_pn_io_ext_channel_error_type,
      { "ExtChannelErrorType", "pn_io.ext_channel_error_type", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ext_channel_add_value,
      { "ExtChannelAddValue", "pn_io.ext_channel_add_value", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_ptcp_subdomain_id,
      { "PTCPSubdomainID", "pn_io.ptcp_subdomain_id", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ir_data_id,
      { "IRDataID", "pn_io.ir_data_id", FT_GUID, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_reserved_interval_begin,
      { "ReservedIntervalBegin", "pn_io.reserved_interval_begin", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_reserved_interval_end,
      { "ReservedIntervalEnd", "pn_io.reserved_interval_end", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_pllwindow,
      { "PLLWindow", "pn_io.pllwindow", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sync_send_factor,
      { "SyncSendFactor", "pn_io.sync_send_factor", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sync_properties,
      { "SyncProperties", "pn_io.sync_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_sync_frame_address,
      { "SyncFrameAddress", "pn_io.sync_frame_address", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_ptcp_timeout_factor,
      { "PTCPTimeoutFactor", "pn_io.ptcp_timeout_factor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_domain_boundary,
      { "DomainBoundary", "pn_io.domain_boundary", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_multicast_boundary,
      { "MulticastBoundary", "pn_io.multicast_boundary", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_adjust_properties,
      { "AdjustProperties", "pn_io.adjust_properties", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_mau_type,
      { "MAUType", "pn_io.mau_type", FT_UINT16, BASE_HEX, VALS(pn_io_mau_type), 0x0, "", HFILL }},
    { &hf_pn_io_port_state,
      { "PortState", "pn_io.port_state", FT_UINT16, BASE_HEX, VALS(pn_io_port_state), 0x0, "", HFILL }},
    { &hf_pn_io_propagation_delay_factor,
      { "PropagationDelayFactor", "pn_io.propagation_delay_factor", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_peers,
      { "NumberOfPeers", "pn_io.number_of_peers", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_peer_port_id,
      { "LengthPeerPortID", "pn_io.length_peer_port_id", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_peer_port_id,
      { "PeerPortID", "pn_io.peer_port_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_peer_chassis_id,
      { "LengthPeerChassisID", "pn_io.length_peer_chassis_id", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_peer_chassis_id,
      { "PeerChassisID", "pn_io.peer_chassis_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_length_own_port_id,
      { "LengthOwnPortID", "pn_io.length_own_port_id", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_own_port_id,
      { "OwnPortID", "pn_io.own_port_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_peer_macadd,
      { "PeerMACAddress", "pn_io.peer_macadd", FT_ETHER, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_media_type,
      { "MediaType", "pn_io.media_type", FT_UINT32, BASE_HEX, VALS(pn_io_media_type), 0x0, "", HFILL }},

    { &hf_pn_io_ethertype,
      { "Ethertype", "pn_io.ethertype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_rx_port,
      { "RXPort", "pn_io.rx_port", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_frame_details,
      { "FrameDetails", "pn_io.frame_details", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_nr_of_tx_port_groups,
      { "NumberOfTxPortGroups", "pn_io.nr_of_tx_port_groups", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_pn_io_subslot,
      { "Subslot", "pn_io.subslot", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_slots,
      { "NumberOfSlots", "pn_io.number_of_slots", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_io_number_of_subslots,
      { "NumberOfSubslots", "pn_io.number_of_subslots", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

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
        &ett_pn_io_subslot
	};

	proto_pn_io = proto_register_protocol ("PROFINET IO", "PNIO", "pn_io");
	proto_register_field_array (proto_pn_io, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
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
