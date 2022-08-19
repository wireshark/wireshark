/* packet-ecmp.c
 *
 * Copyright 2014, James Lynch <lynch007@gmail.com>, Control Techniques
 * Copyright 2015, Luke Orehawa <lukeorehawa@gmail.com>, Control Techniques
 *
 * Revisions:
 * - James Lynch 2014-07-22
 *   - Initial plugin development
 * - Luke Orehawa 2015-11-26
 *	 - Removed commands not yet in released specification
 *	 - All commands implemented are as V0.26 of ECMP Specification
 *	 - Modifications of code to meet Wireshark coding style and current APIs
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
#include "packet-mbtcp.h"

#define PROTO_TAG_ECMP	"ECMP"
#define ECMP_TCP_PORT   6160

void proto_reg_handoff_ecmp(void);
void proto_register_ecmp (void);

static dissector_handle_t ecmp_tcp_handle, ecmp_udp_handle;

/* Wireshark ID of the ECMP protocol */
static int proto_ecmp = -1;

/* Used to set Modbus protocol data */
static int proto_modbus = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t modbus_handle = NULL;

/*smallest size of a packet, number of bytes*/
static const gint ecmp_min_packet_size  = 6;

/* ECMP request codes  */
#define ECMP_COMMAND_IDENTIFY		0x00
#define ECMP_COMMAND_INFO		0x01
#define ECMP_COMMAND_INTERROGATE	0x02
#define ECMP_COMMAND_READ		0x10
#define ECMP_COMMAND_READWITHTYPE	0x11
#define ECMP_COMMAND_WRITE		0x12
#define ECMP_COMMAND_OBJECTINFO		0x13
#define ECMP_COMMAND_GETNEXTOBJECTS	0x14
#define ECMP_COMMAND_FILEOPEN		0x20
#define ECMP_COMMAND_FILEREAD		0x21
#define ECMP_COMMAND_FILEWRITE		0x22
#define ECMP_COMMAND_FILECLOSE		0x23
#define ECMP_COMMAND_FILEINFO		0x24
#define ECMP_COMMAND_FILEDELETE		0x25
#define ECMP_COMMAND_FILESTATE		0x26
#define ECMP_COMMAND_FILEPOS		0x27
#define ECMP_COMMAND_FILELIST		0x28
#define ECMP_COMMAND_FILEEXISTS		0x2a
#define ECMP_COMMAND_CYCLICLINK		0x31
#define ECMP_COMMAND_PROGRAMCONTROL	0x60
#define ECMP_COMMAND_PROGRAMSTATUS	0x61
#define ECMP_COMMAND_CYCLICFRAME	0x70
#define ECMP_COMMAND_TUNNELFRAME	0x73
#define ECMP_COMMAND_MODBUSPDU		0x74

/* cyclic display formats */
static const guint8 cyclic_display_byte_format = 0;
static const guint8 cyclic_display_word_format = 1;
static const guint8 cyclic_display_long_format = 2;

/* Addressing scheme Structure */
static const value_string address_scheme [] = {
	{ 0, "No Route" },
	{ 1, "Intercept" },
	{ 2, "Default Route" },
	{ 3, "Diagnostics" },
	{ 4, "Named" },
	{ 0, NULL }
	/*other commands to be added */
};

/* Address Structure */
static const value_string diagnostic [] = {
	{ 0, "Status" },
	{ 1, "Alarm" },
	{ 2, "Network" },
	{ 3, "Application" },
	{ 0, NULL }
	/*other commands to be added*/
};

/* Command Structure*/
static const value_string command_vals [] = {
	{ 0x00, "Identify"},
	{ 0x01, "Info"},
	{ 0x02, "Interrogate"},
	{ 0x10, "Read"},
	{ 0x11, "ReadWithType"},
	{ 0x12, "Write"},
	{ 0x13, "ObjectInfo"},
	{ 0x14, "GetNextObjects"},
	{ 0x20, "FileOpen"},
	{ 0x21, "FileRead"},
	{ 0x22, "FileWrite"},
	{ 0x23, "FileClose"},
	{ 0x24, "FileInfo"},
	{ 0x25, "FileDelete"},
	{ 0x26, "FileState"},
	{ 0x27, "FilePos"},
	{ 0x28, "FileList"},
	{ 0x2A, "FileExists"},
	{ 0x31, "CyclicSetup"},
	{ 0x60, "ProgramControl"},
	{ 0x61, "ProgramStatus"},
	{ 0x70, "CyclicFrame"},
	{ 0x73, "TunnelFrame"},
	{ 0x74, "ModbusPDU"},
	{ 0, NULL }
	/*other commands to be added*/
};

/* Command Structure for request/response */
static const value_string type_rr [] = {
	{ 0, "Request" },
	{ 1, "Response" },
	{ 0, NULL }
	/*other commands to be added*/
};

/* Option Code structure*/
static const value_string option_code [] = {
	{ 0, "End of Options"},
	{ 1, "Dummy" },
	{ 2, "Process At" },
	{ 3, "Route to Custom Target"},
	{ 0, NULL }
	/* other - "Unknown" */
};

/* Attribute type Structure */
static const value_string attribute [] = {
	{ 0, "Manufacturer Name" },
	{ 1, "Product Family" },
	{ 2, "Product Model" },
	{ 3, "Serial Number" },
	{ 4, "Order Number" },
	{ 5, "Date Code" },
	{ 6, "Device Name" },
	{ 7, "Version Summary" },
	{ 8, "Colour Codes" },
	{ 0, NULL }
	/* other - Unknown*/
};

/* Status type Structure */
static const value_string status [] = {
	{ 0, "OK (no errors detected in request)" },
	{ 1, "OK, chunks follow" },
	{ 2, "Processing Request" },
	{ -1, "Error - Slave not ready" },
	{ -2, "Error - Request Too Long" },
	{ -3, "Error - Chunking Error" },
	{ 0, NULL }
	/* other - Unknown*/
};

/* Category (device) structure*/
static const value_string category [] = {
	{ 0, "Drive" },
	{ 1, "Option Module" },
	{ 0, NULL }
};

/* Cyclic data alignment */
static const value_string cyclic_align [] = {
	{ 0, "8bit" },
	{ 1, "8bit" },
	{ 2, "16bit" },
	{ 4, "32bit" },
	{ 8, "64bit" },
	{ 0, NULL }
};

/* Cyclic data scheme */
static const value_string cyclic_scheme [] = {
	{ 0, "Standard" },
	{ 1, "Synchronised" },
	{ 0, NULL }
};

/* Parameter addressing scheme */
static const value_string parameter_address_scheme [] = {
	{ 0, "Standard" },
	{ 1, "Slot Specific" },
	{ 3, "Variable" },
	{ 0, NULL }
};

#if 0
static const value_string route_address_scheme [] = {
	{ 1, "Intercept" },
	{ 2, "DefaultRoute" },
	{ 0, NULL }
};
#endif

/* Parameter access status */
static const value_string parameter_access_status [] = {
	{ 0, "OK" },
	{ 1, "OK - Converted"},
	{ 2, "OK - Clamped"},
	{ -1, "ERROR - Address Type"},
	{ -2, "ERROR - Timeout"},
	{ -3, "ERROR - Access Denied"},
	{ -4, "ERROR - Does not exist"},
	{ -5, "ERROR - Data Type"},
	{ -6, "ERROR - Failed Read"},
	{ -7, "ERROR - Failed Write"},
	{ -8, "ERROR - Not Readable"},
	{ -9, "ERROR - Not Writeable"},
	{ -10, "ERROR - Over Range"},
	{ -11, "ERROR - Request Invalid"},
	{ -12, "ERROR - Response Too Big"},
	{ -13, "ERROR - Decimal Place"},
	{ 0, NULL}
};

/* Parameter data types */
static const value_string parameter_data_types [] = {
	{ 0, "Boolean"},
	{ 1, "INT8"},
	{ 2, "UINT8"},
	{ 3, "INT16"},
	{ 4, "UINT16"},
	{ 5, "INT32"},
	{ 6, "UINT32"},
	{ 7, "INT64"},
	{ 8, "UINT64"},
	{ 9, "INT128"},
	{ 10, "UINT128"},
	{ 20, "SINGLE"},
	{ 21, "DOUBLE"},
	{ 30, "String ID"},
	{ 31, "String"},
	{ 0, NULL}
};

/* Info types */
static const value_string info_type [] = {
	{ 0, "No Information"},
	{ 1, "Lowest Numbered Parameter in Menu"},
	{ 2, "Highest Numbered Parameter in Menu"},
	{ 3, "Parameter Format"},
	{ 4, "Minimum Value allowed for Parameter"},
	{ 5, "Maximum Value allowed for Parameter"},
	{ 6, "Object Unit Information"},
	{ 7, "Data Type of Parameter"},
	{ 0, NULL }
};

/* Display formats */
static const value_string display_format [] = {
	{ 0, "Standard format"},
	{ 1, "Date format (xx,yy,zz)"},
	{ 2, "Time with seconds format (xx.yy.zz)"},
	{ 3, "Character format"},
	{ 4, "Binary format"},
	{ 5, "IP address format (www.xxx.yyy.zzz)"},
	{ 6, "MAC address format (AA:BB:CC:DD:EE:FF)"},
	{ 7, "Version number (ww.xx.yy.zz)"},
	{ 8, "Slot menu parameter format (x,yy,zzz)"},
	{ 0, NULL}
};

/* Format units */
static const value_string format_units [] = {
	{ 0, "No units"},
	{ 1, "Custom units"},
	{ 2, "Millimetres (mm)"},
	{ 3, "Metres (m)"},
	{ 4, "User units (UU)"},
	{ 5, "Revolutions (revs)"},
	{ 6, "Degrees (')"},
/*	{ 7, ""}, */
	{ 8, "General position unit"},
	{ 9, "Millimetres per second (mm/s)"},
	{ 10, "User units per millisecond (UU/ms)"},
	{ 11, "Revolutions per minute (Rpm)"},
	{ 12, "Hertz (Hz)"},
	{ 13, "Kilohertz (kHz)"},
	{ 14, "Megahertz (MHz)"},
	{ 15, "General speed unit (Hz, rpm, mm/s)"},
	{ 16, "Closed loop speed unit (rpm, mm/s)"},
	{ 17, "Seconds per one thousand millimetres per seconds (s/m/s)"},
	{ 18, "User units per millimetre per second (UU/mm/s)"},
	{ 19, "Seconds per one thousand revolution per minute (s/1000rpm)"},
	{ 20, "Seconds per one hundred hertz (s/100Hz)"},
	{ 21, "General acceleration unit"},
	{ 22, "Closed loop acceleration unit"},
	{ 23, "Seconds squared per one thousand millimetres per second (s^2/1000ms/s)"},
	{ 24, "Seconds squared per user units per millisecond (s^2/UU/ms"},
	{ 25, "Seconds squared per one thousand revolutions per minute (s^2/1000rpm)"},
	{ 26, "Seconds squared per one hundred hertz (s^2/100Hz)"},
	{ 27, "General jerk unit"},
	{ 28, "Closed loop jerk unit"},
	{ 29, "Messages per second (Msg/s)"},
	{ 30, "Hours (Hours)"},
	{ 31, "Minutes (Mins)"},
	{ 32, "Seconds (s)"},
	{ 33, "Milliseconds (ms)"},
	{ 34, "Microseconds (us)"},
	{ 35, "Nanoseconds (ns)"},
	{ 36, "Volts (V)"},
	{ 37, "Amperes (A)"},
	{ 38, "Ohms (Ohms)"},
	{ 39, "Millihenrys (mH)"},
	{ 40, "Kilowatts (kW)"},
	{ 41, "Kilo-Volt-Amps-Reactive (kVAr)"},
	{ 42, "Megawatt hours (MWh)"},
	{ 43, "Kilowatt hours (kWh)"},
	{ 44, "Degrees Celsius ('C)"},
	{ 45, "Reciprocal of degrees Celsius (/'C)"},
	{ 46, "Kilogram-metres squared (kgm^2)"},
	{ 47, "Newton metres (Nm)"},
	{ 48, "Newton metres per ampere (Nm/A)"},
	{ 49, "open-circuit volts per 1000rpm (V/1000rpm)"},
	{ 50, "Bits (Bits)"},
	{ 51, "Bytes (Bytes)"},
	{ 52, "Kilobytes (kB)"},
	{ 53, "Megabytes (MB)"},
	{ 54, "Bits per second (Bit/s)"},
	{ 55, "Baud (Baud)"},
	{ 56, "Kilobaud (kBaud)"},
	{ 57, "Megabaud (MBaud)"},
	{ 58, "Poles (Poles)"},
	{ 59, "Percent (%)"},
	{ 60, "Volts per millisecond (V/ms)"},
	{ 0, NULL}
};

/* File status */
static const value_string file_status [] = {
	{ 0, "Processing"},
	{ 1, "OK"},
	{ 2, "OK - More Data"},
	{ 3, "OK - EOF"},
	{ -1, "ERROR - File Handle"},
	{ -2, "ERROR - Blocked"},
	{ -3, "ERROR - Blocking Mode"},
	{ -4, "ERROR - Not in Progress"},
	{ -5, "ERROR - Not Found"},
	{ -6, "ERROR - Read Only"},
	{ -7, "ERROR - Write Only"},
	{ -8, "ERROR - Not Created"},
	{ -9, "ERROR - No Data"},
	{ -10, "ERROR - Wrong Mode"},
	{ -11, "ERROR - Too Big"},
	{ -12, "ERROR - Protected"},
	{ -13, "ERROR - CRC"},
	{ -14, "ERROR - Length"},
	{ -15, "ERROR - Too Many Open"},
	{ -16, "ERROR - Invalid File"},
	{ -17, "ERROR - Invalid Request"},
	{ -18, "ERROR - No Append"},
	{ -19, "ERROR - Invalid State"},
	{ -20, "ERROR - Incompatible"},
	{ -21, "ERROR - Uninitialized"},
	{ 0, NULL}
};

/* File status mode */
static const value_string file_status_mode [] = {
	{ 0, "Information"},
	{ 1, "Read"},
	{ 2, "Create"},
	{ 3, "Append"},
	{ 4, "New Directory"},
	{ 0, NULL}
};

/* File attributes */
static const value_string file_attributes [] = {
	{ 0, "File Length"},
	{ 1, "File Integrity"},
	{ 2, "Calculate CRC32"},
	{ 3, "File Attributes"},
	{ 4, "Creation Date and Time"},
	{ 5, "Modification Date and Time"},
	{ 0, NULL}
};

/* File reference position */
static const value_string file_ref_point [] = {
	{ 0, "SoF - Start of file"},
	{ 1, "EoF - End of file"},
	{ 2, "Current - Use current file pointer"},
	{ 0, NULL}
};

static const value_string cyclic_setup_mode [] = {
	{ 0, "Create"},
	{ 1, "Edit"},
	{ 2, "Finalise"},
	{ 3, "Delete"},
	{ 4, "Exist"},
	{ 5, "List"},
	{ 6, "Info"},
	{ 10, "Set"},
	{ 11, "Get"},
	{ 12, "Get mappings"},
	{ 0, NULL}
};

static const value_string cyclic_attributes [] = {
	{ 0, "State"},
	{ 1, "Rx/Tx"},
	{ 2, "Synchronised"},
	{ 3, "MEC Offset"},
	{ 4, "Sample Period"},
	{ 5, "MEC Delay"},
	{ 6, "Data Change"},
	{ 7, "Rx Timeout Handler"},
	{ 8, "Rx Data Late Handler"},
	{ 9, "Transport Address"},
	{ 10, "Max Mappings"},
	{ 11, "Number Of Mappings"},
	{ 12, "Mapping Item"},
	{ 13, "Saveable"},
	{ 128, "Max RX Links"},
	{ 129, "Max TX Links"},
	{ 130, "Max Mappings Per Link"},
	{ 131, "Max Sync RX Links"},
	{ 132, "Max Sync TX Links"},
	{ 133, "Max Mappings Per Sync Link"},
	{ 134, "'Process At' Queue Depth"},
	{ 135, "MEC Period"},
	{ 0, NULL}
};

static const value_string cyclic_setup_link_dir [] = {
	{ 0, "Rx"},
	{ 1, "Tx"},
	{ 0, NULL}
};

static const value_string cyclic_setup_link_exists [] = {
	{ 0, "Does not exist"},
	{ 1, "Exists"},
	{ 0, NULL}
};

static const value_string cyclic_link_req_resp [] = {
	{ 0, "Request"},
	{ 1, "Response"},
	{ 0, NULL}
};

static const value_string additional_scheme_vals [] = {
	{ 0, "None"},
	{ 1, "Generic"},
	{ 0, NULL}
};

/* Program Control - command codes  */
static const value_string command_code_list [] = {
	{ 0, "Stop"},
	{ 1, "Start"},
	{ 2, "Reset"},
	{ 0, NULL }
	/*other commands to be added*/
};

/* Program Control - sub command codes  */
static const value_string sub_command_code_list [] = {
	{ 0, "Default"},
	{ 1, "User1"},
	{ 2, "User2"},
	{ 0, NULL }
	/*other sub commands to be added*/
};

/* Program Control - status codes  */
static const value_string status_list [] = {
	{ 0,   "OK"},
	{ -1,  "Error"},
	{ 0,   NULL }
	/*other status to be added*/
};

	/* Program Status - running state codes  */
static const value_string running_state_list [] = {
	{ 0,   "Stopped"},
	{ 1,   "Running"},
	{ 2,   "Exception"},
	{ 3,   "None (no program found in device)"},
	{ 0,   NULL }
	/*other status to be added*/
};

	/* Interrogate - command support states  */
static const value_string Interrogate_support_state [] = {
	{ 0,  "Not Supported"},
	{ 1,  "Supported"},
	{ 0,   NULL }
	/*other status to be added*/
};

	/* Interrogate - command / option states  */
static const value_string Interrogate_command_option_state [] = {
	{ 0,  "Command"},
	{ 1,  "Option"},
	{ 0,   NULL }
	/*other status to be added*/
};

static const value_string item_type_vals[] = {
	{ 0,  "File"},
	{ 1,  "Directory"},
	{ 0,   NULL }
};

static const value_string file_integrity_vals[] = {
	{ 0,  "Error"},
	{ 1,  "OK"},
	{ 0,   NULL }
};


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_ecmp()
*/
static gint hf_ecmp_command = -1;
static gint hf_ecmp_destination_address = -1;
static gint hf_ecmp_source_address = -1;
static gint hf_ecmp_diagnostic = -1;
static gint hf_ecmp_type_rr = -1;
static gint hf_ecmp_chunking = -1;
static gint hf_ecmp_max_response_size = -1;
static gint hf_ecmp_category = -1;
static gint hf_ecmp_option = -1;
static gint hf_ecmp_attribute = -1;
static gint hf_ecmp_no_of_attributes = -1;
static gint hf_ecmp_chunk_id = -1;
static gint hf_ecmp_transaction_id = -1;
static gint hf_ecmp_status = -1;
static gint hf_ecmp_drive_type = -1;
static gint hf_ecmp_drive_derivative = -1;
static gint hf_ecmp_drive_factory_fit_category_id = -1;
static gint hf_ecmp_category_id = -1;
static gint hf_ecmp_attribute_string = -1;
static gint hf_ecmp_file_name = -1;
static gint hf_ecmp_info_command = -1;
static gint hf_ecmp_directory = -1;
static gint hf_ecmp_names_scheme = -1;
static gint hf_ecmp_variable_name = -1;
static gint hf_ecmp_unit_id_string = -1;
static gint hf_ecmp_ecmp_string = -1;
static gint hf_ecmp_process_time = -1;
static gint hf_ecmp_cyclic_frame_time = -1;
static gint hf_ecmp_grandmaster = -1;
static gint hf_ecmp_data = -1;
static gint hf_ecmp_response_data = -1;

static gint hf_ecmp_cyclic_link_num = -1;
static gint hf_ecmp_cyclic_align = -1;
static gint hf_ecmp_cyclic_scheme = -1;
static gint hf_ecmp_cyclic_link_number_display = -1;

/* Cyclic setup */
static gint hf_ecmp_cyclic_setup_mode = -1;
static gint hf_ecmp_cyclic_setup_linkno = -1;
static gint hf_ecmp_cyclic_setup_dir = -1;
static gint hf_ecmp_cyclic_setup_attrib_count = -1;
static gint hf_ecmp_cyclic_setup_rsp_status = -1;
static gint hf_ecmp_cyclic_setup_rsp_err_idx = -1;
static gint hf_ecmp_cyclic_setup_attrib = -1;
static gint hf_ecmp_cyclic_setup_link_exists = -1;
static gint hf_ecmp_cyclic_link_req_resp = -1;

/*for info command */
static gint hf_ecmp_buffer_size = -1;
static gint hf_ecmp_max_response = -1;
static gint hf_ecmp_max_handle = -1;
static gint hf_ecmp_info_address = -1;

/*for parameter access commands*/
static gint hf_ecmp_parameter_address = -1;
static gint hf_ecmp_number_of_parameter_definitions = -1;
static gint hf_ecmp_number_of_parameter_responses = -1;
static gint hf_ecmp_parameter_status = -1;
static gint hf_ecmp_data_type = -1;
static gint hf_ecmp_info_type = -1;

/* for file access commands */
static gint hf_ecmp_file_status = -1;
static gint hf_ecmp_file_handle = -1;
static gint hf_ecmp_file_attributes = -1;
static gint hf_ecmp_file_ref_point = -1;


/* for tunnel frame command */
#define TUNNEL_START_FLAG		0x01
#define TUNNEL_END_FLAG			0x02
#define TUNNEL_CHECK_OUTPUT_FLAG	0x04

static gint hf_ecmp_tunnel_control = -1;
static gint hf_ecmp_tunnel_start_flag = -1;
static gint hf_ecmp_tunnel_end_flag = -1;
static gint hf_ecmp_tunnel_check_output_flag = -1;
static gint hf_ecmp_tunnel_size = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ecmp_physical_address = -1;
static int hf_ecmp_logical_address = -1;
static int hf_ecmp_primary_colour = -1;
static int hf_ecmp_secondary_colour = -1;
static int hf_ecmp_number_of_subsequent_object_requests = -1;
static int hf_ecmp_number_of_decimal_places = -1;
static int hf_ecmp_no_information_available = -1;
static int hf_ecmp_param_format_bit_default_unipolar = -1;
static int hf_ecmp_param_format_write_allowed = -1;
static int hf_ecmp_param_format_read_not_allowed = -1;
static int hf_ecmp_param_format_protected_from_destinations = -1;
static int hf_ecmp_param_format_parameter_not_visible = -1;
static int hf_ecmp_param_format_not_clonable = -1;
static int hf_ecmp_param_format_voltage_or_current_rating_dependent = -1;
static int hf_ecmp_param_format_parameter_has_no_default = -1;
static int hf_ecmp_param_format_number_of_decimal_places = -1;
static int hf_ecmp_param_format_variable_maximum_and_minimum = -1;
static int hf_ecmp_param_format_string_parameter = -1;
static int hf_ecmp_param_format_destination_set_up_parameter = -1;
static int hf_ecmp_param_format_filtered_when_displayed = -1;
static int hf_ecmp_param_format_pseudo_read_only = -1;
static int hf_ecmp_param_format_display_format = -1;
static int hf_ecmp_param_format_floating_point_value = -1;
static int hf_ecmp_param_format_units = -1;
static int hf_ecmp_string_id = -1;
static int hf_ecmp_address_scheme_menu = -1;
static int hf_ecmp_address_scheme_parameter = -1;
static int hf_ecmp_address_scheme_slot = -1;
static int hf_ecmp_address_scheme_null_byte_size = -1;
static int hf_ecmp_display_unit_id = -1;
static int hf_ecmp_data_boolean = -1;
static int hf_ecmp_data_int8 = -1;
static int hf_ecmp_data_uint8 = -1;
static int hf_ecmp_data_int16 = -1;
static int hf_ecmp_data_uint16 = -1;
static int hf_ecmp_data_int32 = -1;
static int hf_ecmp_data_uint32 = -1;
static int hf_ecmp_data_int64 = -1;
static int hf_ecmp_data_uint64 = -1;
static int hf_ecmp_data_float = -1;
static int hf_ecmp_data_double = -1;
static int hf_ecmp_access_mode = -1;
static int hf_ecmp_open_in_non_blocking_mode = -1;
static int hf_ecmp_open_file_relative_to_specified_directory_handle = -1;
static int hf_ecmp_file_access_mode = -1;
static int hf_ecmp_additional_scheme = -1;
static int hf_ecmp_scheme_data_length = -1;
static int hf_ecmp_number_of_requested_bytes = -1;
static int hf_ecmp_number_of_bytes_transferred = -1;
static int hf_ecmp_crc = -1;
static int hf_ecmp_ref_offset = -1;
static int hf_ecmp_number_of_files_to_list = -1;
static int hf_ecmp_file_hash = -1;
static int hf_ecmp_item_type = -1;
static int hf_ecmp_file_integrity = -1;
static int hf_ecmp_display_attr_read_only = -1;
static int hf_ecmp_display_attr_hidden = -1;
static int hf_ecmp_display_attr_system = -1;
static int hf_ecmp_display_attr_volume_label = -1;
static int hf_ecmp_display_attr_subdirectory = -1;
static int hf_ecmp_display_attr_archive = -1;
static int hf_ecmp_display_creation = -1;
static int hf_ecmp_display_modification = -1;
static int hf_ecmp_interrogate_item_type = -1;
static int hf_ecmp_interrogate_count = -1;
static int hf_ecmp_modbus_pdu_size = -1;
/* static int hf_ecmp_destination_scheme = -1; */
static int hf_ecmp_program_control_target = -1;
static int hf_ecmp_program_control_command = -1;
static int hf_ecmp_program_control_sub_command = -1;
static int hf_ecmp_program_control_status = -1;
static int hf_ecmp_program_status_target = -1;
static int hf_ecmp_program_status_status = -1;
static int hf_ecmp_program_status_additional_items = -1;
static int hf_ecmp_cyclic_setup_max_mappings = -1;
static int hf_ecmp_cyclic_setup_start_offset = -1;
static int hf_ecmp_cyclic_setup_tx_count = -1;
static int hf_ecmp_cyclic_setup_rx_count = -1;
static int hf_ecmp_udp_alignment = -1;
static int hf_ecmp_udp_scheme = -1;
static int hf_ecmp_cyclic_data = -1;
static int hf_ecmp_version_summary = -1;
static int hf_ecmp_min_param_menu = -1;
static int hf_ecmp_max_param_menu = -1;
static int hf_ecmp_file_length = -1;
static int hf_ecmp_mec_offset = -1;
static int hf_ecmp_sample_period = -1;
static int hf_ecmp_rx_timeout = -1;
static int hf_ecmp_rx_action = -1;
static int hf_ecmp_rx_event_destination = -1;
static int hf_ecmp_rx_event = -1;
static int hf_ecmp_rx_late_handler_action = -1;
static int hf_ecmp_rx_late_handler_event_destination = -1;
static int hf_ecmp_rx_late_handler_event = -1;
static int hf_ecmp_transport_addr_scheme = -1;
static int hf_ecmp_transport_addr = -1;
static int hf_ecmp_mapping_item_offset = -1;
static int hf_ecmp_mapping_item_scheme = -1;
static int hf_ecmp_setup_attribute = -1;
static int hf_ecmp_mec_period = -1;
static int hf_ecmp_interrogate_command = -1;
/************************************************************/

/* These are the ids of the subtrees that we may be creating */

static gint ett_ecmp = -1;
static gint ett_ecmp_address= -1;
static gint ett_ecmp_response_size = -1;
static gint ett_ecmp_command = -1;
static gint ett_ecmp_category = -1;
static gint ett_ecmp_option = -1;
static gint ett_ecmp_option_data = -1;
static gint ett_ecmp_attribute = -1;
static gint ett_ecmp_attribute_data = -1;
static gint ett_ecmp_cyclic_scheme = -1;
static gint ett_ecmp_info_type = -1;
static gint ett_ecmp_info_count = -1;
static gint ett_ecmp_interrogate_message = -1;
static gint ett_ecmp_param_address = -1;
static gint ett_ecmp_access_mode = -1;
static gint ett_ecmp_access_file = -1;
static gint ett_ecmp_file_read = -1;
static gint ett_ecmp_file_write = -1;
static gint ett_ecmp_file_info = -1;
static gint ett_ecmp_file_info_att = -1;
static gint ett_ecmp_file_position = -1;
static gint ett_ecmp_file_list_no = -1;
static gint ett_ecmp_file_list = -1;
static gint ett_ecmp_tunnel_3s_goodframe = -1;
static gint ett_ecmp_tunnel_3s_size = -1;
static gint ett_ecmp_tunnel_3s_service = -1;
static gint ett_cyclic_setup_attribs = -1;
static gint ett_cyclic_setup_attrib_item = -1;
static gint ett_cyclic_setup_transport_addr = -1;
static gint ett_ecmp_cyclic_data_32_bit_display = -1;
static gint ett_ecmp_cyclic_data_16_bit_display = -1;
static gint ett_ecmp_cyclic_data_8_bit_display = -1;
static gint ett_ecmp_modbus_pdu_message = -1;
static gint ett_ecmp_program_control_message = -1;
static gint ett_ecmp_program_status_message = -1;
static expert_field ei_ecmp_unknown_command = EI_INIT;
static expert_field ei_ecmp_color = EI_INIT;
static expert_field ei_ecmp_option = EI_INIT;
static expert_field ei_ecmp_item_type = EI_INIT;
static expert_field ei_ecmp_options_not_implemented = EI_INIT;
static expert_field ei_ecmp_info_type = EI_INIT;
static expert_field ei_ecmp_attribute_type = EI_INIT;
static expert_field ei_ecmp_parameter_addressing_scheme = EI_INIT;
static expert_field ei_ecmp_data_type = EI_INIT;


/*--------------------------------------------------------------------*/
/* General Commands and Framing Dissectors                            */
/*--------------------------------------------------------------------*/
/*a function to add the initial information about the transport layer (the first bits)*/
static int add_transport_layer_frame(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree, int addr_type)
{
	proto_item *ecmp_address_item = NULL;
	proto_tree *ecmp_address_tree = NULL;
	guint8 byte_test;

	ecmp_address_item = proto_tree_add_item(ecmp_tree, addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	byte_test = tvb_get_guint8(tvb, offset);
	if ((byte_test != 0) && (byte_test != 1)) {
		/* tree to display the data in the address*/
		ecmp_address_tree = proto_item_add_subtree(ecmp_address_item, ett_ecmp_address);

		switch (byte_test)
		{
		case 2: /*  default route scheme*/
			offset++;

			/* displays the values of the addresses*/
			proto_tree_add_item(ecmp_address_tree, hf_ecmp_physical_address, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ecmp_address_tree, hf_ecmp_logical_address, tvb, offset, 1, ENC_NA);
			break;

		case 3:/*  diagnostic scheme*/
			proto_tree_add_item(ecmp_address_tree, hf_ecmp_diagnostic, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 4: /* Names scheme */
			/* Calls a function to display the UTF-8 string data*/
			proto_tree_add_item(ecmp_address_tree, hf_ecmp_names_scheme, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_ASCII);
			offset += (tvb_get_ntohs(tvb, offset) + 2);
			break;
		}
	}
	offset++;

	return offset;
}


/* a function to display option codes */
static int add_option_codes(int offset, packet_info *pinfo, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_option_number_item = NULL;
	proto_item* ecmp_option_item;
	proto_tree* ecmp_option_tree;
	proto_tree* ecmp_option_data_tree = NULL;
	guint8 option_code_display = 0;
	guint16 count = 0; /* number of times the loop iterates*/
	int start_offset;
	gboolean more_options = TRUE;

	offset++;

	start_offset = offset;
	ecmp_option_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 1, ett_ecmp_option, &ecmp_option_number_item, "Options" );

	/* Loop to display all options */
	while(more_options) /* loops until option code is 0*/
	{
		option_code_display = tvb_get_guint8(tvb, offset);
		ecmp_option_item = proto_tree_add_item(ecmp_option_tree, hf_ecmp_option, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option_code_display)
		{
		case 0:/* end of options*/
			proto_item_append_text(ecmp_option_number_item, ": %d", count);
			proto_item_set_len(ecmp_option_number_item, offset-start_offset);
			more_options = FALSE;
			break;
		case 1:/* dummy - 0 bytes of data */
			break;
		case 2:/* process at - 8 bytes of data */
			ecmp_option_data_tree = proto_item_add_subtree(ecmp_option_item, ett_ecmp_option_data);

			proto_tree_add_item(ecmp_option_data_tree, hf_ecmp_process_time, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
			break;
		default: /* Option that is not recognised*/
			proto_item_append_text(ecmp_option_number_item, "%d ", count);
			expert_add_info(pinfo, ecmp_option_number_item, &ei_ecmp_option);
			break;
		}
		count++;
	}
	return offset;
}


/* a function to display attributes */
static void add_attributes(packet_info* pinfo, int offset, tvbuff_t *tvb, proto_tree* ecmp_tree, gboolean request)
{
	proto_item* ecmp_attribute_number_item = NULL;
	proto_item* ecmp_attribute_item = NULL, *color_item;
	proto_tree* ecmp_attribute_tree = NULL;
	proto_tree* ecmp_attribute_data_tree = NULL;
	guint8 no_of_attributes = 0;
	guint8 a = 0; /*values used for looping*/
	guint8 b = 0;
	guint8 c = 0;
	guint8 check = 0;
	guint16 att_length = 0;
	guint32 color;
	gchar* pStr = NULL; /*char array for version string output*/
	int start_offset = offset;

	/*display the number of attributes*/
	ecmp_attribute_number_item = proto_tree_add_item(ecmp_tree, hf_ecmp_no_of_attributes, tvb, offset, 1, ENC_BIG_ENDIAN);
	ecmp_attribute_tree = proto_item_add_subtree(ecmp_attribute_number_item, ett_ecmp_attribute);

	no_of_attributes = tvb_get_guint8(tvb, offset);
	offset++;

	for (a = 0; a < no_of_attributes; a++, offset++) {
		/*attribute header*/
		ecmp_attribute_item = proto_tree_add_item(ecmp_attribute_tree, hf_ecmp_attribute, tvb, offset, 1, ENC_BIG_ENDIAN );
		ecmp_attribute_data_tree = proto_item_add_subtree(ecmp_attribute_item, ett_ecmp_attribute_data);

		if (!request) {
			/*code for dissecting the colour codes attribute*/
			switch(tvb_get_guint8(tvb, offset))
			{
			case 8:
				offset+= 1;
				/*get length of attribute for error checking*/
				offset+= 2;

				/*output primary colour codes- the two bytes representing each colour are output as integers*/
				color = tvb_get_ntohl(tvb, offset);
				color_item = proto_tree_add_uint_format_value(ecmp_attribute_data_tree, hf_ecmp_primary_colour, tvb, offset, 4, color, "(red) %d (green) %d (blue) %d", tvb_get_guint8(tvb, offset+1), tvb_get_guint8(tvb, offset+2), tvb_get_guint8(tvb, offset+3));
				if ((color & 0xFF000000) != 0) {
					/*error check for correct colour code format */
					expert_add_info(pinfo, color_item, &ei_ecmp_color);
				}
				offset+= 4;

				/*output secondary colour codes- the two bytes representing each colour are output as integers*/
				color = tvb_get_ntohl(tvb, offset);
				color_item = proto_tree_add_uint_format_value(ecmp_attribute_data_tree, hf_ecmp_secondary_colour, tvb, offset, 4, color, "(red) %d (green) %d (blue) %d", tvb_get_guint8(tvb, offset+1), tvb_get_guint8(tvb, offset+2), tvb_get_guint8(tvb, offset+3));
				if ((color & 0xFF000000) != 0) {
					/*error check for correct colour code format */
					expert_add_info(pinfo, color_item, &ei_ecmp_color);
				}
				offset+= 4;
				break;
			/*code for dissecting the version summary attribute*/
			case 7:
				offset++;
				att_length = tvb_get_ntohs(tvb, offset);
				pStr = (gchar *)wmem_alloc(wmem_packet_scope(), att_length+1); /* 100 char buffer */
				b = 0;
				offset+= 2;
				if (pStr != NULL) {
					for (c = 0; c < att_length; c++, offset++) {
						check = tvb_get_guint8(tvb,offset);
						if((check == 'V')||(check == '#')||(check == '@')) {
							pStr[b] = ' ';
							b++;
						} else if(tvb_get_guint8(tvb,offset)== (';')) {
							pStr[b] = 0;
							/*display version summary parameter, e.g 'FW', 'BL', 'HW'*/
							proto_tree_add_string(ecmp_attribute_data_tree, hf_ecmp_version_summary, tvb, offset-b, b, pStr);
							b = 0;
						} else {
							pStr[b] = (gchar)tvb_get_guint8(tvb,offset);
							b++;
						}
					}
					pStr[b] = 0;
					/*display last version summary parameter, e.g 'FW', 'BL', 'HW' as no deliminator to check for, just prints out rest of version string*/
					proto_tree_add_string(ecmp_attribute_data_tree, hf_ecmp_version_summary, tvb, offset-b, b, pStr);
					offset-= 1;
				}
				break;
			default:
				/* displays the data inside the attribute*/
				proto_tree_add_item(ecmp_attribute_data_tree, hf_ecmp_attribute_string, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
				offset += (tvb_get_ntohs(tvb, offset+1) + 2);
				break;
			}
		}
	}

	proto_item_set_len(ecmp_attribute_number_item, offset-start_offset);
}


/* a function to display the category codes */
static int add_category_codes(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item *ecmp_category_item = NULL;
	proto_tree *ecmp_category_tree = NULL;
	guint8 category_size = 0;
	int start_offset = offset;
	guint8 category_value = tvb_get_guint8(tvb, offset);

	/* displays the category and creates a tree to display further data*/
	ecmp_category_item = proto_tree_add_item(ecmp_tree, hf_ecmp_category, tvb, offset, 1, ENC_BIG_ENDIAN);
	ecmp_category_tree = proto_item_add_subtree(ecmp_category_item, ett_ecmp_category);
	offset++;

	category_size = tvb_get_guint8(tvb, offset);
	offset++;

	if(category_size==2 && category_value == 1) {
		/*display "option module" and its ID*/
		proto_tree_add_item(ecmp_category_tree, hf_ecmp_category_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=category_size;
	} else if(category_size == 4 && category_value == 0) {
		/*display "drive" and its data (product type, drive derivative and ID*/
		proto_tree_add_item(ecmp_category_tree, hf_ecmp_drive_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ecmp_category_tree, hf_ecmp_drive_derivative, tvb, offset+1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ecmp_category_tree, hf_ecmp_drive_factory_fit_category_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		offset+=category_size;

	} else {
		/* Display unknown and its hex data */
		proto_tree_add_item(ecmp_category_tree, hf_ecmp_data, tvb, offset, category_size, ENC_NA);
		offset += category_size;
	}

	proto_item_set_len(ecmp_category_item, offset-start_offset);
	return offset;
}


/* a function to display response size data */
static int get_response_size(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_max_response_item = NULL;
	proto_tree* ecmp_response_size_tree = NULL;
	guint8 chunks = 0;
	guint16 max_response_size = 0;

	/*get values for number of chunks and max response size*/
	chunks = tvb_get_guint8(tvb, offset)>>4&0x0F;
	max_response_size = tvb_get_ntohs(tvb, offset) & 0x0FFF;

	/*display response subtree */
	ecmp_response_size_tree = proto_tree_add_subtree_format(ecmp_tree, tvb, offset, 2, ett_ecmp_response_size, &ecmp_max_response_item, "Response Size: %X, %X (%d)", chunks, max_response_size, max_response_size);

	/*display chunks and max response size in response subtree*/
	proto_tree_add_item(ecmp_response_size_tree, hf_ecmp_chunking, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecmp_response_size_tree, hf_ecmp_max_response_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+= 2;

	return offset;
}


/* a function to display the command code and type (request/response) */
static int add_command_codes(packet_info* pinfo, int offset, tvbuff_t *tvb, proto_tree* ecmp_tree, guint8 transaction_id_value, guint8* command_value)
{
	proto_tree *ecmp_command_tree;
	const gchar* command_str;
	guint8 command;

	command = tvb_get_guint8(tvb, offset);
	*command_value = command & 0x7F;
	command_str = val_to_str(*command_value, command_vals, "Unknown Type (0x%02x)");

	/*display command subtree*/
	ecmp_command_tree = proto_tree_add_subtree_format(ecmp_tree, tvb, offset, 1, ett_ecmp_command, NULL, "Request Response Code: %s", command_str);

	/* Displays the command */
	proto_tree_add_item(ecmp_command_tree, hf_ecmp_command, tvb, offset, 1, ENC_BIG_ENDIAN);
	/* Displays the type (request/response) */
	proto_tree_add_item(ecmp_command_tree, hf_ecmp_type_rr, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Information displayed in the Info column*/
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s. Transaction ID: %d",
			command_str, val_to_str(((command & 0x80) >> 7), type_rr, "Unknown Type (0x%02x)"), transaction_id_value);

	return offset;
}


/* a function to add a cyclic frame query */
static int add_cyclic_frame_query(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree )
{
	/* display the cyclic link number  */
	proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_link_num, tvb, offset++, 1, ENC_BIG_ENDIAN);
	return offset;
}


/* a function to add a cyclic frame */
static int add_cyclic_frame(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree )
{
	guint8 scheme;
	proto_item *ecmp_scheme_item = NULL;
	proto_tree *ecmp_scheme_tree = NULL;
	proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_link_num, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_align, tvb, offset++, 1, ENC_BIG_ENDIAN);

	/* get scheme */
	scheme = tvb_get_guint8(tvb, offset);

	ecmp_scheme_item = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_scheme, tvb, offset++, 1, ENC_BIG_ENDIAN);

	if (scheme == 1) {
		/* Create a new sub tree spawning off the scheme byte for the synchronisation scheme data to be placed. */
		ecmp_scheme_tree = proto_item_add_subtree(ecmp_scheme_item, ett_ecmp_cyclic_scheme);

		/* grandmaster */
		proto_tree_add_item( ecmp_scheme_tree, hf_ecmp_grandmaster, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;

		proto_tree_add_item(ecmp_scheme_tree, hf_ecmp_cyclic_frame_time, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset, -1, ENC_NA);

	return tvb_reported_length(tvb);
}


/* a function to display cyclic tvb data in byte (8-bit), word (16-bit), and long (32-bit) unsigned formats  */
static int display_raw_cyclic_data(guint8 display, int offset, guint16 buffer_size, tvbuff_t *tvb, proto_tree* ecmp_current_tree )
{
	/****************************************************************************************/
	/*                                                                                      */
	/*     display_raw_cyclic_data - display the cyclic data in various formats.            */
	/*                                                                                      */
	/*     Parameters:   display = selects desired display format.                          */
	/*                             0  =  BYTE_FORMAT (8-bits  1F 20 37 BC ...               */
	/*                             1  =  WORD_FORMAT (16-bits 1F20 37BC 77F1 ...            */
	/*                             2  =  LONG_FORMAT (32-bits  1F2037BC 0013F5CD ...        */
	/*                                                                                      */
	/*                   offset  =  offset within tvb buffer where this data starts.        */
	/*                                                                                      */
	/*                   buffer_size = number of bytes to be converted and displayed.       */
	/*                                                                                      */
	/*                   tvb  =  buffer structure within Wireshark holding this frame.      */
	/*                                                                                      */
	/*                   ecmp_current_tree  =  the tree where the data is to be displayed.  */
	/*                                                                                      */
	/*                                                                                      */
	/*   Notes: we only display so many elements on a line (before continuing on next line) */
	/*                                                                                      */
	/*          16 elements per line for byte (8-bit) and word (16-bit)                     */
	/*           8 elements per line for long (32-bit)                                      */
	/*                                                                                      */
	/*  Programmer: Jim Lynch                                                               */
	/****************************************************************************************/

	/* bail out if the buffer size is zero */
	if (buffer_size == 0) {
		proto_tree_add_bytes_format_value(ecmp_current_tree, hf_ecmp_cyclic_data, tvb, offset-1, 0, NULL, "No data");
	} else {
		/* define some variables  */
		gchar*		pdata = NULL; /* pointer to array that stores the formatted data string */
		guint16		idx = 0; /* counts through formatted string array */
		guint8		value8 = 0; /* placeholder for extracted 8-bit data */
		guint16		value16 = 0; /* placeholder for extracted 16-bit data */
		guint32		value32 = 0; /* placeholder for extracted 32-bit data */
		guint16		num_elements_total = 0; /* contains total number of elements (byte/word/long) to be processed  */
		const guint16	num_byte_elements_per_line = 16; /* number of byte (8-bit) elements per line e.g.  "1B " (3 chars per element)  */
		const guint16	num_word_elements_per_line = 16; /* number of word (16-bit) elements per line e.g.  "A81B " (5 chars per element) */
		const guint16	num_long_elements_per_line = 8; /* number of long (32-bit) elements per line e.g.  "01F4A81B " (9 chars per element) */
		guint16		num_elements_per_line = 8; /* counts the current number of elements per line */
		guint16		num_elements = 0; /* counts the number of elements in the format string */
		guint16		format_string_size = 0; /* size of dynamic array to hold the formatted string */
		guint16		a = 0; /* value used for looping */
		int		start_offset, line_offset;

		/* calculate format string array size and other stuff                               */
		/*                                                                                  */
		/* Note: format string does require a nul-terminator (the + 1 in the equations)     */
		/*                                                                                  */
		/* display = 0:  (byte format  "1D 24 3F ... A3 "                                   */
		/*      format_string_size = (num_byte_elements_per_line * 3) + 1                   */
		/*                                                                                  */
		/* display = 1:  (word format  "1D24 3F84 120B ... 1FA3 "                           */
		/*      format_string_size = (num_word_elements_per_line * 5) + 1                   */
		/*                                                                                  */
		/* display = 2:  (byte format  "1D243F84 9BC08F20 ... 28BB1FA3 "                    */
		/*      format_string_size = (num_long_elements_per_line * 9) + 1                   */
		/*                                                                                  */
		if (display == cyclic_display_byte_format) {
			format_string_size = (num_byte_elements_per_line * 3) + 1; /* format_string_size = 49  */
			num_elements_per_line = num_byte_elements_per_line; /* num_elements_per_line = 16  */
			num_elements_total = buffer_size;
		} else if (display == cyclic_display_word_format) {
			format_string_size = (num_word_elements_per_line * 5) + 1; /* format_string_size = 81  */
			num_elements_per_line = num_word_elements_per_line; /* num_elements_per_line = 16  */
			num_elements_total = buffer_size >> 1;
		} else if (display == cyclic_display_long_format) {
			format_string_size = (num_long_elements_per_line * 9) + 1; /* format_string_size = 73  */
			num_elements_per_line = num_long_elements_per_line; /* num_elements_per_line = 8  */
			num_elements_total = buffer_size >> 2;
		} else {
			format_string_size = (num_byte_elements_per_line * 3) + 1; /* format_string_size = 49  */
			num_elements_per_line = num_byte_elements_per_line; /* num_elements_per_line = 16  */
			num_elements_total = buffer_size;
		}

		/* allocate dynamic memory for one line  */
		pdata = (gchar *)wmem_alloc(wmem_packet_scope(), format_string_size);

		/* OK, let's get started */
		idx = 0;
		num_elements = 0;

		line_offset = start_offset = offset;
		/* work through the display elements, 1 byte\word\long at a time  */
		for (a = 0; a < num_elements_total; a++ )
			{
			/* use Wireshark accessor function to get the next byte, word, or long data  */
			if (display == cyclic_display_byte_format) {
				value8 = tvb_get_guint8(tvb, offset);
				offset++;
			} else if (display == cyclic_display_word_format) {
				value16 = tvb_get_ntohs(tvb, offset);
				offset += 2;
			} else if (display == cyclic_display_long_format) {
				value32 = tvb_get_ntohl(tvb, offset);
				offset += 4;
			}

			/* increment the num_elements we've done on the current line  */
			num_elements++;

			/* check if we hit the max number of byte elements per line  */
			if (num_elements >= num_elements_per_line) {
				/* we hit end of the current line  */
				/* add final value to string */
				if (display == cyclic_display_byte_format) {
					snprintf(&pdata[idx], 32, "%02x",value8);
				} else if (display == cyclic_display_word_format) {
						snprintf(&pdata[idx], 32, "%04x",value16);
				} else if (display == cyclic_display_long_format) {
					snprintf(&pdata[idx], 32, "%08x",value32);
				}

				/* display the completed line in the sub-tree  */
				proto_tree_add_bytes_format(ecmp_current_tree, hf_ecmp_cyclic_data, tvb, offset, offset-line_offset, NULL, "%s", pdata);

				/* start the line over */
				idx = 0;
				num_elements = 0;
				line_offset = offset;

			} else {
				/* we're still adding to the current line  */
				/* add current value to string */
				if (display == cyclic_display_byte_format) {
					snprintf(&pdata[idx], 32, "%02x ",value8);
					idx += 3;
				} else if (display == cyclic_display_word_format) {
					snprintf(&pdata[idx], 32, "%04x ",value16);
					idx += 5;
				} else if (display == cyclic_display_long_format) {
					snprintf(&pdata[idx], 32, "%08x ",value32);
					idx += 9;
				}
			}
		}

		/* if we exited the loop, see if there's a partial line to display  */
		if (num_elements > 0) {
			/* add null-terminator to partial line  */
			pdata[idx] = 0x00;

			/* display the partial line in the sub-tree  */
			proto_tree_add_bytes_format(ecmp_current_tree, hf_ecmp_cyclic_data, tvb, start_offset, offset-start_offset, NULL, "%s", pdata);
		}
	}
	return offset;
}


/* a function returning the information requested by the 'info' command */
static void add_info_response(int offset, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_info_address_item = NULL;
	proto_tree* ecmp_info_tree = NULL;
	proto_tree* ecmp_info_address_tree = NULL, *address_tree;
	guint16 length = 0;
	guint8 no_of_address = 0;
	guint8 i = 0; /*for counting */

	length = tvb_reported_length(tvb);

	/*display info response tree */
	ecmp_info_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 6, ett_ecmp_info_type, NULL, "Response Information");

	/*display buffer size */
	proto_tree_add_item(ecmp_info_tree, hf_ecmp_buffer_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+= 2;

	/*display max response time */
	proto_tree_add_item(ecmp_info_tree, hf_ecmp_max_response, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+= 2;

	/*display max handle period */
	proto_tree_add_item(ecmp_info_tree, hf_ecmp_max_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+= 2;

	if (length > offset) {
		/*display count of default server addresses */
		ecmp_info_address_item = proto_tree_add_item(ecmp_tree, hf_ecmp_info_address, tvb, offset, 1, ENC_BIG_ENDIAN);
		ecmp_info_address_tree = proto_item_add_subtree(ecmp_info_address_item, ett_ecmp_info_count);
		no_of_address = tvb_get_guint8(tvb, offset);

		if (no_of_address > 0) {
			/*do code to display address data */
			for (i = 0; i < no_of_address; i++) {
				address_tree = proto_tree_add_subtree_format(ecmp_info_address_tree, tvb, offset, 1, ett_ecmp_address, NULL, "Address %d", i+1);
				proto_tree_add_item(address_tree, hf_ecmp_physical_address, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(address_tree, hf_ecmp_logical_address, tvb, offset, 1, ENC_NA);
				offset+= 1;
			}
		}
	}
}


/*--------------------------------------------------------------------*/
/*                Parameter Access Commands                           */
/*--------------------------------------------------------------------*/

/* a function to display data given data_type */
static int get_data_type(packet_info* pinfo, int offset, guint8 data_type, tvbuff_t *tvb, proto_tree* ecmp_current_tree)
{
	/*switch to decide correct data_type dissection*/
	switch(data_type)
	{
	case 0: /*display boolean*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_boolean, tvb, offset, 1, ENC_NA);
		break;
	case 1: /*display INT8*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_int8, tvb, offset, 1, ENC_NA);
		break;
	case 2: /*display UINT8*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_uint8, tvb, offset, 1, ENC_NA);
		break;
	case 3: /*display INT16*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_int16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+= 1;
		break;
	case 4: /*display UINT16*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+= 1;
		break;
	case 5: /*display INT32*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+= 3;
		break;
	case 6: /*display UINT32*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+= 3;
		break;
	case 7: /*display INT64*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_int64, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+= 7;
		break;
	case 8: /*display UINT64*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_uint64, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+= 7;
		break;
	case 9:  /*display INT128*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data, tvb, offset, 16, ENC_NA);
		offset += 15;
		break;
	case 10: /*display UINT128*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data, tvb, offset, 16, ENC_NA);
		offset += 15;
		break;
	case 20:/*display single float*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_float, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+= 3;
		break;
	case 21: /*display double float*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_data_double, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+= 7;
		break;
	case 30: /*display string ID*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_string_id, tvb, offset, 2, ENC_NA|ENC_ASCII);
		offset++;
		break;
	case 32: /*display (ECMP) string*/
		proto_tree_add_item(ecmp_current_tree, hf_ecmp_ecmp_string, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
		offset += (tvb_get_ntohs(tvb, offset+1) + 2);
		break;
	default: /*display untyped size*/
		if (data_type < 128) {
			proto_tree_add_expert(ecmp_current_tree, pinfo, &ei_ecmp_data_type, tvb, 0, -1);
		} else {
			proto_tree_add_item(ecmp_current_tree, hf_ecmp_data, tvb, offset, (data_type- 127), ENC_NA);
			offset += (data_type- 128);
		}
		break;
	}
	return offset;
}


/* a function to add the parameter address schemes for 'read' command */
static int get_address_scheme(packet_info* pinfo, int offset, guint8 scheme, tvbuff_t *tvb, proto_tree* ecmp_parameter_tree)
{
	/*if address scheme is standard*/
	switch (scheme)
	{
	case 0:
		/*display Menu no. */
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_menu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+= 2;

		/*display parameter no. */
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_parameter, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset++;
		break;

	case 1:/*if address scheme is slot specific*/
		/*display slot number*/
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_slot, tvb, offset, 1, ENC_NA);
		offset++;

		/*display Menu no. */
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_menu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+= 2;

		/*display parameter no. */
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_parameter, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset++;
		break;

	case 3: /*if address scheme is variable*/
		/*display variable name */
		offset--;
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_variable_name, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
		offset += (tvb_get_ntohs(tvb, offset+1) + 2);
		break;

	case 4: /*if address scheme is NULL*/
		/*null size*/
		proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_address_scheme_null_byte_size, tvb, offset, 1, ENC_NA);
		offset++;
		break;

	default:
		proto_tree_add_expert(ecmp_parameter_tree, pinfo, &ei_ecmp_parameter_addressing_scheme, tvb, offset, 1);
	}
	return offset;
}


/* a function to display an array of the read address schemes */
static void get_parameter_definitions(packet_info* pinfo, int offset, guint8 command_value, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_parameter_item = NULL;
	proto_tree* ecmp_parameter_number_tree = NULL;
	proto_tree* ecmp_parameter_tree = NULL;
	guint8 count = 0;
	guint8 a = 0;
	guint8 data_type = 0;
	gint8 dec = 0;
	guint8 scheme = 0;
	guint16 n = 0;

	scheme = tvb_get_guint8(tvb, offset);

	ecmp_parameter_item = proto_tree_add_item(ecmp_tree, hf_ecmp_parameter_address, tvb, offset, 1, ENC_BIG_ENDIAN);
	ecmp_parameter_tree = proto_item_add_subtree(ecmp_parameter_item, ett_ecmp_param_address);

	offset++;
	/* if "GetNextObjects" command */
	if(command_value == ECMP_COMMAND_GETNEXTOBJECTS)
	{
		offset = get_address_scheme(pinfo, offset, scheme, tvb, ecmp_parameter_tree);
		offset++;
		proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_subsequent_object_requests, tvb, offset, 1, ENC_NA);
	}else
	{
		/*display tree with count of definitions */
		ecmp_parameter_item = proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_parameter_definitions, tvb, offset, 1, ENC_BIG_ENDIAN);
		ecmp_parameter_number_tree = proto_item_add_subtree(ecmp_parameter_item, ett_ecmp_param_address);

		count = tvb_get_guint8(tvb,offset);

		offset++;

		switch(scheme)/*sets n so that the tree highlights bytes in scheme specific data*/
		{
			case 0:
				n = 4;
				break;
			case 1:
				n = 5;
				break;
			case 3:
				n = 1 + ((tvb_get_guint8(tvb, offset+1)<<8)|(tvb_get_guint8(tvb, offset+2)));
				break;
			default:
				n = 0;
				break;
		}

		if (command_value == ECMP_COMMAND_OBJECTINFO) {
			n += 1;
		}

		for (a = 0; a < count; a++) {
			ecmp_parameter_tree = proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, n, ett_ecmp_param_address, NULL, "Parameter Definition %d:", (a+1));

			if (command_value == ECMP_COMMAND_OBJECTINFO) {
				proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_info_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				offset = get_address_scheme(pinfo, offset, scheme, tvb, ecmp_parameter_tree);
				offset++;
			} else {
				/*output the address schemes of the parameter requests */
				offset = get_address_scheme(pinfo, offset, scheme, tvb, ecmp_parameter_tree);
				offset++;
				if (command_value == ECMP_COMMAND_WRITE) {
					data_type = tvb_get_guint8(tvb, offset);
					proto_tree_add_item(ecmp_parameter_tree, hf_ecmp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					dec = tvb_get_gint8(tvb, offset);
					if (dec != -1) {
						proto_tree_add_int(ecmp_parameter_tree, hf_ecmp_number_of_decimal_places, tvb, offset, 1, dec);
					} else {
						proto_tree_add_int_format_value(ecmp_parameter_tree, hf_ecmp_number_of_decimal_places, tvb, offset, 1, dec, "0 (Invalid type)");
					}
					offset++;
					offset = get_data_type(pinfo, offset, data_type, tvb, ecmp_parameter_tree);
					offset++;
				}
			}
		}
	}
}


/* a function to show the "objectinfo" command response */
static void get_object_info_response(packet_info* pinfo, int offset, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_response_item = NULL;
	proto_tree* ecmp_parameter_number_tree = NULL;
	proto_tree* ecmp_parameter_response_tree = NULL;
	guint8 count = 0; /*stores number of parameter read responses */
	guint8 a = 0; /*counting varables */
	guint8 n = 0;
	guint8 info_type0 = 0;
	guint16 length = 0;
	guint8 data_type = 0;

	length = tvb_reported_length(tvb);

	ecmp_response_item = proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_parameter_responses, tvb, offset, 1, ENC_BIG_ENDIAN);
	ecmp_parameter_number_tree = proto_item_add_subtree(ecmp_response_item, ett_ecmp_param_address);

	count = tvb_get_guint8(tvb, offset);

	if (count == 0) {
		offset++;
		proto_tree_add_item(ecmp_parameter_number_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);

	} else {
		/*display info data response */
		for (a = 0; a < count; a++) {
			if (a==0) {
				n = (length-offset)/count;
			}
			offset++;
			/*display response header */
			proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, n, ett_ecmp_command, NULL, "Response %d:", (a+1));

			/*display response status */
			proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			/*display response data */
			proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_info_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			info_type0 = tvb_get_guint8(tvb, offset);

			switch(info_type0)
			{
				case 0:
					/*no information available */
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_no_information_available, tvb, offset, 1, ENC_NA);
					break;
				case 1:
					/*display min parameter in menu */
					offset++;
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_min_param_menu, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset++;
					break;
				case 2:
					/*display max parameter in menu */
					offset++;
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_max_param_menu, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset++;
					break;
				case 3:
					{
						static int * const fields[] = {
							&hf_ecmp_param_format_bit_default_unipolar,
							&hf_ecmp_param_format_write_allowed,
							&hf_ecmp_param_format_read_not_allowed,
							&hf_ecmp_param_format_protected_from_destinations,
							&hf_ecmp_param_format_parameter_not_visible,
							&hf_ecmp_param_format_not_clonable,
							&hf_ecmp_param_format_voltage_or_current_rating_dependent,
							&hf_ecmp_param_format_parameter_has_no_default,
							&hf_ecmp_param_format_number_of_decimal_places,
							&hf_ecmp_param_format_variable_maximum_and_minimum,
							&hf_ecmp_param_format_string_parameter,
							&hf_ecmp_param_format_destination_set_up_parameter,
							&hf_ecmp_param_format_filtered_when_displayed,
							&hf_ecmp_param_format_pseudo_read_only,
							&hf_ecmp_param_format_display_format,
							&hf_ecmp_param_format_floating_point_value,
							&hf_ecmp_param_format_units,
							NULL
						};

						/*display data for parameter format- UNITS and Display Format need dissecting? */
						offset++;
						proto_tree_add_bitmask_list(ecmp_parameter_response_tree, tvb, offset, 4, fields, ENC_BIG_ENDIAN);
						offset+= 3;
					}
					break;
				case 4:
					/*display minimum allowed value*/
					offset++;
					data_type = tvb_get_guint8(tvb,offset);
					ecmp_response_item = proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					offset = get_data_type(pinfo, offset, data_type, tvb, ecmp_parameter_response_tree);
					break;
				case 5:
					/*display maximum allowed value*/
					offset++;
					data_type = tvb_get_guint8(tvb,offset);
					ecmp_response_item = proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					offset = get_data_type(pinfo, offset, data_type, tvb, ecmp_parameter_response_tree);
					break;
				case 6:
					/*display Units- ID string */
					offset++;
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_string_id, tvb, offset, 2, ENC_NA|ENC_ASCII);
					offset++;
					break;
				case 7:
					/*display data type */
					offset++;
					ecmp_response_item = proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					break;
				default:
					expert_add_info(pinfo, ecmp_response_item, &ei_ecmp_info_type);
					break;
			}
		}
	}
}


/* a function to display an array of the read responses */
static int get_parameter_responses(packet_info* pinfo, int offset, guint8 command_value, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_response_item = NULL;
	proto_tree* ecmp_parameter_number_tree = NULL;
	proto_tree* ecmp_parameter_response_tree = NULL;
	guint8 count = 0; /*stores number of parameter read responses */
	guint8 a = 0; /*counting varables */
	guint8 data_type = 0;
	guint8 unit_id = 0;
	gint8 dec = 0;
	guint16 n = 0;
	guint8 st_error = 0;
	guint16 length = 0;
	guint8 scheme = 0;
	int start_offset;

	scheme = tvb_get_guint8(tvb, offset);
	length = tvb_reported_length(tvb);

	if (command_value == ECMP_COMMAND_GETNEXTOBJECTS) {
		/*display addressing scheme*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_parameter_address, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	/*display number of responses*/
	ecmp_response_item = proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_parameter_responses, tvb, offset, 1, ENC_BIG_ENDIAN);
	ecmp_parameter_number_tree = proto_item_add_subtree(ecmp_response_item, ett_ecmp_param_address);

	count = tvb_get_guint8(tvb, offset);

	if (count == 0) {
		offset++;
		if (command_value != ECMP_COMMAND_GETNEXTOBJECTS) {
			/*display parameter status*/
			proto_tree_add_item(ecmp_parameter_number_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
	} else {
		/*loop for outputting parameter data responses*/
		for (a = 0; a < count; a++) {
			if (command_value == ECMP_COMMAND_WRITE) {
				if (a==0) {
					n = (length-offset)/count; /*set byte highlighting*/
				}
				offset++;
				/*display response: (a+1)*/
				ecmp_parameter_response_tree = proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, n, ett_ecmp_command, NULL, "Response %d:", (a+1));
				ecmp_response_item = proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);

			} else if (command_value == ECMP_COMMAND_GETNEXTOBJECTS) {
				if (a==0) {
					n = (length-offset)/count;
				}
				offset++;
				/*display response: (a+1)*/
				ecmp_parameter_response_tree = proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, n, ett_ecmp_command, NULL, "Response %d:", (a+1));
				offset = get_address_scheme(pinfo, offset, scheme, tvb, ecmp_parameter_response_tree);
			} else {
				/*if status is error */
				if (tvb_get_gint8(tvb, offset+1) < 0) {
					/*output status*/
					st_error = 1;
					offset++;
					ecmp_parameter_response_tree = proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, 1, ett_ecmp_command, NULL, "Response %d:", (a+1));
					ecmp_response_item = proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
					if ((a+1) != count) {
						/*loop to move to next data_type (skips bytes == 0)*/
						while(1) {
							if(tvb_get_guint8(tvb, offset+1)==0) {
								offset++;
							} else {
								break;
							}
						}
					}
				} else {
					offset++;
					/*display response data_byte*/
					start_offset = offset;
					ecmp_parameter_response_tree = proto_tree_add_subtree_format(ecmp_parameter_number_tree, tvb, offset, 0, ett_ecmp_command, &ecmp_response_item, "Response %d:", (a+1));
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_parameter_status, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					data_type = tvb_get_guint8(tvb,offset);
					offset++;
					offset = get_data_type(pinfo, offset, data_type, tvb, ecmp_parameter_response_tree);

					/*if "ReadWithType" */
					if ((command_value == ECMP_COMMAND_READWITHTYPE) && (st_error!= 1)) {
						offset++;
						/*display decimal places*/
						dec = tvb_get_gint8(tvb, offset);
						if (dec != -1) {
							proto_tree_add_int(ecmp_parameter_response_tree, hf_ecmp_number_of_decimal_places, tvb, offset, 1, dec);
						} else {
							proto_tree_add_int_format_value(ecmp_parameter_response_tree, hf_ecmp_number_of_decimal_places, tvb, offset, 1, dec, "0 (Invalid type)");
						}
						offset++;
						/*display unit ID*/
						unit_id = tvb_get_guint8(tvb, offset);
						proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_display_unit_id, tvb, offset, 1, ENC_NA);
						if (unit_id == 255) {
							offset++;
							proto_tree_add_item(ecmp_parameter_response_tree, hf_ecmp_unit_id_string, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_ASCII);
							offset += (tvb_get_ntohs(tvb, offset) + 2);
						}
					}

					proto_item_set_len(ecmp_response_item, offset-start_offset);
				}

			}
		}
	}
	return offset;
}


/*--------------------------------------------------------------------*/
/*                   File Access Commands                             */
/*--------------------------------------------------------------------*/
/* a function to dissect "FileOpen" command */
static void file_open(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_tree* ecmp_scheme_data_tree = NULL;
	guint8 additional_scheme = 0;
	guint8 relative = 0;

	if (request) {
		static int * const fields[] = {
			&hf_ecmp_open_in_non_blocking_mode,
			&hf_ecmp_open_file_relative_to_specified_directory_handle,
			&hf_ecmp_file_access_mode,
			NULL
		};

		proto_tree_add_bitmask(ecmp_tree, tvb, offset, hf_ecmp_access_mode, ett_ecmp_access_mode, fields, ENC_BIG_ENDIAN);
		relative = (tvb_get_guint8(tvb, offset) & 0x40) ? 1 : 0;
		offset++;

		/*display additional scheme*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_additional_scheme, tvb, offset, 1, ENC_BIG_ENDIAN);
		additional_scheme= tvb_get_guint8(tvb, offset);

		/*display file name*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_name, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
		offset += (tvb_get_ntohs(tvb, offset+1) + 2);

		/*only show file handle in relative mode*/
		if (relative == 1) {
			offset++;

			/*display file handle*/
			proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		}

		if (additional_scheme == 1) {
			/*display additional data*/
			offset+= 2;
			ecmp_scheme_data_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, -1, ett_ecmp_access_file, NULL, "Additional scheme data");
			proto_tree_add_item(ecmp_scheme_data_tree, hf_ecmp_scheme_data_length, tvb, offset, 1, ENC_NA);
			offset++;
			proto_tree_add_item(ecmp_scheme_data_tree, hf_ecmp_data, tvb, offset, -1, ENC_NA);
		}
	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);

		if (tvb_get_gint8(tvb, offset) >= 0) {
			offset++;
			/*display file handle*/
			proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
	}
}


/* a function to dissect "FileRead" command */
static void file_read(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	guint16 req_bytes = 0;

	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		/*display requested bytes*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_requested_bytes, tvb, offset, 2, ENC_BIG_ENDIAN);

	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);

		if (tvb_get_gint8(tvb, offset)>= 0) {
			offset++;

			/*display bytes for reading*/
			req_bytes = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(ecmp_tree, hf_ecmp_response_data, tvb, offset, req_bytes+2, ENC_NA);
			/*offset += (2+req_bytes);*/
		}
	}
}


/* a function to dissect "FileWrite" command */
static void file_write(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	guint16 req_bytes;

	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		/*display bytes for writing*/
		req_bytes = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset+2, req_bytes, ENC_NA);
		/*offset += (2+req_bytes);*/

	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		/*offset++;*/
	}
}


/*a function to dissect "FileClose" command*/
static void file_close(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		/*display number of data bytes transferred*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_bytes_transferred, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+= 4;

		/*display CRC value*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}
}


/*a function to display file attributes*/
static int get_file_attribute(packet_info* pinfo, int offset, tvbuff_t *tvb, proto_tree* ecmp_current_tree)
{
	proto_item *ecmp_file_info_att_item;
	proto_tree *ecmp_file_info_att_tree;
	guint32 attribute0;
	int start_offset = offset;

	ecmp_file_info_att_item = proto_tree_add_item_ret_uint(ecmp_current_tree,
			hf_ecmp_file_attributes, tvb, offset, 1, ENC_BIG_ENDIAN, &attribute0);
	offset++;
	ecmp_file_info_att_tree = proto_item_add_subtree(ecmp_file_info_att_item, ett_ecmp_file_info_att);

	switch(attribute0)
	{
		case 0: /*display length of file*/
			proto_tree_add_item(ecmp_file_info_att_tree, hf_ecmp_file_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case 1: /*display integrity*/
			proto_tree_add_item(ecmp_file_info_att_tree, hf_ecmp_file_integrity, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 2:	/*display CRC*/
			proto_tree_add_item(ecmp_file_info_att_tree, hf_ecmp_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case 3:	/*display attrib*/
			{
				static int * const fields[] = {
					&hf_ecmp_display_attr_read_only,
					&hf_ecmp_display_attr_hidden,
					&hf_ecmp_display_attr_system,
					&hf_ecmp_display_attr_volume_label,
					&hf_ecmp_display_attr_subdirectory,
					&hf_ecmp_display_attr_archive,
					NULL
				};

				proto_tree_add_bitmask_list(ecmp_file_info_att_tree, tvb, offset, 1, fields, ENC_BIG_ENDIAN);
				offset++;
			}
			break;
		case 4:	/*display creation date*/
			proto_tree_add_item(ecmp_file_info_att_tree, hf_ecmp_display_creation, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case 5:	/*display modification date*/
			proto_tree_add_item(ecmp_file_info_att_tree, hf_ecmp_display_modification, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;
			break;
		default: /*display incorrect attribute type error*/
			proto_tree_add_expert(ecmp_file_info_att_tree, pinfo, &ei_ecmp_attribute_type, tvb, offset, 1);
			offset++;
			break;
	}
	proto_item_set_len(ecmp_file_info_att_item, offset - start_offset);
	return offset;
}


/*a function to dissect "FileInfo" command*/
static void file_info(packet_info* pinfo, int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_tree *ecmp_file_info_tree;
	guint32 a, no_of_att;
	int start_offset;

	if (request) {
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		start_offset = offset;
		ecmp_file_info_tree = proto_tree_add_subtree(ecmp_tree,
				tvb, offset, -1, ett_ecmp_file_info, NULL, "Requested Attributes");
		proto_tree_add_item_ret_uint(ecmp_file_info_tree,
				hf_ecmp_no_of_attributes, tvb, offset, 1, ENC_BIG_ENDIAN, &no_of_att);
		offset++;

		for (a = 0; a < no_of_att; a++) {
			proto_tree_add_item(ecmp_file_info_tree,
					hf_ecmp_file_attributes, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
		proto_item_set_len(ecmp_file_info_tree, offset - start_offset);
	} else {
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		start_offset = offset;
		ecmp_file_info_tree = proto_tree_add_subtree(ecmp_tree,
				tvb, offset, -1, ett_ecmp_file_info, NULL, "Received Attributes");

		proto_tree_add_item_ret_uint(ecmp_file_info_tree,
				hf_ecmp_no_of_attributes, tvb, offset, 1, ENC_BIG_ENDIAN, &no_of_att);
		offset++;

		/*display attributes*/
		for (a = 0; a < no_of_att; a++) {
			offset = get_file_attribute(pinfo, offset, tvb, ecmp_file_info_tree);
		}
		proto_item_set_len(ecmp_file_info_tree, offset-start_offset);
	}
}


/*a function to dissect	"FileStatus"/"FileDelete" commands*/
static void file_state_delete(guint16 offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);

	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}


/*a function to dissect "FilePos" command*/
static void file_pos(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_tree* ecmp_file_position_tree = NULL;

	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		/*display "position" header*/
		ecmp_file_position_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 5, ett_ecmp_file_position, NULL, "Position");

		/*display reference point*/
		proto_tree_add_item(ecmp_file_position_tree, hf_ecmp_file_ref_point, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		/*display offset from ref point*/
		proto_tree_add_item(ecmp_file_position_tree, hf_ecmp_ref_offset, tvb, offset, 4, ENC_BIG_ENDIAN);

	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);

		if(tvb_get_gint8(tvb,offset) >= 0) {
			offset++;

			/*display offset from ref point*/
			proto_tree_add_item(ecmp_file_position_tree, hf_ecmp_ref_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
		}
	}
}


/*a function to dissect "FileList" command*/
static void file_list(packet_info* pinfo, int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item* ecmp_file_list_item, *ecmp_file_list_item2, *item_type_item;
	proto_tree* ecmp_file_list_no_tree = NULL;
	proto_tree* ecmp_file_list_tree = NULL;
	guint8 no_of_items = 0;
	guint8 item_type = 0;
	guint8 a = 0;
	guint16 n = 0;
	int start_offset, start_offset2;

	if (request) {
		/*display file handle*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+= 2;

		/*display number of files to list*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_files_to_list, tvb, offset, 1, ENC_NA);
	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);

		if (tvb_get_gint8(tvb,offset) >= 0) {
			offset++;

			/*display number of files to list*/
			no_of_items = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(ecmp_tree, hf_ecmp_number_of_files_to_list, tvb, offset, 1, ENC_NA);
			offset++;

			/*display hash value (dissection TBD)*/
			ecmp_file_list_item = proto_tree_add_item(ecmp_tree, hf_ecmp_file_hash, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset++;

			/*display subtree for files*/
			start_offset = offset+1;
			ecmp_file_list_no_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset+1, no_of_items, ett_ecmp_file_list_no, &ecmp_file_list_item, "Files");

			/*display list of file names*/
			for (a = 0; a < no_of_items; a++) {
				start_offset2 = offset;
				offset++;
				item_type = tvb_get_guint8(tvb, offset);
				n = tvb_get_ntohs(tvb, offset+1);
				ecmp_file_list_tree = proto_tree_add_subtree_format(ecmp_file_list_no_tree, tvb, offset, n+2, ett_ecmp_file_list, &ecmp_file_list_item2, "File %d:", a+1);
				item_type_item = proto_tree_add_item(ecmp_file_list_tree, hf_ecmp_item_type, tvb, offset, 1, ENC_NA);

				switch(item_type)
				{
					case 0: /*if item type is "file"*/
						proto_tree_add_item(ecmp_file_list_tree, hf_ecmp_file_name, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
						break;

					case 1: /*if item type is "directory"*/
						proto_tree_add_item(ecmp_file_list_tree, hf_ecmp_directory, tvb, offset+1, 2, ENC_BIG_ENDIAN|ENC_ASCII);
						break;

					default: /*if item type is not "file" or "directory"*/
						expert_add_info(pinfo, item_type_item, &ei_ecmp_item_type);
						break;
				}
				offset+= n;

				proto_item_set_len(ecmp_file_list_item2, offset-start_offset2);
			}

			proto_item_set_len(ecmp_file_list_item, (offset+1)-start_offset);
		}
	}
}


/*a function to dissect "FileExists" command*/
static void file_exists(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	if (request) {
		/*display filename*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_name, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_ASCII);
	} else {
		/*display file status*/
		proto_tree_add_item(ecmp_tree, hf_ecmp_file_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
}


static int add_cyclic_setup_attributes(packet_info* pinfo, int offset, guint16 length, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_item *cyclic_setup_attributes_root = NULL;
	proto_item *cyclic_setup_attributes = NULL;
	proto_item *cyclic_setup_attrib_item_root = NULL;
	proto_tree *cyclic_setup_attrib_item = NULL;
	guint8 attrib;

	/* num attribs */
	cyclic_setup_attributes_root = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_attrib_count, tvb, offset++, 1, ENC_BIG_ENDIAN);

	/* attrib list */
	cyclic_setup_attributes = proto_item_add_subtree(cyclic_setup_attributes_root, ett_cyclic_setup_attribs);

	while (offset < length) {
		attrib = tvb_get_guint8(tvb, offset);
		cyclic_setup_attrib_item_root = proto_tree_add_item(cyclic_setup_attributes, hf_ecmp_cyclic_setup_attrib, tvb, offset++, 1, ENC_BIG_ENDIAN);

		cyclic_setup_attrib_item = proto_item_add_subtree(cyclic_setup_attrib_item_root, ett_cyclic_setup_attrib_item);

		switch (attrib) {
			case 3: /* mec offset */
			{
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_mec_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

			case 4: /* sample period */
			case 5: /* mec delay */
			{
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_sample_period, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
			}
			break;

			case 7: /* rx timeout */
			{
				/* tout */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				/* action */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_action, tvb, offset++, 1, ENC_NA);

				/* event dest */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_event_destination, tvb, offset++, 1, ENC_NA);

				/* event */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_event, tvb, offset++, 1, ENC_NA);

			}
			break;

			case 8: /* rx late handler */
			{
				/* action */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_late_handler_action, tvb, offset++, 1, ENC_NA);

				/* event dest */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_late_handler_event_destination, tvb, offset++, 1, ENC_NA);

				/* event */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_rx_late_handler_event, tvb, offset++, 1, ENC_NA);
			}
			break;

			case 9: /* transport addr */
			{
				/* scheme */
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_transport_addr_scheme, tvb, offset++, 1, ENC_NA);

				/* todo - make this check the scheme is actually 0! */

				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_transport_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

			case 12: /* mapping item */
			{
				guint8 addrScheme;

				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_mapping_item_offset, tvb, offset++, 1, ENC_NA);

				addrScheme = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_mapping_item_scheme, tvb, offset++, 1, ENC_NA);

				offset = get_address_scheme(pinfo, offset, addrScheme, tvb, cyclic_setup_attrib_item);

				/* todo - should this be done in the last function itself??? */
				offset++;
			}
			break;

			case 0: /* state */
			case 1: /* rx/tx */
			case 2: /* synchronised */
			case 6: /* data change */
			case 10: /* max mappings */
			case 11: /* num mappings */
			case 13: /* saveable */
			case 128: /* max rx links */
			case 129: /* max tx links */
			case 130: /* max mappings per link */
			case 131: /* max sync rx links */
			case 132: /* max sync tx links */
			case 133: /* max mappings per sync link */
			case 134: /* process at queue depth */
			{
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_setup_attribute, tvb, offset++, 1, ENC_NA);
			}
			break;

			case 135: /* mec period */
			{
				proto_tree_add_item(cyclic_setup_attrib_item, hf_ecmp_mec_period, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

			default:
			break;

		} /* attribute switch */
	} /* loop through list */

	return offset;
}


static void cyclic_setup(packet_info* pinfo, guint16 offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	guint16 length = 0;
	proto_item* cyclic_setup_attributes_root = NULL;
	proto_item* cyclic_setup_attributes = NULL;
	guint8 Mode;

	length = tvb_reported_length(tvb);

	/* if a request add the check output flag */
	if (request) {
		proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_linkno, tvb, offset++, 1, ENC_BIG_ENDIAN);

		Mode = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(ecmp_tree, hf_ecmp_cyclic_setup_mode, tvb, offset++, 1, Mode);

		switch (Mode) {
			case 0: /* create  */
			case 10: /* set  */
			{
				/* link direction */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_dir, tvb, offset++, 1, ENC_BIG_ENDIAN);

				/* add the attributesd as a tree */
				add_cyclic_setup_attributes(pinfo, offset, length, tvb, ecmp_tree);
			}
			break;

			case 1: /* edit */
			case 2: /* finalise */
			case 3: /* delete */
			case 4: /* exist */
				/* link direction */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_dir, tvb, offset++, 1, ENC_BIG_ENDIAN);
			break;

			case 5: /* list */
				/* tx/rx bits */
				proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
			break;

			case 11: /* get */
			case 6: /* info */
			{
				if (Mode == 11) {
					/* link dir */
					proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_dir, tvb, offset++, 1, ENC_BIG_ENDIAN);
				}

				/* num attribs */
				cyclic_setup_attributes_root = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_attrib_count, tvb, offset++, 1, ENC_BIG_ENDIAN);

				/* attrib list */
				cyclic_setup_attributes = proto_item_add_subtree(cyclic_setup_attributes_root, ett_cyclic_setup_attribs);
				while (offset < length) {
					proto_tree_add_item(cyclic_setup_attributes, hf_ecmp_cyclic_setup_attrib, tvb, offset++, 1, ENC_BIG_ENDIAN);
				}
			}
			break;

			case 12: /* get mappings */
			{
				/* link dir */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_dir, tvb, offset++, 1, ENC_BIG_ENDIAN);

				/* max mappings */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_max_mappings, tvb, offset++, 1, ENC_NA);

				/* start offset */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_start_offset, tvb, offset++, 1, ENC_NA);
			}
			break;

			default:
				/* display payload as hex bytes */
				proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
			break;
		}
	} else {
		proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_rsp_status, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_rsp_err_idx, tvb, offset++, 1, ENC_BIG_ENDIAN);

		Mode = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(ecmp_tree, hf_ecmp_cyclic_setup_mode, tvb, offset++, 1, Mode);

		switch (Mode) {
			case 0: /* create */
			case 1: /* edit */
			case 2: /* finalise */
			case 3: /* delete */
				/* no mode specific data */
			break;

			case 4: /* exist */
				proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_link_exists, tvb, offset++, 1, ENC_BIG_ENDIAN);
			break;

			case 5: /* list */
			{
				guint8 txCount, rxCount, linkno;

				/* num attribs */
				txCount = tvb_get_guint8(tvb, offset);
				cyclic_setup_attributes_root = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_tx_count, tvb, offset++, 1, ENC_NA);

				/* link list */
				cyclic_setup_attributes = proto_item_add_subtree(cyclic_setup_attributes_root, ett_cyclic_setup_attribs);
				while (txCount > 0) {
					linkno = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(cyclic_setup_attributes, hf_ecmp_cyclic_setup_linkno, tvb, offset++, 1, linkno);
					txCount--;
				}

				rxCount = tvb_get_guint8(tvb, offset);
				cyclic_setup_attributes_root = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_rx_count, tvb, offset++, 1, ENC_NA);

				/* link list */
				cyclic_setup_attributes = proto_item_add_subtree(cyclic_setup_attributes_root, ett_cyclic_setup_attribs);
				while (rxCount > 0) {
					linkno = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(cyclic_setup_attributes, hf_ecmp_cyclic_setup_linkno, tvb, offset++, 1, linkno);
					rxCount--;
				}
			}
			break;

			case 10: /* set */
			{
				/* num attribs */
				cyclic_setup_attributes_root = proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_setup_attrib_count, tvb, offset++, 1, ENC_BIG_ENDIAN);

				/* attrib list */
				cyclic_setup_attributes = proto_item_add_subtree(cyclic_setup_attributes_root, ett_cyclic_setup_attribs);
				while (offset < length) {
					proto_tree_add_item(cyclic_setup_attributes, hf_ecmp_cyclic_setup_attrib, tvb, offset++, 1, ENC_BIG_ENDIAN);
				}
			}
			break;

			case 11: /* get */
			case 12: /* get mappings */
			case 6: /* info */
				/* add the attributesd as a tree */
				add_cyclic_setup_attributes(pinfo, offset, length, tvb, ecmp_tree);
			break;

			default:
				/* display payload as hex bytes */
				proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
			break;
		}
	}
}


/*a function to dissect "ProgramStatus" command  */
static void program_status(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
/*  Description:function to dissect Program Status command              */
/*                                                                      */
/*  Inputs:                                                             */
/*    offset - current offset of pointer within the ECMP frame          */
/*    command_value - function code of ECMP message                     */
/*    request - (1 = query, 0 = response)                               */
/*    tvb - Wireshark protocol tree                                     */
/*    ecmp_tree - Wireshark protocol tree                               */
/*    tree - Wireshark protocol tree                                    */
/*                                                                      */
/*  Returns: nothing                                                    */
/*                                                                      */
/*  Notes: for queries, the "offset" points to the "target".            */
/*         for responses, the "offset" points to the "status".          */
/*                                                                      */
/*  sample ECMP Request Frame                                           */
/*  0x61 - request code  (program control)                              */
/*  0x00 - option terminator                                            */
/*  0x00 - target   (0 = default program) <======== offset              */
/*                                                                      */
/*  sample ECMP Response Frame                                          */
/*  0xE1 - response code  (program control)                             */
/*  0x00 - option terminator                                            */
/*  0x01 - running state  (0=Stopped, 1=Running ... ) <======== offset  */
/*  0x00 - additional items                                             */

	proto_item*		ecmp_program_status_message_tree = NULL;

	/* differentiate between ECMP query and response  */
	if (request) {
		/*display the program control details sub-tree  */
		ecmp_program_status_message_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 1, ett_ecmp_program_status_message, NULL, "Program Status: (Query)");

		/* read the target  */
		proto_tree_add_item(ecmp_program_status_message_tree, hf_ecmp_program_status_target, tvb, offset, 1, ENC_NA);
	} else {
		/*display the program status details sub-tree  */
		ecmp_program_status_message_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_program_status_message, NULL, "Program Status: (Response)");

		/* read and display the Status */
		proto_tree_add_item(ecmp_program_status_message_tree, hf_ecmp_program_status_status, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* read and display the Additional Items */
		proto_tree_add_item(ecmp_program_status_message_tree, hf_ecmp_program_status_additional_items, tvb, offset, 1, ENC_NA);
	}
}


/*a function to dissect "ProgramControl" command  */
static void program_control(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
/*  Description:function to dissect Program Control command             */
/*                                                                      */
/*  Inputs:                                                             */
/*    offset - current offset of pointer within the ECMP frame          */
/*    command_value - function code of ECMP message                     */
/*    request - (1 = query, 0 = response)	                        */
/*    tvb - Wireshark protocol tree                                     */
/*    ecmp_tree - Wireshark protocol tree                               */
/*    tree - Wireshark protocol tree                                    */
/*                                                                      */
/*  Returns: nothing                                                    */
/*                                                                      */
/* Notes: for queries, the "offset" points to the "target".              */
/*         for responses, the "offset" points to the "status".          */
/*                                                                      */
/*  sample ECMP Request Frame                                           */
/*  0x60 - request code  (program control)                              */
/*  0x00 - option terminator                                            */
/*  0x00 - target   (0 = default program) <======== offset              */
/*  0x01 - command  (1 = start the program)                             */
/*  0x00 - sub command                                                  */
/*                                                                      */
/*  sample ECMP Response Frame                                          */
/*  0xE0 - response code  (program control)                             */
/*  0x00 - option terminator                                            */
/*  0x00 - status  (0 = OK)  <======== offset                           */
/*                                                                      */

	proto_item*		ecmp_program_control_message_tree = NULL;

	/* differentiate between ECMP query and response  */
	if (request) {
		/*display the program control details sub-tree  */
		ecmp_program_control_message_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 3, ett_ecmp_program_control_message, NULL, "Program Control: (Query)");

		/* read the target  */
		proto_tree_add_item(ecmp_program_control_message_tree, hf_ecmp_program_control_target, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* read the command  */
		proto_tree_add_item(ecmp_program_control_message_tree, hf_ecmp_program_control_command, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* read the subcommand  */
		proto_tree_add_item(ecmp_program_control_message_tree, hf_ecmp_program_control_sub_command, tvb, offset, 1, ENC_NA);
	} else {
		/*display the program control details sub-tree  */
		ecmp_program_control_message_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 1, ett_ecmp_program_control_message, NULL, "Program Control: (Response)");

		/* read and display the Status */
		proto_tree_add_item(ecmp_program_control_message_tree, hf_ecmp_program_control_status, tvb, offset, 1, ENC_NA);
	}
}


/*a function to dissect "ModbusPDU" command  */
static void modbus_pdu(int offset, gboolean request, tvbuff_t *tvb, packet_info* pinfo, proto_tree* ecmp_tree)
{
/*  Description:function to dissect Modbus PDU ECMP transactions        */
/*                                                                      */
/*  Inputs:                                                             */
/*    offset - current offset of pointer within the ECMP frame          */
/*    command_value - function code of ECMP message                     */
/*    request - (1 = query, 0 = response)                               */
/*    tvb - Wireshark protocol tree                                     */
/*    ecmp-tree - Wireshark protocol tree                               */
/*    tree - Wireshark protocol tree                                    */
/*                                                                      */
/*  Returns: nothing                                                    */
/*                                                                      */
/*  Notes: for queries, the "offset" points to the "size".               */
/*         for responses, the "offset" points to the size.              */
/*                                                                      */
/*  sample ECMP Request Frame (Read Holding Registers)                  */
/*  0x74 -  request code  (ModbusMaster)                                */
/*  0x00 - option terminator                                            */
/*  0x00 - size                             msb <======== offset        */
/*  0x05 - size                             lsb                         */
/*  0x03 - function code - read hold reg                                */
/*  0x07 - register address (#20.021)       msb                         */
/*  0xE4 - register address                 lsb                         */
/*  0x00 - number registers                 msb                         */
/*  0x03 - number registers                 lsb                         */
/*                                                                      */
/*  sample ECMP Response Frame                                          */
/*  0xF4 - response code  (ModbusMaster)                                */
/*  0x00 - option terminator                                            */
/*  0x00 - size                             msb <======== offset        */
/*  0x08 - size                             lsb                         */
/*  0x03 - function code - read hold reg                                */
/*  0x06 - byte count                                                   */
/*  0x30 - register #2021 value 12345       msb                         */
/*  0x39 - register #2021 value             lsb                         */
/*  0x03 - register #2022 value  787        msb                         */
/*  0x13 - register #2022 value             lsb                         */
/*  0x00 - register #2023 value  100        msb                         */
/*  0x64 - register #2023 value             lsb                         */

	tvbuff_t*		next_tvb;
	guint16			size = 0; /* from Modbus TCP/IP spec: number of bytes that follow */
	modbus_data_t   modbus_data;

	/* differentiate between ECMP query and response  */
	if (request) {
		/* read and display the Size  */
		size = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(ecmp_tree, hf_ecmp_modbus_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* keep packet context */
		modbus_data.packet_type = QUERY_PACKET;
		modbus_data.mbtcp_transid = 0;
		modbus_data.unit_id = 0;
		next_tvb = tvb_new_subset_length(tvb, offset, size);
		call_dissector_with_data(modbus_handle, next_tvb, pinfo, ecmp_tree, &modbus_data);

	} else {
		/* read and display the Size  */
		size = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(ecmp_tree, hf_ecmp_modbus_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		modbus_data.packet_type = RESPONSE_PACKET;
		modbus_data.mbtcp_transid = 0;
		modbus_data.unit_id = 0;
		next_tvb = tvb_new_subset_length(tvb, offset, size);
		call_dissector_with_data(modbus_handle, next_tvb, pinfo, ecmp_tree, &modbus_data);
	}
}


/*a function to dissect "Interrogate" command  */
static void interrogate(packet_info* pinfo, int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
/*  Description:  function to dissect Interrogate command               */
/*                                                                      */
/*  Inputs:                                                             */
/*    offset - current offset of pointer within the ECMP frame          */
/*    request - (1 = query, 0 = response)                               */
/*    tvb - rather complex structure that has the frame data            */
/*    ecmp-tree - Wireshark protocol tree                               */
/*                                                                      */
/*  Returns: nothing                                                    */
/*                                                                      */
/*  Notes: for queries, the "offset" points to the "item type".          */
/*         for responses, the "offset" points to the "item type".       */
/*                                                                      */
/*  sample ECMP Request Frame                          	                */
/*  0x02 - request code  (interrogate)                                  */
/*  0x00 - option terminator                           	                */
/*  0x00 - item type (0=ECMP command, 1=ECMP option)  <==== offset      */
/*  0x05 - count  (number of commands/options to follow)                */
/*  0x10 - item code #1  ECMP Read command                              */
/*  0x11 - item code #2  ECMP ReadWithType command                      */
/*  0x12 - item code #3  ECMP Write command                             */
/*  0x13 - item code #4  ECMP ObjectInfo command                        */
/*  0x14 - item code #5  ECMP GetNextObject command                     */
/*                                                                      */
/*  sample ECMP Response Frame                                          */
/*  0x82 - response code  (program control)                             */
/*  0x00 - option terminator                                            */
/*  0x00 - item type (0=ECMP command, 1=ECMP option)  <==== offset      */
/*  0x05 - count  (number of commands/options to follow)                */
/*  0x10 - item code #1                                                 */
/*  0x01 - supported    (ECMP Read command)                             */
/*  0x11 - item code #2                                               	*/
/*  0x01 - supported    (ECMP ReadWithType command)                     */
/*  0x12 - item code #3                                                 */
/*  0x01 - supported    (ECMP Write command)                            */
/*  0x13 - item code #4                                                 */
/*  0x01 - supported    (ECMP ObjectInfo command)                       */
/*  0x14 - item code #5                                                 */
/*  0x01 - supported    (ECMP GetNextObject command)                    */
/*                                                                      */
/*                                                                      */
/*  Item Type: 0 = ECMP command                                         */
/*             1 = ECMP option  (not currently implemented)             */
/*                                                                      */
/*  Item Code: 0 .. 0x7F for commands                                   */
/*             0 .. 2    for options                                    */
/*                                                                      */
/*  Item Support:  0 = not supported                                    */
/*                 1 = supported                                        */
/*                                                                      */


	const guint8 interrogate_type_command = 0;

	proto_tree*		ecmp_interrogate_message_tree = NULL, *ecmp_interrogate_tree;
	proto_item*		ecmp_interrogate_message_item = NULL;
	guint8			item_type = 0; /* 0=ECMP command,  1=ECMP option  */
	guint8			command_req = 0; /* ECMP command  */
	guint8			supported = 0; /* ECMP command support status: 1=supported,  0=not supported  */
	guint32			count = 0; /* number of ECMP commands to be checked  */
	guint32			j; /* loop counter  */


	/* differentiate between ECMP query and response  */
	if (request) {

		/* identify the ECMP command we're dissecting  */
		ecmp_interrogate_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_interrogate_message, NULL, "Interrogate: (Query)");

		/* read the item_type (command/option setting)  */
		item_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ecmp_interrogate_tree, hf_ecmp_interrogate_item_type, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* read the count  */
		count = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ecmp_interrogate_tree, hf_ecmp_interrogate_count, tvb, offset, 1, ENC_NA);
		offset += 1;

		/*create the interrogate details sub-tree  */
		ecmp_interrogate_message_tree = proto_tree_add_subtree(ecmp_interrogate_tree, tvb, offset, count, ett_ecmp_interrogate_message, &ecmp_interrogate_message_item, "ECMP Commands to be Checked");

		/* display the item_codes (commands to be checked)  */
		if (item_type == interrogate_type_command) {
			/* loop on the commands  */
			for (j = 0; j < count; j++) {

				/* display the commands to be checked  */
				proto_tree_add_item(ecmp_interrogate_message_tree, hf_ecmp_interrogate_command, tvb, offset, 1, ENC_NA);
				offset += 1;
			}
			proto_item_set_len(ecmp_interrogate_message_item, count);

		} else {
			expert_add_info(pinfo, ecmp_interrogate_message_item, &ei_ecmp_options_not_implemented);
		}

	} else {
		/* identify the ECMP command we're dissecting  */
		ecmp_interrogate_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_interrogate_message, NULL, "Interrogate: (Response)");

		/* read the item_type (command/option setting)  */
		item_type = tvb_get_guint8(tvb, offset);
		offset += 1;

		/* read the count  */
		count = tvb_get_guint8(tvb, offset);
		offset += 1;

		/* display the item_codes (commands to be checked)  */
		if (item_type == interrogate_type_command) {

			/*create the interrogate details sub-tree  */
			ecmp_interrogate_message_tree = proto_tree_add_subtree(ecmp_interrogate_tree, tvb, offset, 1, ett_ecmp_interrogate_message, &ecmp_interrogate_message_item, "ECMP Commands Supported");

			/* loop on the commands  */
			for (j = 0; j < count; j++) {
				/* get the command code  */
				command_req = tvb_get_guint8(tvb, offset);
				offset += 1;

				/* get the support status  */
				supported = tvb_get_guint8(tvb, offset);
				offset += 1;

				/* display if the command is supported  */
				proto_tree_add_uint_format(ecmp_interrogate_message_tree, hf_ecmp_interrogate_command, tvb, offset, 1, command_req, "%s: %s",
					                try_val_to_str(command_req, command_vals),
					                try_val_to_str(supported, Interrogate_support_state));
			}

		} else {

			expert_add_info(pinfo, ecmp_interrogate_message_item, &ei_ecmp_options_not_implemented);
		}
	}
}


static void tunnel_frame(int offset, gboolean request, tvbuff_t *tvb, proto_tree* ecmp_tree)
{
	proto_tree_add_item(ecmp_tree, hf_ecmp_tunnel_control, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecmp_tree, hf_ecmp_tunnel_start_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecmp_tree, hf_ecmp_tunnel_end_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* if a request add the check output flag */
	if (request) {
		proto_tree_add_item(ecmp_tree, hf_ecmp_tunnel_check_output_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	}

	offset+= 1;

	/* Payload length */
	proto_tree_add_item(ecmp_tree, hf_ecmp_tunnel_size, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+= 2;

	proto_tree_add_item(ecmp_tree, hf_ecmp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
	/*offset = tvb_reported_length(tvb);*/
}


/*  dissect_ecmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
*   -----------------------------------------------------------------
*
*   Purpose:  Wireshark dissector for Emerson Control Techniques ECMP protocol
*
*
*   Inputs:     tvbuff_t        *tvb        - complex buffer structure holding the packet's bytes
*               packet_info     *pinfo      - structure holding information about the packet
*               proto_tree      *tree       - pointer to top-level tree (print lines)
*
*   Outputs:    none
*
*
*    Notes:      if tree = NULL, packet capture is running and dissector will only write into the Summary Line (Info Field)
*
*               if tree is non-NULL, packet capture has stopped because a packet has been selected (clicked)
*               In this case, we will display quite a bit of additional information about the packet.
*
*
*               To inspect the frame buffer (very difficult using the *tvb pointer), it's best to add this little debug
*               code snippet at the top of the program to copy the frame buffer into an array that you can inspect.
*
*                   static guint8  jimbuf[512];                     // temp buffer for current frame data
*                   static gint    lenframe = 0;                    // num bytes in the frame
*                   static gint    j = 0;                           // loop counter
*                   static gint16  saved_offset = 0;                // saves offset for later restoration
*
*                   lenframe = tvb_captured_length(tvb);            // get the length of the frame
*                   saved_offset = offset;                          // temporarily save the "offset"
*
*                   for (j = 0; j < lenframe; j++) {                // loop to copy the frame buffer
*                       jimbuf[j] = tvb_get_guint8(tvb, offset);    // Wireshark function to read the frame buffer
*                       offset += 1;
*                   }
*                   offset = saved_offset;                          // restore the offset
*
*
*   Authors:  Sarah Bouremoum, Jim Lynch, Luke Orehawa, Others
*/

static int dissect_ecmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* Initialize the items and trees*/
	proto_item		*ecmp_item = NULL;
	proto_item		*ecmp_transaction_id_item = NULL;
	proto_item		*ecmp_chunk_id_item = NULL;
	proto_tree		*ecmp_tree = NULL;

	/*initialise the values to be used */
	guint8	command_value = 0;
	gboolean request;
	guint8	transaction_id_value = 0;
	int	    offset = 0; /* index used to read data from the buffer*/
	gint    framelen = 0; /* number of bytes in the frame   */

	/* note length of the UDP frame  */
	framelen = tvb_reported_length(tvb);

	if (framelen < ecmp_min_packet_size) {
		return 0;
	}

	/* this code block processes ECMP TCP messages (most of them)  */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ECMP);
	col_clear(pinfo->cinfo,COL_INFO);


	/*declaration of variables*/
	offset = 4;

	/*display the first line of the tree (ECMP data)*/
	ecmp_item = proto_tree_add_item(tree, proto_ecmp, tvb, 0, -1, ENC_NA);
	ecmp_tree = proto_item_add_subtree(ecmp_item, ett_ecmp);

	/* display the information for the destination address */
	offset = add_transport_layer_frame(offset, tvb, ecmp_tree, hf_ecmp_destination_address);

	/* display the information for the source address */
	offset = add_transport_layer_frame(offset, tvb, ecmp_tree, hf_ecmp_source_address);

	/*display the transaction ID*/
	ecmp_transaction_id_item = proto_tree_add_item(ecmp_tree, hf_ecmp_transaction_id, tvb, offset, 1, ENC_BIG_ENDIAN );
	transaction_id_value = tvb_get_guint8(tvb, offset);

	if(transaction_id_value == 0) {
		proto_item_append_text(ecmp_transaction_id_item, "%s", " -> Not initiated by Request");
	}
	offset++;

	request = ((tvb_get_guint8(tvb, offset+2) & 0x80) == 0);
	if (request) {
		/* Calls the function to display the Response size */
		offset = get_response_size(offset, tvb, ecmp_tree);

		/* Calls the function to display the command and request/response */
		offset = add_command_codes(pinfo, offset, tvb, ecmp_tree, transaction_id_value, &command_value);

		/* Calls the function to display the option codes and its data */
		offset = add_option_codes(offset, pinfo, tvb, ecmp_tree);

		/* up til here all code for the request should be the same */
		switch(command_value)
		{
			case ECMP_COMMAND_IDENTIFY:
				/*Calls a method to display the attributes and its data */
				add_attributes(pinfo, offset, tvb, ecmp_tree, request);
				break;
			case ECMP_COMMAND_INFO:
				/* Info command is just the request code, nothing else to display  */
				proto_tree_add_item(ecmp_tree, hf_ecmp_info_command, tvb, 0, -1, ENC_NA);
				/*do nothing, no more data is present */
				break;
			case ECMP_COMMAND_INTERROGATE:
				interrogate(pinfo, offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_READ:
				get_parameter_definitions(pinfo, offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_READWITHTYPE:
				get_parameter_definitions(pinfo, offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_WRITE:
				get_parameter_definitions(pinfo, offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_OBJECTINFO:
				get_parameter_definitions(pinfo, offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_GETNEXTOBJECTS:
				get_parameter_definitions(pinfo, offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEOPEN:
				file_open(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEREAD:
				file_read(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEWRITE:
				file_write(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILECLOSE:
				file_close(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEINFO:
				file_info(pinfo, offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEDELETE:
				file_state_delete(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILESTATE:
				file_state_delete(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEPOS:
				file_pos(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILELIST:
				file_list(pinfo, offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_FILEEXISTS:
				file_exists(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_CYCLICLINK:
				cyclic_setup(pinfo, offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_PROGRAMCONTROL:
				program_control(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_PROGRAMSTATUS:
				program_status(offset, request, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_CYCLICFRAME:
				add_cyclic_frame_query(offset, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_TUNNELFRAME:
				tunnel_frame(offset, command_value, tvb, ecmp_tree);
				break;
			case ECMP_COMMAND_MODBUSPDU:
				modbus_pdu(offset, request, tvb, pinfo, ecmp_tree);
				break;
			default:
				proto_tree_add_expert(ecmp_tree, pinfo, &ei_ecmp_unknown_command, tvb, 0, -1);
				break;
		}

		/* END of code to be modified */
	} else {
		guint8 chunk_id_value = 0;
		gint8 status_value = 0;

		status_value = tvb_get_gint8(tvb, offset); /*stores a signed value for status */

		proto_tree_add_item(ecmp_tree, hf_ecmp_status, tvb, offset, 1, ENC_BIG_ENDIAN);


		if (status_value >= 0) {
			offset++;
			chunk_id_value = tvb_get_guint8(tvb, offset);
			ecmp_chunk_id_item = proto_tree_add_item(ecmp_tree, hf_ecmp_chunk_id, tvb, offset, 1, ENC_BIG_ENDIAN);

			if(chunk_id_value == 0) {
				proto_item_append_text(ecmp_chunk_id_item, "%s", " -> Response is NOT Chunked");
			}

			offset++;

			/* Calls the function to display the option codes */
			offset = add_command_codes(pinfo, offset, tvb, ecmp_tree, transaction_id_value, &command_value);

			if ((status_value == 0) || (status_value == 1)) {
				/* Calls a method to display option codes */
				offset = add_option_codes(offset, pinfo, tvb, ecmp_tree);

				/* up til here all code for the response should be the same */
				switch(command_value)
				{
					case ECMP_COMMAND_IDENTIFY:
						/*Call a method to add category data */
						offset = add_category_codes(offset, tvb, ecmp_tree);
						/*Call a method to add attributes */
						add_attributes(pinfo, offset, tvb, ecmp_tree, request);
						break;
					case ECMP_COMMAND_INFO:
						add_info_response(offset, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_INTERROGATE:
						interrogate(pinfo, offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_READ:
						get_parameter_responses(pinfo, offset, command_value, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_READWITHTYPE:
						get_parameter_responses(pinfo, offset, command_value, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_WRITE:
						get_parameter_responses(pinfo, offset, command_value, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_OBJECTINFO:
						get_object_info_response(pinfo, offset, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_GETNEXTOBJECTS:
						get_parameter_responses(pinfo, offset, command_value, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEOPEN:
						file_open(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEREAD:
						file_read(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEWRITE:
						file_write(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILECLOSE:
						file_close(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEINFO:
						file_info(pinfo, offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEDELETE:
						file_state_delete(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILESTATE:
						file_state_delete(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEPOS:
						file_pos(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILELIST:
						file_list(pinfo, offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_FILEEXISTS:
						file_exists(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_CYCLICLINK:
						cyclic_setup(pinfo, offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_PROGRAMCONTROL:
						program_control(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_PROGRAMSTATUS:
						program_status(offset, request, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_CYCLICFRAME:
						add_cyclic_frame(offset, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_TUNNELFRAME:
						tunnel_frame(offset, command_value, tvb, ecmp_tree);
						break;
					case ECMP_COMMAND_MODBUSPDU:
						modbus_pdu(offset, request, tvb, pinfo, ecmp_tree);
						break;
					default:
						proto_tree_add_expert(ecmp_tree, pinfo, &ei_ecmp_unknown_command, tvb, 0, -1);
						break;
				}
/********************************* END of code to be modified ***********************************/
			}
		}
	}

	return framelen;
}

/* this code block processes ECMP UDP messages (cyclic data)  */
static int dissect_ecmp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item		*ecmp_item = NULL;
	proto_tree		*ecmp_tree = NULL;
	proto_tree		*ecmp_cyclic_data_32_bit_display_tree = NULL;
	proto_tree		*ecmp_cyclic_data_16_bit_display_tree = NULL;
	proto_tree		*ecmp_cyclic_data_8_bit_display_tree = NULL;
	guint8	command_value = 0;
	guint8	type_value = 0;
	guint8	transaction_id_value = 0;
	guint16	offset = 0; /* index used to read data from the buffer*/
	gint    framelen = 0; /* number of bytes in the frame   */
	guint8	scheme = 0; /* 0=no scheme, 1=grandmaster setup */

	/* note length of the UDP frame  */
	framelen = tvb_reported_length(tvb);

	if (framelen < ecmp_min_packet_size) {
		return 0;
	}

	/* display the "ECMP" protocol indication in the PROTOCOL field  */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ECMP);

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* adjust offset to point at transaction ID  */
	offset += 2;

	/*getting the information from the buffer*/
	transaction_id_value = tvb_get_guint8(tvb, offset);

	/* adjust offset to point at ECMP query/response code  */
	offset += 3;

	/* calculate if it's a query or response (type_r_r)  */
	type_value = tvb_get_guint8(tvb, offset);

	/* determine the ECMP command code  */
	command_value = type_value & 0x7f;

	/* update offset to point to cyclic link number  */
	offset += 2;

	/* Information displayed in the Info column*/
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s. Transaction ID: %d",
					val_to_str(command_value, command_vals, "Unknown Type:0x%02x"),
					val_to_str((type_value & 0x80) >> 7, type_rr, "Unknown Type:0x%02x"), transaction_id_value);

	/*display the first line of the tree (ECMP data)*/
	ecmp_item = proto_tree_add_item(tree, proto_ecmp, tvb, 0, -1, ENC_NA); /*item created*/
	ecmp_tree = proto_item_add_subtree(ecmp_item, ett_ecmp); /*tree created*/

	/* indicate cyclic link message  */
	proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_link_req_resp, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* display the cyclic link number  */
	proto_tree_add_item(ecmp_tree, hf_ecmp_cyclic_link_number_display, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (type_value & 0x80) {
		/* response data handled here  */
		/* display the alignment  */
		proto_tree_add_item(ecmp_tree, hf_ecmp_udp_alignment, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* display the scheme  */
		scheme = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ecmp_tree, hf_ecmp_udp_scheme, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* if the scheme is 1, there is grandmaster data to be printed  */
		if (scheme == 1) {
			proto_tree_add_item(ecmp_tree, hf_ecmp_grandmaster, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;

			proto_tree_add_item(ecmp_tree, hf_ecmp_process_time, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}

		/* create the Cyclic Data Display (guint32 format) sub-tree  */
		ecmp_cyclic_data_32_bit_display_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_cyclic_data_32_bit_display, NULL,
				"Cyclic Data (32-bit hex unsigned format): ");

		/* display the raw hex data for the cyclic data in a 32-bit format  */
		display_raw_cyclic_data(cyclic_display_long_format, offset, framelen - offset, tvb, ecmp_cyclic_data_32_bit_display_tree);

		/* create the Cyclic Data Display (guint16 format) sub-tree  */
		ecmp_cyclic_data_16_bit_display_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_cyclic_data_16_bit_display, NULL,
				"Cyclic Data (16-bit hex unsigned format): ");

		/* display the raw hex data for the cyclic data in a 16-bit format  */
		display_raw_cyclic_data(cyclic_display_word_format, offset, framelen - offset, tvb, ecmp_cyclic_data_16_bit_display_tree);

		/* display the raw hex data for the cyclic data in a guint8 format  */
		ecmp_cyclic_data_8_bit_display_tree = proto_tree_add_subtree(ecmp_tree, tvb, offset, 2, ett_ecmp_cyclic_data_8_bit_display, NULL,
				"Cyclic Data (8-bit hex unsigned format): ");

		/* display the raw hex data for the cyclic data in 8-bit format */
		display_raw_cyclic_data(cyclic_display_byte_format, offset, framelen - offset, tvb, ecmp_cyclic_data_8_bit_display_tree);
	}

	return tvb_reported_length(tvb);
}

/* Function to register the protcol*/
/* Wireshark literally scans this file (packet-ecmp.c) to find this function  */
/* note: this function MUST start in column 1, due to the scanning mentioned above */
void proto_register_ecmp (void)
{
	/* A header field is something you can search/filter on.
	*
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/

	static hf_register_info hf[] = {

	{ &hf_ecmp_destination_address,
	{ "Destination Address scheme", "ecmp.destination_address", FT_UINT8, BASE_DEC, VALS(address_scheme), 0, NULL, HFILL }},

	{ &hf_ecmp_source_address,
	{ "Source Address scheme", "ecmp.source_address", FT_UINT8, BASE_DEC, VALS(address_scheme), 0, NULL, HFILL }},

	{ &hf_ecmp_diagnostic,
	{ "Diagnostic group", "ecmp.diagnostic", FT_UINT8, BASE_DEC, VALS(diagnostic), 0, NULL, HFILL }},

	{ &hf_ecmp_command,
	{ "Command", "ecmp.command", FT_UINT8, BASE_DEC, VALS(command_vals), 0x7F, NULL, HFILL }},

	{ &hf_ecmp_option,
	{ "Option", "ecmp.option", FT_UINT8, BASE_DEC, VALS(option_code), 0x0, NULL, HFILL }},

	{ &hf_ecmp_type_rr,
	{ "Type", "ecmp.type", FT_UINT8, BASE_DEC, VALS(type_rr), 0x80, "ECMP Type (request/response)", HFILL }},

	{ &hf_ecmp_chunking,
	{ "Chunks allowed","ecmp.chunking", FT_UINT16, BASE_DEC, NULL,0xF000, "ECMP number of chunks allowed", HFILL}},

	{ &hf_ecmp_max_response_size,
	{ "Maximum Response Size","ecmp.response_size", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0FFF, NULL, HFILL}},

	{ &hf_ecmp_category,
	{ "Device", "ecmp.category", FT_UINT8, BASE_DEC, VALS(category), 0x0, "ECMP Category (drive or option module)", HFILL }},

	{ &hf_ecmp_attribute,
	{ "Attribute", "ecmp.attribute", FT_UINT8, BASE_DEC, VALS(attribute), 0x0, NULL, HFILL }},

	{ &hf_ecmp_no_of_attributes,
	{ "Number of attributes", "ecmp.attribute_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_status,
	{ "Status", "ecmp.status", FT_INT8, BASE_DEC, VALS(status), 0x0, NULL, HFILL }},

	{ &hf_ecmp_chunk_id,
	{ "Chunk ID", "ecmp.chunkID", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_transaction_id,
	{ "Transaction ID", "ecmp.transactionID", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_drive_type,
	{ "Product Type", "ecmp.drive_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_drive_derivative,
	{ "Drive Derivative", "ecmp.drive_derivative", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_drive_factory_fit_category_id,
	{ "Factory Fitted Option ID", "ecmp.drive_factory_fit_category_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_category_id,
	{ "Option ID", "ecmp.category_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_cyclic_link_num,
	{ "Cyclic Link Number", "ecmp.link_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_cyclic_align,
	{ "Alignment", "ecmp.cyclic_align", FT_UINT8, BASE_DEC, VALS(cyclic_align), 0x0, "ECMP Cyclic Data Alignment", HFILL }},

	{ &hf_ecmp_cyclic_scheme,
	{ "Scheme", "ecmp.cyclic_scheme", FT_UINT8, BASE_DEC, VALS(cyclic_scheme), 0x0, "ECMP Cyclic Scheme", HFILL }},

	{ &hf_ecmp_cyclic_link_number_display,
	{ "Cyclic Link Number Display", "ecmp.link_num_display", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_buffer_size,
	{"Buffer Size", "ecmp.buffer_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_max_response,
	{"Maximum Response Time", "ecmp.max_response", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_max_handle,
	{"Maximum Handle Period", "ecmp.max_handle", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_info_address,
	{"Number of Default Route Addresses", "ecmp.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_parameter_address,
	{"Parameter Addressing Scheme", "ecmp.parameter.address", FT_UINT8, BASE_DEC, VALS(parameter_address_scheme), 0x0, NULL, HFILL}},

	{ &hf_ecmp_number_of_parameter_definitions,
	{"Number of Parameter Definitions", "ecmp.parameter.definitions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_number_of_parameter_responses,
	{"Number of Parameter Responses", "ecmp.parameter.response", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_parameter_status,
	{"Parameter Status", "ecmp.parameter.status", FT_INT8, BASE_DEC, VALS(parameter_access_status), 0x0, NULL, HFILL}},

	{ &hf_ecmp_data_type,
	{"Parameter Data Type", "ecmp.parameter.data_type", FT_UINT8, BASE_DEC, VALS(parameter_data_types), 0x0, NULL, HFILL}},

	{ &hf_ecmp_info_type,
	{"Info Type", "ecmp.info_type", FT_UINT8, BASE_DEC, VALS(info_type), 0x0, NULL, HFILL}},

	{ &hf_ecmp_file_status,
	{"File Status", "ecmp.file.status", FT_INT8, BASE_DEC, VALS(file_status), 0x0, NULL, HFILL}},

	{ &hf_ecmp_file_handle,
	{"File Handle", "ecmp.file.handle", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

	{ &hf_ecmp_file_attributes,
	{"Attribute", "ecmp.file.attribute", FT_UINT8, BASE_DEC, VALS(file_attributes), 0x0, "File attributes", HFILL}},

	{ &hf_ecmp_file_ref_point,
	{"Reference Point", "ecmp.file.reference", FT_UINT8, BASE_DEC, VALS(file_ref_point), 0x0, "File reference points", HFILL}},

	{ &hf_ecmp_tunnel_control,
	{"Control", "ecmp.tunnel_control", FT_UINT8, BASE_DEC, NULL, 0x0, "Tunnel frame control field", HFILL}},

	{ &hf_ecmp_tunnel_start_flag,
	{"Start", "ecmp.tunnel_control.start", FT_BOOLEAN, 8, NULL, TUNNEL_START_FLAG, "Tunnel frame control field start flag", HFILL}},

	{ &hf_ecmp_tunnel_end_flag,
	{"End", "ecmp.tunnel_control.end", FT_BOOLEAN, 8, NULL, TUNNEL_END_FLAG, "Tunnel frame control field end flag", HFILL}},

	{ &hf_ecmp_tunnel_check_output_flag,
	{"Check Output", "ecmp.tunnel_control.check", FT_BOOLEAN, 8, NULL, TUNNEL_CHECK_OUTPUT_FLAG, "Tunnel frame control field check output flag", HFILL}},

	{ &hf_ecmp_tunnel_size,
	{"Size", "ecmp.tunnel_size", FT_UINT16, BASE_DEC, NULL, 0x0, "Tunnel frame payload size", HFILL}},

	{ &hf_ecmp_cyclic_setup_mode,
	{"Mode", "ecmp.cyclic_setup.mode", FT_UINT8, BASE_DEC, VALS(cyclic_setup_mode), 0x0, "Cyclic setup mode", HFILL}},

	{ &hf_ecmp_cyclic_setup_linkno,
	{"Link No", "ecmp.cyclic_setup.linkno", FT_UINT8, BASE_DEC, NULL, 0x0, "Cyclic setup link no", HFILL}},

	{ &hf_ecmp_cyclic_setup_dir,
	{"Direction", "ecmp.cyclic_setup.direction", FT_UINT8, BASE_DEC, VALS(cyclic_setup_link_dir), 0x0, "Cyclic setup link direction", HFILL}},

	{ &hf_ecmp_cyclic_setup_attrib_count,
	{"Count", "ecmp.cyclic_setup.attrib_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Cyclic setup attribute count", HFILL}},

	{ &hf_ecmp_cyclic_setup_attrib,
	{"Attribute", "ecmp.cyclic_setup.attrib", FT_UINT8, BASE_DEC, VALS(cyclic_attributes), 0x0, "Cyclic setup attribute", HFILL}},

	{ &hf_ecmp_cyclic_setup_rsp_status,
	{"Status", "ecmp.cyclic_setup.rsp_status", FT_INT8, BASE_DEC, NULL, 0x0, "Cyclic setup status", HFILL}},

	{ &hf_ecmp_cyclic_setup_rsp_err_idx,
	{"Error Index", "ecmp.cyclic_setup.rsp_err_idx", FT_UINT8, BASE_DEC, NULL, 0x0, "Cyclic setup error index", HFILL}},

	{ &hf_ecmp_cyclic_setup_link_exists,
	{"Existence State", "ecmp.cyclic_setup.exists.state", FT_UINT8, BASE_DEC, VALS(cyclic_setup_link_exists), 0x0, "Cyclic setup exists state", HFILL}},

	{ &hf_ecmp_cyclic_link_req_resp,
	{"Cyclic Link - Request-Response", "ecmp.cyclic_link.request.response", FT_UINT8, BASE_DEC, VALS(cyclic_link_req_resp), 0x0, "Cyclic link request - response", HFILL}},

	{ &hf_ecmp_attribute_string,
	{ "Attribute string", "ecmp.attribute_string", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_file_name,
	{ "File name", "ecmp.file_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_directory,
	{ "Directory", "ecmp.directory", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_names_scheme,
	{ "Names Scheme", "ecmp.names_scheme", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_variable_name,
	{ "Variable name", "ecmp.variable_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_unit_id_string,
	{ "Unit ID String", "ecmp.unit_id_string", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_ecmp_string,
	{ "ECMP string", "ecmp.ecmp_string", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_info_command,
	{ "Info command data", "ecmp.info_command", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_process_time,
	{ "ProcessAt time", "ecmp.processat_time",  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_cyclic_frame_time,
	{ "Cyclic frame time", "ecmp.cyclic_frame_time",  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_grandmaster,
	{ "Grandmaster", "ecmp.grandmaster",  FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_data,
	{ "Data", "ecmp.data",  FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }},

	{ &hf_ecmp_response_data,
	{ "Response Data", "ecmp.response_data",  FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }},

	/* Generated from convert_proto_tree_add_text.pl */
	{ &hf_ecmp_physical_address, { "Physical address", "ecmp.physical_address", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
	{ &hf_ecmp_logical_address, { "Logical address", "ecmp.logical_address", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
	{ &hf_ecmp_primary_colour, { "Primary Colour", "ecmp.primary_colour", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_secondary_colour, { "Secondary Colour", "ecmp.secondary_colour", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_number_of_subsequent_object_requests, { "Number of subsequent object requests", "ecmp.number_of_subsequent_object_requests", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_number_of_decimal_places, { "Number of decimal places", "ecmp.number_of_decimal_places", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_no_information_available, { "No Information available", "ecmp.no_information_available", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_param_format_bit_default_unipolar, { "BU- Bit default/Unipolar", "ecmp.param_format.bit_default_unipolar", FT_UINT32, BASE_DEC, NULL, 0x00000001, NULL, HFILL }},
	{ &hf_ecmp_param_format_write_allowed, { "W- Write allowed", "ecmp.param_format.write_allowed", FT_UINT32, BASE_DEC, NULL, 0x00000002, NULL, HFILL }},
	{ &hf_ecmp_param_format_read_not_allowed, { "NR- Read not allowed", "ecmp.param_format.read_not_allowed", FT_UINT32, BASE_DEC, NULL, 0x00000004, NULL, HFILL }},
	{ &hf_ecmp_param_format_protected_from_destinations, { "PT- Protected from destinations", "ecmp.param_format.protected_from_destinations", FT_UINT32, BASE_DEC, NULL, 0x00000008, NULL, HFILL }},
	{ &hf_ecmp_param_format_parameter_not_visible, { "NV- Parameter not visible", "ecmp.param_format.parameter_not_visible", FT_UINT32, BASE_DEC, NULL, 0x00000010, NULL, HFILL }},
	{ &hf_ecmp_param_format_not_clonable, { "NC- Not clonable", "ecmp.param_format.not_clonable", FT_UINT32, BASE_DEC, NULL, 0x00000020, NULL, HFILL }},
	{ &hf_ecmp_param_format_voltage_or_current_rating_dependent, { "RA- Voltage or current rating dependent", "ecmp.param_format.voltage_or_current_rating_dependent", FT_UINT32, BASE_DEC, NULL, 0x00000040, NULL, HFILL }},
	{ &hf_ecmp_param_format_parameter_has_no_default, { "ND- Parameter has no default", "ecmp.param_format.parameter_has_no_default", FT_UINT32, BASE_DEC, NULL, 0x00000080, NULL, HFILL }},
	{ &hf_ecmp_param_format_number_of_decimal_places, { "DP- Number of Decimal places", "ecmp.param_format.number_of_decimal_places", FT_UINT32, BASE_DEC, NULL, 0x00000F00, NULL, HFILL }},
	{ &hf_ecmp_param_format_variable_maximum_and_minimum, { "VM- Variable maximum and minimum", "ecmp.param_format.variable_maximum_and_minimum", FT_UINT32, BASE_DEC, NULL, 0x00001000, NULL, HFILL }},
	{ &hf_ecmp_param_format_string_parameter, { "TE- String parameter", "ecmp.param_format.string_parameter", FT_UINT32, BASE_DEC, NULL, 0x00002000, NULL, HFILL }},
	{ &hf_ecmp_param_format_destination_set_up_parameter, { "DE- destination set-up parameter", "ecmp.param_format.destination_set_up_parameter", FT_UINT32, BASE_DEC, NULL, 0x00004000, NULL, HFILL }},
	{ &hf_ecmp_param_format_filtered_when_displayed, { "FI- Filtered when displayed", "ecmp.param_format.filtered_when_displayed", FT_UINT32, BASE_DEC, NULL, 0x00008000, NULL, HFILL }},
	{ &hf_ecmp_param_format_pseudo_read_only, { "PR- Pseudo read only", "ecmp.param_format.pseudo_read_only", FT_UINT32, BASE_DEC, NULL, 0x00010000, NULL, HFILL }},
	{ &hf_ecmp_param_format_display_format, { "DF- Display Format", "ecmp.param_format.display_format", FT_UINT32, BASE_DEC, VALS(display_format), 0x001E0000, NULL, HFILL }},
	{ &hf_ecmp_param_format_floating_point_value, { "FL- Floating point value", "ecmp.param_format.floating_point_value", FT_UINT32, BASE_DEC, NULL, 0x00200000, NULL, HFILL }},
	{ &hf_ecmp_param_format_units, { "UNITS", "ecmp.param_format.units", FT_UINT32, BASE_DEC, VALS(format_units), 0x0FC00000, NULL, HFILL }},
	{ &hf_ecmp_string_id, { "String ID", "ecmp.string_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_address_scheme_menu, { "Menu", "ecmp.address_scheme.menu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_address_scheme_parameter, { "Parameter", "ecmp.address_scheme.parameter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_address_scheme_slot, { "Slot", "ecmp.address_scheme.slot", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_address_scheme_null_byte_size, { "NULL byte size", "ecmp.address_scheme.null_byte_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_display_unit_id, { "Unit ID", "ecmp.display_unit_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_boolean, { "Data", "ecmp.data.boolean", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
	{ &hf_ecmp_data_int8, { "Data", "ecmp.data.int8", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_uint8, { "Data", "ecmp.data.uint8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_int16, { "Data", "ecmp.data.int16", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_uint16, { "Data", "ecmp.data.uint16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_int32, { "Data", "ecmp.data.int32", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_uint32, { "Data", "ecmp.data.uint32", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_int64, { "Data", "ecmp.data.int64", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_uint64, { "Data", "ecmp.data.uint64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_float, { "Data", "ecmp.data.float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_data_double, { "Data", "ecmp.data.double", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_access_mode, { "Access Mode", "ecmp.access_mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_open_in_non_blocking_mode, { "Open in non-blocking mode", "ecmp.open_in_non_blocking_mode", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
	{ &hf_ecmp_open_file_relative_to_specified_directory_handle, { "Open file relative to specified directory handle", "ecmp.open_file_relative_to_specified_directory_handle", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
	{ &hf_ecmp_file_access_mode, { "File Access Mode", "ecmp.file_access_mode", FT_UINT8, BASE_DEC, VALS(file_status_mode), 0x0F, NULL, HFILL }},
	{ &hf_ecmp_additional_scheme, { "Additional Scheme", "ecmp.additional_scheme", FT_UINT8, BASE_DEC, VALS(additional_scheme_vals), 0x0, NULL, HFILL }},
	{ &hf_ecmp_scheme_data_length, { "Length", "ecmp.scheme_data_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_number_of_requested_bytes, { "Number of requested bytes", "ecmp.number_of_requested_bytes", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_number_of_bytes_transferred, { "Number of bytes transferred", "ecmp.number_of_bytes_transferred", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_crc, { "CRC", "ecmp.crc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_ref_offset, { "Offset", "ecmp.ref_offset", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_number_of_files_to_list, { "Number of files to list", "ecmp.number_of_files_to_list", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_file_hash, { "Hash", "ecmp.file_hash", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_item_type, { "Item type", "ecmp.item_type", FT_UINT8, BASE_DEC, VALS(item_type_vals), 0x0, NULL, HFILL }},
	{ &hf_ecmp_file_integrity, { "File Integrity", "ecmp.file_integrity", FT_UINT8, BASE_DEC, VALS(file_integrity_vals), 0x01, NULL, HFILL }},
	{ &hf_ecmp_display_attr_read_only, { "Read Only", "ecmp.display_attr.read_only", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_ecmp_display_attr_hidden, { "Hidden", "ecmp.display_attr.hidden", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_ecmp_display_attr_system, { "System", "ecmp.display_attr.system", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	{ &hf_ecmp_display_attr_volume_label, { "Volume Label", "ecmp.display_attr.volume_label", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	{ &hf_ecmp_display_attr_subdirectory, { "Subdirectory", "ecmp.display_attr.subdirectory", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
	{ &hf_ecmp_display_attr_archive, { "Archive", "ecmp.display_attr.archive", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
	{ &hf_ecmp_display_creation, { "Display creation", "ecmp.display_creation", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_display_modification, { "Display modification", "ecmp.display_modification", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_interrogate_item_type, { "Item Type", "ecmp.interrogate_item_type", FT_UINT8, BASE_DEC, VALS(Interrogate_command_option_state), 0x0, NULL, HFILL }},
	{ &hf_ecmp_interrogate_count, { "Count", "ecmp.interrogate_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_modbus_pdu_size, { "Size", "ecmp.modbus_pdu_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#if 0
	{ &hf_ecmp_destination_scheme, { "Destination Scheme", "ecmp.destination_scheme", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif
	{ &hf_ecmp_program_control_target, { "Target", "ecmp.program_control_target", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_control_command, { "Command", "ecmp.program_control_command", FT_UINT8, BASE_DEC, VALS(command_code_list), 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_control_sub_command, { "Sub-Command", "ecmp.program_control_sub_command", FT_UINT8, BASE_DEC, VALS(sub_command_code_list), 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_control_status, { "Status", "ecmp.program_control_status", FT_UINT8, BASE_DEC, VALS(status_list), 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_status_target, { "Target", "ecmp.program_status_target", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_status_status, { "Status", "ecmp.program_status_status", FT_UINT8, BASE_DEC, VALS(running_state_list), 0x0, NULL, HFILL }},
	{ &hf_ecmp_program_status_additional_items, { "Additional Items", "ecmp.program_status_additional_items", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_cyclic_setup_max_mappings, { "Max Mappings", "ecmp.cyclic_setup.max_mappings", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_cyclic_setup_start_offset, { "Start Offset", "ecmp.cyclic_setup.start_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_cyclic_setup_tx_count, { "Tx Count", "ecmp.cyclic_setup.tx_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_cyclic_setup_rx_count, { "Rx Count", "ecmp.cyclic_setup.rx_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_udp_alignment, { "Alignment", "ecmp.udp_alignment", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_udp_scheme, { "Scheme", "ecmp.udp_scheme", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_cyclic_data, { "Cyclic Data", "ecmp.cyclic_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_version_summary, { "Version summary", "ecmp.version_summary", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_min_param_menu, { "Min parameter in menu", "ecmp.min_param_menu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_max_param_menu, { "Max parameter in menu", "ecmp.max_param_menu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_file_length, { "File length", "ecmp.file_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_mec_offset, { "mec_offset", "ecmp.mec_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_sample_period, { "Sample period", "ecmp.sample_period", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_timeout, { "RX Timeout", "ecmp.rx_timeout", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_action, { "Action", "ecmp.rx_action", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_event_destination, { "Event Destination", "ecmp.rx_event_destination", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_event, { "Event", "ecmp.rx_event", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_late_handler_action, { "Action", "ecmp.rx_late_handler_action", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_late_handler_event_destination, { "Event Destination", "ecmp.rx_late_handler_event_destination", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_rx_late_handler_event, { "Event", "ecmp.rx_late_handler_event", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_transport_addr_scheme, { "Scheme", "ecmp.transport_addr_scheme", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_transport_addr, { "Transport address", "ecmp.transport_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_mapping_item_offset, { "Offset", "ecmp.mapping_item_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_mapping_item_scheme, { "Scheme", "ecmp.mapping_item_scheme", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_setup_attribute, { "Attribute", "ecmp.setup_attribute", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_mec_period, { "mec period", "ecmp.mec_period", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_ecmp_interrogate_command, { "Command", "ecmp.interrogate_command", FT_UINT8, BASE_DEC, VALS(command_vals), 0x0, NULL, HFILL }}
};

/* array to store pointers to the ids of the subtrees that we may be creating */
	static gint *ett[] = {
		&ett_ecmp,
		&ett_ecmp_address,
		&ett_ecmp_response_size,
		&ett_ecmp_command,
		&ett_ecmp_category,
		&ett_ecmp_option,
		&ett_ecmp_option_data,
		&ett_ecmp_attribute,
		&ett_ecmp_attribute_data,
		&ett_ecmp_cyclic_scheme,
		&ett_ecmp_interrogate_message,
		&ett_ecmp_info_type,
		&ett_ecmp_info_count,
		&ett_ecmp_param_address,
		&ett_ecmp_access_mode,
		&ett_ecmp_access_file,
		&ett_ecmp_file_read,
		&ett_ecmp_file_write,
		&ett_ecmp_file_info,
		&ett_ecmp_file_info_att,
		&ett_ecmp_file_position,
		&ett_ecmp_file_list_no,
		&ett_ecmp_file_list,
		&ett_ecmp_tunnel_3s_goodframe,
		&ett_ecmp_tunnel_3s_size,
		&ett_ecmp_tunnel_3s_service,
		&ett_cyclic_setup_attribs,
		&ett_cyclic_setup_transport_addr,
		&ett_cyclic_setup_attrib_item,
		&ett_ecmp_cyclic_data_32_bit_display,
		&ett_ecmp_cyclic_data_16_bit_display,
		&ett_ecmp_cyclic_data_8_bit_display,
		&ett_ecmp_modbus_pdu_message,
		&ett_ecmp_program_control_message,
		&ett_ecmp_program_status_message
	};

	static ei_register_info ei[] = {
		{ &ei_ecmp_unknown_command, { "ecmp.unknown_command", PI_PROTOCOL, PI_WARN, "Unknown Command", EXPFILL }},
		{ &ei_ecmp_color, { "ecmp.color_invalid", PI_PROTOCOL, PI_WARN, "Invalid color data value", EXPFILL }},
		{ &ei_ecmp_option, { "ecmp.ecmp_option.unknown", PI_PROTOCOL, PI_WARN, "ERROR - Unrecognised Option Code", EXPFILL }},
		{ &ei_ecmp_data_type, { "ecmp.data_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Data Type", EXPFILL }},
		{ &ei_ecmp_parameter_addressing_scheme, { "ecmp.incorrect_parameter_addressing_scheme", PI_PROTOCOL, PI_WARN, "Incorrect parameter addressing scheme", EXPFILL }},
		{ &ei_ecmp_info_type, { "ecmp.info_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown info type", EXPFILL }},
		{ &ei_ecmp_attribute_type, { "ecmp.attribute_type.unknown", PI_PROTOCOL, PI_WARN, "Wrong attribute type", EXPFILL }},
		{ &ei_ecmp_item_type, { "ecmp.item_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown item type", EXPFILL }},
		{ &ei_ecmp_options_not_implemented, { "ecmp.options_not_implemented", PI_UNDECODED, PI_WARN, "ECMP Options Not Implemented", EXPFILL }}
	};

	expert_module_t* expert_ecmp;

	proto_ecmp = proto_register_protocol ("ECMP", PROTO_TAG_ECMP, "ecmp");
	ecmp_tcp_handle = register_dissector("ecmp_tcp", dissect_ecmp_tcp, proto_ecmp);
	ecmp_udp_handle = register_dissector("ecmp_udp", dissect_ecmp_udp, proto_ecmp);


	/* full name short name and abbreviation (display filter name)*/
	proto_register_field_array(proto_ecmp, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	expert_ecmp = expert_register_protocol(proto_ecmp);
	expert_register_field_array(expert_ecmp, ei, array_length(ei));
}

/* Function to initialise the dissector*/
/* Wireshark literally scans this file (packet-ecmp.c) to find this function  */
void proto_reg_handoff_ecmp(void)
{
	/* Cyclic frames are over UDP and non-cyclic are over TCP */
	dissector_add_uint_with_preference("udp.port", ECMP_TCP_PORT, ecmp_udp_handle);
	dissector_add_uint_with_preference("tcp.port", ECMP_TCP_PORT, ecmp_tcp_handle);

	/* Modbus dissector hooks */
	modbus_handle = find_dissector_add_dependency("modbus", proto_ecmp);
	proto_modbus = proto_get_id_by_filter_name( "modbus" );
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
