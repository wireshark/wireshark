/* packet-ndps.c
 * Routines for NetWare's NDPS
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2003
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include <epan/strutil.h>

#include "packet-ipx.h"
#include "packet-tcp.h"
#include "packet-ndps.h"

/* Limit the number of items we can add to the tree. */
#define NDPS_MAX_ITEMS 100

/* Tables for reassembly of fragments. */
static GHashTable *ndps_fragment_table = NULL;
static GHashTable *ndps_reassembled_table = NULL;

/* desegmentation of ndps */
static gboolean ndps_defragment = TRUE;

static guint32  tid = 1;

/* Show ID's value */
static gboolean ndps_show_oids=FALSE;

/* Global Attribute for evaluation of Values */
static const char *global_attribute_name=NULL;

static int dissect_ndps_request(tvbuff_t*, packet_info*, proto_tree*, guint32, guint32, int);

static int dissect_ndps_reply(tvbuff_t *, packet_info*, proto_tree*, int);

static int hf_ndps_segments = -1;
static int hf_ndps_segment = -1;
static int hf_ndps_segment_overlap = -1;
static int hf_ndps_segment_overlap_conflict = -1;
static int hf_ndps_segment_multiple_tails = -1;
static int hf_ndps_segment_too_long_segment = -1;
static int hf_ndps_segment_error = -1;
static int hf_ndps_segment_count = -1;
static int hf_ndps_reassembled_length = -1;

static gint ett_ndps_segments = -1;
static gint ett_ndps_segment = -1;

static int proto_ndps = -1;
static int hf_ndps_record_mark = -1;
static int hf_ndps_length = -1;
static int hf_ndps_xid = -1;
static int hf_ndps_packet_type = -1;
static int hf_ndps_rpc_version = -1;
static int hf_ndps_error = -1;
static int hf_ndps_num_objects = -1;
static int hf_ndps_num_attributes = -1;
static int hf_ndps_sbuffer = -1;
static int hf_ndps_rbuffer = -1;
static int hf_ndps_user_name = -1;
static int hf_ndps_broker_name = -1;
static int hf_ndps_num_results = -1;
static int hf_ndps_num_options = -1;
static int hf_ndps_num_jobs = -1;
static int hf_ndps_pa_name = -1;
static int hf_ndps_tree = -1;
static int hf_ndps_reqframe = -1;
static int hf_ndps_error_val = -1;
static int hf_ndps_ext_error = -1;
static int hf_ndps_object = -1;
static int hf_ndps_cred_type = -1;
static int hf_ndps_server_name = -1;
static int hf_ndps_connection = -1;
static int hf_ndps_auth_null = -1;
static int hf_ndps_rpc_accept = -1;
static int hf_ndps_rpc_acc_stat = -1;
static int hf_ndps_rpc_rej_stat = -1;
static int hf_ndps_rpc_acc_results = -1;
static int hf_ndps_problem_type = -1;
static int hf_security_problem_type = -1;
static int hf_service_problem_type = -1;
static int hf_access_problem_type = -1;
static int hf_printer_problem_type = -1;
static int hf_selection_problem_type = -1;
static int hf_doc_access_problem_type = -1;
static int hf_attribute_problem_type = -1;
static int hf_update_problem_type = -1;
static int hf_obj_id_type = -1;
static int hf_oid_struct_size = -1;
static int hf_object_name = -1;
static int hf_ndps_document_number = -1;
static int hf_ndps_nameorid = -1;
static int hf_ndps_local_object_name = -1;
static int hf_ndps_printer_name = -1;
static int hf_ndps_qualified_name = -1;
static int hf_ndps_item_count = -1;
static int hf_ndps_num_passwords = -1;
static int hf_ndps_num_servers = -1;
static int hf_ndps_num_locations = -1;
static int hf_ndps_num_areas = -1;
static int hf_ndps_num_address_items = -1;
static int hf_ndps_num_job_categories = -1;
static int hf_ndps_num_page_selects = -1;
static int hf_ndps_num_page_informations = -1;
static int hf_ndps_num_names = -1;
static int hf_ndps_num_categories = -1;
static int hf_ndps_num_colorants = -1;
static int hf_ndps_num_events = -1;
static int hf_ndps_num_args = -1;
static int hf_ndps_num_transfer_methods = -1;
static int hf_ndps_num_doc_types = -1;
static int hf_ndps_num_destinations = -1;
static int hf_ndps_qualifier = -1;
static int hf_ndps_lib_error = -1;
static int hf_ndps_other_error = -1;
static int hf_ndps_other_error_2 = -1;
static int hf_ndps_session = -1;
static int hf_ndps_abort_flag = -1;
static int hf_ndps_obj_attribute_type = -1;
static int hf_ndps_attribute_value = -1;
static int hf_ndps_lower_range = -1;
static int hf_ndps_upper_range = -1;
static int hf_ndps_n64 = -1;
static int hf_ndps_lower_range_n64 = -1;
static int hf_ndps_upper_range_n64 = -1;
static int hf_ndps_attrib_boolean = -1;
static int hf_ndps_realization = -1;
static int hf_ndps_xdimension_n64 = -1;
static int hf_ndps_ydimension_n64 = -1;
static int hf_ndps_dim_value = -1;
static int hf_ndps_dim_flag = -1;
static int hf_ndps_xydim_value = -1;
static int hf_ndps_location_value = -1;
static int hf_ndps_xmin_n64 = -1;
static int hf_ndps_xmax_n64 = -1;
static int hf_ndps_ymin_n64 = -1;
static int hf_ndps_ymax_n64 = -1;
static int hf_ndps_edge_value = -1;
static int hf_ndps_cardinal_or_oid = -1;
static int hf_ndps_cardinal_name_or_oid = -1;
static int hf_ndps_integer_or_oid = -1;
static int hf_ndps_profile_id = -1;
static int hf_ndps_persistence = -1;
static int hf_ndps_language_count = -1;
static int hf_ndps_language_id = -1;
static int hf_address_type = -1;
static int hf_ndps_address = -1;
static int hf_ndps_add_bytes = -1;
static int hf_ndps_event_type = -1;
static int hf_ndps_event_object_identifier = -1;
static int hf_ndps_octet_string = -1;
static int hf_ndps_scope = -1;
static int hf_address_len = -1;
static int hf_ndps_net = -1;
static int hf_ndps_node = -1;
static int hf_ndps_socket = -1;
static int hf_ndps_port = -1;
static int hf_ndps_ip = -1;
static int hf_ndps_server_type = -1;
static int hf_ndps_num_services = -1;
static int hf_ndps_service_type = -1;
static int hf_ndps_service_enabled = -1;
static int hf_ndps_method_name = -1;
static int hf_ndps_method_ver = -1;
static int hf_ndps_file_name = -1;
static int hf_ndps_admin_submit = -1;
static int hf_ndps_oid = -1;
static int hf_ndps_object_op = -1;
static int hf_answer_time = -1;
static int hf_oid_asn1_type = -1;
static int hf_ndps_item_ptr = -1;
static int hf_ndps_len = -1;
static int hf_ndps_limit_enc = -1;
static int hf_ndps_delivery_add_count = -1;
static int hf_ndps_qualified_name2 = -1;
static int hf_ndps_delivery_add_type = -1;
static int hf_ndps_criterion_type = -1;
static int hf_ndps_num_ignored_attributes = -1;
static int hf_ndps_ignored_type = -1;
static int hf_ndps_num_resources = -1;
static int hf_ndps_resource_type = -1;
static int hf_ndps_identifier_type = -1;
static int hf_ndps_page_flag = -1;
static int hf_ndps_media_type = -1;
static int hf_ndps_doc_content = -1;
static int hf_ndps_page_size = -1;
static int hf_ndps_direction = -1;
static int hf_ndps_page_order = -1;
static int hf_ndps_medium_size = -1;
static int hf_ndps_long_edge_feeds = -1;
static int hf_ndps_inc_across_feed = -1;
static int hf_ndps_size_inc_in_feed = -1;
static int hf_ndps_page_orientation = -1;
static int hf_ndps_numbers_up = -1;
static int hf_ndps_xdimension = -1;
static int hf_ndps_ydimension = -1;
static int hf_ndps_state_severity = -1;
static int hf_ndps_training = -1;
static int hf_ndps_colorant_set = -1;
static int hf_ndps_card_enum_time = -1;
static int hf_ndps_attrs_arg = -1;
static int hf_ndps_context_len = -1;
static int hf_ndps_context = -1;
static int hf_ndps_filter = -1;
static int hf_ndps_item_filter = -1;
static int hf_ndps_substring_match = -1;
static int hf_ndps_time_limit = -1;
static int hf_ndps_count_limit = -1;
static int hf_ndps_operator = -1;
static int hf_ndps_password = -1;
static int hf_ndps_retrieve_restrictions = -1;
static int hf_ndps_bind_security_option_count = -1;
static int hf_bind_security = -1;
static int hf_ndps_max_items = -1;
static int hf_ndps_status_flags = -1;
static int hf_ndps_resource_list_type = -1;
static int hf_os_count = -1;
static int hf_os_type = -1;
static int hf_ndps_printer_type_count = -1;
static int hf_ndps_printer_type = -1;
static int hf_ndps_printer_manuf = -1;
static int hf_ndps_inf_file_name = -1;
static int hf_ndps_vendor_dir = -1;
static int hf_banner_type = -1;
static int hf_font_type = -1;
static int hf_printer_id = -1;
static int hf_ndps_font_name = -1;
static int hf_ndps_return_code = -1;
static int hf_ndps_banner_count = -1;
static int hf_ndps_banner_name = -1;
static int hf_ndps_font_type_count = -1;
static int hf_font_type_name = -1;
static int hf_ndps_font_file_count = -1;
static int hf_font_file_name = -1;
static int hf_ndps_printer_def_count = -1;
static int hf_ndps_prn_file_name = -1;
static int hf_ndps_prn_dir_name = -1;
static int hf_ndps_def_file_name = -1;
static int hf_ndps_num_win31_keys = -1;
static int hf_ndps_num_win95_keys = -1;
static int hf_ndps_num_windows_keys = -1;
static int hf_ndps_windows_key = -1;
static int hf_archive_type = -1;
static int hf_archive_file_size = -1;
static int hf_ndps_data = -1;
static int hf_get_status_flag = -1;
static int hf_res_type = -1;
static int hf_file_timestamp = -1;
static int hf_sub_complete = -1;
static int hf_doc_content = -1;
static int hf_ndps_doc_name = -1;
static int hf_print_arg = -1;
static int hf_local_id = -1;
static int hf_ndps_included_doc_len = -1;
static int hf_ndps_included_doc = -1;
static int hf_ndps_ref_name = -1;
static int hf_interrupt_job_type = -1;
static int hf_pause_job_type = -1;
static int hf_ndps_force = -1;
static int hf_resubmit_op_type = -1;
static int hf_shutdown_type = -1;
static int hf_ndps_supplier_flag = -1;
static int hf_ndps_language_flag = -1;
static int hf_ndps_method_flag = -1;
static int hf_ndps_delivery_address_flag = -1;
static int hf_ndps_list_profiles_type = -1;
static int hf_ndps_list_profiles_choice_type = -1;
static int hf_ndps_list_profiles_result_type = -1;
static int hf_ndps_integer_type_flag = -1;
static int hf_ndps_integer_type_value = -1;
static int hf_ndps_continuation_option = -1;
static int hf_ndps_ds_info_type = -1;
static int hf_ndps_guid = -1;
static int hf_ndps_list_services_type = -1;
static int hf_ndps_item_bytes = -1;
static int hf_ndps_certified = -1;
static int hf_ndps_attribute_set = -1;
static int hf_ndps_data_item_type = -1;
static int hf_info_int = -1;
static int hf_info_int16 = -1;
static int hf_info_int32 = -1;
static int hf_info_boolean = -1;
static int hf_info_string = -1;
static int hf_info_bytes = -1;
static int hf_ndps_list_local_servers_type = -1;
static int hf_ndps_registry_name = -1;
static int hf_ndps_client_server_type = -1;
static int hf_ndps_session_type = -1;
static int hf_time = -1;
static int hf_ndps_supplier_name = -1;
static int hf_ndps_message = -1;
static int hf_ndps_delivery_method_count = -1;
static int hf_delivery_method_type = -1;
static int hf_ndps_get_session_type = -1;
static int hf_packet_count = -1;
static int hf_last_packet_flag = -1;
static int hf_ndps_get_resman_session_type = -1;
static int hf_problem_type = -1;
static int hf_ndps_num_values = -1;
static int hf_ndps_object_ids_7 = -1;
static int hf_ndps_object_ids_8 = -1;
static int hf_ndps_object_ids_9 = -1;
static int hf_ndps_object_ids_10 = -1;
static int hf_ndps_object_ids_11 = -1;
static int hf_ndps_object_ids_12 = -1;
static int hf_ndps_object_ids_13 = -1;
static int hf_ndps_object_ids_14 = -1;
static int hf_ndps_object_ids_15 = -1;
static int hf_ndps_object_ids_16 = -1;
static int hf_ndps_attribute_time = -1;
static int hf_print_security = -1;
static int hf_notify_time_interval = -1;
static int hf_notify_sequence_number = -1;
static int hf_notify_lease_exp_time = -1;
static int hf_notify_printer_uri = -1;
static int hf_level = -1;
static int hf_interval = -1;
static int hf_ndps_other_error_string = -1;

static int hf_spx_ndps_program = -1;
static int hf_spx_ndps_version = -1;
static int hf_spx_ndps_func_print = -1;
static int hf_spx_ndps_func_registry = -1;
static int hf_spx_ndps_func_notify = -1;
static int hf_spx_ndps_func_resman = -1;
static int hf_spx_ndps_func_delivery = -1;
static int hf_spx_ndps_func_broker = -1;

static gint ett_ndps = -1;
static dissector_handle_t ndps_data_handle;

/* desegmentation of NDPS over TCP */
static gboolean ndps_desegment = TRUE;

static const value_string true_false[] = {
    { 0x00000000, "Accept" },
    { 0x00000001, "Deny" },
    { 0,          NULL }
};

static const value_string ndps_limit_enc_enum[] = {
    { 0x00000000, "Time" },
    { 0x00000001, "Count" },
    { 0x00000002, "Error" },
    { 0,          NULL }
};

static const value_string problem_type_enum[] = {
    { 0x00000000, "Standard" },
    { 0x00000001, "Extended" },
    { 0,          NULL }
};

static const value_string accept_stat[] = {
    { 0x00000000, "Success" },
    { 0x00000001, "Program Unavailable" },
    { 0x00000002, "Program Mismatch" },
    { 0x00000003, "Procedure Unavailable" },
    { 0x00000004, "Garbage Arguments" },
    { 0x00000005, "System Error" },
    { 0,          NULL }
};

static const value_string reject_stat[] = {
    { 0x00000000, "RPC Mismatch" },
    { 0x00000001, "Authentication Error" },
    { 0,          NULL }
};

static const value_string error_type_enum[] = {
    { 0x00000000, "Security Error" },
    { 0x00000001, "Service Error" },
    { 0x00000002, "Access Error" },
    { 0x00000003, "Printer Error" },
    { 0x00000004, "Selection Error" },
    { 0x00000005, "Document Access Error" },
    { 0x00000006, "Attribute Error" },
    { 0x00000007, "Update Error" },
    { 0,          NULL }
};

static const value_string security_problem_enum[] = {
    { 0x00000000, "Authentication" },
    { 0x00000001, "Credentials" },
    { 0x00000002, "Rights" },
    { 0x00000003, "Invalid PAC" },
    { 0,          NULL }
};

static const value_string service_problem_enum[] = {
    { 0x00000000, "Sever Busy" },
    { 0x00000001, "Server Unavailable" },
    { 0x00000002, "Complex Operation" },
    { 0x00000003, "Resource Limit" },
    { 0x00000004, "Unclassified Server Error" },
    { 0x00000005, "Too Many Items in List" },
    { 0x00000006, "Resource not Available" },
    { 0x00000007, "Cancel Document Support" },
    { 0x00000008, "Modify Document Support" },
    { 0x00000009, "Multiple Document Support" },
    { 0x0000000a, "Parameter Valid Support" },
    { 0x0000000b, "Invalid Checkpoint" },
    { 0x0000000c, "Continuation Context" },
    { 0x0000000d, "Pause Limit Exceeded" },
    { 0x0000000e, "Unsupported Operation" },
    { 0x0000000f, "Notify Service Error" },
    { 0x00000010, "Accounting Service Error" },
    { 0,          NULL }
};

static const value_string access_problem_enum[] = {
    { 0x00000000, "Wrong Object Class" },
    { 0x00000001, "Lack of Access Rights" },
    { 0x00000002, "Can't Interrupt Job" },
    { 0x00000003, "Wrong Object State" },
    { 0x00000004, "Client Not Bound" },
    { 0x00000005, "Not Available" },
    { 0x00000006, "Notify Service Not Connected" },
    { 0x00000007, "PDS Not Connected" },
    { 0,          NULL }
};

static const value_string printer_problem_enum[] = {
    { 0x00000000, "Printer Error" },
    { 0x00000001, "Printer Needs Attention" },
    { 0x00000002, "Printer Needs Key Operator" },
    { 0,          NULL }
};

static const value_string selection_problem_enum[] = {
    { 0x00000000, "Invalid ID" },
    { 0x00000001, "Unknown ID" },
    { 0x00000002, "Object Exists" },
    { 0x00000003, "ID Changed" },
    { 0,          NULL }
};

static const value_string doc_access_problem_enum[] = {
    { 0x00000000, "Access Not Available" },
    { 0x00000001, "Time Expired" },
    { 0x00000002, "Access Denied" },
    { 0x00000003, "Unknown Document" },
    { 0x00000004, "No Documents in Job" },
    { 0,          NULL }
};

static const value_string attribute_problem_enum[] = {
    { 0x00000000, "Invalid Syntax" },
    { 0x00000001, "Undefined Type" },
    { 0x00000002, "Wrong Matching" },
    { 0x00000003, "Constraint Violated" },
    { 0x00000004, "Unsupported Type" },
    { 0x00000005, "Illegal Modification" },
    { 0x00000006, "Consists With Other Attribute" },
    { 0x00000007, "Undefined Attribute Value" },
    { 0x00000008, "Unsupported Value" },
    { 0x00000009, "Invalid Noncompulsed Modification" },
    { 0x0000000a, "Per Job Inadmissible" },
    { 0x0000000b, "Not Multivalued" },
    { 0x0000000c, "Mandatory Omitted" },
    { 0x0000000d, "Illegal For Class" },
    { 0,          NULL }
};

static const value_string update_problem_enum[] = {
    { 0x00000000, "No Modifications Allowed" },
    { 0x00000001, "Insufficient Rights" },
    { 0x00000002, "Previous Operation Incomplete" },
    { 0x00000003, "Cancel Not Possible" },
    { 0,          NULL }
};

static const value_string obj_identification_enum[] = {
    { 0x00000000, "Printer Contained Object ID" },
    { 0x00000001, "Document Identifier" },
    { 0x00000002, "Object Identifier" },
    { 0x00000003, "Object Name" },
    { 0x00000004, "Name or Object ID" },
    { 0x00000005, "Simple Name" },
    { 0x00000006, "Printer Configuration Object ID" },
    { 0x00000007, "Qualified Name" },
    { 0x00000008, "Event Object ID" },
    { 0,          NULL }
};

static const value_string nameorid_enum[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Global" },
    { 0x00000002, "Local" },
    { 0,          NULL }
};

static const value_string qualified_name_enum[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Simple" },
    { 0x00000002, "NDS" },
    { 0,          NULL }
};

static const value_string qualified_name_enum2[] = {
    { 0x00000000, "NDS" },
    { 0,          NULL }
};

static const value_string spx_ndps_program_vals[] = {
    { 0x00060976, "Print Program" },
    { 0x00060977, "Broker Program" },
    { 0x00060978, "Registry Program" },
    { 0x00060979, "Notify Program" },
    { 0x0006097a, "Resource Manager Program" },
    { 0x0006097b, "Programmatic Delivery Program" },
    { 0,          NULL }
};

static const value_string spx_ndps_print_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Bind PSM" },
    { 0x00000002, "Bind PA" },
    { 0x00000003, "Unbind" },
    { 0x00000004, "Print" },
    { 0x00000005, "Modify Job" },
    { 0x00000006, "Cancel Job" },
    { 0x00000007, "List Object Attributes" },
    { 0x00000008, "Promote Job" },
    { 0x00000009, "Interrupt" },
    { 0x0000000a, "Pause" },
    { 0x0000000b, "Resume" },
    { 0x0000000c, "Clean" },
    { 0x0000000d, "Create" },
    { 0x0000000e, "Delete" },
    { 0x0000000f, "Disable PA" },
    { 0x00000010, "Enable PA" },
    { 0x00000011, "Resubmit Jobs" },
    { 0x00000012, "Set" },
    { 0x00000013, "Shutdown PA" },
    { 0x00000014, "Startup PA" },
    { 0x00000015, "Reorder Job" },
    { 0x00000016, "Pause PA" },
    { 0x00000017, "Resume PA" },
    { 0x00000018, "Transfer Data" },
    { 0x00000019, "Device Control" },
    { 0x0000001a, "Add Event Profile" },
    { 0x0000001b, "Remove Event Profile" },
    { 0x0000001c, "Modify Event Profile" },
    { 0x0000001d, "List Event Profiles" },
    { 0x0000001e, "Shutdown PSM" },
    { 0x0000001f, "Cancel PSM Shutdown" },
    { 0x00000020, "Set Printer DS Information" },
    { 0x00000021, "Clean User Jobs" },
    { 0x00000022, "Map GUID to NDS Name" },
    { 0x00000023, "Add Event Profile 2" },
    { 0x00000024, "List Event Profile 2" },
    { 0,          NULL }
};

static const value_string spx_ndps_notify_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Notify Bind" },
    { 0x00000002, "Notify Unbind" },
    { 0x00000003, "Register Supplier" },
    { 0x00000004, "Deregister Supplier" },
    { 0x00000005, "Add Profile" },
    { 0x00000006, "Remove Profile" },
    { 0x00000007, "Modify Profile" },
    { 0x00000008, "List Profiles" },
    { 0x00000009, "Report Event" },
    { 0x0000000a, "List Supported Languages" },
    { 0x0000000b, "Report Notification" },
    { 0x0000000c, "Add Delivery Method" },
    { 0x0000000d, "Remove Delivery Method" },
    { 0x0000000e, "List Delivery Methods" },
    { 0x0000000f, "Get Delivery Method Information" },
    { 0x00000010, "Get Notify NDS Object Name" },
    { 0x00000011, "Get Notify Session Information" },
    { 0,          NULL }
};

static const value_string spx_ndps_deliver_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Delivery Bind" },
    { 0x00000002, "Delivery Unbind" },
    { 0x00000003, "Delivery Send" },
    { 0x00000004, "Delivery Send2" },
    { 0,          NULL }
};

static const value_string spx_ndps_registry_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "Register Server" },
    { 0x00000004, "Deregister Server" },
    { 0x00000005, "Register Registry" },
    { 0x00000006, "Deregister Registry" },
    { 0x00000007, "Registry Update" },
    { 0x00000008, "List Local Servers" },
    { 0x00000009, "List Servers" },
    { 0x0000000a, "List Known Registries" },
    { 0x0000000b, "Get Registry NDS Object Name" },
    { 0x0000000c, "Get Registry Session Information" },
    { 0,          NULL }
};

static const value_string spx_ndps_resman_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "Add Resource File" },
    { 0x00000004, "Delete Resource File" },
    { 0x00000005, "List Resources" },
    { 0x00000006, "Get Resource File" },
    { 0x00000007, "Get Resource File Date" },
    { 0x00000008, "Get Resource Manager NDS Object Name" },
    { 0x00000009, "Get Resource Manager Session Information" },
    { 0x0000000a, "Set Resource Language Context" },
    { 0,          NULL }
};

static const value_string spx_ndps_broker_func_vals[] = {
    { 0x00000000, "None" },
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "List Services" },
    { 0x00000004, "Enable Service" },
    { 0x00000005, "Disable Service" },
    { 0x00000006, "Down Broker" },
    { 0x00000007, "Get Broker NDS Object Name" },
    { 0x00000008, "Get Broker Session Information" },
    { 0,          NULL }
};

static const value_string ndps_packet_types[] = {
    { 0x00000000, "Request" },
    { 0x00000001, "Reply" },
    { 0,          NULL }
};

static const value_string ndps_realization_enum[] = {
    { 0x00000000, "Logical" },
    { 0x00000001, "Physical" },
    { 0x00000002, "Logical & Physical" },
    { 0,          NULL }
};

static const value_string ndps_dim_value_enum[] = {
    { 0x00000000, "Numeric" },
    { 0x00000001, "Named" },
    { 0,          NULL }
};

static const value_string ndps_xydim_value_enum[] = {
    { 0x00000000, "Real" },
    { 0x00000001, "Named" },
    { 0x00000002, "Cardinal" },
    { 0,          NULL }
};

static const value_string ndps_location_value_enum[] = {
    { 0x00000000, "Numeric" },
    { 0x00000001, "Named" },
    { 0,          NULL }
};

static const value_string ndps_edge_value_enum[] = {
    { 0x00000000, "Bottom" },
    { 0x00000001, "Right" },
    { 0x00000002, "Top" },
    { 0x00000003, "Left" },
    { 0,          NULL }
};

static const value_string ndps_card_or_oid_enum[] = {
    { 0x00000000, "Number" },
    { 0x00000001, "ID" },
    { 0,          NULL }
};

static const value_string ndps_card_name_or_oid_enum[] = {
    { 0x00000000, "Number" },
    { 0x00000001, "ID" },
    { 0,          NULL }
};

static const value_string ndps_integer_or_oid_enum[] = {
    { 0x00000000, "ID" },
    { 0x00000001, "Number" },
    { 0,          NULL }
};

static const value_string ndps_persistence_enum[] = {
    { 0x00000000, "Permanent" },
    { 0x00000001, "Volatile" },
    { 0,          NULL }
};

static const value_string ndps_address_type_enum[] = {
    { 0x00000000, "User" },
    { 0x00000001, "Server" },
    { 0x00000002, "Volume" },
    { 0x00000003, "Organization Unit" },
    { 0x00000004, "Organization" },
    { 0x00000005, "Group" },
    { 0x00000006, "Distinguished Name" },
    { 0x00000007, "User or Container" },
    { 0x00000008, "Case Exact String" },
    { 0x00000009, "Case Ignore String" },
    { 0x0000000a, "Numeric String" },
    { 0x0000000b, "DOS File Name" },
    { 0x0000000c, "Phone Number" },
    { 0x0000000d, "Boolean" },
    { 0x0000000e, "Integer" },
    { 0x0000000f, "Network Address" },
    { 0x00000010, "Choice" },
    { 0x00000011, "GroupWise User" },
    { 0,          NULL }
};

static const value_string ndps_address_enum[] = {
    { 0x00000000, "IPX" },
    { 0x00000001, "IP" },
    { 0x00000002, "SDLC" },
    { 0x00000003, "Token Ring to Ethernet" },
    { 0x00000004, "OSI" },
    { 0x00000005, "AppleTalk" },
    { 0x00000006, "Count" },
    { 0,          NULL }
};


static const value_string ndps_server_type_enum[] = {
    { 0x00000000, "All" },
    { 0x00000001, "Public Access Printer Agent" },
    { 0x00000002, "Notification Server" },
    { 0x00000003, "Resource Manager" },
    { 0x00000004, "Network Port Handler" },
    { 0,          NULL }
};

static const value_string ndps_event_object_enum[] = {
    { 0x00000000, "Object" },
    { 0x00000001, "Filter" },
    { 0x00000002, "Detail" },
    { 0,          NULL }
};

static const value_string ndps_service_type_enum[] = {
    { 0x00000000, "SRS" },
    { 0x00000001, "ENS" },
    { 0x00000002, "RMS" },
    { 0,          NULL }
};

static const value_string ndps_delivery_add_enum[] = {
    { 0x00000000, "MHS Address" },
    { 0x00000001, "Distinguished Name" },
    { 0x00000002, "Text" },
    { 0x00000003, "Octet String" },
    { 0x00000004, "Distinguished Name String" },
    { 0x00000005, "RPC Address" },
    { 0x00000006, "Qualified Name" },
    { 0,          NULL }
};

static const value_string ndps_resource_enum[] = {
    { 0x00000000, "Name or ID" },
    { 0x00000001, "Text" },
    { 0,          NULL }
};


static const value_string ndps_identifier_enum[] = {
    { 0x00000000, "ID Nominal Number" },
    { 0x00000001, "ID Alpha-numeric" },
    { 0x00000002, "ID Tag" },
    { 0,          NULL }
};

static const value_string ndps_media_enum[] = {
    { 0x00000000, "Select All Pages" },
    { 0x00000001, "Selected Pages" },
    { 0,          NULL }
};

static const value_string ndps_page_size_enum[] = {
    { 0x00000000, "ID" },
    { 0x00000001, "Dimensions" },
    { 0,          NULL }
};

static const value_string ndps_pres_direction_enum[] = {
    { 0x00000000, "Right to Bottom" },
    { 0x00000001, "Left to Bottom" },
    { 0x00000002, "Bidirectional to Bottom" },
    { 0x00000003, "Right to Top" },
    { 0x00000004, "Left to Top" },
    { 0x00000005, "Bidirectional to Top" },
    { 0x00000006, "Bottom to Right" },
    { 0x00000007, "Bottom to Left" },
    { 0x00000008, "Top to Left" },
    { 0x00000009, "Top to Right" },
    { 0,          NULL }
};

static const value_string ndps_page_order_enum[] = {
    { 0x00000000, "Unknown" },
    { 0x00000001, "First to Last" },
    { 0x00000002, "Last to First" },
    { 0,          NULL }
};

static const value_string ndps_medium_size_enum[] = {
    { 0x00000000, "Discrete" },
    { 0x00000001, "Continuous" },
    { 0,          NULL }
};

static const value_string ndps_page_orientation_enum[] = {
    { 0x00000000, "Unknown" },
    { 0x00000001, "Face Up" },
    { 0x00000002, "Face Down" },
    { 0,          NULL }
};

static const value_string ndps_print_security[] = {
    { 0x00000001, "Low" },
    { 0x00000002, "Medium" },
    { 0x00000003, "High" },
    { 0,          NULL }
};

static const value_string ndps_numbers_up_enum[] = {
    { 0x00000000, "Cardinal" },
    { 0x00000001, "Name or Object ID" },
    { 0x00000002, "Cardinal Range" },
    { 0,          NULL }
};


static const value_string ndps_state_severity_enum[] = {
    { 0x00000001, "Other" },
    { 0x00000002, "Warning" },
    { 0x00000003, "Critical" },
    { 0,          NULL }
};


static const value_string ndps_training_enum[] = {
    { 0x00000001, "Other" },
    { 0x00000002, "Unknown" },
    { 0x00000003, "Untrained" },
    { 0x00000004, "Trained" },
    { 0x00000005, "Field Service" },
    { 0x00000006, "Management" },
    { 0,          NULL }
};

static const value_string ndps_colorant_set_enum[] = {
    { 0x00000000, "Name" },
    { 0x00000001, "Description" },
    { 0,          NULL }
};

static const value_string ndps_card_enum_time_enum[] = {
    { 0x00000000, "Cardinal" },
    { 0x00000001, "Enumeration" },
    { 0x00000002, "Time" },
    { 0,          NULL }
};

static const value_string ndps_attrs_arg_enum[] = {
    { 0x00000000, "Continuation" },
    { 0x00000001, "Specification" },
    { 0,          NULL }
};


static const value_string ndps_filter_enum[] = {
    { 0x00000000, "Item" },
    { 0x00000001, "And" },
    { 0x00000002, "Or" },
    { 0x00000003, "Not" },
    { 0,          NULL }
};


static const value_string ndps_filter_item_enum[] = {
    { 0x00000000, "Equality" },
    { 0x00000001, "Substrings" },
    { 0x00000002, "Greater then or Equal to" },
    { 0x00000003, "Less then or Equal to" },
    { 0x00000004, "Present" },
    { 0x00000005, "Subset of" },
    { 0x00000006, "Superset of" },
    { 0x00000007, "Non NULL Set Intersect" },
    { 0,          NULL }
};

static const value_string ndps_match_criteria_enum[] = {
    { 0x00000000, "Exact" },
    { 0x00000001, "Case Insensitive" },
    { 0x00000002, "Same Letter" },
    { 0x00000003, "Approximate" },
    { 0,          NULL }
};

static const value_string ndps_operator_enum[] = {
    { 0x00000000, "Attributes" },
    { 0x00000002, "Ordered Jobs" },
    { 0,          NULL }
};

static const value_string ndps_resource_type_enum[] = {
    { 0x00000000, "Printer Drivers" },
    { 0x00000001, "Printer Definitions" },
    { 0x00000002, "Printer Definitions Short" },
    { 0x00000003, "Banner Page Files" },
    { 0x00000004, "Font Types" },
    { 0x00000005, "Printer Driver Files" },
    { 0x00000006, "Printer Definition File" },
    { 0x00000007, "Font Files" },
    { 0x00000008, "Generic Type" },
    { 0x00000009, "Generic Files" },
    { 0x0000000a, "Printer Definition File 2" },
    { 0x0000000b, "Printer Driver Types 2" },
    { 0x0000000c, "Printer Driver Files 2" },
    { 0x0000000d, "Printer Driver Types Archive" },
    { 0x0000000e, "Languages Available" },
    { 0,          NULL }
};

static const value_string ndps_os_type_enum[] = {
    { 0x00000000, "DOS" },
    { 0x00000001, "Windows 3.1" },
    { 0x00000002, "Windows 95" },
    { 0x00000003, "Windows NT" },
    { 0x00000004, "OS2" },
    { 0x00000005, "MAC" },
    { 0x00000006, "UNIX" },
    { 0x00000007, "Windows NT 4.0" },
    { 0x00000008, "Windows 2000/XP" },
    { 0x00000009, "Windows 98" },
    { 0xffffffff, "None" },
    { 0,          NULL }
};

static const value_string ndps_banner_type_enum[] = {
    { 0x00000000, "All" },
    { 0x00000001, "PCL" },
    { 0x00000002, "PostScript" },
    { 0x00000003, "ASCII Text" },
    { 0,          NULL }
};

static const value_string ndps_font_type_enum[] = {
    { 0x00000000, "TrueType" },
    { 0x00000001, "PostScript" },
    { 0x00000002, "System" },
    { 0x00000003, "SPD" },
    { 0x00000004, "True Doc" },
    { 0,          NULL }
};

static const value_string ndps_archive_enum[] = {
    { 0x00000000, "ZIP" },
    { 0x00000001, "JAR" },
    { 0,          NULL }
};


static const value_string ndps_res_type_enum[] = {
    { 0x00000000, "Printer Driver" },
    { 0x00000001, "Printer Definition" },
    { 0x00000002, "Banner Page" },
    { 0x00000003, "Font" },
    { 0x00000004, "Generic Resource" },
    { 0x00000005, "Print Driver Archive" },
    { 0,          NULL }
};

static const value_string ndps_print_arg_enum[] = {
    { 0x00000000, "Create Job" },
    { 0x00000001, "Add Document" },
    { 0x00000002, "Close Job" },
    { 0,          NULL }
};

static const value_string ndps_doc_content_enum[] = {
    { 0x00000000, "Content Included" },
    { 0x00000001, "Content Referenced" },
    { 0,          NULL }
};

static const value_string ndps_interrupt_job_enum[] = {
    { 0x00000000, "Job ID" },
    { 0x00000001, "Name" },
    { 0,          NULL }
};

static const value_string ndps_pause_job_enum[] = {
    { 0x00000000, "Job ID" },
    { 0x00000001, "Name" },
    { 0,          NULL }
};

static const value_string ndps_resubmit_op_enum[] = {
    { 0x00000000, "Copy" },
    { 0x00000001, "Move" },
    { 0,          NULL }
};

static const value_string ndps_shutdown_enum[] = {
    { 0x00000000, "Do Current Jobs" },
    { 0x00000001, "Immediate" },
    { 0x00000002, "Do Pending Jobs" },
    { 0,          NULL }
};

static const value_string ndps_list_profiles_choice_enum[] = {
    { 0x00000000, "ID" },
    { 0x00000001, "Filter" },
    { 0,          NULL }
};

static const value_string ndps_list_profiles_result_enum[] = {
    { 0x00000000, "Complete" },
    { 0x00000001, "No Event Objects" },
    { 0x00000002, "Profile ID's" },
    { 0,          NULL }
};

static const value_string ndps_ds_info_enum[] = {
    { 0x00000000, "Add" },
    { 0x00000001, "Remove" },
    { 0x00000002, "Update" },
    { 0,          NULL }
};

static const value_string ndps_list_services_enum[] = {
    { 0x00000000, "Supported" },
    { 0x00000001, "Enabled" },
    { 0,          NULL }
};

static const value_string ndps_data_item_enum[] = {
    { 0x00000000, "Int8" },
    { 0x00000001, "Int16" },
    { 0x00000002, "Int32" },
    { 0x00000003, "Boolean" },
    { 0x00000004, "Character String" },
    { 0x00000005, "Byte String" },
    { 0,          NULL }
};

static const value_string ndps_list_local_servers_enum[] = {
    { 0x00000000, "Specification" },
    { 0x00000001, "Continuation" },
    { 0,          NULL }
};

static const value_string ndps_delivery_method_enum[] = {
    { 0x00000000, "Specification" },
    { 0x00000001, "Continuation" },
    { 0,          NULL }
};

static const value_string ndps_attribute_enum[] = {
    { 0x00000000, "Null" },
    { 0x00000001, "Text" },
    { 0x00000002, "Descriptive Name" },
    { 0x00000003, "Descriptor" },
    { 0x00000004, "Message" },
    { 0x00000005, "Error Message" },
    { 0x00000006, "Simple Name" },
    { 0x00000007, "Distinguished Name String" },
    { 0x00000008, "Distinguished Name Seq" },
    { 0x00000009, "Delta Time" },
    { 0x0000000a, "Time" },
    { 0x0000000b, "Integer" },
    { 0x0000000c, "Integer Seq" },
    { 0x0000000d, "Cardinal" },
    { 0x0000000e, "Cardinal Seq" },
    { 0x0000000f, "Positive Integer" },
    { 0x00000010, "Integer Range" },
    { 0x00000011, "Cardinal Range" },
    { 0x00000012, "Maximum Integer" },
    { 0x00000013, "Minimum Integer" },
    { 0x00000014, "Integer 64" },
    { 0x00000015, "Integer 64 Seq" },
    { 0x00000016, "Cardinal 64" },
    { 0x00000017, "Cardinal 64 Seq" },
    { 0x00000018, "Positive Integer 64" },
    { 0x00000019, "Integer 64 Range" },
    { 0x0000001a, "Cardinal 64 Range" },
    { 0x0000001b, "Maximum Integer 64" },
    { 0x0000001c, "Minimum Integer 64" },
    { 0x0000001d, "Real" },
    { 0x0000001e, "Real Seq" },
    { 0x0000001f, "Non-Negative Real" },
    { 0x00000020, "Real Range" },
    { 0x00000021, "Non-Negative Real Range" },
    { 0x00000022, "Boolean" },
    { 0x00000023, "Percent" },
    { 0x00000024, "Object Identifier" },
    { 0x00000025, "Object Identifier Seq" },
    { 0x00000026, "Name or OID" },
    { 0x00000027, "Name or OID Seq" },
    { 0x00000028, "Distinguished Name" },
    { 0x00000029, "Relative Distinguished Name Seq" },
    { 0x0000002a, "Realization" },
    { 0x0000002b, "Medium Dimensions" },
    { 0x0000002c, "Dimension" },
    { 0x0000002d, "XY Dimensions" },
    { 0x0000002e, "Locations" },
    { 0x0000002f, "Area" },
    { 0x00000030, "Area Seq" },
    { 0x00000031, "Edge" },
    { 0x00000032, "Font Reference" },
    { 0x00000033, "Cardinal or OID" },
    { 0x00000034, "OID Cardinal Map" },
    { 0x00000035, "Cardinal or Name or OID" },
    { 0x00000036, "Positive Integer or OID" },
    { 0x00000037, "Event Handling Profile" },
    { 0x00000038, "Octet String" },
    { 0x00000039, "Priority" },
    { 0x0000003a, "Locale" },
    { 0x0000003b, "Method Delivery Address" },
    { 0x0000003c, "Object Identification" },
    { 0x0000003d, "Results Profile" },
    { 0x0000003e, "Criteria" },
    { 0x0000003f, "Job Password" },
    { 0x00000040, "Job Level" },
    { 0x00000041, "Job Categories" },
    { 0x00000042, "Print Checkpoint" },
    { 0x00000043, "Ignored Attribute" },
    { 0x00000044, "Resource" },
    { 0x00000045, "Medium Substitution" },
    { 0x00000046, "Font Substitution" },
    { 0x00000047, "Resource Context Seq" },
    { 0x00000048, "Sides" },
    { 0x00000049, "Page Select Seq" },
    { 0x0000004a, "Page Media Select" },
    { 0x0000004b, "Document Content" },
    { 0x0000004c, "Page Size" },
    { 0x0000004d, "Presentation Direction" },
    { 0x0000004e, "Page Order" },
    { 0x0000004f, "File Reference" },
    { 0x00000050, "Medium Source Size" },
    { 0x00000051, "Input Tray Medium" },
    { 0x00000052, "Output Bins Chars" },
    { 0x00000053, "Page ID Type" },
    { 0x00000054, "Level Range" },
    { 0x00000055, "Category Set" },
    { 0x00000056, "Numbers Up Supported" },
    { 0x00000057, "Finishing" },
    { 0x00000058, "Print Contained Object ID" },
    { 0x00000059, "Print Config Object ID" },
    { 0x0000005a, "Typed Name" },
    { 0x0000005b, "Network Address" },
    { 0x0000005c, "XY Dimensions Value" },
    { 0x0000005d, "Name or OID Dimensions Map" },
    { 0x0000005e, "Printer State Reason" },
    { 0x0000005f, "Enumeration" },
    { 0x00000060, "Qualified Name" },
    { 0x00000061, "Qualified Name Set" },
    { 0x00000062, "Colorant Set" },
    { 0x00000063, "Resource Printer ID" },
    { 0x00000064, "Event Object ID" },
    { 0x00000065, "Qualified Name Map" },
    { 0x00000066, "File Path" },
    { 0x00000067, "Uniform Resource Identifier" },
    { 0x00000068, "Cardinal or Enum or Time" },
    { 0x00000069, "Print Contained Object ID Set" },
    { 0x0000006a, "Octet String Pair" },
    { 0x0000006b, "Octet String Integer Pair" },
    { 0x0000006c, "Extended Resource Identifier" },
    { 0x0000006d, "Event Handling Profile 2" },
    { 0,          NULL }
};

static const value_string ndps_error_types[] = {
    { 0x00000000, "Ok" },
    { 0x00000001, "Error" },
    { 0x01000001, "Invalid Parameter" },
    { 0x01000002, "Parameter Value Unrecognized" },
    { 0x01000003, "Call Back Error" },
    { 0x01000004, "Standard IO Error" },
    { 0x01000005, "NDS Error" },
    { 0x01000006, "Unicode Error" },
    { 0x01000007, "Invalid Operator" },
    { 0x01000009, "Parameter Value Unsupported" },
    { 0x0100000a, "Windows Error" },
    { 0x0100000b, "WSA Last Error" },
    { 0x0100000c, "SLP Error" },
    { 0x0100000d, "NetWare Client Error" },
    { 0x03000005, "NDS Error with Position" },
    { 0x030a0001, "No Memory" },
    { 0x030a0009, "Artificial Memory Limit" },
    { 0x030a000c, "Memory Allocated with Wrong NLM ID" },
    { 0xFFFFFC18, "Broker Out of Memory" },      /* Broker Errors */
    { 0xFFFFFC17, "Broker Bad NetWare Version" },
    { 0xFFFFFC16, "Broker Wrong Command Line Arguments" },
    { 0xFFFFFC15, "Broker Name Not Given" },
    { 0xFFFFFC14, "Not Broker Class" },
    { 0xFFFFFC13, "Invalid Broker Password" },
    { 0xFFFFFC12, "Invalid Broker Name" },
    { 0xFFFFFC11, "Broker Failed to Create Thread" },
    { 0xFFFFFC10, "Broker Failed to Initialize NUT" },
    { 0xFFFFFC0F, "Broker Failed to Get Messages" },
    { 0xFFFFFC0E, "Broker Failed to Allocate Resources" },
    { 0xFFFFFC0D, "Broker Service Name Must be Fully Distinguished" },
    { 0xFFFFFC0C, "Broker Uninitialized Module" },
    { 0xFFFFFC0B, "Broker DS Value Size Too Large" },
    { 0xFFFFFC0A, "Broker No Attribute Values" },
    { 0xFFFFFC09, "Broker Unknown Session" },
    { 0xFFFFFC08, "Broker Service Disabled" },
    { 0xFFFFFC07, "Broker Unknown Modify Operation" },
    { 0xFFFFFC06, "Broker Invalid Arguments" },
    { 0xFFFFFC05, "Broker Duplicate Session ID" },
    { 0xFFFFFC04, "Broker Unknown Service" },
    { 0xFFFFFC03, "Broker Service Already Enabled" },
    { 0xFFFFFC02, "Broker Service Already Disabled" },
    { 0xFFFFFC01, "Broker Invalid Credential" },
    { 0xFFFFFC00, "Broker Unknown Designator" },
    { 0xFFFFFBFF, "Broker Failed to Make Change Permanent" },
    { 0xFFFFFBFE, "Broker Not Admin Type Session" },
    { 0xFFFFFBFD, "Broker Option Not Supported" },
    { 0xFFFFFBFC, "Broker No Effective Rights" },
    { 0xFFFFFBFB, "Broker Could Not Find File" },
    { 0xFFFFFBFA, "Broker Error Reading File" },
    { 0xFFFFFBF9, "Broker Not NLM File Format" },
    { 0xFFFFFBF8, "Broker Wrong NLM File Version" },
    { 0xFFFFFBF7, "Broker Reentrant Initialization Failure" },
    { 0xFFFFFBF6, "Broker Already in Progress" },
    { 0xFFFFFBF5, "Broker Initialize Failure" },
    { 0xFFFFFBF4, "Broker Inconsistent File Format" },
    { 0xFFFFFBF3, "Broker Can't Load at Startup" },
    { 0xFFFFFBF2, "Broker Autoload Modules Not Loaded" },
    { 0xFFFFFBF1, "Broker Unresolved External" },
    { 0xFFFFFBF0, "Broker Public Already Defined" },
    { 0xFFFFFBEF, "Broker Other Broker Using Object" },
    { 0xFFFFFBEE, "Broker Service Failed to Initialize" },
    { 0xFFFFFBB4, "Registry Out of Memory" },       /* SRS Errors */
    { 0xFFFFFBB3, "Registry Bad NetWare Version" },
    { 0xFFFFFBB2, "Registry Failed to Create Context" },
    { 0xFFFFFBB1, "Registry Failed Login" },
    { 0xFFFFFBB0, "Registry Failed to Create Thread" },
    { 0xFFFFFBAF, "Registry Failed to Get Messages" },
    { 0xFFFFFBAE, "Registry Service Name Must Be Fully Distinguished" },
    { 0xFFFFFBAD, "Registry DS Value Size Too Large" },
    { 0xFFFFFBAC, "Registry No Attribute Values" },
    { 0xFFFFFBAB, "Registry Unknown Session" },
    { 0xFFFFFBAA, "Registry Service Disabled" },
    { 0xFFFFFBA9, "Registry Unknown Modify Operation" },
    { 0xFFFFFBA8, "Registry Can't Start Advertise" },
    { 0xFFFFFBA7, "Registry Duplicate Server Entry" },
    { 0xFFFFFBA6, "Registry Can't Bind to Registry" },
    { 0xFFFFFBA5, "Registry Can't Create Client" },
    { 0xFFFFFBA4, "Registry Invalid Arguments" },
    { 0xFFFFFBA3, "Registry Duplicate Session ID" },
    { 0xFFFFFBA2, "Registry Unknown Server Entry" },
    { 0xFFFFFBA1, "Registry Invalid Credential" },
    { 0xFFFFFBA0, "Registry Type Session" },
    { 0xFFFFFB9F, "Registry Server Type Session" },
    { 0xFFFFFB9E, "Registry Not Server Type Session" },
    { 0xFFFFFB9D, "Not Registry Type Session" },
    { 0xFFFFFB9C, "Registry Unknown Designator" },
    { 0xFFFFFB9B, "Registry Option Not Supported" },
    { 0xFFFFFB9A, "Registry Not in List Iteration" },
    { 0xFFFFFB99, "Registry Invalid Continuation Handle" },
    { 0xFFFFFB50, "Notify Out of Memory" },        /* Notification Service Errors */
    { 0xFFFFFB4F, "Notify Bad NetWare Version" },
    { 0xFFFFFB4E, "Notify Failed to Create Thread" },
    { 0xFFFFFB4D, "Notify Failed to Get Messages" },
    { 0xFFFFFB4C, "Notify Failed to Create Context" },
    { 0xFFFFFB4B, "Notify Failed Login" },
    { 0xFFFFFB4A, "Notify Service Name Must be Fully Distiguished" },
    { 0xFFFFFB49, "Notify DS Value Size Too Large" },
    { 0xFFFFFB48, "Notify No Attribute Values" },
    { 0xFFFFFB47, "Notify Unknown Session" },
    { 0xFFFFFB46, "Notify Unknown Notify Profile" },
    { 0xFFFFFB45, "Notify Error Reading File" },
    { 0xFFFFFB44, "Notify Error Writing File" },
    { 0xFFFFFB43, "Wrong Notify Database Version" },
    { 0xFFFFFB42, "Corrupted Notify Database" },
    { 0xFFFFFB41, "Notify Unknown Event Object ID" },
    { 0xFFFFFB40, "Notify Method Already Installed" },
    { 0xFFFFFB3F, "Notify Unknown Method" },
    { 0xFFFFFB3E, "Notify Service Disabled" },
    { 0xFFFFFB3D, "Notify Unknown Modify Operation" },
    { 0xFFFFFB3C, "Out of Notify Entries" },
    { 0xFFFFFB3B, "Notify Unknown Language ID" },
    { 0xFFFFFB3A, "Notify Queue Empty" },
    { 0xFFFFFB39, "Notify Can't Load Delivery Method" },
    { 0xFFFFFB38, "Notify Invalid Arguments" },
    { 0xFFFFFB37, "Notify Duplicate Session ID" },
    { 0xFFFFFB36, "Notify Invalid Credentials" },
    { 0xFFFFFB35, "Notify Unknown Choice" },
    { 0xFFFFFB34, "Notify Unknown Attribute Value" },
    { 0xFFFFFB33, "Notify Error Writing Database" },
    { 0xFFFFFB32, "Notify Unknown Object ID" },
    { 0xFFFFFB31, "Notify Unknown Designator" },
    { 0xFFFFFB30, "Notify Failed to Make Change Permanent" },
    { 0xFFFFFB2F, "Notify User Interface Not Supported" },
    { 0xFFFFFB2E, "Notify Not Supplied Type of Session" },
    { 0xFFFFFB2D, "Notify Not Admin Type Session" },
    { 0xFFFFFB2C, "Notify No Service Registry Available" },
    { 0xFFFFFB2B, "Notify Failed to Register With Any Server" },
    { 0xFFFFFB2A, "Notify Empty Event Object Set" },
    { 0xFFFFFB29, "Notify Unknown Notify Handle" },
    { 0xFFFFFB28, "Notify Option Not Supported" },
    { 0xFFFFFB27, "Notify Unknown RPC Session" },
    { 0xFFFFFB26, "Notify Initialization Error" },
    { 0xFFFFFB25, "Notify No Effective Rights" },
    { 0xFFFFFB24, "Notify No Persistent Storage" },
    { 0xFFFFFB23, "Notify Bad Method Filename" },
    { 0xFFFFFB22, "Notify Unknown Continuation Handle" },
    { 0xFFFFFB21, "Notify Invalid Continuation Handle" },
    { 0xFFFFFB20, "Notify Could Not Find File" },
    { 0xFFFFFB1F, "Notify Error Reading File" },
    { 0xFFFFFB1E, "Notify Not NLM File Format" },
    { 0xFFFFFB1D, "Notify Wrong NLM File Version" },
    { 0xFFFFFB1C, "Notify Reentrant Initialization Failure" },
    { 0xFFFFFB1B, "Notify Already in Progress" },
    { 0xFFFFFB1A, "Notify Initialization Failure" },
    { 0xFFFFFB19, "Notify Inconsistent File Format" },
    { 0xFFFFFB18, "Notify Can't Load at Startup" },
    { 0xFFFFFB17, "Notify Autoload Modules Not Loaded" },
    { 0xFFFFFB16, "Notify Unresolved External" },
    { 0xFFFFFB15, "Notify Public Already Defined" },
    { 0xFFFFFB14, "Notify Using Unknown Methods" },
    { 0xFFFFFB13, "Notify Service Not Fully Enabled" },
    { 0xFFFFFB12, "Notify Foreign NDS Tree Name" },
    { 0xFFFFFB11, "Notify Delivery Method Rejected Address" },
    { 0xFFFFFB10, "Notify Unsupported Delivery Address Type" },
    { 0xFFFFFB0F, "Notify User Object No Default Server" },
    { 0xFFFFFB0E, "Notify Failed to Send Notification" },
    { 0xFFFFFB0D, "Notify Bad Volume in Address" },
    { 0xFFFFFB0C, "Notify Broker Has No File Rights" },
    { 0xFFFFFB0B, "Notify Maximum Methods Supported" },
    { 0xFFFFFB0A, "Notify No Filter Provided" },
    { 0xFFFFFB09, "Notify IPX Not Supported By Method" },
    { 0xFFFFFB08, "Notify IP Not Supported By Method" },
    { 0xFFFFFB07, "Notify Failed to Startup Winsock" },
    { 0xFFFFFB06, "Notify No Protocols Available" },
    { 0xFFFFFB05, "Notify Failed to Launch RPC Server" },
    { 0xFFFFFB04, "Notify Invalid SLP Attribute Format" },
    { 0xFFFFFB03, "Notify Invalid SLP URL Format" },
    { 0xFFFFFB02, "Notify Unknown Attribute Object ID" },
    { 0xFFFFFB01, "Notify Duplicate Session ID" },
    { 0xFFFFFB00, "Notify Failed to Authenticate" },
    { 0xFFFFFAFF, "Notify Failed to Authenticate Protocol Mismatch" },
    { 0xFFFFFAFE, "Notify Failed to Authenticate Internal Error" },
    { 0xFFFFFAFD, "Notify Failed to Authenticate Connection Error" },
    { 0xFFFFFC7C, "Resource Manager Out of Memory" },  /* ResMan Errors */
    { 0xFFFFFC7B, "Resource Manager Bad NetWare Version" },
    { 0xFFFFFC7A, "Resource Manager Wrong Command Line Arguments" },
    { 0xFFFFFC79, "Resource Manager Broker Name Not Given" },
    { 0xFFFFFC78, "Resource Manager Invalid Broker Password" },
    { 0xFFFFFC77, "Resource Manager Invalid Broker Name" },
    { 0xFFFFFC76, "Resource Manager Failed to Create Thread" },
    { 0xFFFFFC75, "Resource Manager Service Name Must be Fully Distinguished" },
    { 0xFFFFFC74, "Resource Manager DS Value Size Too Large" },
    { 0xFFFFFC73, "Resource Manager No Attribute Values" },
    { 0xFFFFFC72, "Resource Manager Unknown Session" },
    { 0xFFFFFC71, "Resource Manager Error Reading File" },
    { 0xFFFFFC70, "Resource Manager Error Writing File" },
    { 0xFFFFFC6F, "Resource Manager Service Disabled" },
    { 0xFFFFFC6E, "Resource Manager Unknown Modify Operation" },
    { 0xFFFFFC6D, "Resource Manager Duplicate Session ID" },
    { 0xFFFFFC6C, "Resource Manager Invalid Credentials" },
    { 0xFFFFFC6B, "Resource Manager No Service Registry Available" },
    { 0xFFFFFC6A, "Resource Manager Failed to Register With any Server" },
    { 0xFFFFFC69, "Resource Manager Failed to Get Messages" },
    { 0xFFFFFC68, "Resource Manager Failed to Create Context" },
    { 0xFFFFFC67, "Resource Manager Failed to Login" },
    { 0xFFFFFC66, "Resource Manager NPD Files Generation Error" },
    { 0xFFFFFC65, "Resource Manager INF File Format Error" },
    { 0xFFFFFC64, "Resource Manager No Printer Type in INF File" },
    { 0xFFFFFC63, "Resource Manager No INF Files Present" },
    { 0xFFFFFC62, "Resource Manager File Open Error" },
    { 0xFFFFFC61, "Resource Manager Read File Error" },
    { 0xFFFFFC60, "Resource Manager Write File Error" },
    { 0xFFFFFC5F, "Resource Manager Resource Type Invalid" },
    { 0xFFFFFC5E, "Resource Manager No Such Filename" },
    { 0xFFFFFC5D, "Resource Manager Banner Type Invalid" },
    { 0xFFFFFC5C, "Resource Manager List Type Unknown" },
    { 0xFFFFFC5B, "Resource Manager OS Not Supported" },
    { 0xFFFFFC5A, "Resource Manager No Banner Files Present" },
    { 0xFFFFFC59, "Resource Manager Printer Definition Type Unknown" },
    { 0xFFFFFC58, "Resource Manager No Printer Types in List" },
    { 0xFFFFFC57, "Resource Manager Option Not Supported" },
    { 0xFFFFFC56, "Resource Manager Unicode Convention Error" },
    { 0xFFFFFC55, "Resource Manager Invalid Arguments" },
    { 0xFFFFFC54, "Resource Manager Initialization Error" },
    { 0xFFFFFC53, "Resource Manager No Service Registry Available" },
    { 0xFFFFFC52, "Resource Manager Failed to Register to Any Server" },
    { 0xFFFFFC51, "Resource Manager Unknown Designator" },
    { 0xFFFFFC50, "Resource Manager Not Admin Session" },
    { 0xFFFFFC4F, "Resource Manager No Effective Rights" },
    { 0xFFFFFC4E, "Resource Manager Bad File Attribute" },
    { 0xFFFFFC4D, "Resource Manager Document ID Format Error" },
    { 0xFFFFFC4C, "Resource Manager Unknown RPC Session" },
    { 0xFFFFFC4B, "Resource Manager Session Being Removed" },
    { 0xFFFFFC49, "Resource Manager Font Manager IO Error" },
    { 0xFFFFFC48, "Resource Manager Font Manager Reentrancy" },
    { 0xFFFFFC47, "Resource Manager Font Manager Sequence Error" },
    { 0xFFFFFC46, "Resource Manager Font Manager Corrupt Index File" },
    { 0xFFFFFC45, "Resource Manager Font Manager No Such Font" },
    { 0xFFFFFC44, "Resource Manager Font Manager Not Initialized" },
    { 0xFFFFFC43, "Resource Manager Font Manager System Error" },
    { 0xFFFFFC42, "Resource Manager Font Manager Bad Parameter" },
    { 0xFFFFFC41, "Resource Manager Font Manager Path Too Long" },
    { 0xFFFFFC40, "Resource Manager Font Manager Failure" },
    { 0xFFFFFC3F, "Resource Manager Duplicate TIRPC Session" },
    { 0xFFFFFC3E, "Resource Manager Connection Lost RMS Data" },
    { 0xFFFFFC3D, "Resource Manager Failed to Start Winsock" },
    { 0xFFFFFC3C, "Resource Manager No Protocols Available" },
    { 0xFFFFFC3B, "Resource Manager Failed to Launch RPC Server" },
    { 0xFFFFFC3A, "Resource Manager Invalid SLP Attribute Format" },
    { 0xFFFFFC39, "Resource Manager Invalid SLP URL Format" },
    { 0xFFFFFC38, "Resource Manager Unresolved External" },
    { 0xFFFFFC37, "Resource Manager Failed to Authenticate" },
    { 0xFFFFFC36, "Resource Manager Failed to Authenticate Protocol Mismatch" },
    { 0xFFFFFC35, "Resource Manager Failed to Authenticate Internal Error" },
    { 0xFFFFFC34, "Resource Manager Failed to Authenticate Connection Error" },
    { 0xFFFFFC33, "Resource Manager No Rights to Remote Resdir" },
    { 0xFFFFFC32, "Resource Manager Can't Initialize NDPS Library" },
    { 0xFFFFFC31, "Resource Manager Can't Create Resource Reference" },
    { 0xFFFFFC30, "Resource Manager File is Zero Length" },
    { 0xFFFFFC2F, "Resource Manager Failed to Write INF in Address" },
    { 0xFFFFFCDF, "NDPSM No Memory" },               /* NDPSM Errors */
    { 0xFFFFFCDE, "NDPSM Memory Not Found" },
    { 0xFFFFFCDD, "NDPSM Job Storage Limit" },
    { 0xFFFFFCDC, "NDPSM Job Retention Limit" },
    { 0xFFFFFCDB, "NDPSM Unsupported Type" },
    { 0xFFFFFCDA, "NDPSM Undefined Type" },
    { 0xFFFFFCD9, "NDPSM Unsupported Operation" },
    { 0xFFFFFCD8, "NDPSM Error Accessing Database" },
    { 0xFFFFFCD7, "NDPSM No PDS" },
    { 0xFFFFFCD6, "NDPSM Invalid Class" },
    { 0xFFFFFCD5, "NDPSM Bad Parameter" },
    { 0xFFFFFCD4, "NDPSM Object Not Found" },
    { 0xFFFFFCD3, "NDPSM Attribute Not Found" },
    { 0xFFFFFCD2, "NDPSM Value Not Found" },
    { 0xFFFFFCD1, "NDPSM Values Not Comparable" },
    { 0xFFFFFCD0, "NDPSM Invalid Value Syntax" },
    { 0xFFFFFCCF, "NDPSM Job Not Found" },
    { 0xFFFFFCCE, "NDPSM Communications Error" },
    { 0xFFFFFCCD, "NDPSM Printer Agent Initializing" },
    { 0xFFFFFCCC, "NDPSM Printer Agent Going Down" },
    { 0xFFFFFCCB, "NDPSM Printer Agent Disabled" },
    { 0xFFFFFCCA, "NDPSM Printer Agent Paused" },
    { 0xFFFFFCC9, "NDPSM Bad Printer Agent Handle" },
    { 0xFFFFFCC8, "NDPSM Object Not Locked" },
    { 0xFFFFFCC7, "NDPSM Version Incompatible" },
    { 0xFFFFFCC6, "NDPSM PSM Initializing" },
    { 0xFFFFFCC5, "NDPSM PSM Going Down" },
    { 0xFFFFFCC4, "NDPSM Notification Service Error" },
    { 0xFFFFFCC3, "NDPSM Medium Needs Mounted" },
    { 0xFFFFFCC2, "NDPSM PDS Not Responding" },
    { 0xFFFFFCC1, "NDPSM Session Not Found" },
    { 0xFFFFFCC0, "NDPSM RPC Failure" },
    { 0xFFFFFCBF, "NDPSM Duplicate Value" },
    { 0xFFFFFCBE, "NDPSM PDS Refuses Rename" },
    { 0xFFFFFCBD, "NDPSM No Mandatory Attribute" },
    { 0xFFFFFCBC, "NDPSM Already Attached" },
    { 0xFFFFFCBB, "NDPSM Can't Attach" },
    { 0xFFFFFCBA, "NDPSM Too Many NetWare Servers" },
    { 0xFFFFFCB9, "NDPSM Can't Create Document File" },
    { 0xFFFFFCB8, "NDPSM Can't Delete Document File" },
    { 0xFFFFFCB7, "NDPSM Can't Open Document File" },
    { 0xFFFFFCB6, "NDPSM Can't Write Document File" },
    { 0xFFFFFCB5, "NDPSM Job is Active" },
    { 0xFFFFFCB4, "NDPSM No Scheduler" },
    { 0xFFFFFCB3, "NDPSM Changing Connection" },
    { 0xFFFFFCB2, "NDPSM Could not Create Account Reference" },
    { 0xFFFFFCB1, "NDPSM Accounting Service Error" },
    { 0xFFFFFCB0, "NDPSM RMS Service Error" },
    { 0xFFFFFCAF, "NDPSM Failed Validation" },
    { 0xFFFFFCAE, "NDPSM Broker Server Connecting" },
    { 0xFFFFFCAD, "NDPSM SRS Service Error" },
    { 0xFFFFFD44, "JPM Execute Request Later" },
    { 0xFFFFFD43, "JPM Failed to Open Document" },
    { 0xFFFFFD42, "JPM Failed to Read Document File" },
    { 0xFFFFFD41, "JPM Bad Printer Agent Handle" },
    { 0xFFFFFD40, "JPM Bad Job Handle" },
    { 0xFFFFFD3F, "JPM Bad Document Handle" },
    { 0xFFFFFD3E, "JPM Unsupported Operation" },
    { 0xFFFFFD3D, "JPM Request Queue Full" },
    { 0xFFFFFD3C, "JPM Printer Agent Not Found" },
    { 0xFFFFFD3B, "JPM Invalid Request" },
    { 0xFFFFFD3A, "JPM Not Accepting Requests" },
    { 0xFFFFFD39, "JPM Printer Agent Already Serviced By PDS" },
    { 0xFFFFFD38, "JPM No Job" },
    { 0xFFFFFD37, "JPM Job Not Found" },
    { 0xFFFFFD36, "JPM Could not Access Database" },
    { 0xFFFFFD35, "JPM Bad Object Type" },
    { 0xFFFFFD34, "JPM Job Already Closed" },
    { 0xFFFFFD33, "JPM Document Already Closed" },
    { 0xFFFFFD32, "JPM Print Handler Not Registered" },
    { 0xFFFFFD31, "JPM Version Incompatible" },
    { 0xFFFFFD30, "JPM Printer Agent Paused" },
    { 0xFFFFFD2F, "JPM Printer Agent Shutdown" },
    { 0xFFFFFD2E, "JPM No CLIB Context" },
    { 0xFFFFFD2D, "JPM Accounting Already Serviced" },
    { 0xFFFFFC7B, "Database Can't Create File" },
    { 0xFFFFFC7A, "Database Can't Find Data File" },
    { 0xFFFFFC79, "Database Can't Open Data File" },
    { 0xFFFFFC78, "Database Can't Open Index File" },
    { 0xFFFFFC77, "Database Index File Not Open" },
    { 0xFFFFFC76, "Database Can't Rename File" },
    { 0xFFFFFC75, "Database Can't Read Data File" },
    { 0xFFFFFC74, "Database Can't Read Index File" },
    { 0xFFFFFC73, "Database Can't Write Data File" },
    { 0xFFFFFC72, "Database Can't Write Index File" },
    { 0xFFFFFC71, "Database Can't Delete Printer Agent Directory" },
    { 0xFFFFFC70, "Database Already Deleted" },
    { 0xFFFFFC6F, "Database Object Exists" },
    { 0xFFFFFC6E, "Database Descriptor In Use" },
    { 0xFFFFFC6D, "Database Descriptor Being Deleted" },
    { 0xffffffff, "(-1) Insufficient Space" },
    { 0xffffff89, "(-119) Buffer too Small" },
    { 0xffffff88, "(-120) RR Volume Flag Not Set" },
    { 0xffffff87, "(-121) No Items Found" },
    { 0xffffff86, "(-122) Connection Already Temporary" },
    { 0xffffff85, "(-123) Connection Already Logged In" },
    { 0xffffff84, "(-124) Connection Not Authenticated" },
    { 0xffffff83, "(-125) Connection Not Logged In" },
    { 0xffffff82, "(-126) NCP Boundary Check Failed" },
    { 0xffffff81, "(-127) Lock Waiting" },
    { 0xffffff80, "(-128) Lock Fail" },
    { 0xffffff7f, "(-129) Out of Handles" },
    { 0xffffff7e, "(-130) No Open Privilege" },
    { 0xffffff7d, "(-131) Hard IO Error" },
    { 0xffffff7c, "(-132) No Create Privilege" },
    { 0xffffff7b, "(-133) No Create Delete Privilege" },
    { 0xffffff7a, "(-134) Create Duplicate When Read Only" },
    { 0xffffff79, "(-135) Create File with Invalid Name" },
    { 0xffffff78, "(-136) Invalid File Handle" },
    { 0xffffff77, "(-137) No Search Privilege"   },
    { 0xffffff76, "(-138) No Delete Privilege" },
    { 0xffffff75, "(-139) No Rename Privilege" },
    { 0xffffff74, "(-140) No Set Privilege" },
    { 0xffffff73, "(-141) Some File in Use" },
    { 0xffffff72, "(-142) All File in Use" },
    { 0xffffff71, "(-143) Some Read Only" },
    { 0xffffff70, "(-144) All Read Only" },
    { 0xffffff6f, "(-145) Some names Exist" },
    { 0xffffff6e, "(-146) All Names Exist" },
    { 0xffffff6d, "(-147) No Read Privilege" },
    { 0xffffff6c, "(-148) No Write Privilege" },
    { 0xffffff6b, "(-149) File Detached" },
    { 0xffffff6a, "(-150) No Alloc Space/Target Not a Subdirectory/Insuffficient Memory" },
    { 0xffffff69, "(-151) No Spool Space" },
    { 0xffffff68, "(-152) Invalid Volume" },
    { 0xffffff67, "(-153) Directory Full" },
    { 0xffffff66, "(-154) Rename Across Volume" },
    { 0xffffff65, "(-155) Bad Directory Handle" },
    { 0xffffff64, "(-156) Invalid Path/No Such Extension" },
    { 0xffffff63, "(-157) No Directory Handles" },
    { 0xffffff62, "(-158) Bad File Name" },
    { 0xffffff61, "(-159) Directory Active" },
    { 0xffffff60, "(-160) Directory Not Empty" },
    { 0xffffff5f, "(-161) Directory IO Error" },
    { 0xffffff5e, "(-162) IO Locked" },
    { 0xffffff5d, "(-163) Transaction Restarted" },
    { 0xffffff5c, "(-164) Rename Directory Invalid" },
    { 0xffffff5b, "(-165) Invalid Open/Create Mode" },
    { 0xffffff5a, "(-166) Already in Use" },
    { 0xffffff59, "(-167) Invalid Resource Tag" },
    { 0xffffff58, "(-168) Access Denied" },
    { 0xffffff44, "(-188) Login Signing Required" },
    { 0xffffff43, "(-189) Login Encryption Required" },
    { 0xffffff42, "(-190) Invalid Data Stream" },
    { 0xffffff41, "(-191) Invalid Name Space" },
    { 0xffffff40, "(-192) No Accounting Privileges" },
    { 0xffffff3f, "(-193) No Account Balance" },
    { 0xffffff3e, "(-194) Credit Limit Exceeded" },
    { 0xffffff3d, "(-195) Too Many Holds" },
    { 0xffffff3c, "(-196) Accounting Disabled" },
    { 0xffffff3b, "(-197) Intruder Login Lockout" },
    { 0xffffff3a, "(-198) No Console Rights" },
    { 0xffffff30, "(-208) Queue IO Failure" },
    { 0xffffff2f, "(-209) No Queue" },
    { 0xffffff2e, "(-210) No Queue Server" },
    { 0xffffff2d, "(-211) No Queue Rights" },
    { 0xffffff2c, "(-212) Queue Full" },
    { 0xffffff2b, "(-213) No Queue Job" },
    { 0xffffff2a, "(-214) No Queue Job Rights/Unencrypted Not Allowed" },
    { 0xffffff29, "(-215) Queue In Service/Duplicate Password" },
    { 0xffffff28, "(-216) Queue Not Active/Password Too Short" },
    { 0xffffff27, "(-217) Queue Station Not Server/Maximum Logins Exceeded" },
    { 0xffffff26, "(-218) Queue Halted/Bad Login Time" },
    { 0xffffff25, "(-219) Queue Maximum Servers/Node Address Violation" },
    { 0xffffff24, "(-220) Login Account Expired" },
    { 0xffffff22, "(-222) Bad Password" },
    { 0xffffff21, "(-223) Password Expired" },
    { 0xffffff20, "(-224) No Login Connection Available" },
    { 0xffffff18, "(-232) Write to Group Property" },
    { 0xffffff17, "(-233) Member Already Exists" },
    { 0xffffff16, "(-234) No Such Member" },
    { 0xffffff15, "(-235) Property Not Group" },
    { 0xffffff14, "(-236) No Such Value Set" },
    { 0xffffff13, "(-237) Property Already Exists" },
    { 0xffffff12, "(-238) Object Already Exists" },
    { 0xffffff11, "(-239) Illegal Name" },
    { 0xffffff10, "(-240) Illegal Wildcard" },
    { 0xffffff0f, "(-241) Bindery Security" },
    { 0xffffff0e, "(-242) No Object Read Rights" },
    { 0xffffff0d, "(-243) No Object Rename Rights" },
    { 0xffffff0c, "(-244) No Object Delete Rights" },
    { 0xffffff0b, "(-245) No Object Create Rights" },
    { 0xffffff0a, "(-246) No Property Delete Rights" },
    { 0xffffff09, "(-247) No Property Create Rights" },
    { 0xffffff08, "(-248) No Property Write Rights" },
    { 0xffffff07, "(-249) No Property Read Rights" },
    { 0xffffff06, "(-250) Temp Remap" },
    { 0xffffff05, "(-251) Unknown Request/No Such Property" },
    { 0xffffff04, "(-252) Message Queue Full/Target Already Has Message/No Such Object" },
    { 0xffffff03, "(-253) Bad Station Number" },
    { 0xffffff02, "(-254) Bindery Locked/Directory Locked/Spool Delete/Trustee not Found/Timeout" },
    { 0xffffff01, "(-255) Hard Failure" },
    { 0xfffffed3, "(-301) Not Enough Memory" },
    { 0xfffffed2, "(-302) Bad Key" },
    { 0xfffffed1, "(-303) Bad Context" },
    { 0xfffffed0, "(-304) Buffer Full" },
    { 0xfffffecf, "(-305) List Empty" },
    { 0xfffffece, "(-306) Bad Syntax"   },
    { 0xfffffecd, "(-307) Buffer Empty" },
    { 0xfffffecc, "(-308) Bad Verb" },
    { 0xfffffecb, "(-309) Expected Identifier" },
    { 0xfffffeca, "(-310) Expected Equals" },
    { 0xfffffec9, "(-311) Attribute Type Expected" },
    { 0xfffffec8, "(-312) Attribute Type Not Expected" },
    { 0xfffffec7, "(-313) Filter Tree Empty" },
    { 0xfffffec6, "(-314) Invalid Object Name" },
    { 0xfffffec5, "(-315) Expected RDN Delimiter" },
    { 0xfffffec4, "(-316) Too Many Tokens" },
    { 0xfffffec3, "(-317) Inconsistent MultiAVA" },
    { 0xfffffec2, "(-318) Country Name Too Long" },
    { 0xfffffec1, "(-319) Internal Error" },
    { 0xfffffec0, "(-320) Can't Add Root" },
    { 0xfffffebf, "(-321) Unable to Attach" },
    { 0xfffffebe, "(-322) Invalid Iteration Handle" },
    { 0xfffffebd, "(-323) Buffer Zero Length" },
    { 0xfffffebc, "(-324) Invalid Replica Type" },
    { 0xfffffebb, "(-325) Invalid Attribute Syntax" },
    { 0xfffffeba, "(-326) Invalid Filter Syntax" },
    { 0xfffffeb8, "(-328) Unicode Error during Context Creation" },
    { 0xfffffeb7, "(-329) Invalid Union Tag" },
    { 0xfffffeb6, "(-330) Invalid Server Response" },
    { 0xfffffeb5, "(-331) Null Pointer" },
    { 0xfffffeb4, "(-332) No Server Found" },
    { 0xfffffeb3, "(-333) No Connection" },
    { 0xfffffeb2, "(-334) RDN Too Long" },
    { 0xfffffeb1, "(-335) Duplicate Type" },
    { 0xfffffeb0, "(-336) Data Store Failure" },
    { 0xfffffeaf, "(-337) Not Logged In" },
    { 0xfffffeae, "(-338) Invalid Password Characters" },
    { 0xfffffead, "(-339) Failed Server Authentication" },
    { 0xfffffeac, "(-340) Transport Failed" },
    { 0xfffffeab, "(-341) No Such Syntax" },
    { 0xfffffeaa, "(-342) Invalid DS Name" },
    { 0xfffffea9, "(-343) Attribute Name Too Long" },
    { 0xfffffea8, "(-344) Invalid TDS" },
    { 0xfffffea7, "(-345) Invalid DS Version" },
    { 0xfffffea6, "(-346) Unicode Translation" },
    { 0xfffffea5, "(-347) Schema Name Too Long" },
    { 0xfffffea4, "(-348) Unicode File Not Found" },
    { 0xfffffea3, "(-349) Unicode Already Loaded" },
    { 0xfffffea2, "(-350) Not Context Owner" },
    { 0xfffffea1, "(-351) Attempt to Authenticate" },
    { 0xfffffea0, "(-352) No Writable Replicas" },
    { 0xfffffe9f, "(-353) DN Too Long" },
    { 0xfffffe9e, "(-354) Rename Not Allowed" },
    { 0xfffffe9d, "(-355) Not NDS for NT" },
    { 0xfffffe9c, "(-356) NDS for NT - No Domain" },
    { 0xfffffe9b, "(-357) NDS for NT - Sync Disabled" },
    { 0xfffffe9a, "(-358) Iterator Invalid Handle" },
    { 0xfffffe99, "(-359) Iterator Invalid Position" },
    { 0xfffffe98, "(-360) Iterator Invalid Search Data" },
    { 0xfffffe97, "(-361) Iterator Invalid Scope" },
    { 0xfffffda7, "(-601) No Such Entry" },
    { 0xfffffda6, "(-602) No Such Value" },
    { 0xfffffda5, "(-603) No Such Attribute" },
    { 0xfffffda4, "(-604) No Such Class" },
    { 0xfffffda3, "(-605) No Such Partition" },
    { 0xfffffda2, "(-606) Entry Already Exists" },
    { 0xfffffda1, "(-607) Not Effective Class" },
    { 0xfffffda0, "(-608) Illegal Attribute" },
    { 0xfffffd9f, "(-609) Missing Mandatory" },
    { 0xfffffd9e, "(-610) Illegal DS Name" },
    { 0xfffffd9d, "(-611) Illegal Containment" },
    { 0xfffffd9c, "(-612) Can't Have Multiple Values" },
    { 0xfffffd9b, "(-613) Syntax Violation" },
    { 0xfffffd9a, "(-614) Duplicate Value" },
    { 0xfffffd99, "(-615) Attribute Already Exists" },
    { 0xfffffd98, "(-616) Maximum Entries Exist" },
    { 0xfffffd97, "(-617) Database Format" },
    { 0xfffffd96, "(-618) Inconsistent Database" },
    { 0xfffffd95, "(-619) Invalid Comparison" },
    { 0xfffffd94, "(-620) Comparison Failed" },
    { 0xfffffd93, "(-621) Transaction Tracking Disabled" },
    { 0xfffffd92, "(-622) Invalid Transport" },
    { 0xfffffd91, "(-623) Syntax Invalid in Name" },
    { 0xfffffd90, "(-624) Replica Already Exists" },
    { 0xfffffd8f, "(-625) Transport Failure" },
    { 0xfffffd8e, "(-626) All Referrals Failed" },
    { 0xfffffd8d, "(-627) Can't Remove Naming Value" },
    { 0xfffffd8c, "(-628) Object Class Violation" },
    { 0xfffffd8b, "(-629) Entry is Not Leaf" },
    { 0xfffffd8a, "(-630) Different Tree" },
    { 0xfffffd89, "(-631) Illegal Replica Type" },
    { 0xfffffd88, "(-632) System Failure" },
    { 0xfffffd87, "(-633) Invalid Entry for Root" },
    { 0xfffffd86, "(-634) No Referrals" },
    { 0xfffffd85, "(-635) Remote Failure" },
    { 0xfffffd84, "(-636) Unreachable Server" },
    { 0xfffffd83, "(-637) Previous Move in Progress" },
    { 0xfffffd82, "(-638) No Character Mapping" },
    { 0xfffffd81, "(-639) Incomplete Authentication" },
    { 0xfffffd80, "(-640) Invalid Certificate" },
    { 0xfffffd7f, "(-641) Invalid Request" },
    { 0xfffffd7e, "(-642) Invalid Iteration" },
    { 0xfffffd7d, "(-643) Schema is Non-removable" },
    { 0xfffffd7c, "(-644) Schema is in Use" },
    { 0xfffffd7b, "(-645) Class Already Exists" },
    { 0xfffffd7a, "(-646) Bad Naming Attributes" },
    { 0xfffffd79, "(-647) Not Root Partition" },
    { 0xfffffd78, "(-648) Insufficient Stack" },
    { 0xfffffd77, "(-649) Insufficient Buffer" },
    { 0xfffffd76, "(-650) Ambiguous Containment" },
    { 0xfffffd75, "(-651) Ambiguous Naming" },
    { 0xfffffd74, "(-652) Duplicate Mandatory" },
    { 0xfffffd73, "(-653) Duplicate Optional" },
    { 0xfffffd72, "(-654) Partition Busy" },
    { 0xfffffd71, "(-655) Multiple Replicas" },
    { 0xfffffd70, "(-656) Crucial Replica" },
    { 0xfffffd6f, "(-657) Schema Sync in Progress" },
    { 0xfffffd6e, "(-658) Skulk in Progress" },
    { 0xfffffd6d, "(-659) Time Not Synchronized" },
    { 0xfffffd6c, "(-660) Record in Use" },
    { 0xfffffd6b, "(-661) DS Volume Not Mounted" },
    { 0xfffffd6a, "(-662) DS Volume IO Failure" },
    { 0xfffffd69, "(-663) DS Locked" },
    { 0xfffffd68, "(-664) Old Epoch" },
    { 0xfffffd67, "(-665) New Epoch" },
    { 0xfffffd66, "(-666) Incompatible DS Version" },
    { 0xfffffd65, "(-667) Partition Root" },
    { 0xfffffd64, "(-668) Entry Not Container" },
    { 0xfffffd63, "(-669) Failed Authentication" },
    { 0xfffffd62, "(-670) Invalid Context" },
    { 0xfffffd61, "(-671) No Such Parent" },
    { 0xfffffd60, "(-672) No Access" },
    { 0xfffffd5f, "(-673) Replica Not On" },
    { 0xfffffd5e, "(-674) Invalid Name Service" },
    { 0xfffffd5d, "(-675) Invalid Task" },
    { 0xfffffd5c, "(-676) Invalid Connection Handle" },
    { 0xfffffd5b, "(-677) Invalid Identity" },
    { 0xfffffd5a, "(-678) Duplicate ACL" },
    { 0xfffffd59, "(-679) Partition Already Exists" },
    { 0xfffffd58, "(-680) Transport Modified" },
    { 0xfffffd57, "(-681) Alias of an Alias" },
    { 0xfffffd56, "(-682) Auditing Failed" },
    { 0xfffffd55, "(-683) Invalid API Version" },
    { 0xfffffd54, "(-684) Secure NCP Violation" },
    { 0xfffffd53, "(-685) Move in Progress" },
    { 0xfffffd52, "(-686) Not a Leaf Partition" },
    { 0xfffffd51, "(-687) Cannot Abort" },
    { 0xfffffd50, "(-688) Cache Overflow" },
    { 0xfffffd4f, "(-689) Invalid Subordinate Count" },
    { 0xfffffd4e, "(-690) Invalid RDN" },
    { 0xfffffd4d, "(-691) Modification Time Not Current" },
    { 0xfffffd4c, "(-692) Incorrect Base Class" },
    { 0xfffffd4b, "(-693) Missing Reference" },
    { 0xfffffd4a, "(-694) Lost Entry" },
    { 0xfffffd49, "(-695) Agent Already Registered" },
    { 0xfffffd48, "(-696) DS Loader Busy" },
    { 0xfffffd47, "(-697) DS Cannot Reload" },
    { 0xfffffd46, "(-698) Replica in Skulk" },
    { 0xfffffd45, "(-699) Fatal" },
    { 0xfffffd44, "(-700) Obsolete API" },
    { 0xfffffd43, "(-701) Synchronization Disabled" },
    { 0xfffffd42, "(-702) Invalid Parameter" },
    { 0xfffffd41, "(-703) Duplicate Template" },
    { 0xfffffd40, "(-704) No Master Replica" },
    { 0xfffffd3f, "(-705) Duplicate Containment" },
    { 0xfffffd3e, "(-706) Not a Sibling" },
    { 0xfffffd3d, "(-707) Invalid Signature" },
    { 0xfffffd3c, "(-708) Invalid Response" },
    { 0xfffffd3b, "(-709) Insufficient Sockets" },
    { 0xfffffd3a, "(-710) Database Read Fail" },
    { 0xfffffd39, "(-711) Invalid Code Page" },
    { 0xfffffd38, "(-712) Invalid Escape Character" },
    { 0xfffffd37, "(-713) Invalid Delimiters" },
    { 0xfffffd36, "(-714) Not Implemented" },
    { 0xfffffd35, "(-715) Checksum Failure" },
    { 0xfffffd34, "(-716) Checksumming Not Supported" },
    { 0xfffffd33, "(-717) CRC Failure" },
    { 0xfffffd32, "(-718) Invalid Entry Handle" },
    { 0xfffffd31, "(-719) Invalid Value Handle" },
    { 0xfffffd30, "(-720) Connection Denied" },
    { 0xfffffd2f, "(-721) No Such Federation Link" },
    { 0xfffffd2e, "(-722) Operational Schema Mismatch" },
    { 0xfffffd2d, "(-723) Stream Not Found" },
    { 0xfffffd2c, "(-724) DClient Unavailable" },
    { 0xfffffd2b, "(-725) MASV No Access" },
    { 0xfffffd2a, "(-726) MASV Invalid Request" },
    { 0xfffffd29, "(-727) MASV Failure" },
    { 0xfffffd28, "(-728) MASV Already Exists" },
    { 0xfffffd27, "(-729) MASV Not Found" },
    { 0xfffffd26, "(-730) MASV Bad Range" },
    { 0xfffffd25, "(-731) Value Data" },
    { 0xfffffd24, "(-732) Database Locked" },
    { 0xfffffd21, "(-735) Nothing to Abort" },
    { 0xfffffd20, "(-736) End of Stream" },
    { 0xfffffd1f, "(-737) No Such Template" },
    { 0xfffffd1e, "(-738) SAS Locked" },
    { 0xfffffd1d, "(-739) Invalid SAS Version" },
    { 0xfffffd1c, "(-740) SAS Already Registered" },
    { 0xfffffd1b, "(-741) Name Type Not Supported" },
    { 0xfffffd1a, "(-742) Wrong DS Version" },
    { 0xfffffd19, "(-743) Invalid Control Function" },
    { 0xfffffd18, "(-744) Invalid Control State" },
    { 0xfffffd17, "(-745) Cache in Use" },
    { 0xfffffd16, "(-746) Zero Creation Time" },
    { 0xfffffd15, "(-747) Would Block" },
    { 0xfffffd14, "(-748) Connection Timeout" },
    { 0xfffffd13, "(-749) Too Many Referrals" },
    { 0xfffffd12, "(-750) Operation Cancelled" },
    { 0xfffffd11, "(-751) Unknown Target" },
    { 0xfffffd10, "(-752) GUID Failure" },
    { 0xfffffd0f, "(-753) Incompatible OS" },
    { 0xfffffd0e, "(-754) Callback Cancel" },
    { 0xfffffd0d, "(-755) Invalid Synchronization Data" },
    { 0xfffffd0c, "(-756) Stream Exists" },
    { 0xfffffd0b, "(-757) Auxiliary Has Containment" },
    { 0xfffffd0a, "(-758) Auxiliary Not Container" },
    { 0xfffffd09, "(-759) Auxiliary Not Effective" },
    { 0xfffffd08, "(-760) Auxiliary On Alias" },
    { 0xfffffd07, "(-761) Have Seen State" },
    { 0xfffffd06, "(-762) Verb Locked" },
    { 0xfffffd05, "(-763) Verb Exceeds Table Length" },
    { 0xfffffd04, "(-764) BOF Hit" },
    { 0xfffffd03, "(-765) EOF Hit" },
    { 0xfffffd02, "(-766) Incompatible Replica Version" },
    { 0xfffffd01, "(-767) Query Timeout" },
    { 0xfffffd00, "(-768) Query Maximum Count" },
    { 0xfffffcff, "(-769) Duplicate Naming" },
    { 0xfffffcfe, "(-770) No Transaction Active" },
    { 0xfffffcfd, "(-771) Transaction Active" },
    { 0xfffffcfc, "(-772) Illegal Transaction Operation" },
    { 0xfffffcfb, "(-773) Iterator Syntax" },
    { 0xfffffcfa, "(-774) Repairing DIB" },
    { 0xfffffcf9, "(-775) Invalid OID Format" },
    { 0xfffffcf8, "(-776) Attempted to perform an NDS operation, and the DS agent on this server is closing" },
    { 0xfffffcf7, "(-777) Attempted to modify an object's attribute that is not stored on the sparse replica" },
    { 0xfffffcf6, "(-778) VpVector and VpvUser which must be correlated, are out of sync" },
    { 0xfffffcf5, "(-779) Error Cannot Go Remote" },
    { 0xfffffcf4, "(-780) Request not Supported" },
    { 0xfffffcf3, "(-781) Entry Not Local" },
    { 0xfffffcf2, "(-782) Root Unreachable" },
    { 0xfffffcf1, "(-783) VRDIM Not Initialized" },
    { 0xfffffcf0, "(-784) Wait Timeout" },
    { 0xfffffcef, "(-785) DIB Error" },
    { 0xfffffcee, "(-786) DIB IO Failure" },
    { 0xfffffced, "(-787) Illegal Schema Attribute" },
    { 0xfffffcec, "(-788) Error Schema Partition" },
    { 0xfffffceb, "(-789) Invalid Template" },
    { 0xfffffcea, "(-790) Error Opening File" },
    { 0xfffffce9, "(-791) Error Direct Opening File" },
    { 0xfffffce8, "(-792) Error Creating File" },
    { 0xfffffce7, "(-793) Error Direct Creating File" },
    { 0xfffffce6, "(-794) Error Reading File" },
    { 0xfffffce5, "(-795) Error Direct Reading File" },
    { 0xfffffce4, "(-796) Error Writing File" },
    { 0xfffffce3, "(-797) Error Direct Writing File" },
    { 0xfffffce2, "(-798) Error Positioning in File" },
    { 0xfffffce1, "(-799) Error Getting File Size" },
    { 0xffffe88f, "(-6001) Error Truncating File" },
    { 0xffffe88e, "(-6002) Error Parsing File Name" },
    { 0xffffe88d, "(-6003) Error Closing File" },
    { 0xffffe88c, "(-6004) Error Getting File Info" },
    { 0xffffe88b, "(-6005) Error Expanding File" },
    { 0xffffe88a, "(-6006) Error Getting Free Blocks" },
    { 0xffffe889, "(-6007) Error Checking File Existence" },
    { 0xffffe888, "(-6008) Error Deleting File" },
    { 0xffffe887, "(-6009) Error Renaming File" },
    { 0xffffe886, "(-6010) Error Initializing IO System" },
    { 0xffffe885, "(-6011) Error Flushing File" },
    { 0xffffe884, "(-6012) Error Setting Up for Read" },
    { 0xffffe883, "(-6013) Error Setting up for Write" },
    { 0xffffe882, "(-6014) Error Old View" },
    { 0xffffe881, "(-6015) Server in Skulk" },
    { 0xffffe880, "(-6016) Error Returning Partial Results" },
    { 0xffffe87f, "(-6017) No Such Schema" },
    { 0xffffe87e, "(-6018) Serial Number Mismatch" },
    { 0xffffe87d, "(-6019) Bad Referral Database Serial Number" },
    { 0xffffe87c, "(-6020) Bad Referral Serial Number" },
    { 0xffffe87b, "(-6021) Invalid File Sequence" },
    { 0xffffe87a, "(-6022) Error Referral Trans Gap" },
    { 0xffffe879, "(-6023) Bad Referral File Number" },
    { 0xffffe878, "(-6024) Referral File Not Found" },
    { 0xffffe877, "(-6025) Error Backup Active" },
    { 0xffffe876, "(-6026) Referral Device Full" },
    { 0xffffe875, "(-6027) Unsupported Version" },
    { 0xffffe874, "(-6028) Error Must Wait Checkpoint" },
    { 0xffffe873, "(-6029) Attribute Maintenance in Progress" },
    { 0xffffe872, "(-6030) Error Abort Transaction" },
    { 0,          NULL }
};

static const value_string ndps_credential_enum[] = {
    { 0, "SIMPLE" },
    { 1, "CERTIFIED" },
    { 2, "NDPS 0" },
    { 3, "NDPS 1" },
    { 4, "NDPS 2" },
    { 0, NULL }
};

static const value_string ndps_object_op_enum[] = {
    { 0, "None" },
    { 1, "Add" },
    { 2, "Delete" },
    { 3, "Delete Object" },
    { 0, NULL }
};

static const value_string ndps_client_server_enum[] = {
    { 0, "Client" },
    { 1, "Server" },
    { 2, "Client and Server" },
    { 0, NULL }
};

static const value_string ndps_session_type_enum[] = {
    { 0, "Unknown" },
    { 1, "User" },
    { 2, "Admin" },
    { 3, "Server" },
    { 4, "Registry" },
    { 0, NULL }
};

static const value_string ndps_get_session_type_enum[] = {
    { 0, "Unknown" },
    { 1, "User" },
    { 2, "Admin" },
    { 3, "Supplier" },
    { 0, NULL }
};

static const value_string ndps_get_resman_session_type_enum[] = {
    { 0, "Unknown" },
    { 1, "User" },
    { 2, "Admin" },
    { 0, NULL }
};

static int
align_4(tvbuff_t *tvb, int aoffset)
{
    if(tvb_length_remaining(tvb, aoffset) > 4 )
    {
        return (aoffset%4);
    }
    return 0;
}

/*
 * XXX - is there something in the packet to indicate whether a string
 * is ASCII or Unicode, or is it a characteristic of the attribute?
 * Currently, we use a heuristic - if the length is odd, we assume
 * it's ASCII (as it's a length in bytes, not characters), otherwise if
 * if the length is 2, we assume it's ASCII (as strings are null-
 * terminated, so a Unicode string would have to be at least 4 bytes),
 * otherwise if the second byte of the string is 0, we assume it's
 * Unicode (as an ASCII string would, in that case, have at least two
 * characters before the terminating NUL).
 */
static int
ndps_string(tvbuff_t* tvb, int hfinfo, proto_tree *ndps_tree, int offset, char **stringval)
{
    int     foffset = offset;
    guint32 str_length;
    char *string;

    str_length = tvb_get_ntohl(tvb, foffset);
    foffset += 4;
    if(str_length == 0)
    {
        proto_tree_add_string(ndps_tree, hfinfo, tvb, offset, 4, "<Not Specified>");
        if (stringval != NULL)
          *stringval = ep_strdup("");
        return foffset;
    }
    if (str_length <= 2 || (str_length & 0x01) || tvb_get_guint8(tvb, foffset + 1) != 0) {
        /*
         * ASCII.
         */
        string = tvb_get_ephemeral_string(tvb, foffset, str_length);
    } else {
        /*
         * Unicode.
         */
        string = tvb_get_ephemeral_unicode_string(tvb, foffset, str_length, ENC_LITTLE_ENDIAN);
    }
    foffset += str_length;
    proto_tree_add_string(ndps_tree, hfinfo, tvb, offset, str_length + 4, string);
    foffset += align_4(tvb, foffset);
    if (stringval != NULL)
        *stringval = string;
    return foffset;
}

static int
objectidentifier(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     length;
    const char  *label=NULL;
    guint32     label_value=0;
    proto_tree  *atree;
    proto_item  *aitem;
    gboolean    found=TRUE;

    length = tvb_get_ntohl(tvb, foffset);
    if (length==0)
    {
        return foffset;
    }
    if (ndps_show_oids)
    {
        proto_tree_add_uint(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, length);
    }
    foffset += 4;
    switch (length)
    {
    case 9:
        label_value = tvb_get_ntohl(tvb, foffset+5);
        label = match_strval(label_value, object_ids_7);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_7, tvb, foffset, length, "%s", label);
        break;
    case 10:
        label_value = tvb_get_ntohl(tvb, foffset+6);
        label = match_strval(label_value, object_ids_8);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_8, tvb, foffset, length, "%s", label);
        break;
    case 11:
        label_value = tvb_get_ntohl(tvb, foffset+7);
        label = match_strval(label_value, object_ids_9);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_9, tvb, foffset, length, "%s", label);
        break;
    case 12:
        label_value = tvb_get_ntohl(tvb, foffset+8);
        label = match_strval(label_value, object_ids_10);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_10, tvb, foffset, length, "%s", label);
        break;
    case 13:
        label_value = tvb_get_ntohl(tvb, foffset+9);
        label = match_strval(label_value, object_ids_11);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_11, tvb, foffset, length, "%s", label);
        break;
    case 14:
        label_value = tvb_get_ntohl(tvb, foffset+10);
        label = match_strval(label_value, object_ids_12);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_12, tvb, foffset, length, "%s", label);
        break;
    case 15:
        label_value = tvb_get_ntohl(tvb, foffset+11);
        label = match_strval(label_value, object_ids_13);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_13, tvb, foffset, length, "%s", label);
        break;
    case 16:
        label_value = tvb_get_ntohl(tvb, foffset+12);
        label = match_strval(label_value, object_ids_14);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_14, tvb, foffset, length, "%s", label);
        break;
    case 17:
        label_value = tvb_get_ntohl(tvb, foffset+13);
        label = match_strval(label_value, object_ids_15);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_15, tvb, foffset, length, "%s", label);
        break;
    case 18:
        label_value = tvb_get_ntohl(tvb, foffset+14);
        label = match_strval(label_value, object_ids_16);
        if (label==NULL)
        {
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
            found=FALSE;
            break;
        }
        aitem = proto_tree_add_none_format(ndps_tree, hf_ndps_object_ids_16, tvb, foffset, length, "%s", label);
        break;
    default:
        aitem = proto_tree_add_text(ndps_tree, tvb, foffset, length, "Unknown ID");
        found=FALSE;
        break;
    }
    if (!found)
    {
        label_value = 1;
        label = match_strval(label_value, object_ids_7);
    }
    if (ndps_show_oids)
    {
        atree = proto_item_add_subtree(aitem, ett_ndps);
        proto_tree_add_item(atree, hf_oid_asn1_type, tvb, foffset, 1, ENC_BIG_ENDIAN);
        foffset += 1;
        length = tvb_get_guint8(tvb, foffset);
        foffset += 1;
        tvb_ensure_bytes_exist(tvb, foffset, length);
        proto_tree_add_item(atree, hf_ndps_oid, tvb, foffset, length, ENC_NA);
        foffset += length;
    }
    else
    {
        if (!found)
        {
            tvb_ensure_bytes_exist(tvb, foffset, length);
            foffset += length;
        }
        else
        {
            foffset += 1;
            length = tvb_get_guint8(tvb, foffset);
            foffset += 1;
            tvb_ensure_bytes_exist(tvb, foffset, length);
            foffset += length;
        }
    }
    global_attribute_name = label;
    /* XXX - There's probably a better way to handle this */
    if ((int) (foffset+(length%2)) < 0) {
        THROW(ReportedBoundsError);
    }
    return foffset+(length%2);
}

static int
name_or_id(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32 name_or_id_val;

    name_or_id_val = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 4, name_or_id_val);
    foffset += 4;
    switch (name_or_id_val)
    {
        case 1: /* Global */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            break;

        case 2: /* Local */
            foffset = ndps_string(tvb, hf_ndps_local_object_name, ndps_tree, foffset, NULL);
            break;
    }
    foffset += align_4(tvb, foffset);
    return foffset;
}

static int
qualifiedname(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     qualified_name_type=0;

    qualified_name_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_qualified_name, tvb, foffset, 4, qualified_name_type);
    foffset += 4;
    if (qualified_name_type != 0) {
        if (qualified_name_type == 1) {
            foffset = ndps_string(tvb, hf_ndps_printer_name, ndps_tree, foffset, NULL);
        }
        else
        {
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
        }
    }
    return foffset;
}

static int
objectidentification(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     object_type=0;
    proto_tree  *atree;
    proto_item  *aitem;

    object_type = tvb_get_ntohl(tvb, foffset);
    aitem = proto_tree_add_item(ndps_tree, hf_obj_id_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
    atree = proto_item_add_subtree(aitem, ett_ndps);
    foffset += 4;
    switch(object_type)
    {
        case 0:         /* Printer Contained Object ID */
            foffset = ndps_string(tvb, hf_ndps_printer_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_ndps_object, tvb, foffset,
            4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 1:         /* Document Identifier */
            foffset = ndps_string(tvb, hf_ndps_printer_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_ndps_document_number, tvb, foffset,
            4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 2:         /* Object Identifier */
            foffset = objectidentifier(tvb, atree, foffset);
            break;
        case 3:         /* Object Name */
            foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                return foffset;
            }
            foffset = name_or_id(tvb, atree, foffset);
            break;
        case 4:         /* Name or Object ID */
            foffset = name_or_id(tvb, atree, foffset);
            break;
        case 5:         /* Simple Name */
            foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
            break;
        case 6:         /* Printer Configuration Object ID */
            foffset = ndps_string(tvb, hf_ndps_printer_name, atree, foffset, NULL);
            break;
        case 7:         /* Qualified Name */
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 8:         /* Event Object ID */
            foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_tree_add_item(atree, hf_ndps_event_type, tvb, foffset,
            4, ENC_BIG_ENDIAN);
            foffset += 4;
        default:
            break;
    }
    return foffset;
}

static int
print_address(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     addr_type=0;
    guint32     addr_len=0;

    addr_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_address, tvb, foffset, 4, addr_type);
    foffset += 4;
    addr_len = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_item(ndps_tree, hf_address_len, tvb, foffset, 4, ENC_BIG_ENDIAN);
    foffset += 4;
    /*
     * XXX - are these address types the same as the NDS_PTYPE_ #defines
     * in packet-ncp2222.inc?
     *
     * XXX - should this code - and the code in packet-ncp2222.inc to
     * dissect addresses - check the length for the types it supports?
     */
    switch(addr_type)
    {
    case 0x00000000:
        proto_tree_add_item(ndps_tree, hf_ndps_net, tvb, foffset, 4, ENC_NA);
        proto_tree_add_item(ndps_tree, hf_ndps_node, tvb, foffset+4, 6, ENC_NA);
        proto_tree_add_item(ndps_tree, hf_ndps_socket, tvb, foffset+10, 2, ENC_BIG_ENDIAN);
        break;
    case 0x00000001:
        proto_tree_add_item(ndps_tree, hf_ndps_port, tvb, foffset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ndps_tree, hf_ndps_ip, tvb, foffset+2, 4, ENC_BIG_ENDIAN);
        break;
    default:
        break;
    }
    tvb_ensure_bytes_exist(tvb, foffset, addr_len);
    foffset += addr_len;
    return foffset+(addr_len%4);
}

static int
address_item(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     addr_type=0;

    addr_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_address_type, tvb, foffset, 4, addr_type);
    foffset += 4;
    switch(addr_type)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
        foffset = qualifiedname(tvb, ndps_tree, foffset);
        break;
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
        foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
        break;
    case 13:
        proto_tree_add_item(ndps_tree, hf_ndps_attrib_boolean, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        break;
    case 14:
        proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        break;
    case 15:
        foffset = print_address(tvb, ndps_tree, foffset);
        break;
    case 16:
    case 17:
    default:
        foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
        break;
    }
    return foffset;
}

static int
credentials(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     cred_type=0;
    guint32     length=0;
    guint32     number_of_items;
    guint32     i;
    proto_tree  *atree;
    proto_item  *aitem;

    cred_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_item(ndps_tree, hf_ndps_cred_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
    foffset += 4;
    switch (cred_type)
    {
    case 0:
        foffset = ndps_string(tvb, hf_ndps_user_name, ndps_tree, foffset, NULL);
        number_of_items=tvb_get_ntohl(tvb, foffset);
        proto_tree_add_uint(ndps_tree, hf_ndps_num_passwords, tvb, foffset, 4, number_of_items);
        foffset += 4;
        for (i = 1 ; i <= number_of_items; i++ )
        {
            if (i > NDPS_MAX_ITEMS) {
                proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                break;
            }
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Password %d", i);
            atree = proto_item_add_subtree(aitem, ett_ndps);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(atree, hf_ndps_password, tvb, foffset, length, ENC_NA);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset += length;
        }
        break;
    case 1:
        length = tvb_get_ntohl(tvb, foffset);
        foffset += 4;
        if (length!=0)
        {
            tvb_ensure_bytes_exist(tvb, foffset, length);
            proto_tree_add_item(ndps_tree, hf_ndps_certified, tvb, foffset, length, ENC_NA);
        }
        foffset += length;
        break;
    case 2:
        foffset = ndps_string(tvb, hf_ndps_server_name, ndps_tree, foffset, NULL);
        foffset += 2;
        proto_tree_add_item(ndps_tree, hf_ndps_connection, tvb, foffset, 2, ENC_BIG_ENDIAN);
        foffset += 2;
        break;
    case 3:
        length=tvb_get_ntohl(tvb, foffset);
        foffset = ndps_string(tvb, hf_ndps_server_name, ndps_tree, foffset, NULL);
        if (length == 0)
        {
            foffset += 2;
        }
        if (tvb_get_ntohs(tvb, foffset)==0)  /* NDPS 1.0 */
        {
            foffset+=2;
            if (tvb_get_ntohs(tvb, foffset)==0)  /* NDPS 1.1 */
            {
                foffset += 2;
            }
        }
        proto_tree_add_item(ndps_tree, hf_ndps_connection, tvb, foffset, 2, ENC_BIG_ENDIAN);
        foffset += 2;
        foffset = ndps_string(tvb, hf_ndps_user_name, ndps_tree, foffset, NULL);
        break;
    case 4:
        foffset = ndps_string(tvb, hf_ndps_server_name, ndps_tree, foffset, NULL);
        foffset += 2;
        proto_tree_add_item(ndps_tree, hf_ndps_connection, tvb, foffset, 2, ENC_BIG_ENDIAN);
        foffset += 2;
        foffset = ndps_string(tvb, hf_ndps_user_name, ndps_tree, foffset, NULL);
        foffset += 8;   /* Don't know what these 8 bytes signify */
        proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;   /* XXX - what does this count? */
        foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
        foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
        break;
    default:
        break;
    }
    return foffset;
}


static int
event_object_set(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     number_of_items;
    guint32     number_of_items2;
    guint32     i;
    guint32     j;
    guint32     object_identifier;
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;
    proto_tree  *ctree;
    proto_item  *citem;

    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event");
    atree = proto_item_add_subtree(aitem, ett_ndps);
    number_of_items = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(atree, hf_ndps_num_events, tvb, foffset, 4, number_of_items);
    foffset += 4;
    for (i = 1 ; i <= number_of_items; i++ )
    {
        if (i > NDPS_MAX_ITEMS) {
            proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
            break;
        }
        bitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event %u", i);
        btree = proto_item_add_subtree(bitem, ett_ndps);
        proto_tree_add_item(btree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        foffset = objectidentifier(tvb, btree, foffset);
        foffset += align_4(tvb, foffset);
        foffset = objectidentification(tvb, btree, foffset);
        foffset += align_4(tvb, foffset);
        proto_tree_add_item(btree, hf_ndps_object_op, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        object_identifier = tvb_get_ntohl(tvb, foffset);
        proto_tree_add_uint(btree, hf_ndps_event_object_identifier, tvb, foffset, 4, object_identifier);
        foffset += 4;
        switch (object_identifier)
        {
            case 1:
                foffset = objectidentifier(tvb, btree, foffset);
                foffset += align_4(tvb, foffset);
                break;

            case 2:
                number_of_items2 = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_item_count, tvb, foffset, 4, number_of_items2);
                foffset += 4;
                for (j = 1 ; j <= number_of_items2; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Item %u", j);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = objectidentifier(tvb, ctree, foffset);
                    foffset += align_4(tvb, foffset);
                    proto_item_set_end(citem, tvb, foffset);
                }
                break;
        }
        proto_item_set_end(bitem, tvb, foffset);
    }
    proto_item_set_end(aitem, tvb, foffset);
    return foffset;
}


static int
cardinal_seq(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     number_of_items;
    guint32     length;
    guint32     i;
    proto_tree  *atree;
    proto_item  *aitem;

    number_of_items = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
    foffset += 4;
    for (i = 1 ; i <= number_of_items; i++ )
    {
        if (i > NDPS_MAX_ITEMS) {
            proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
            break;
        }
        aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Cardinal %u", i);
        atree = proto_item_add_subtree(aitem, ett_ndps);
        length = tvb_get_ntohl(tvb, foffset);
        foffset += 4;
        if (length==4)
        {
            proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
        }
        tvb_ensure_bytes_exist(tvb, foffset, length);
        foffset += length;
        foffset += (length%2);
        if ((int) foffset <= 0)
            THROW(ReportedBoundsError);
        proto_item_set_end(aitem, tvb, foffset);
    }
    return foffset;
}


static int
server_entry(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    char        *server_name;
    guint32     number_of_items;
    guint32     i;
    guint32     data_type;
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;

    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Server Info");
    atree = proto_item_add_subtree(aitem, ett_ndps);
    foffset = ndps_string(tvb, hf_ndps_server_name, ndps_tree, foffset, &server_name);
    proto_item_append_text(aitem, ": %s", format_text(server_name, strlen(server_name)));
    proto_tree_add_item(atree, hf_ndps_server_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
    foffset += 4;
    foffset = print_address(tvb, atree, foffset);
    number_of_items = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(atree, hf_ndps_num_servers, tvb, foffset, 4, number_of_items);
    foffset += 4;
    for (i = 1 ; i <= number_of_items; i++ )
    {
        if (i > NDPS_MAX_ITEMS) {
            proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
            break;
        }
        bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Info %u", i);
        btree = proto_item_add_subtree(bitem, ett_ndps);
        data_type = tvb_get_ntohl(tvb, foffset);
        proto_tree_add_item(btree, hf_ndps_data_item_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        switch (data_type)
        {
        case 0:   /* Int8 */
            proto_tree_add_item(btree, hf_info_int, tvb, foffset, 1, ENC_BIG_ENDIAN);
            foffset++;
            break;
        case 1:   /* Int16 */
            proto_tree_add_item(btree, hf_info_int16, tvb, foffset, 2, ENC_BIG_ENDIAN);
            foffset += 2;
            break;
        case 2:   /* Int32 */
            proto_tree_add_item(btree, hf_info_int32, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 3:   /* Boolean */
            proto_tree_add_item(btree, hf_info_boolean, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 4:   /* String */
        case 5:   /* Bytes */
            foffset = ndps_string(tvb, hf_info_string, btree, foffset, NULL);
            break;
        default:
            break;
        }
        proto_item_set_end(bitem, tvb, foffset);
    }
    proto_item_set_end(aitem, tvb, foffset);
    return foffset;
}


static int
attribute_value(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     i;
    guint32     j;
    guint32     number_of_items;
    guint32     number_of_items2;
    guint32     attribute_type;
    guint32     integer_or_oid;
    guint32     event_object_type;
    guint32     ignored_type;
    guint32     resource_type;
    guint32     identifier_type;
    guint32     criterion_type;
    guint32     card_enum_time;
    guint32     media_type;
    guint32     doc_content;
    guint32     page_size;
    guint32     medium_size;
    guint32     numbers_up;
    guint32     colorant_set;
    guint32     length;
    guint32     dimension;
    guint32     location;
    guint32     cardinal;
    const char  *label;
    guint32     label_value;
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;

    if (global_attribute_name==NULL)
    {
        label_value = 1;
        label = match_strval(label_value, object_ids_7);
        global_attribute_name = label;
    }
    attribute_type = tvb_get_ntohl(tvb, foffset);
    if (ndps_show_oids)
    {
        proto_tree_add_item(ndps_tree, hf_ndps_obj_attribute_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
    }
    foffset += 4;
    switch(attribute_type)
    {
        case 0:         /* Null */
            proto_tree_add_item(ndps_tree, hf_ndps_data, tvb, foffset+4, tvb_get_ntohl(tvb, foffset), ENC_NA);
            break;
        case 1:         /* Text */
        case 2:         /* Descriptive Name */
        case 3:         /* Descriptor */
        case 6:         /* Simple Name */
        case 40:         /* Distinguished Name*/
        case 50:         /* Font Reference */
        case 58:         /* Locale */
        case 102:         /* File Path */
        case 103:         /* Uniform Resource Identifier */
        case 108:         /* Extended Resource Identifier */
            foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
            break;
        case 4:         /* Message */
        case 5:         /* Error Message */
        case 38:         /* Name or OID */
            foffset = name_or_id(tvb, ndps_tree, foffset);
            break;
        case 39:         /* Name or OID Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = name_or_id(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 7:         /* Distinguished Name String*/
        case 79:         /* File Reference */
            foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
            foffset = name_or_id(tvb, ndps_tree, foffset);
            break;
        case 8:         /* Distinguished Name String Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Name %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
                foffset = name_or_id(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 9:          /* Delta Time */
        case 10:         /* Time */
        case 11:         /* Integer */
        case 13:         /* Cardinal */
        case 15:         /* Positive Integer */
        case 18:         /* Maximum Integer */
        case 19:         /* Minimum Integer */
        case 35:         /* Percent */
        case 57:         /* Job Priority */
        case 72:         /* Sides */
        case 95:         /* Enumeration */
            if (global_attribute_name != NULL &&
                strcmp(global_attribute_name,"(Novell) Attribute PRINTER SECURITY LEVEL")==0)
            {
                proto_tree_add_item(ndps_tree, hf_print_security, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            else
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        case 12:         /* Integer Seq */
        case 14:         /* Cardinal Seq */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_info_int32, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            tvb_ensure_bytes_exist(tvb, foffset, length);
            foffset += length;
            break;
        case 16:         /* Integer Range */
        case 17:         /* Cardinal Range */
            proto_tree_add_item(ndps_tree, hf_ndps_lower_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_upper_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 20:         /* Integer 64 */
        case 22:         /* Cardinal 64 */
        case 24:         /* Positive Integer 64 */
        case 31:         /* Non-Negative Real */
        case 29:         /* Real */
            proto_tree_add_item(ndps_tree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 21:         /* Integer 64 Seq */
        case 23:         /* Cardinal 64 Seq */
        case 30:         /* Real Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 25:         /* Integer 64 Range */
        case 26:         /* Cardinal 64 Range */
        case 32:         /* Real Range */
        case 33:         /* Non-Negative Real Range */
            proto_tree_add_item(ndps_tree, hf_ndps_lower_range_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            proto_tree_add_item(ndps_tree, hf_ndps_upper_range_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 27:         /* Maximum Integer 64 */
            proto_tree_add_item(ndps_tree, hf_ndps_lower_range_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 28:         /* Minimum Integer 64 */
            proto_tree_add_item(ndps_tree, hf_ndps_upper_range_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 34:         /* Boolean */
            proto_tree_add_item(ndps_tree, hf_ndps_attrib_boolean, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 36:         /* Object Identifier */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            break;
        case 37:         /* Object Identifier Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = objectidentifier(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 41:         /* Relative Distinguished Name Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_names, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Name %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 42:         /* Realization */
            proto_tree_add_item(ndps_tree, hf_ndps_realization, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 43:         /* Medium Dimensions */
            proto_tree_add_item(ndps_tree, hf_ndps_xdimension_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            proto_tree_add_item(ndps_tree, hf_ndps_ydimension_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 44:         /* Dimension */
            dimension = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_dim_value, tvb, foffset, 4, dimension);
            foffset += 4;
            if (dimension == 0) {
                proto_tree_add_item(ndps_tree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
            }
            else
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            proto_tree_add_item(ndps_tree, hf_ndps_dim_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 45:         /* XY Dimensions */
            dimension = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_xydim_value, tvb, foffset, 4, dimension);
            foffset += 4;
            if (dimension == 1) {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            else
            {
                proto_tree_add_item(ndps_tree, hf_ndps_xdimension_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ydimension_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
            }
            proto_tree_add_item(ndps_tree, hf_ndps_dim_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 46:         /* Locations */
            location = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_location_value, tvb, foffset, 4, location);
            foffset += 4;
            if (location == 0) {
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_num_locations, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Location %u", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
                    foffset += 8;
                    proto_item_set_end(aitem, tvb, foffset);
                }
            }
            else
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            proto_tree_add_item(ndps_tree, hf_ndps_dim_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 47:         /* Area */
            proto_tree_add_item(ndps_tree, hf_ndps_xmin_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            proto_tree_add_item(ndps_tree, hf_ndps_xmax_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            proto_tree_add_item(ndps_tree, hf_ndps_ymin_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            proto_tree_add_item(ndps_tree, hf_ndps_ymax_n64, tvb, foffset, 8, ENC_NA);
            foffset += 8;
            break;
        case 48:         /* Area Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_areas, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Area %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_xmin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(atree, hf_ndps_xmax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(atree, hf_ndps_ymin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(atree, hf_ndps_ymax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 49:         /* Edge */
            proto_tree_add_item(ndps_tree, hf_ndps_edge_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 51:         /* Cardinal or OID */
            cardinal = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_cardinal_or_oid, tvb, foffset, 4, cardinal);
            foffset += 4;
            if (cardinal==0) {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            else
            {
                foffset = objectidentifier(tvb, ndps_tree, foffset);
            }
            break;
        case 52:         /* OID Cardinal Map */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 53:         /* Cardinal or Name or OID */
            cardinal = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_cardinal_name_or_oid, tvb, foffset, 4, cardinal);
            foffset += 4;
            if (cardinal==0) {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            else
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            break;
        case 54:         /* Positive Integer or OID */
            integer_or_oid = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_integer_or_oid, tvb, foffset, 4, integer_or_oid);
            foffset += 4;
            if (integer_or_oid==0) {
                foffset = objectidentifier(tvb, ndps_tree, foffset);
            }
            else
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        case 55:         /* Event Handling Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = name_or_id(tvb, ndps_tree, foffset);

            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_address_items, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Address Item %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = address_item(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_events, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = objectidentifier(tvb, atree, foffset);
                foffset += align_4(tvb, foffset);
                foffset = objectidentification(tvb, atree, foffset);
                proto_tree_add_item(atree, hf_ndps_object_op, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                event_object_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_event_object_identifier, tvb, foffset, 4, event_object_type);
                foffset += 4;
                switch (event_object_type)
                {
                    case 2:
                        /* Number of Objects */
                        number_of_items2 = tvb_get_ntohl(tvb, foffset);
                        proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items2);
                        foffset += 4;
                        for (j = 1 ; j <= number_of_items2; j++ )
                        {
                            if (j > NDPS_MAX_ITEMS) {
                                proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                                break;
                            }
                            foffset = objectidentifier(tvb, atree, foffset);
                        }
                        foffset += 4;
                        break;

                    case 1:
                        foffset = objectidentifier(tvb, atree, foffset);
                        break;

                    case 0:
                        number_of_items2 = tvb_get_ntohl(tvb, foffset);
                        proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items2);
                        foffset += 4;
                        for (j = 1 ; j <= number_of_items2; j++ )
                        {
                            if (j > NDPS_MAX_ITEMS) {
                                proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                                break;
                            }
                            bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object %u", i);
                            btree = proto_item_add_subtree(bitem, ett_ndps);
                            foffset = objectidentifier(tvb, btree, foffset);
                            proto_item_set_end(bitem, tvb, foffset);
                        }
                        break;
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 56:         /* Octet String */
        case 63:         /* Job Password */
        case 66:         /* Print Checkpoint */
            length = tvb_get_ntohl(tvb, foffset);
            ndps_string(tvb, hf_info_string, ndps_tree, foffset, NULL);
            foffset += length+2;
            foffset += align_4(tvb, foffset);
            break;
        case 59:         /* Method Delivery Address */
            proto_tree_add_item(ndps_tree, hf_ndps_delivery_add_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            event_object_type = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            switch(event_object_type)
            {
                case 0:     /*MHS ADDR*/
                case 1:     /*DISTINGUISHED_NAME*/
                case 2:     /*TEXT*/
                case 3:     /*OCTET_STRING*/
                    foffset = ndps_string(tvb, hf_info_string, ndps_tree, foffset, NULL);
                    break;
                case 4:     /*DIST_NAME_STRING*/
                    foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
                    foffset = name_or_id(tvb, ndps_tree, foffset);
                    break;
                case 5:     /*RPC_ADDRESS*/
                case 6:     /*QUALIFIED_NAME*/
                    foffset = objectidentifier(tvb, ndps_tree, foffset);
                    foffset = qualifiedname(tvb, ndps_tree, foffset);
                    break;
                default:
                    break;
            }
            break;
        case 60:         /* Object Identification */
            foffset = objectidentification(tvb, ndps_tree, foffset);
            break;
        case 61:         /* Results Profile */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            foffset = name_or_id(tvb, ndps_tree, foffset);
            foffset = address_item(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = name_or_id(tvb, ndps_tree, foffset);
            break;
        case 62:         /* Criteria */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            criterion_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_criterion_type, tvb, foffset, 4, criterion_type);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 64:         /* Job Level */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 65:         /* Job Categories */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_job_categories, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                foffset += length;
                foffset += (length%2);
                if ((int) foffset <= 0)
                    THROW(ReportedBoundsError);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 67:         /* Ignored Attribute */
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_ignored_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Ignored Attribute %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                ignored_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_ignored_type, tvb, foffset, 4, ignored_type);
                foffset += 4;
                if (ignored_type == 38)
                {
                    foffset = name_or_id(tvb, atree, foffset);
                }
                else
                {
                    foffset = objectidentifier(tvb, atree, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 68:         /* Resource */
            resource_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_resource_type, tvb, foffset, 4, resource_type);
            foffset += 4;
            if (resource_type == 0)
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            else
            {
                foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
            }
            break;
        case 69:         /* Medium Substitution */
            foffset = name_or_id(tvb, ndps_tree, foffset);
            foffset = name_or_id(tvb, ndps_tree, foffset);
            break;
        case 70:         /* Font Substitution */
            foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
            break;
        case 71:         /* Resource Context Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_resources, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resource %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                resource_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_resource_type, tvb, foffset, 4, resource_type);
                foffset += 4;
                if (resource_type == 0)
                {
                    foffset = name_or_id(tvb, atree, foffset);
                }
                else
                {
                    foffset = ndps_string(tvb, hf_ndps_tree, atree, foffset, NULL);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 73:         /* Page Select Seq */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_page_selects, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Page Select %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_page_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                identifier_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_identifier_type, tvb, foffset, 4, identifier_type);
                foffset += 4;
                if (identifier_type == 0)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                if (identifier_type == 1)
                {
                    foffset = ndps_string(tvb, hf_ndps_tree, atree, foffset, NULL);
                }
                if (identifier_type == 2)
                {
                    foffset = name_or_id(tvb, atree, foffset);
                }
                proto_tree_add_item(atree, hf_ndps_page_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                identifier_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_identifier_type, tvb, foffset, 4, identifier_type);
                foffset += 4;
                if (identifier_type == 0)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                if (identifier_type == 1)
                {
                    foffset = ndps_string(tvb, hf_ndps_tree, atree, foffset, NULL);
                }
                if (identifier_type == 2)
                {
                    foffset = name_or_id(tvb, atree, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 74:         /* Page Media Select */
            media_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_media_type, tvb, foffset, 4, media_type);
            foffset += 4;
            if (media_type == 0)
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            else
            {
                foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %u", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    proto_tree_add_item(atree, hf_ndps_page_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    identifier_type = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(atree, hf_ndps_identifier_type, tvb, foffset, 4, identifier_type);
                    foffset += 4;
                    if (identifier_type == 0)
                    {
                        proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        foffset += 4;
                    }
                    if (identifier_type == 1)
                    {
                        foffset = ndps_string(tvb, hf_ndps_tree, atree, foffset, NULL);
                    }
                    if (identifier_type == 2)
                    {
                        foffset = name_or_id(tvb, atree, foffset);
                    }
                    proto_item_set_end(aitem, tvb, foffset);
                }
            }
            break;
        case 75:         /* Document Content */
            doc_content = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_doc_content, tvb, foffset, 4, doc_content);
            foffset += 4;
            if (doc_content == 0)
            {
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                if ((int) foffset <= 0)
                    THROW(ReportedBoundsError);
            }
            else
            {
                foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            break;
        case 76:         /* Page Size */
            page_size = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_page_size, tvb, foffset, 4, page_size);
            foffset += 4;
            if (page_size == 0)
            {
                foffset = objectidentifier(tvb, ndps_tree, foffset);
            }
            else
            {
                proto_tree_add_item(ndps_tree, hf_ndps_xdimension_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ydimension_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
            }
            break;
        case 77:         /* Presentation Direction */
            proto_tree_add_item(ndps_tree, hf_ndps_direction, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 78:         /* Page Order */
            proto_tree_add_item(ndps_tree, hf_ndps_page_order, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 80:         /* Medium Source Size */
            foffset = name_or_id(tvb, ndps_tree, foffset);
            medium_size = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_medium_size, tvb, foffset, 4, medium_size);
            foffset += 4;
            if (medium_size == 0)
            {
                page_size = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_page_size, tvb, foffset, 4, page_size);
                foffset += 4;
                if (page_size == 0)
                {
                    foffset = objectidentifier(tvb, ndps_tree, foffset);
                }
                else
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_xdimension_n64, tvb, foffset, 8, ENC_NA);
                    foffset += 8;
                    proto_tree_add_item(ndps_tree, hf_ndps_ydimension_n64, tvb, foffset, 8, ENC_NA);
                    foffset += 8;
                }
                proto_tree_add_item(ndps_tree, hf_ndps_long_edge_feeds, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_ndps_xmin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_xmax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ymin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ymax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
            }
            else
            {
                proto_tree_add_item(ndps_tree, hf_ndps_lower_range_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_upper_range_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_inc_across_feed, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_lower_range_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_upper_range_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_size_inc_in_feed, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_long_edge_feeds, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_ndps_xmin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_xmax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ymin_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
                proto_tree_add_item(ndps_tree, hf_ndps_ymax_n64, tvb, foffset, 8, ENC_NA);
                foffset += 8;
            }
            break;
        case 81:         /* Input Tray Medium */
            foffset = name_or_id(tvb, ndps_tree, foffset);
            foffset = name_or_id(tvb, ndps_tree, foffset);
            break;
        case 82:         /* Output Bins Characteristics */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_page_informations, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Page Information %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_page_order, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(atree, hf_ndps_page_orientation, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 83:         /* Page ID Type */
            proto_tree_add_item(ndps_tree, hf_ndps_identifier_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 84:         /* Level Range */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_lower_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_upper_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 85:         /* Category Set */
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_categories, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Category %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                foffset += length;
                foffset += (length%2);
                if ((int) foffset <= 0)
                    THROW(ReportedBoundsError);
            }
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_values, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Value %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                foffset += length;
                foffset += (length%2);
                if ((int) foffset <= 0)
                    THROW(ReportedBoundsError);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 86:         /* Numbers Up Supported */
            numbers_up=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_numbers_up, tvb, foffset, 4, numbers_up);
            foffset += 4;
            switch(numbers_up)
            {
            case 0:     /*Cardinal*/
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            case 1:     /*Name or OID*/
                foffset = name_or_id(tvb, ndps_tree, foffset);
                break;
            case 2:     /*Cardinal Range*/
                proto_tree_add_item(ndps_tree, hf_ndps_lower_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_ndps_upper_range, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            default:
                break;
            }
            break;
        case 87:         /* Finishing */
        case 88:         /* Print Contained Object ID */
            foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 89:         /* Print Config Object ID */
            foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 90:         /* Typed Name */
            foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_level, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_interval, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 91:         /* Network Address */
            proto_tree_add_item(ndps_tree, hf_ndps_address, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_add_bytes, tvb, foffset, 4, ENC_NA);
            }
            foffset += length;
            break;
        case 92:         /* XY Dimensions Value */
            dimension = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_xydim_value, tvb, foffset, 4, dimension);
            foffset += 4;
            switch (dimension)
            {
                case 1:
                    foffset = name_or_id(tvb, ndps_tree, foffset);
                    break;

                case 0:
                    proto_tree_add_item(ndps_tree, hf_ndps_xdimension_n64, tvb, foffset, 8, ENC_NA);
                    foffset += 8;
                    proto_tree_add_item(ndps_tree, hf_ndps_ydimension_n64, tvb, foffset, 8, ENC_NA);
                    foffset += 8;
                    break;

                default:
                    proto_tree_add_item(ndps_tree, hf_ndps_xdimension, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item(ndps_tree, hf_ndps_ydimension, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    break;
            }
            break;
        case 93:         /* Name or OID Dimensions Map */
            foffset = name_or_id(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_xdimension, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_ydimension, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 94:         /* Printer State Reason */
            foffset += 4;
            foffset = name_or_id(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_state_severity, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_training, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            foffset += align_4(tvb, foffset);
            foffset = objectidentification(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4*number_of_items;
            /*foffset += align_4(tvb, foffset);*/
            foffset = name_or_id(tvb, ndps_tree, foffset);

            break;
        case 96:         /* Qualified Name */
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 97:         /* Qualified Name Set */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_names, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Name %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = qualifiedname(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 98:         /* Colorant Set */
            colorant_set = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_colorant_set, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (colorant_set==0)
            {
                foffset = name_or_id(tvb, ndps_tree, foffset);
            }
            else
            {

                foffset = objectidentifier(tvb, ndps_tree, foffset);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_num_colorants, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Colorant %u", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = name_or_id(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                }
            }
            break;
        case 99:         /* Resource Printer ID */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_printer_def_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Printer %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_printer_type, atree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_printer_manuf, atree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_inf_file_name, atree, foffset, NULL);
                proto_item_set_end(aitem, tvb, foffset);
            }
            proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 100:         /* Event Object ID */
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 101:         /* Qualified Name Map */
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 104:         /* Cardinal or Enum or Time */
            card_enum_time = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_card_enum_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            switch (card_enum_time)
            {
                case 0:
                    proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    break;

                case 1:
                    proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    break;

                default:
                    proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    break;
            }
            break;
        case 105:         /* Print Contained Object ID Set */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 106:         /* Octet String Pair */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset += (length%2);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset += (length%2);
            if ((int) foffset <= 0)
                THROW(ReportedBoundsError);
            break;
        case 107:         /* Octet String Integer Pair */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset += (length%2);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 109:         /* Event Handling Profile 2 */
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset += (length%2);
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = name_or_id(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_delivery_add_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            event_object_type = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            switch(event_object_type)
            {
                case 0:     /*MHS ADDR*/
                case 1:     /*DISTINGUISHED_NAME*/
                case 2:     /*TEXT*/
                    foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
                    break;
                case 3:     /*OCTET_STRING*/
                    length = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    if (length!=0)
                    {
                        tvb_ensure_bytes_exist(tvb, foffset, length);
                        proto_tree_add_item(ndps_tree, hf_ndps_octet_string, tvb, foffset, length, ENC_NA);
                    }
                    foffset += length;
                    foffset += (length%2);
                    if ((int) foffset <= 0)
                        THROW(ReportedBoundsError);
                    break;
                case 4:     /*DIST_NAME_STRING*/
                    foffset = ndps_string(tvb, hf_object_name, ndps_tree, foffset, NULL);
                    foffset = name_or_id(tvb, ndps_tree, foffset);
                    break;
                case 5:     /*RPC_ADDRESS*/
                case 6:     /*QUALIFIED_NAME*/
                    foffset = objectidentifier(tvb, ndps_tree, foffset);
                    foffset = qualifiedname(tvb, ndps_tree, foffset);
                    break;
                default:
                    break;
            }
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_events, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_object_name, atree, foffset, NULL);
                foffset = objectidentifier(tvb, atree, foffset);
                proto_tree_add_item(atree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
            }
            foffset = objectidentifier(tvb, ndps_tree, foffset);
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = objectidentifier(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            break;
        default:
            break;
    }
    return foffset;
}


static int
commonarguments(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     number_of_items;
    guint32     i;
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;

    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Common Arguments");
    atree = proto_item_add_subtree(aitem, ett_ndps);
    number_of_items = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(atree, hf_ndps_num_args, tvb, foffset, 4, number_of_items);
    foffset += 4;
    for (i = 1 ; i <= number_of_items; i++ )
    {
        if (i > NDPS_MAX_ITEMS) {
            proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
            break;
        }
        bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Argument %u", i);
        btree = proto_item_add_subtree(bitem, ett_ndps);
        foffset = attribute_value(tvb, btree, foffset);
        proto_item_set_end(bitem, tvb, foffset);
    }
    proto_item_set_end(aitem, tvb, foffset);
    return foffset;
}

static int
res_add_input_data(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     resource_type=0;

    resource_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_res_type, tvb, foffset, 4, resource_type);
    foffset += 4;
    switch (resource_type)
    {
    case 0:     /* Print Drivers */
        proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        foffset = ndps_string(tvb, hf_ndps_prn_dir_name, ndps_tree, foffset, NULL);
        foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
        break;
    case 1:     /* Printer Definitions */
        foffset = ndps_string(tvb, hf_ndps_vendor_dir, ndps_tree, foffset, NULL);
        foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
        break;
    case 2:     /* Banner Page Files */
        foffset = ndps_string(tvb, hf_ndps_banner_name, ndps_tree, foffset, NULL);
        break;
    case 3:     /* Font Types */
        proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_font_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
        break;
    case 4:     /* Generic Files/ Archive */
    case 5:     /* Printer Driver Archive */
        proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        foffset = ndps_string(tvb, hf_ndps_prn_dir_name, ndps_tree, foffset, NULL);
        proto_tree_add_item(ndps_tree, hf_archive_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        break;
    default:
        break;
    }
    return foffset;
}


static const fragment_items ndps_frag_items = {
    &ett_ndps_segment,
    &ett_ndps_segments,
    &hf_ndps_segments,
    &hf_ndps_segment,
    &hf_ndps_segment_overlap,
    &hf_ndps_segment_overlap_conflict,
    &hf_ndps_segment_multiple_tails,
    &hf_ndps_segment_too_long_segment,
    &hf_ndps_segment_error,
    &hf_ndps_segment_count,
    NULL,
    &hf_ndps_reassembled_length,
    "segments"
};

static dissector_handle_t ndps_data_handle;

/* NDPS packets come in request/reply pairs. The request packets tell the
 * Function and Program numbers. The response, unfortunately, only
 * identifies itself via the Exchange ID; you have to know what type of NDPS
 * request the request packet contained in order to successfully parse the
 * response. A global method for doing this does not exist in wireshark yet
 * (NFS also requires it), so for now the NDPS section will keep its own hash
 * table keeping track of NDPS packets.
 *
 * We construct a conversation specified by the client and server
 * addresses and the connection number; the key representing the unique
 * NDPS request then is composed of the pointer to the conversation
 * structure, cast to a "guint" (which may throw away the upper 32
 * bits of the pointer on a P64 platform, but the low-order 32 bits
 * are more likely to differ between conversations than the upper 32 bits),
 * and the sequence number.
 *
 * The value stored in the hash table is the ncp_req_hash_value pointer. This
 * struct tells us the NDPS Program and Function and gives the NDPS_record pointer.
 */
typedef struct {
    conversation_t      *conversation;
    guint32              ndps_xport;
} ndps_req_hash_key;

typedef struct {
    guint32             ndps_prog;
    guint32             ndps_func;
    guint32             ndps_frame_num;
    gboolean            ndps_frag;
    guint32             ndps_end_frag;
} ndps_req_hash_value;

static GHashTable *ndps_req_hash = NULL;

/* Hash Functions */
static gint
ndps_equal(gconstpointer v, gconstpointer v2)
{
    const ndps_req_hash_key     *val1 = (const ndps_req_hash_key*)v;
    const ndps_req_hash_key     *val2 = (const ndps_req_hash_key*)v2;

    if (val1->conversation == val2->conversation &&
        val1->ndps_xport   == val2->ndps_xport ) {
        return 1;
    }
    return 0;
}

static guint
ndps_hash(gconstpointer v)
{
    const ndps_req_hash_key *ndps_key = (const ndps_req_hash_key*)v;
    return GPOINTER_TO_UINT(ndps_key->conversation) + ndps_key->ndps_xport;
}

/* Initializes the hash table each time a new
 * file is loaded or re-loaded in wireshark */
static void
ndps_init_protocol(void)
{
    /* fragment */
    fragment_table_init(&ndps_fragment_table);
    reassembled_table_init(&ndps_reassembled_table);

    if (ndps_req_hash)
        g_hash_table_destroy(ndps_req_hash);

    ndps_req_hash = g_hash_table_new(ndps_hash, ndps_equal);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
ndps_postseq_cleanup(void)
{
    if (ndps_req_hash) {
        /* Destroy the hash, but don't clean up request_condition data. */
        g_hash_table_destroy(ndps_req_hash);
        ndps_req_hash = NULL;
    }
    /* Don't free the ncp_req_hash_values, as they're
     * needed during random-access processing of the proto_tree.*/
}

static ndps_req_hash_value*
ndps_hash_insert(conversation_t *conversation, guint32 ndps_xport)
{
    ndps_req_hash_key           *request_key;
    ndps_req_hash_value         *request_value;

    /* Now remember the request, so we can find it if we later
       a reply to it. */
    request_key = se_alloc(sizeof(ndps_req_hash_key));
    request_key->conversation = conversation;
    request_key->ndps_xport = ndps_xport;

    request_value = se_alloc(sizeof(ndps_req_hash_value));
    request_value->ndps_prog = 0;
    request_value->ndps_func = 0;
    request_value->ndps_frame_num = 0;
    request_value->ndps_frag = FALSE;
    request_value->ndps_end_frag = 0;

    g_hash_table_insert(ndps_req_hash, request_key, request_value);

    return request_value;
}

/* Returns the ncp_rec*, or NULL if not found. */
static ndps_req_hash_value*
ndps_hash_lookup(conversation_t *conversation, guint32 ndps_xport)
{
    ndps_req_hash_key           request_key;

    request_key.conversation = conversation;
    request_key.ndps_xport = ndps_xport;

    return g_hash_table_lookup(ndps_req_hash, &request_key);
}

/* ================================================================= */
/* NDPS                                                               */
/* ================================================================= */

static void
dissect_ndps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree)
{
    guint32     ndps_xid;
    guint32     ndps_prog;
    guint32     ndps_packet_type;
    int         foffset;
    guint32     ndps_hfname;
    guint32     ndps_func;
    const char  *ndps_program_string;
    const char  *ndps_func_string;


    ndps_packet_type = tvb_get_ntohl(tvb, 8);
    if (ndps_packet_type != 0 && ndps_packet_type != 1) {     /* Packet Type */
        col_set_str(pinfo->cinfo, COL_INFO, "(Continuation Data)");
        proto_tree_add_text(ndps_tree, tvb, 0, tvb_length(tvb), "Data - (%d Bytes)", tvb_length(tvb));
        return;
    }
    foffset = 0;
    proto_tree_add_item(ndps_tree, hf_ndps_record_mark, tvb,
                   foffset, 2, ENC_BIG_ENDIAN);
    foffset += 2;
    proto_tree_add_item(ndps_tree, hf_ndps_length, tvb,
                   foffset, 2, ENC_BIG_ENDIAN);
    foffset += 2;

    ndps_xid = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_xid, tvb, foffset, 4, ndps_xid);
    foffset += 4;
    ndps_packet_type = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_packet_type, tvb, foffset, 4, ndps_packet_type);
    foffset += 4;
    if(ndps_packet_type == 0x00000001)          /* Reply packet */
    {
        col_set_str(pinfo->cinfo, COL_INFO, "R NDPS ");
        proto_tree_add_item(ndps_tree, hf_ndps_rpc_accept, tvb, foffset, 4, ENC_BIG_ENDIAN);
        if (tvb_get_ntohl(tvb, foffset)==0) {
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_auth_null, tvb, foffset, 8, ENC_NA);
            foffset += 8;
        }
        else
        {
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_rpc_rej_stat, tvb, foffset+4, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        dissect_ndps_reply(tvb, pinfo, ndps_tree, foffset);
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_INFO, "C NDPS ");
        proto_tree_add_item(ndps_tree, hf_ndps_rpc_version, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        ndps_prog = tvb_get_ntohl(tvb, foffset);
        ndps_program_string = match_strval(ndps_prog, spx_ndps_program_vals);
        if( ndps_program_string != NULL)
        {
            proto_tree_add_item(ndps_tree, hf_spx_ndps_program, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO))
            {
                col_append_str(pinfo->cinfo, COL_INFO, (const gchar*) ndps_program_string);
                col_append_str(pinfo->cinfo, COL_INFO, ", ");
            }
            proto_tree_add_item(ndps_tree, hf_spx_ndps_version, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            ndps_func = tvb_get_ntohl(tvb, foffset);
            switch(ndps_prog)
            {
                case 0x060976:
                    ndps_hfname = hf_spx_ndps_func_print;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_print_func_vals);
                    break;
                case 0x060977:
                    ndps_hfname = hf_spx_ndps_func_broker;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_broker_func_vals);
                    break;
                case 0x060978:
                    ndps_hfname = hf_spx_ndps_func_registry;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_registry_func_vals);
                    break;
                case 0x060979:
                    ndps_hfname = hf_spx_ndps_func_notify;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_notify_func_vals);
                    break;
                case 0x06097a:
                    ndps_hfname = hf_spx_ndps_func_resman;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_resman_func_vals);
                    break;
                case 0x06097b:
                    ndps_hfname = hf_spx_ndps_func_delivery;
                    ndps_func_string = match_strval(ndps_func, spx_ndps_deliver_func_vals);
                    break;
                default:
                    ndps_hfname = 0;
                    ndps_func_string = NULL;
                    break;
            }
            if(ndps_hfname != 0)
            {
                proto_tree_add_item(ndps_tree, ndps_hfname, tvb, foffset, 4, ENC_BIG_ENDIAN);
                if (ndps_func_string != NULL)
                {
                    if (check_col(pinfo->cinfo, COL_INFO))
                        col_append_str(pinfo->cinfo, COL_INFO, (const gchar*) ndps_func_string);

                    foffset += 4;
                    proto_tree_add_item(ndps_tree, hf_ndps_auth_null, tvb, foffset, 16, ENC_NA);
                    foffset+=16;
                    dissect_ndps_request(tvb, pinfo, ndps_tree, ndps_prog, ndps_func, foffset);
                }
            }
        }
    }
}

static guint
get_ndps_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return tvb_get_ntohs(tvb, offset +2) + 4;
}

static void
dissect_ndps_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *ndps_tree = NULL;
    proto_item      *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDPS");

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ndps, tvb, 0, -1, ENC_NA);
        ndps_tree = proto_item_add_subtree(ti, ett_ndps);
    }
    dissect_ndps(tvb, pinfo, ndps_tree);
}

/*
 * Defrag logic
 *
 * SPX EOM not being set indicates we are inside or at the
 * beginning of a fragment. But when the end of the fragment
 * is encounterd the flag is set. So we must mark what the
 * frame number is of the end fragment so that we will be
 * able to redissect if the user clicks on the packet
 * or resorts/filters the trace.
 *
 * Once we are certain that we are in a fragment sequence
 * then we can just process each fragment in this conversation
 * until we reach the eom message packet. We can tell we are at
 * the final fragment because it is flagged as SPX EOM.
 *
 * We will be able to easily determine if a conversation is a fragment
 * with the exception of the last packet in the fragment. So remember
 * the last fragment packet number.
 */
static void
ndps_defrag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint                 len=0;
    tvbuff_t            *next_tvb = NULL;
    fragment_data       *fd_head;
    spx_info            *spx_info_p;
    ndps_req_hash_value *request_value = NULL;
    conversation_t      *conversation;

    /* Get SPX info from SPX dissector */
    spx_info_p = pinfo->private_data;
    /* Check to see if defragmentation is enabled in the dissector */
    if (!ndps_defragment) {
        dissect_ndps(tvb, pinfo, tree);
        return;
    }
    /* Has this already been dissected? */
    if (!pinfo->fd->flags.visited)
    {
        /* Lets see if this is a new conversation */
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
            PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->srcport, 0);

        if (conversation == NULL)
        {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->srcport, 0);
        }

        /* So now we need to get the request info for this conversation */
        request_value = ndps_hash_lookup(conversation, (guint32) pinfo->srcport);
        if (request_value == NULL)
        {
            /* We haven't seen a packet with this conversation yet so create one. */
            request_value = ndps_hash_insert(conversation, (guint32) pinfo->srcport);
        }
        /* Add it to pinfo so we can get it on further dissection requests */
        p_add_proto_data(pinfo->fd, proto_ndps, (void*) request_value);
    }
    else
    {
        /* Get request value data */
        request_value = p_get_proto_data(pinfo->fd, proto_ndps);
    }
    if (!request_value)
    {
        /* Can't find the original request packet so this is not any fragment packet */
        dissect_ndps(tvb, pinfo, tree);
        return;
    }
    /* Check to see of this is a fragment. If so then mark as a fragment. */
    if (!spx_info_p->eom) {
        request_value->ndps_frag = TRUE;
    }
    /* Now we process the fragments */
    if (request_value->ndps_frag || (request_value->ndps_end_frag == pinfo->fd->num))
    {
        /*
         * Fragment
         */
        tid = (pinfo->srcport+pinfo->destport);
        len = tvb_reported_length(tvb);
        if (tvb_length(tvb) >= len)
        {
            fd_head = fragment_add_seq_next(tvb, 0, pinfo, tid, ndps_fragment_table, ndps_reassembled_table, len, !spx_info_p->eom);
            if (fd_head != NULL)
            {
                /* Is this the last fragment? EOM will indicate */
                if (fd_head->next != NULL && spx_info_p->eom)
                {
                    proto_item *frag_tree_item;

                    next_tvb = tvb_new_child_real_data(tvb, fd_head->data,
                        fd_head->len, fd_head->len);
                    add_new_data_source(pinfo,
                        next_tvb,
                        "Reassembled NDPS");
                    /* Show all fragments. */
                    if (tree)
                    {
                        show_fragment_seq_tree(fd_head,
                            &ndps_frag_items,
                            tree, pinfo,
                            next_tvb, &frag_tree_item);
                        tid++;
                    }
                    /* Remember this fragment number so we can dissect again */
                    request_value->ndps_end_frag = pinfo->fd->num;

                }
                else
                {
                    /* This is either a beggining or middle fragment on second dissection */
                    next_tvb = tvb_new_subset_remaining(tvb, 0);
                    if (check_col(pinfo->cinfo, COL_INFO))
                    {
                      if (!spx_info_p->eom)
                      {
                        col_append_str(pinfo->cinfo, COL_INFO, "[NDPS Fragment]");
                      }
                    }
                }
            }
            else
            {
                /* Fragment from first pass of dissection */
                if (check_col(pinfo->cinfo, COL_INFO))
                {
                  if (!spx_info_p->eom)
                  {
                    col_append_str(pinfo->cinfo, COL_INFO, "[NDPS Fragment]");
                  }
                }
                next_tvb = NULL;
            }
        }
        else
        {
            /*
             * There are no bytes so Dissect this
             */
            next_tvb = tvb_new_subset_remaining(tvb, 0);
        }
        if (next_tvb == NULL)
        {
            /* This is a fragment packet */
            next_tvb = tvb_new_subset_remaining (tvb, 0);
            call_dissector(ndps_data_handle, next_tvb, pinfo, tree);
        }
        else
        {
            /* This is the end fragment so dissect and mark end */
            if (spx_info_p->eom) {
                request_value->ndps_frag = FALSE;
                dissect_ndps(next_tvb, pinfo, tree);
            }
        }
    }
    else
    {
        /* This is not any fragment packet */
        request_value->ndps_frag = FALSE;
        dissect_ndps(tvb, pinfo, tree);
    }
}

static void
dissect_ndps_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, ndps_desegment, 4, get_ndps_pdu_len, dissect_ndps_pdu);
}


static void
dissect_ndps_ipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree      *ndps_tree = NULL;
    proto_item      *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDPS");

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ndps, tvb, 0, -1, ENC_NA);
        ndps_tree = proto_item_add_subtree(ti, ett_ndps);
    }
    ndps_defrag(tvb, pinfo, ndps_tree);
}

static int
dissect_ndps_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, guint32 ndps_prog, guint32 ndps_func, int foffset)
{
    ndps_req_hash_value *request_value = NULL;
    conversation_t      *conversation;
    guint32             i;
    guint32             j;
    guint32             field_len;
    guint32             cred_type;
    guint32             resource_type;
    guint32             filter_type;
    guint32             print_type;
    guint32             length;
    guint32             number_of_items;
    guint32             number_of_items2;
    guint32             doc_content;
    guint32             list_attr_op;
    guint32             scope;
    guint32             job_type;
    gboolean            supplier_flag;
    gboolean            language_flag;
    gboolean            method_flag;
    gboolean            delivery_address_flag;
    guint32             profiles_type;
    guint32             profiles_choice_type;
    guint32             integer_type_flag;
    guint32             local_servers_type;
    gint                length_remaining;
    proto_tree          *atree;
    proto_item          *aitem;
    proto_tree          *btree;
    proto_item          *bitem;
    proto_tree          *ctree;
    proto_item          *citem;
    proto_tree          *dtree;
    proto_item          *ditem;

    if (!pinfo->fd->flags.visited)
    {
        /* This is the first time we've looked at this packet.
        Keep track of the Program and connection whence the request
        came, and the address and connection to which the request
        is being sent, so that we can match up calls with replies.
        (We don't include the sequence number, as we may want
        to have all packets over the same connection treated
        as being part of a single conversation so that we can
        let the user select that conversation to be displayed.) */

        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
            PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->srcport, 0);

        if (conversation == NULL)
        {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                PT_NCP, (guint32) pinfo->srcport, (guint32) pinfo->srcport, 0);
        }

        request_value = ndps_hash_insert(conversation, (guint32) pinfo->srcport);
        request_value->ndps_prog = ndps_prog;
        request_value->ndps_func = ndps_func;
        request_value->ndps_frame_num = pinfo->fd->num;
    }
    switch(ndps_prog)
    {
    case 0x060976:  /* Print */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind PSM */
            foffset = credentials(tvb, ndps_tree, foffset);
            break;
        case 0x00000002:    /* Bind PA */
            foffset = credentials(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_retrieve_restrictions, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_bind_security_option_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Security %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                if (length==4)
                {
                    proto_tree_add_uint(atree, hf_bind_security, tvb, foffset, 4, length);
                }
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
            }
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 0x00000003:    /* Unbind */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset,
            4, ENC_BIG_ENDIAN);
            break;
        case 0x00000004:    /* Print */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            print_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_print_arg, tvb, foffset, 4, print_type);
            foffset += 4;
            switch (print_type)
            {
            case 0:     /* Create Job */
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
                proto_tree_add_item(ndps_tree, hf_sub_complete, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Transfer Method");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset);
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items2);
                    foffset += 4;
                    for (j = 1 ; j <= number_of_items2; j++ )
                    {
                        if (j > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        citem = proto_tree_add_text(btree, tvb, foffset, -1, "Value %u", j);
                        ctree = proto_item_add_subtree(citem, ett_ndps);
                        foffset = attribute_value(tvb, ctree, foffset);
                        proto_item_set_end(citem, tvb, foffset);
                    }
                    proto_tree_add_item(btree, hf_ndps_qualifier, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Content");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Type %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset);
                    proto_item_set_end(bitem, tvb, foffset);
                }
                foffset += align_4(tvb, foffset);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
                foffset += 4;
                doc_content = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_doc_content, tvb, foffset, 4, doc_content);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Value %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    if (doc_content==0)
                    {
                        length = tvb_get_ntohl(tvb, foffset);
                        proto_tree_add_uint(btree, hf_ndps_included_doc_len, tvb, foffset, 4, length);
                        foffset += 4;
                        length_remaining = tvb_length_remaining(tvb, foffset);
                        if (length_remaining == -1 || length > (guint32) length_remaining) /* Segmented Data */
                        {
                            proto_tree_add_item(btree, hf_ndps_data, tvb, foffset, -1, ENC_NA);
                            return foffset;
                        }
                        if (length==4)
                        {
                            proto_tree_add_item(btree, hf_ndps_included_doc, tvb, foffset, length, ENC_NA);
                        }
                        foffset += length;
                        foffset += (length%2);
                        if ((int) foffset <= 0)
                            THROW(ReportedBoundsError);
                    }
                    else
                    {
                        foffset = ndps_string(tvb, hf_ndps_ref_name, btree, foffset, NULL);
                        foffset = name_or_id(tvb, btree, foffset);
                    }
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
                foffset += 4;
                if (align_4(tvb, foffset)>0) {
                    foffset += align_4(tvb, foffset);
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Type");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset);
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items2);
                    foffset += 4;
                    for (j = 1 ; j <= number_of_items2; j++ )
                    {
                        if (j > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        citem = proto_tree_add_text(btree, tvb, foffset, -1, "Value %u", j);
                        ctree = proto_item_add_subtree(citem, ett_ndps);
                        foffset = attribute_value(tvb, ctree, foffset);
                        proto_item_set_end(citem, tvb, foffset);
                    }
                    proto_tree_add_item(btree, hf_ndps_qualifier, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Attributes");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = attribute_value(tvb, btree, foffset);  /* Document Attributes */
                    proto_item_set_end(bitem, tvb, foffset);
                }
                break;
            case 1:     /* Add Job */
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
                proto_tree_add_item(ndps_tree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_sub_complete, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Transfer Method");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_transfer_methods, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Method %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset); /* Transfer Method */
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_tree_add_item(ndps_tree, hf_doc_content, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Type");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_doc_types, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Type %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset); /* Document Type */
                    proto_item_set_end(bitem, tvb, foffset);
                }
                foffset += align_4(tvb, foffset);
                proto_item_set_end(aitem, tvb, foffset);
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Attributes");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = attribute_value(tvb, btree, foffset);  /* Document Attributes */
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset);
                break;
            case 2:     /* Close Job */
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
                proto_tree_add_item(ndps_tree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            default:
                break;
            }
            break;
        case 0x00000005:    /* Modify Job */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_document_number, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job Modifications");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Modification %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Job Modifications */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Document Modifications");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Modification %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Document Modifications */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000006:    /* Cancel Job */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_document_number, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* XXX - what does this count? */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Cancel Message");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Retention Period");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            proto_tree_add_item(atree, hf_ndps_status_flags, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000007:    /* List Object Attributes */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            list_attr_op = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_attrs_arg, tvb, foffset, 4, list_attr_op);
            foffset += 4;
            if (list_attr_op==0) /* Continuation */
            {
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Attribute %u", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = attribute_value(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                }
            }
            else                                  /* Specification */
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Class");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = objectidentifier(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
                foffset += 4;
                foffset += align_4(tvb, foffset);
                scope = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_scope, tvb, foffset, 4, scope);
                foffset += 4;
                if (scope!=0)    /* Scope Does not equal 0 */
                {
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Selector Option");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    number_of_items = tvb_get_ntohl(tvb, foffset); /* Start of NWDPSelector */
                    proto_tree_add_uint(atree, hf_ndps_num_options, tvb, foffset, 4, number_of_items);
                    foffset += 4;
                    for (i = 1 ; i <= number_of_items; i++ )
                    {
                        if (i > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Option %u", i);
                        btree = proto_item_add_subtree(bitem, ett_ndps);
                        foffset = objectidentification(tvb, btree, foffset);
                        proto_item_set_end(bitem, tvb, foffset);
                    }
                    proto_item_set_end(aitem, tvb, foffset);
                    foffset += align_4(tvb, foffset);
                    filter_type = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(ndps_tree, hf_ndps_filter, tvb, foffset, 4, filter_type);
                    foffset += 4;
                    /*if (filter_type == 0 || filter_type == 3 )
                    {
                        foffset = filteritem(tvb, ndps_tree, foffset);
                    }
                    else
                    {
                        aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Filter Items");
                        atree = proto_item_add_subtree(aitem, ett_ndps);
                        number_of_items = tvb_get_ntohl(tvb, foffset);
                        proto_tree_add_uint(atree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
                        foffset += 4;
                        for (i = 1 ; i <= number_of_items; i++ )
                        {
                            if (i > NDPS_MAX_ITEMS) {
                                proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                                break;
                            }
                            foffset = filteritem(tvb, ndps_tree, foffset);
                        }
                        proto_item_set_end(aitem, tvb, foffset);
                    }*/
                    proto_tree_add_item(ndps_tree, hf_ndps_time_limit, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item(ndps_tree, hf_ndps_count_limit, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4; /* End of NWDPSelector  */
                }
                foffset += 4;   /* Don't know what this is */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Requested Attributes");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset); /* Start of NWDPObjectIdentifierSet */
                proto_tree_add_uint(atree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset = objectidentifier(tvb, btree, foffset);
                    proto_item_set_end(bitem, tvb, foffset);
                }
                proto_item_set_end(aitem, tvb, foffset); /* End of NWDPObjectIdentifierSet */
                if (number_of_items == 0)
                {
                    break;
                }
                proto_tree_add_item(ndps_tree, hf_ndps_operator, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = commonarguments(tvb, ndps_tree, foffset);
            }
            break;
        case 0x00000008:    /* Promote Job */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000009:    /* Interrupt */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            job_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_interrupt_job_type, tvb, foffset, 4, job_type);
            foffset += 4;
            if (job_type==0)
            {
                /* Start of NWDPPrtContainedObjectId */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
                /* End of NWDPPrtContainedObjectId */
            }
            else
            {
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            }
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Interrupt Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Interrupting Job");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000a:    /* Pause */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            job_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_pause_job_type, tvb, foffset, 4, job_type);
            foffset += 4;
            if (job_type==0)
            {
                /* Start of NWDPPrtContainedObjectId */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
                /* End of NWDPPrtContainedObjectId */
            }
            else
            {
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            }
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Pause Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000b:    /* Resume */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resume Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000c:    /* Clean */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of nameorid */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Clean Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of nameorid */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000d:    /* Create */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_force, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Reference Object Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* Start of AttributeSet */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Attribute");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000e:    /* Delete */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000000f:    /* Disable PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Disable PA Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000010:    /* Enable PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Enable PA Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000011:    /* Resubmit Jobs */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            foffset = address_item(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_resubmit_op_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resubmit Job");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset); /* Start of ResubmitJob Set */
            proto_tree_add_uint(atree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                /* Start of NWDPPrtContainedObjectId */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Job ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, btree, foffset, NULL);
                proto_tree_add_item(btree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                /* End of NWDPPrtContainedObjectId */
                proto_tree_add_item(atree, hf_ndps_document_number, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                /* Start of AttributeSet */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Job Attributes");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                number_of_items2 = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items2);
                foffset += 4;
                for (j = 1 ; j <= number_of_items2; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Attribute %u", j);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = attribute_value(tvb, ctree, foffset);  /* Object Attribute Set */
                    proto_item_set_end(citem, tvb, foffset);
                }
                proto_item_set_end(bitem, tvb, foffset);
                /* End of AttributeSet */
                /* Start of AttributeSet */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Document Attributes");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                number_of_items2 = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items2);
                foffset += 4;
                for (j = 1 ; j <= number_of_items2; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Attribute %u", j);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = attribute_value(tvb, ctree, foffset);  /* Object Attribute Set */
                    proto_item_set_end(citem, tvb, foffset);
                }
                proto_item_set_end(bitem, tvb, foffset);
                /* End of AttributeSet */
            }
            proto_item_set_end(aitem, tvb, foffset);   /* End of ResubmitJob Set */
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resubmit Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000012:    /* Set */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            /* Start of AttributeSet */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Attribute Modifications");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Modification %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000013:    /* Shutdown PA */
        case 0x0000001e:    /* Shutdown PSM */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_shutdown_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Shutdown Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
        case 0x00000014:    /* Startup PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Startup Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000015:    /* Reorder Job */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job Identification");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Reference Job ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000016:    /* Pause PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Pause Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000017:    /* Resume PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resume Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000018:    /* Transfer Data */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_get_status_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_data, tvb, foffset+4, tvb_get_ntohl(tvb, foffset), ENC_NA);
            break;
        case 0x00000019:    /* Device Control */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of Object Identifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Operation ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of Object Identifier */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x0000001a:    /* Add Event Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of Eventhandling2 */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            foffset = ndps_string(tvb, hf_ndps_supplier_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            foffset += align_4(tvb, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Address");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = event_object_set(tvb, ndps_tree, foffset);
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            break;
        case 0x0000001b:    /* Remove Event Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x0000001c:    /* Modify Event Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            supplier_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_supplier_flag, tvb, foffset, 4, supplier_flag);
            foffset += 4;
            if (supplier_flag)
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                tvb_ensure_bytes_exist(tvb, foffset, length);
                foffset += length;
                proto_item_set_end(aitem, tvb, foffset);
            }
            language_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_language_flag, tvb, foffset, 4, language_flag);
            foffset += 4;
            if (language_flag)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            method_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_method_flag, tvb, foffset, 4, method_flag);
            foffset += 4;
            if (method_flag)
            {
                /* Start of NameorID */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = name_or_id(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
                /* End of NameorID */
            }
            delivery_address_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_delivery_address_flag, tvb, foffset, 4, delivery_address_flag);
            foffset += 4;
            if (delivery_address_flag)
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Address");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = print_address(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            foffset = event_object_set(tvb, ndps_tree, foffset);
            break;
        case 0x0000001d:    /* List Event Profiles */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            profiles_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_list_profiles_type, tvb, foffset, 4, profiles_type);
            foffset += 4;
            if (profiles_type==0)   /* Spec */
            {
                foffset = qualifiedname(tvb, ndps_tree, foffset);
                profiles_choice_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_list_profiles_choice_type, tvb, foffset, 4, profiles_choice_type);
                foffset += 4;
                if (profiles_choice_type==0)   /* Choice */
                {
                    foffset = cardinal_seq(tvb, ndps_tree, foffset);
                }
                else
                {
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = qualifiedname(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                    /* Start of NameorID */
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = name_or_id(tvb, atree, foffset);
                    /* End of NameorID */
                    proto_tree_add_item(atree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(aitem, tvb, foffset);
                }
                proto_tree_add_item(ndps_tree, hf_ndps_list_profiles_result_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                /* Start of integeroption */
                integer_type_flag = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_integer_type_flag, tvb, foffset, 4, integer_type_flag);
                foffset += 4;
                if (integer_type_flag!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_integer_type_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                /* End of integeroption */
            }
            else                                    /* Cont */
            {
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        case 0x0000001f:    /* Cancel PSM Shutdown */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Cancel Shutdown Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000020:    /* Set Printer DS Information */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_ds_info_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_printer_name, ndps_tree, foffset, NULL);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "DS Object Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000021:    /* Clean User Jobs */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Clean Message Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = commonarguments(tvb, ndps_tree, foffset);
            break;
        case 0x00000022:    /* Map GUID to NDS Name */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_guid, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            break;
        case 0x00000023:    /* AddEventProfile2 */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of Eventhandling2 */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            foffset = ndps_string(tvb, hf_ndps_supplier_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            foffset += align_4(tvb, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Address");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = event_object_set(tvb, ndps_tree, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Account");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* Start of object identifier set */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Notify Attributes");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of object identifier set */
            proto_tree_add_item(ndps_tree, hf_notify_time_interval, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_notify_sequence_number, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_notify_lease_exp_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = ndps_string(tvb, hf_notify_printer_uri, ndps_tree, foffset, NULL);
            /* End of Eventhandling2 */
            break;
        case 0x00000024:    /* ListEventProfiles2 */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            profiles_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_list_profiles_type, tvb, foffset, 4, profiles_type);
            foffset += 4;
            if (profiles_type==0)   /* Spec */
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier Alias");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = qualifiedname(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
                profiles_choice_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_list_profiles_choice_type, tvb, foffset, 4, profiles_choice_type);
                foffset += 4;
                if (profiles_choice_type==0)   /* Choice */
                {
                    foffset = cardinal_seq(tvb, ndps_tree, foffset);
                }
                else
                {
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = qualifiedname(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                    /* Start of NameorID */
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = name_or_id(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                    /* End of NameorID */
                    proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                proto_tree_add_item(ndps_tree, hf_ndps_list_profiles_result_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                /* Start of integeroption */
                integer_type_flag = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_integer_type_flag, tvb, foffset, 4, integer_type_flag);
                foffset += 4;
                if (integer_type_flag!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_integer_type_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                /* End of integeroption */
            }
            else                                    /* Cont */
            {
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        default:
            break;
        }
        break;
    case 0x060977:  /* Broker */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            foffset = credentials(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_retrieve_restrictions, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_bind_security_option_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Security %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_bind_security, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Unbind */
            break;
        case 0x00000003:    /* List Services */
            proto_tree_add_item(ndps_tree, hf_ndps_list_services_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x00000004:    /* Enable Service */
            proto_tree_add_item(ndps_tree, hf_ndps_service_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Parameters");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(atree, hf_ndps_item_bytes, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
            }
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000005:    /* Disable Service */
            proto_tree_add_item(ndps_tree, hf_ndps_list_services_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x00000006:    /* Down Broker */
        case 0x00000007:    /* Get Broker NDS Object Name */
        case 0x00000008:    /* Get Broker Session Information */
        default:
            break;
        }
        break;
    case 0x060978:  /* Registry */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            foffset = credentials(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_retrieve_restrictions, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_bind_security_option_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Security %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_bind_security, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Unbind */
            break;
        case 0x00000003:    /* Register Server */
            foffset = server_entry(tvb, ndps_tree, foffset);
            break;
        case 0x00000004:    /* Deregister Server */
        case 0x00000006:    /* Deregister Registry */
        case 0x0000000b:    /* Get Registry NDS Object Name */
        case 0x0000000c:    /* Get Registry Session Information */
            /* NoOp */
            break;
        case 0x00000005:    /* Register Registry */
            foffset = ndps_string(tvb, hf_ndps_registry_name, ndps_tree, foffset, NULL);
            foffset = print_address(tvb, ndps_tree, foffset);
            break;
        case 0x00000007:    /* Registry Update */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Add");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Entry %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = server_entry(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Remove");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Entry %u", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = server_entry(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000008:    /* List Local Servers */
        case 0x00000009:    /* List Servers */
        case 0x0000000a:    /* List Known Registries */
            local_servers_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_list_local_servers_type, tvb, foffset, 4, local_servers_type);
            foffset += 4;
            if (local_servers_type==0)
            {
                /* Start of integeroption */
                integer_type_flag = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_integer_type_flag, tvb, foffset, 4, integer_type_flag);
                foffset += 4;
                if (integer_type_flag!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_integer_type_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                /* End of integeroption */
            }
            else
            {
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        default:
            break;
        }
        break;
    case 0x060979:  /* Notify */
        switch(ndps_func)
        {
        case 0x00000001:    /* Notify Bind */
            foffset = credentials(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_retrieve_restrictions, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items=tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Security %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_bind_security, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Notify Unbind */
        case 0x0000000a:    /* List Supported Languages */
        case 0x00000010:    /* Get Notify NDS Object Name */
        case 0x00000011:    /* Get Notify Session Information */
            /* NoOp */
            break;
        case 0x00000003:    /* Register Supplier */
            foffset = ndps_string(tvb, hf_ndps_supplier_name, ndps_tree, foffset, NULL);
            /* Start of QualifiedName Set*/
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier Alias %u", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = qualifiedname(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            /* End of QualifiedName Set*/
            break;
        case 0x00000004:    /* Deregister Supplier */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x00000005:    /* Add Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier Alias");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* Start of Eventhandling */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Addresses");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = event_object_set(tvb, ndps_tree, foffset);
            /* End of Eventhandling */
            break;
        case 0x00000006:    /* Remove Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x00000007:    /* Modify Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            supplier_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_supplier_flag, tvb, foffset, 4, supplier_flag);
            foffset += 4;
            if (supplier_flag)
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                tvb_ensure_bytes_exist(tvb, foffset, length);
                foffset += length;
                proto_item_set_end(aitem, tvb, foffset);
            }
            language_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_language_flag, tvb, foffset, 4, language_flag);
            foffset += 4;
            if (language_flag)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            method_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_method_flag, tvb, foffset, 4, method_flag);
            foffset += 4;
            if (method_flag)
            {
                /* Start of NameorID */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = name_or_id(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
                /* End of NameorID */
            }
            delivery_address_flag = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_boolean(ndps_tree, hf_ndps_delivery_address_flag, tvb, foffset, 4, delivery_address_flag);
            foffset += 4;
            if (delivery_address_flag)
            {
                foffset = print_address(tvb, ndps_tree, foffset);
            }
            foffset = event_object_set(tvb, ndps_tree, foffset);
            break;
        case 0x00000008:    /* List Profiles */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            profiles_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_list_profiles_type, tvb, foffset, 4, profiles_type);
            foffset += 4;
            if (profiles_type==0)   /* Spec */
            {
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Supplier Alias");
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = qualifiedname(tvb, atree, foffset);
                profiles_choice_type = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_list_profiles_choice_type, tvb, foffset, 4, profiles_choice_type);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
                if (profiles_choice_type==0)   /* Choice */
                {
                    foffset = cardinal_seq(tvb, ndps_tree, foffset);
                }
                else
                {
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = qualifiedname(tvb, atree, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                    /* Start of NameorID */
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = name_or_id(tvb, atree, foffset);
                    /* End of NameorID */
                    proto_tree_add_item(atree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(aitem, tvb, foffset);
                }
                proto_tree_add_item(ndps_tree, hf_ndps_list_profiles_result_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                /* Start of integeroption */
                integer_type_flag = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_integer_type_flag, tvb, foffset, 4, integer_type_flag);
                foffset += 4;
                if (integer_type_flag!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_integer_type_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                /* End of integeroption */
            }
            else                                    /* Cont */
            {
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            break;
        case 0x00000009:    /* Report Event */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of ReportEventItemSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event Items");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Item %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                /* Start of ReportEventItem */
                proto_tree_add_item(btree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Containing Class");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentifier(tvb, ctree, foffset);
                proto_item_set_end(citem, tvb, foffset);
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Containing Object");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentification(tvb, ctree, foffset);
                proto_item_set_end(citem, tvb, foffset);
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Filter Class");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentifier(tvb, ctree, foffset);
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Object Class");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentifier(tvb, ctree, foffset);
                proto_item_set_end(citem, tvb, foffset);
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Object ID");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentification(tvb, ctree, foffset);
                proto_item_set_end(citem, tvb, foffset);
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Event Object ID");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = objectidentifier(tvb, ctree, foffset);
                proto_item_set_end(citem, tvb, foffset);
                /* Start of AttributeSet */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Attribute Modifications");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                for (j = 1 ; j <= number_of_items; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ctree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    ditem = proto_tree_add_text(ctree, tvb, foffset, -1, "Modification %d", j);
                    dtree = proto_item_add_subtree(ditem, ett_ndps);
                    foffset = attribute_value(tvb, dtree, foffset);  /* Object Attribute Set */
                    proto_item_set_end(ditem, tvb, foffset);
                }
                proto_item_set_end(citem, tvb, foffset);
                /* End of AttributeSet */
                foffset = ndps_string(tvb, hf_ndps_message, btree, foffset, NULL);
                proto_tree_add_item(btree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                /* End of ReportEventItem */
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of ReportEventItemSet */
            break;
        case 0x0000000b:    /* Report Notification */
            /* Start of DestinationSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_destinations, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Destination %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                /* Start of Destination */
                /* Start of NameorID */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Method ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = name_or_id(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* End of NameorID */
                /* Start of NotifyDeliveryAddr */
                proto_tree_add_item(atree, hf_address_len, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = print_address(tvb, atree, foffset);
                /* End of NotifyDeliveryAddr */
                proto_item_set_end(aitem, tvb, foffset);
                /* End of Destination */
            }
            /* End of DestinationSet */
            foffset = ndps_string(tvb, hf_ndps_supplier_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Containing Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Containing Object");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Filter Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Class");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentification(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event Object ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* Start of AttributeSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Attributes");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            foffset = ndps_string(tvb, hf_ndps_message, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Account");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x0000000c:    /* Add Delivery Method */
            foffset = ndps_string(tvb, hf_ndps_file_name, ndps_tree, foffset, NULL);
            break;
        case 0x0000000d:    /* Remove Delivery Method */
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            break;
        case 0x0000000e:    /* List Delivery Methods */
            cred_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_delivery_method_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            switch (cred_type)
            {
            case 0:        /* Specification */
                /* Start of integeroption */
                integer_type_flag = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_integer_type_flag, tvb, foffset, 4, integer_type_flag);
                foffset += 4;
                if (integer_type_flag!=0)
                {
                    proto_tree_add_item(ndps_tree, hf_ndps_integer_type_value, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                }
                /* End of integeroption */
                proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            case 1:       /* Continuation */
                length = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_context_len, tvb, foffset, 4, length);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_context, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                foffset += (length%2);
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            default:
                break;
            }
            break;
        case 0x0000000f:    /* Get Delivery Method Information */
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        default:
            break;
        }
        break;
    case 0x06097a:  /* Resman */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            foffset = credentials(tvb, ndps_tree, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_retrieve_restrictions, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_bind_security_option_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Security %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(atree, hf_bind_security, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Unbind */
        case 0x00000008:    /* Get Resource Manager NDS Object Name */
        case 0x00000009:    /* Get Resource Manager Session Information */
            /* NoOp */
            break;
        case 0x00000003:    /* Add Resource File */
            proto_tree_add_item(ndps_tree, hf_packet_count, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_last_packet_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_file_timestamp, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = res_add_input_data(tvb, ndps_tree, foffset);
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length=tvb_get_ntohl(tvb, foffset);
                length_remaining = tvb_length_remaining(tvb, foffset);
                if(length_remaining == -1 || (guint32) length_remaining < length)
                {
                    return foffset;
                }
                proto_tree_add_item(atree, hf_ndps_item_ptr, tvb, foffset, length, ENC_NA);
                foffset += length;
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000004:    /* Delete Resource File */
            foffset = res_add_input_data(tvb, ndps_tree, foffset);
            break;
        case 0x00000005:    /* List Resources */
            proto_tree_add_item(ndps_tree, hf_ndps_max_items, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_status_flags, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_resource_list_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            resource_type = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            switch (resource_type)
            {
            case 0:     /* Print Drivers */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            case 1:     /* Printer Definitions */
            case 2:     /* Printer Definitions Short */
                foffset = ndps_string(tvb, hf_ndps_vendor_dir, ndps_tree, foffset, NULL);
                break;
            case 3:     /* Banner Page Files */
                proto_tree_add_item(ndps_tree, hf_banner_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            case 4:     /* Font Types */
                proto_tree_add_item(ndps_tree, hf_font_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            case 5:     /* Printer Driver Files */
            case 12:    /* Printer Driver Files 2 */
            case 9:     /* Generic Files */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_printer_type, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_printer_manuf, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_inf_file_name, ndps_tree, foffset, NULL);
                field_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_printer_id, tvb, foffset, field_len, ENC_NA);
                break;
            case 6:     /* Printer Definition File */
            case 10:    /* Printer Definition File 2 */
                foffset = ndps_string(tvb, hf_ndps_vendor_dir, ndps_tree, foffset, NULL);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_printer_type, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_printer_manuf, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_inf_file_name, ndps_tree, foffset, NULL);
                field_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_printer_id, tvb, foffset, field_len, ENC_NA);
                break;
            case 7:     /* Font Files */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_font_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_font_name, ndps_tree, foffset, NULL);
                break;
            case 8:     /* Generic Type */
            case 11:    /* Printer Driver Types 2 */
            case 13:    /* Printer Driver Types Archive */
                foffset = ndps_string(tvb, hf_ndps_printer_manuf, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_printer_type, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_inf_file_name, ndps_tree, foffset, NULL);
                break;
            case 14:    /* Languages Available */
                break;
            default:
                break;
            }
            break;
        case 0x00000006:    /* Get Resource File */
            proto_tree_add_item(ndps_tree, hf_get_status_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_res_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            resource_type = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            switch (resource_type)
            {
            case 0:     /* Print Drivers */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_prn_dir_name, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
                break;
            case 1:     /* Printer Definitions */
                foffset = ndps_string(tvb, hf_ndps_vendor_dir, ndps_tree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
                break;
            case 2:     /* Banner Page Files */
                foffset = ndps_string(tvb, hf_ndps_banner_name, ndps_tree, foffset, NULL);
                break;
            case 3:     /* Font Types */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_font_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_prn_file_name, ndps_tree, foffset, NULL);
                break;
            case 4:     /* Generic Files/ Archive */
            case 5:     /* Printer Driver Archive */
                proto_tree_add_item(ndps_tree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_prn_dir_name, ndps_tree, foffset, NULL);
                proto_tree_add_item(ndps_tree, hf_archive_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                break;
            default:
                break;
            }
            break;
        case 0x00000007:    /* Get Resource File Date */
            proto_tree_add_item(ndps_tree, hf_ndps_status_flags, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = res_add_input_data(tvb, ndps_tree, foffset);
            break;
        case 0x0000000a:    /* Set Resource Language Context */
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        default:
            break;
        }
        break;
    case 0x06097b:  /* Delivery */
        switch(ndps_func)
        {
        case 0x00000001:    /* Delivery Bind */
            foffset = credentials(tvb, ndps_tree, foffset);
            break;
        case 0x00000002:    /* Delivery Unbind */
            /* NoOp */
            break;
        case 0x00000003:    /* Delivery Send */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Supplier ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(btree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                foffset += length;
                proto_tree_add_item(btree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Containing Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Containing Object");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentification(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Filter Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentification(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Event Object ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                foffset = attribute_value(tvb, atree, foffset);
                foffset = ndps_string(tvb, hf_ndps_message, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Account");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = qualifiedname(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000004:    /* Delivery Send2 */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Supplier ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length==4)
                {
                    proto_tree_add_item(btree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
                }
                foffset += length;
                proto_tree_add_item(atree, hf_ndps_event_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Containing Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Containing Object");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentification(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Filter Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object Class");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentification(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Event Object ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* Start of AttributeSet */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    foffset = attribute_value(tvb, btree, foffset);
                }
                proto_item_set_end(bitem, tvb, foffset);
                /* End of AttributeSet */
                foffset = ndps_string(tvb, hf_ndps_message, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Account");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = qualifiedname(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return foffset;
}

static int
ndps_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, int foffset)
{
    guint32     number_of_items;
    guint32     ndps_problem_type;
    guint32     problem_type;
    guint32     i;
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;
    proto_item  *expert_item;

    ndps_problem_type = tvb_get_ntohl(tvb, foffset);
    col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
    expert_item = proto_tree_add_uint(ndps_tree, hf_ndps_problem_type, tvb, foffset, 4, ndps_problem_type);
    expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Fault: %s", val_to_str(ndps_problem_type, error_type_enum, "Unknown NDPS Error (0x%08x)"));
    foffset += 4;
    switch(ndps_problem_type)
    {
    case 0:                 /* Security Error */
        problem_type = tvb_get_ntohl(tvb, foffset);
        proto_tree_add_uint(ndps_tree, hf_problem_type, tvb, foffset, 4, problem_type);
        foffset += 4;
        if (problem_type==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_security_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        /* Start of NameorID */
        aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Message");
        atree = proto_item_add_subtree(aitem, ett_ndps);
        foffset = name_or_id(tvb, atree, foffset);
        proto_item_set_end(aitem, tvb, foffset);
        /* End of NameorID */
        break;
    case 1:                 /* Service Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_service_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        foffset = attribute_value(tvb, ndps_tree, foffset);  /* Object Attribute Set */
        proto_tree_add_item(ndps_tree, hf_ndps_lib_error, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_ndps_other_error, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_ndps_other_error_2, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_length_remaining(tvb, foffset) >= 4) {
            foffset = ndps_string(tvb, hf_ndps_other_error_string, ndps_tree, foffset, NULL);
        }
        break;
    case 2:                 /* Access Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_access_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        break;
    case 3:                 /* Printer Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_printer_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        break;
    case 4:                 /* Selection Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_selection_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        foffset = attribute_value(tvb, ndps_tree, foffset);  /* Object Attribute Set */
        break;
    case 5:                 /* Document Access Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_doc_access_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset = objectidentifier(tvb, ndps_tree, foffset);
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        break;
    case 6:                 /* Attribute Error */
        number_of_items = tvb_get_ntohl(tvb, foffset);
        proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
        foffset += 4;
        for (i = 1 ; i <= number_of_items; i++ )
        {
            if (i > NDPS_MAX_ITEMS) {
                proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                break;
            }
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
            atree = proto_item_add_subtree(aitem, ett_ndps);
            proto_tree_add_item(atree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
            {
                proto_tree_add_item(atree, hf_attribute_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            else                /* Extended Error */
            {
                /* Start of objectidentifier */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Extended Error");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = objectidentifier(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* End of objectidentifier */
            }
            foffset = attribute_value(tvb, atree, foffset);  /* Object Attribute Set */
            proto_item_set_end(aitem, tvb, foffset);
        }
        break;
    case 7:                 /* Update Error */
        proto_tree_add_item(ndps_tree, hf_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_get_ntohl(tvb, foffset-4)==0) /* Standard Error */
        {
            proto_tree_add_item(ndps_tree, hf_update_problem_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
        }
        else                /* Extended Error */
        {
            /* Start of objectidentifier */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Extended Error");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = objectidentifier(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of objectidentifier */
        }
        foffset = objectidentification(tvb, ndps_tree, foffset);
        break;
    default:
        break;
    }
    return foffset;
}

static int
return_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, int foffset)
{
    guint32     expert_status;
    proto_item  *expert_item;

    expert_status = tvb_get_ntohl(tvb, foffset);
    expert_item = proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
    if (expert_status != 0) {
        expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Fault: %s", val_to_str(expert_status, ndps_error_types, "Unknown NDPS Error (0x%08x)"));
    }
    foffset += 4;
    if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
        col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
    if (tvb_get_ntohl(tvb, foffset-4) == 0)
    {
        return foffset;
    }
    proto_tree_add_item(ndps_tree, hf_ndps_ext_error, tvb, foffset, 4, ENC_BIG_ENDIAN);
    foffset += 4;
    return foffset;
}

static int
dissect_ndps_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, int foffset)
{
    conversation_t          *conversation = NULL;
    ndps_req_hash_value     *request_value = NULL;
    proto_tree              *atree;
    proto_item              *aitem;
    proto_tree              *btree;
    proto_item              *bitem;
    proto_tree              *ctree;
    proto_item              *citem;
    proto_tree              *dtree;
    proto_item              *ditem;
    guint32                 i;
    guint32                 j;
    guint32                 k;
    guint32                 number_of_items=0;
    guint32                 number_of_items2=0;
    guint32                 number_of_items3=0;
    guint32                 length=0;
    guint32                 ndps_func=0;
    guint32                 ndps_prog=0;
    guint32                 error_val=0;
    guint32                 resource_type=0;
    gint                    length_remaining;
    proto_item              *expert_item;
    guint32                 expert_status;

    if (!pinfo->fd->flags.visited) {
        /* Find the conversation whence the request would have come. */
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
            PT_NCP, (guint32) pinfo->destport, (guint32) pinfo->destport, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
            this reply */
            request_value = ndps_hash_lookup(conversation, (guint32) pinfo->destport);
            p_add_proto_data(pinfo->fd, proto_ndps, (void*) request_value);
        }
        /* else... we haven't seen an NDPS Request for that conversation. */
    }
    else {
        request_value = p_get_proto_data(pinfo->fd, proto_ndps);
    }
    if (request_value) {
        ndps_prog = request_value->ndps_prog;
        ndps_func = request_value->ndps_func;
        proto_tree_add_uint_format(ndps_tree, hf_ndps_reqframe, tvb, 0,
           0, request_value->ndps_frame_num,
           "Response to Request in Frame Number: %u",
           request_value->ndps_frame_num);
    }

    if (tvb_length_remaining(tvb, foffset) < 12 && tvb_get_ntohl(tvb, foffset) == 0) /* No error and no return data */
    {
        proto_tree_add_uint(ndps_tree, hf_ndps_error_val, tvb, foffset, 4, error_val);
        col_append_str(pinfo->cinfo, COL_INFO, "- Ok");
        return foffset;
    }
    if(ndps_func == 1 || ndps_func == 2)
    {
        expert_item = proto_tree_add_item(ndps_tree, hf_ndps_rpc_acc_stat, tvb, foffset, 4, ENC_BIG_ENDIAN);
        expert_status = tvb_get_ntohl(tvb, foffset);
        if (expert_status != 0) {
            expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Fault: %s", val_to_str(expert_status, accept_stat, "Unknown NDPS Error (0x%08x)"));
        }
        foffset += 4;
        if (tvb_length_remaining(tvb,foffset) < 4 ) {
            col_append_str(pinfo->cinfo, COL_INFO, "- Error");
            return foffset;
        }
        proto_tree_add_item(ndps_tree, hf_ndps_rpc_acc_results, tvb, foffset, 4, ENC_BIG_ENDIAN);
        foffset += 4;
        if (tvb_length_remaining(tvb,foffset) < 4) {
            col_append_str(pinfo->cinfo, COL_INFO, "- Error");
            return foffset;
        }
    }
    error_val = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_error_val, tvb, foffset, 4, error_val);
    foffset += 4;
    /* Some functions return an error with no data, 0 is ok */
    if (match_strval(tvb_get_ntohl(tvb, foffset), ndps_error_types) && tvb_length_remaining(tvb,foffset) < 8 && (tvb_get_ntohl(tvb, foffset)!=0))
    {
        expert_status = tvb_get_ntohl(tvb, foffset);
        expert_item = proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
        expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Fault: %s", val_to_str(expert_status, ndps_error_types, "Unknown NDPS Error (0x%08x)"));
        col_append_str(pinfo->cinfo, COL_INFO, "- Error");
        return foffset;
    }
    col_append_str(pinfo->cinfo, COL_INFO, "- Ok");
    switch(ndps_prog)
    {
    case 0x060976:  /* Print */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind PSM */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
                if(tvb_length_remaining(tvb, foffset) < 4)
                {
                    break;
                }
                proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "PSM Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            break;
        case 0x00000002:    /* Bind PA */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
                if(tvb_length_remaining(tvb, foffset) < 4)
                {
                    break;
                }
                proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
            }
                foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            break;
        case 0x00000003:    /* Unbind */
            break;
        case 0x00000004:    /* Print */
            foffset = ndps_string(tvb, hf_ndps_pa_name, ndps_tree, foffset, NULL);
            proto_tree_add_item(ndps_tree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000005:    /* Modify Job */
        case 0x00000006:    /* Cancel Job */
        case 0x00000008:    /* Promote Job */
        case 0x0000000b:    /* Resume */
        case 0x0000000d:    /* Create */
            /* Start of AttributeSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Attribute Set");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000007:    /* List Object Attributes */
            proto_tree_add_item(ndps_tree, hf_answer_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Continuation Option */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Continuation Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_options, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Option %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                length=tvb_get_ntohl(tvb, foffset);
                length_remaining = tvb_length_remaining(tvb, foffset);
                if(length_remaining == -1 || (guint32) length_remaining < length)
                {
                    return foffset;
                }
                proto_tree_add_item(btree, hf_ndps_item_ptr, tvb, foffset, length, ENC_NA);
                foffset += length;
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* Limit Encountered Option */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Limit Encountered Option");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            proto_tree_add_item(atree, hf_ndps_len, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_limit_enc, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* Object Results Set */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Results Set");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_num_results, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated Result]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Results: (%d)", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                if (i>1) {
                    foffset += 2;
                }
                foffset = objectidentification(tvb, btree, foffset);
                number_of_items2 = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_num_objects, tvb, foffset, 4, number_of_items2);
                foffset += 4;
                for (j = 1 ; j <= number_of_items2; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated Object]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Object: (%d)", j);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = objectidentifier(tvb, ctree, foffset);
                    foffset += align_4(tvb, foffset);
                    number_of_items3 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(ctree, hf_ndps_num_values, tvb, foffset, 4, number_of_items3);
                    foffset += 4;
                    for (k = 1 ; k <= number_of_items3; k++ )
                    {
                        if (k > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(ctree, tvb, foffset, -1, "[Truncated Value]");
                            break;
                        }
                        ditem = proto_tree_add_text(ctree, tvb, foffset, -1, "Value: (%d)", k);
                        dtree = proto_item_add_subtree(ditem, ett_ndps);
                        foffset = attribute_value(tvb, dtree, foffset);
                        proto_item_set_end(ditem, tvb, foffset);
                    }
                    proto_tree_add_item(ctree, hf_ndps_qualifier, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    foffset += align_4(tvb, foffset);
                    proto_item_set_end(citem, tvb, foffset);
                }

                /*foffset += align_4(tvb, foffset);*/
                foffset = objectidentifier(tvb, btree, foffset);
                /*foffset += align_4(tvb, foffset);*/
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000009:    /* Interrupt */
        case 0x0000000a:    /* Pause */
            /* Start of NWDPPrtContainedObjectId */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = ndps_string(tvb, hf_ndps_pa_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NWDPPrtContainedObjectId */
            /* Start of AttributeSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Object Attribute Set");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Attribute %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x0000000c:    /* Clean */
        case 0x0000000e:    /* Delete */
        case 0x0000000f:    /* Disable PA */
        case 0x00000010:    /* Enable PA */
        case 0x00000012:    /* Set */
        case 0x00000013:    /* Shutdown PA */
        case 0x00000014:    /* Startup PA */
        case 0x00000018:    /* Transfer Data */
        case 0x00000019:    /* Device Control */
        case 0x0000001b:    /* Remove Event Profile */
        case 0x0000001c:    /* Modify Event Profile */
        case 0x0000001e:    /* Shutdown PSM */
        case 0x0000001f:    /* Cancel PSM Shutdown */
        case 0x00000020:    /* Set Printer DS Information */
        case 0x00000021:    /* Clean User Jobs */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000011:    /* Resubmit Jobs */
            number_of_items = tvb_get_ntohl(tvb, foffset); /* Start of ResubmitJob Set */
            proto_tree_add_uint(ndps_tree, hf_ndps_num_jobs, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Resubmit Job");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Job %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                /* Start of NWDPPrtContainedObjectId */
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Old Job");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, ctree, foffset, NULL);
                proto_tree_add_item(ctree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(citem, tvb, foffset);
                /* End of NWDPPrtContainedObjectId */
                /* Start of NWDPPrtContainedObjectId */
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "New Job");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                foffset = ndps_string(tvb, hf_ndps_pa_name, ctree, foffset, NULL);
                proto_tree_add_item(ctree, hf_local_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(citem, tvb, foffset);
                /* End of NWDPPrtContainedObjectId */
                /* Start of AttributeSet */
                number_of_items2 = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ctree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items2);
                foffset += 4;
                citem = proto_tree_add_text(btree, tvb, foffset, -1, "Job Status");
                ctree = proto_item_add_subtree(citem, ett_ndps);
                for (j = 1 ; j <= number_of_items2; j++ )
                {
                    if (j > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ctree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    ditem = proto_tree_add_text(ctree, tvb, foffset, -1, "Object %d", j);
                    dtree = proto_item_add_subtree(ditem, ett_ndps);
                    foffset = attribute_value(tvb, dtree, foffset);  /* Object Attribute Set */
                    proto_item_set_end(ditem, tvb, foffset);
                }
                proto_item_set_end(citem, tvb, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* End of AttributeSet */
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of ResubmitJob Set */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000015:    /* Reorder Job */
            /* Start of AttributeSet */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Job Status");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000016:    /* Pause PA */
        case 0x00000017:    /* Resume PA */
            /* Start of AttributeSet */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Printer Status");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Object %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = attribute_value(tvb, btree, foffset);  /* Object Attribute Set */
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            /* End of AttributeSet */
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x0000001a:    /* Add Event Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x0000001d:    /* List Event Profiles */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            /* Start of Eventhandling */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Addresses");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = event_object_set(tvb, ndps_tree, foffset);
            /* End of Eventhandling */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_continuation_option, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000022:    /* Map GUID to NDS Name */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "NDS Printer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000023:    /* AddEventProfile2 */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_notify_lease_exp_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if(error_val != 0)
            {
                foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
            }
            break;
        case 0x00000024:    /* ListEventProfiles2 */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_events, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Event %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                /* Start of Eventhandling2 */
                proto_tree_add_item(atree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(atree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Consumer Name");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = qualifiedname(tvb, btree, foffset);
                foffset = ndps_string(tvb, hf_ndps_supplier_name, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(bitem, tvb, foffset);
                /* Start of NameorID */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Method ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = name_or_id(tvb, btree, foffset);
                foffset += align_4(tvb, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* End of NameorID */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(atree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Delivery Addresses");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Address %d", i);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = address_item(tvb, ctree, foffset);
                    proto_item_set_end(citem, tvb, foffset);
                }
                proto_item_set_end(bitem, tvb, foffset);
                foffset = event_object_set(tvb, atree, foffset);
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Account");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = qualifiedname(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* Start of object identifier set */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Notify Attributes");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(btree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    citem = proto_tree_add_text(btree, tvb, foffset, -1, "Attribute %d", i);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    foffset = objectidentifier(tvb, ctree, foffset);
                    proto_item_set_end(citem, tvb, foffset);
                }
                proto_item_set_end(bitem, tvb, foffset);
                /* End of object identifier set */
                proto_tree_add_item(atree, hf_notify_time_interval, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(atree, hf_notify_sequence_number, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(atree, hf_notify_lease_exp_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                foffset = ndps_string(tvb, hf_notify_printer_uri, atree, foffset, NULL);
                proto_item_set_end(aitem, tvb, foffset);
                /* End of Eventhandling2 */
                length = tvb_get_ntohl(tvb, foffset); /* Added on 10-17-03 */
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(ndps_tree, hf_ndps_continuation_option, tvb, foffset, length, ENC_NA);
                }
                foffset += length;
                if(error_val != 0)
                {
                    foffset = ndps_error(tvb, pinfo, ndps_tree, foffset);
                }
            }
            break;
        default:
            break;
        }
        break;
    case 0x060977:  /* Broker */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
        case 0x00000002:    /* Unbind */
        case 0x00000004:    /* Enable Service */
        case 0x00000005:    /* Disable Service */
        case 0x00000006:    /* Down Broker */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000003:    /* List Services */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_services, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Service %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                proto_tree_add_item(atree, hf_ndps_service_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_tree_add_item(atree, hf_ndps_service_enabled, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
            }
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000007:    /* Get Broker NDS Object Name */
            proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset,
            4, ENC_BIG_ENDIAN);  /* XXX - what does this count? */
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_broker_name, ndps_tree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000008:    /* Get Broker Session Information */
        default:
            break;
        }
        break;
    case 0x060978:  /* Registry */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Attribute %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(atree, hf_ndps_attribute_set, tvb, foffset, length, ENC_NA);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Unbind */
            /* NoOp */
            break;
        case 0x00000003:    /* Register Server */
        case 0x00000004:    /* Deregister Server */
        case 0x00000005:    /* Register Registry */
        case 0x00000006:    /* Deregister Registry */
        case 0x00000007:    /* Registry Update */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000008:    /* List Local Servers */
        case 0x00000009:    /* List Servers */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset = server_entry(tvb, atree, foffset);
                proto_item_set_end(aitem, tvb, foffset);
            }
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_continuation_option, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000a:    /* List Known Registries */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_item(ndps_tree, hf_ndps_client_server_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                foffset += 4;
                foffset = ndps_string(tvb, hf_ndps_registry_name, atree, foffset, NULL);
                foffset = print_address(tvb, atree, foffset);
            }
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_continuation_option, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000b:    /* Get Registry NDS Object Name */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "NDS Printer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000c:    /* Get Registry Session Information */
            proto_tree_add_item(ndps_tree, hf_ndps_session_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        default:
            break;
        }
        break;
    case 0x060979:  /* Notify */
        switch(ndps_func)
        {
        case 0x00000001:    /* Notify Bind */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_num_attributes, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Attribute %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                length = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                if (length!=0)
                {
                    tvb_ensure_bytes_exist(tvb, foffset, length);
                    proto_tree_add_item(atree, hf_ndps_attribute_set, tvb, foffset, length, ENC_NA);
                }
                proto_item_set_end(aitem, tvb, foffset);
            }
            break;
        case 0x00000002:    /* Notify Unbind */
            /* NoOp */
            break;
        case 0x00000003:    /* Register Supplier */
            proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = event_object_set(tvb, ndps_tree, foffset);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000004:    /* Deregister Supplier */
        case 0x0000000b:    /* Report Notification */
        case 0x0000000d:    /* Remove Delivery Method */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000005:    /* Add Profile */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = event_object_set(tvb, ndps_tree, foffset);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000006:    /* Remove Profile */
        case 0x00000007:    /* Modify Profile */
        case 0x00000009:    /* Report Event */
            foffset = event_object_set(tvb, ndps_tree, foffset);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000008:    /* List Profiles */
            /* Start of ProfileResultSet */
            proto_tree_add_item(ndps_tree, hf_ndps_len, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of Eventhandling */
            proto_tree_add_item(ndps_tree, hf_ndps_profile_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_persistence, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Consumer Name");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = qualifiedname(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Addresses");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = event_object_set(tvb, ndps_tree, foffset);
            /* End of Eventhandling */
            /* End of ProfileResultSet */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_continuation_option, tvb, foffset, length, ENC_NA);
            }
            foffset += length;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000a:    /* List Supported Languages */
            /* Start of IntegerSeq */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length==4)
            {
                proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, length, ENC_BIG_ENDIAN);
            }
            foffset += length;
            /* End of IntegerSeq */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000c:    /* Add Delivery Method */
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            proto_item_set_end(aitem, tvb, foffset);
            /* End of NameorID */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000e:    /* List Delivery Methods */
            /* Start of DeliveryMethodSet */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_delivery_method_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                /* Start of DeliveryMethod */
                aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method %d", i);
                atree = proto_item_add_subtree(aitem, ett_ndps);
                /* Start of NameorID */
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Method ID");
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = name_or_id(tvb, btree, foffset);
                foffset += align_4(tvb, foffset);
                proto_item_set_end(bitem, tvb, foffset);
                /* End of NameorID */
                foffset = ndps_string(tvb, hf_ndps_method_name, atree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_method_ver, atree, foffset, NULL);
                foffset = ndps_string(tvb, hf_ndps_file_name, atree, foffset, NULL);
                proto_tree_add_item(atree, hf_ndps_admin_submit, tvb, foffset, 4, ENC_BIG_ENDIAN);
                foffset += 4;
                proto_item_set_end(aitem, tvb, foffset);
                /* End of DeliveryMethod */
            }
            /* End of DeliveryMethodSet */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000f:    /* Get Delivery Method Information */
            /* Start of DeliveryMethod */
            /* Start of NameorID */
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Method ID");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset = name_or_id(tvb, atree, foffset);
            /* End of NameorID */
            foffset = ndps_string(tvb, hf_ndps_method_name, atree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_method_ver, atree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_file_name, atree, foffset, NULL);
            proto_tree_add_item(atree, hf_ndps_admin_submit, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_item_set_end(aitem, tvb, foffset);
            /* End of DeliveryMethod */
            number_of_items = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_delivery_add_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Delivery Addresses");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Address %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                foffset = address_item(tvb, btree, foffset);
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000010:    /* Get Notify NDS Object Name */
            proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset,
            4, ENC_BIG_ENDIAN);  /* XXX - what does this count? */
            foffset += 4;
            foffset = ndps_string(tvb, hf_ndps_broker_name, ndps_tree, foffset, NULL);
            foffset = ndps_string(tvb, hf_ndps_tree, ndps_tree, foffset, NULL);
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000011:    /* Get Notify Session Information */
            proto_tree_add_item(ndps_tree, hf_ndps_get_session_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        default:
            break;
        }
        break;
    case 0x06097a:  /* Resman */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            length = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            if (length!=0)
            {
                tvb_ensure_bytes_exist(tvb, foffset, length);
                proto_tree_add_item(ndps_tree, hf_ndps_attribute_set, tvb, foffset, length, ENC_NA);
            }
            break;
        case 0x00000002:    /* Unbind */
            /* NoOp */
            break;
        case 0x00000003:    /* Add Resource File */
        case 0x00000004:    /* Delete Resource File */
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x00000005:    /* List Resources */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            if (tvb_get_ntohl(tvb, foffset-4) != 0)
            {
                break;
            }
            proto_tree_add_item(ndps_tree, hf_ndps_status_flags, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_resource_list_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            resource_type = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            switch (resource_type)
            {
            case 0:     /* Print Drivers */
            case 1:     /* Printer Definitions */
            case 2:     /* Printer Definitions Short */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_printer_def_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Definition %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    if (tvb_get_ntohl(tvb, foffset)==0) {  /* Offset for old type support */
                        foffset += 2;
                    }
                    foffset += 4; /* Item always == 1 */
                    foffset = ndps_string(tvb, hf_ndps_printer_manuf, atree, foffset, NULL);
                    if (tvb_get_ntohl(tvb, foffset)==0) {
                        foffset += 2;
                    }
                    foffset += 4;
                    foffset = ndps_string(tvb, hf_ndps_printer_type, atree, foffset, NULL);
                    if (tvb_get_ntohl(tvb, foffset)==0) {
                        foffset += 2;
                    }
                    foffset += 4;
                    foffset = ndps_string(tvb, hf_ndps_inf_file_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 3:     /* Banner Page Files */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Banner %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_ndps_banner_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 4:     /* Font Types */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_font_type_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Font %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_font_type_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 7:     /* Font Files */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_font_file_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Font File %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_font_file_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 5:     /* Printer Driver Files */
            case 12:    /* Printer Driver Files 2 */
            case 9:     /* Generic Files */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_printer_def_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "File %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_ndps_prn_file_name, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_prn_dir_name, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_inf_file_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 6:     /* Printer Definition File */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_printer_def_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Definition %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_ndps_prn_file_name, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_prn_dir_name, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_inf_file_name, atree, foffset, NULL);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Item %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_ndps_def_file_name, atree, foffset, NULL);
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(atree, hf_ndps_num_win31_keys, tvb, foffset, 4, number_of_items2);
                    bitem = proto_tree_add_text(atree, tvb, foffset, 4, "Windows 3.1 Keys");
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset += 4;
                    for (i = 1 ; i <= number_of_items2; i++ )
                    {
                        if (i > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        foffset = ndps_string(tvb, hf_ndps_windows_key, btree, foffset, NULL);
                    }
                    proto_item_set_end(bitem, tvb, foffset);
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(atree, hf_ndps_num_win95_keys, tvb, foffset, 4, number_of_items2);
                    bitem = proto_tree_add_text(atree, tvb, foffset, 4, "Windows 95 Keys");
                    btree = proto_item_add_subtree(bitem, ett_ndps);
                    foffset += 4;
                    for (i = 1 ; i <= number_of_items2; i++ )
                    {
                        if (i > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(btree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        foffset = ndps_string(tvb, hf_ndps_windows_key, btree, foffset, NULL);
                    }
                    proto_item_set_end(bitem, tvb, foffset);
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 10:    /* Printer Definition File 2 */
                foffset = ndps_string(tvb, hf_ndps_def_file_name, ndps_tree, foffset, NULL);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_os_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "OS %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    proto_tree_add_item(atree, hf_os_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    proto_tree_add_uint(atree, hf_ndps_num_windows_keys, tvb, foffset, 4, number_of_items2);
                    foffset += 4;
                    for (i = 1 ; i <= number_of_items2; i++ )
                    {
                        if (i > NDPS_MAX_ITEMS) {
                            proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                            break;
                        }
                        bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Key %d", i);
                        btree = proto_item_add_subtree(bitem, ett_ndps);
                        foffset = ndps_string(tvb, hf_ndps_windows_key, btree, foffset, NULL);
                        proto_item_set_end(bitem, tvb, foffset);
                    }
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 8:     /* Generic Type */
            case 11:    /* Printer Driver Types 2 */
            case 13:    /* Printer Driver Types Archive */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_printer_type_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Type %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    foffset = ndps_string(tvb, hf_ndps_printer_manuf, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_printer_type, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_prn_file_name, atree, foffset, NULL);
                    foffset = ndps_string(tvb, hf_ndps_prn_dir_name, atree, foffset, NULL);
                    proto_tree_add_item(atree, hf_archive_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_tree_add_item(atree, hf_archive_file_size, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            case 14:    /* Languages Available */
                number_of_items = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_uint(ndps_tree, hf_ndps_language_count, tvb, foffset, 4, number_of_items);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    if (i > NDPS_MAX_ITEMS) {
                        proto_tree_add_text(ndps_tree, tvb, foffset, -1, "[Truncated]");
                        break;
                    }
                    aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Language %d", i);
                    atree = proto_item_add_subtree(aitem, ett_ndps);
                    proto_tree_add_item(atree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
                    foffset += 4;
                    proto_item_set_end(aitem, tvb, foffset);
                }
                break;
            default:
                break;
            }
            break;
        case 0x00000006:    /* Get Resource File */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            if (tvb_get_ntohl(tvb, foffset-4) != 0)
            {
                break;
            }
            proto_tree_add_item(ndps_tree, hf_get_status_flag, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_file_timestamp, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_data, tvb, foffset, -1, ENC_NA);
            break;
        case 0x00000007:    /* Get Resource File Date */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            if (tvb_get_ntohl(tvb, foffset-4) != 0)
            {
                break;
            }
            proto_tree_add_item(ndps_tree, hf_file_timestamp, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        case 0x00000008:    /* Get Resource Manager NDS Object Name */
            foffset = qualifiedname(tvb, ndps_tree, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_error_val, tvb, foffset, 4, error_val);
            foffset += 4;
            break;
        case 0x00000009:    /* Get Resource Manager Session Information */
            proto_tree_add_item(ndps_tree, hf_ndps_get_resman_session_type, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_time, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            foffset = return_code(tvb, pinfo, ndps_tree, foffset);
            break;
        case 0x0000000a:    /* Set Resource Language Context */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            if (tvb_get_ntohl(tvb, foffset-4) != 0)
            {
                break;
            }
            proto_tree_add_item(ndps_tree, hf_ndps_language_id, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            break;
        default:
            break;
        }
        break;
    case 0x06097b:  /* Delivery */
        switch(ndps_func)
        {
        case 0x00000001:    /* Delivery Bind */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            break;
        case 0x00000002:    /* Delivery Unbind */
            /* NoOp */
            break;
        case 0x00000003:    /* Delivery Send */
        case 0x00000004:    /* Delivery Send2 */
            proto_tree_add_item(ndps_tree, hf_ndps_return_code, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            if (check_col(pinfo->cinfo, COL_INFO) && tvb_get_ntohl(tvb, foffset-4) != 0)
                col_set_str(pinfo->cinfo, COL_INFO, "R NDPS - Error");
            if (tvb_get_ntohl(tvb, foffset-4) != 0)
            {
                break;
            }
            number_of_items=tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, number_of_items);
            foffset += 4;
            aitem = proto_tree_add_text(ndps_tree, tvb, foffset, -1, "Failed Items");
            atree = proto_item_add_subtree(aitem, ett_ndps);
            for (i = 1 ; i <= number_of_items; i++ )
            {
                if (i > NDPS_MAX_ITEMS) {
                    proto_tree_add_text(atree, tvb, foffset, -1, "[Truncated]");
                    break;
                }
                bitem = proto_tree_add_text(atree, tvb, foffset, -1, "Item %d", i);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                length=tvb_get_ntohl(tvb, foffset);
                length_remaining = tvb_length_remaining(tvb, foffset);
                if(length_remaining == -1 || (guint32) length_remaining < length)
                {
                    return foffset;
                }
                proto_tree_add_item(btree, hf_ndps_item_ptr, tvb, foffset, length, ENC_NA);
                foffset += length;
                proto_item_set_end(bitem, tvb, foffset);
            }
            proto_item_set_end(aitem, tvb, foffset);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return foffset;
}

void
proto_register_ndps(void)
{
    static hf_register_info hf_ndps[] = {
        { &hf_ndps_record_mark,
          { "Record Mark",              "ndps.record_mark", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ndps_packet_type,
          { "Packet Type",    "ndps.packet_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_packet_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_length,
          { "Record Length",    "ndps.record_length",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_xid,
          { "Exchange ID",    "ndps.xid",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_rpc_version,
          { "RPC Version",    "ndps.rpc_version",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_program,
          { "NDPS Program Number",    "spx.ndps_program",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_program_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_version,
          { "Program Version",    "spx.ndps_version",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_error,
          { "NDPS Error",    "spx.ndps_error",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_other_error_string,
          { "Extended Error String",    "ndps.ext_err_string",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_print,
          { "Print Program",    "spx.ndps_func_print",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_print_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_notify,
          { "Notify Program",    "spx.ndps_func_notify",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_notify_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_delivery,
          { "Delivery Program",    "spx.ndps_func_delivery",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_deliver_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_registry,
          { "Registry Program",    "spx.ndps_func_registry",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_registry_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_resman,
          { "ResMan Program",    "spx.ndps_func_resman",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_resman_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_spx_ndps_func_broker,
          { "Broker Program",    "spx.ndps_func_broker",
            FT_UINT32,    BASE_HEX,   VALS(spx_ndps_broker_func_vals),   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_objects,
          { "Number of Objects",    "ndps.num_objects",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_attributes,
          { "Number of Attributes",    "ndps.num_attributes",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_sbuffer,
          { "Server",    "ndps.sbuffer",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_rbuffer,
          { "Connection",    "ndps.rbuffer",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_user_name,
          { "Trustee Name",    "ndps.user_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_broker_name,
          { "Broker Name",    "ndps.broker_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_results,
          { "Number of Results",    "ndps.num_results",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_options,
          { "Number of Options",    "ndps.num_options",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_jobs,
          { "Number of Jobs",    "ndps.num_jobs",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_pa_name,
          { "Printer Name",    "ndps.pa_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_tree,
          { "Tree",    "ndps.tree",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_reqframe,
          { "Request Frame",    "ndps.reqframe",
            FT_FRAMENUM,  BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_error_val,
          { "Return Status",    "ndps.error_val",
            FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_object,
          { "Object ID",    "ndps.object",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_cred_type,
          { "Credential Type",    "ndps.cred_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_credential_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_server_name,
          { "Server Name",    "ndps.server_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_connection,
          { "Connection",    "ndps.connection",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ext_error,
          { "Extended Error Code",    "ndps.ext_error",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_auth_null,
          { "Auth Null",    "ndps.auth_null",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_rpc_accept,
          { "RPC Accept or Deny",    "ndps.rpc_acc",
            FT_UINT32,    BASE_HEX,   VALS(true_false),   0x0,
            NULL, HFILL }},

        { &hf_ndps_rpc_acc_stat,
          { "RPC Accept Status",    "ndps.rpc_acc_stat",
            FT_UINT32,    BASE_HEX,   VALS(accept_stat),   0x0,
            NULL, HFILL }},

        { &hf_ndps_rpc_rej_stat,
          { "RPC Reject Status",    "ndps.rpc_rej_stat",
            FT_UINT32,    BASE_HEX,   VALS(reject_stat),   0x0,
            NULL, HFILL }},

        { &hf_ndps_rpc_acc_results,
          { "RPC Accept Results",    "ndps.rpc_acc_res",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_problem_type,
          { "Problem Type",    "ndps.rpc_prob_type",
            FT_UINT32,    BASE_HEX,   VALS(error_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_security_problem_type,
          { "Security Problem",    "ndps.rpc_sec_prob",
            FT_UINT32,    BASE_HEX,   VALS(security_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_service_problem_type,
          { "Service Problem",    "ndps.rpc_serv_prob",
            FT_UINT32,    BASE_HEX,   VALS(service_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_access_problem_type,
          { "Access Problem",    "ndps.rpc_acc_prob",
            FT_UINT32,    BASE_HEX,   VALS(access_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_printer_problem_type,
          { "Printer Problem",    "ndps.rpc_print_prob",
            FT_UINT32,    BASE_HEX,   VALS(printer_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_selection_problem_type,
          { "Selection Problem",    "ndps.rpc_sel_prob",
            FT_UINT32,    BASE_HEX,   VALS(selection_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_doc_access_problem_type,
          { "Document Access Problem",    "ndps.rpc_doc_acc_prob",
            FT_UINT32,    BASE_HEX,   VALS(doc_access_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_attribute_problem_type,
          { "Attribute Problem",    "ndps.rpc_attr_prob",
            FT_UINT32,    BASE_HEX,   VALS(attribute_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_update_problem_type,
          { "Update Problem",    "ndps.rpc_update_prob",
            FT_UINT32,    BASE_HEX,   VALS(update_problem_enum),   0x0,
            NULL, HFILL }},

        { &hf_obj_id_type,
          { "Object ID Type",    "ndps.rpc_obj_id_type",
            FT_UINT32,    BASE_HEX,   VALS(obj_identification_enum),   0x0,
            NULL, HFILL }},

        { &hf_oid_struct_size,
          { "OID Struct Size",    "ndps.rpc_oid_struct_size",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_object_name,
          { "Object Name",    "ndps.object_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_document_number,
          { "Document Number",    "ndps.doc_num",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_doc_content,
          { "Document Content",    "ndps.doc_content",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_nameorid,
          { "Name or ID Type",    "ndps.nameorid",
            FT_UINT32,    BASE_HEX,   VALS(nameorid_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_local_object_name,
          { "Local Object Name",    "ndps.loc_object_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_printer_name,
          { "Printer Name",    "ndps.printer_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_qualified_name,
          { "Qualified Name Type",    "ndps.qual_name_type",
            FT_UINT32,    BASE_HEX,   VALS(qualified_name_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_qualified_name2,
          { "Qualified Name Type",    "ndps.qual_name_type2",
            FT_UINT32,    BASE_HEX,   VALS(qualified_name_enum2),   0x0,
            NULL, HFILL }},

        { &hf_ndps_item_count,
          { "Number of Items",    "ndps.item_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_passwords,
          { "Number of Passwords",    "ndps.num_passwords",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_servers,
          { "Number of Servers",    "ndps.num_servers",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_locations,
          { "Number of Locations",    "ndps.num_locations",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_areas,
          { "Number of Areas",    "ndps.num_areas",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_address_items,
          { "Number of Address Items",    "ndps.num_address_items",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_job_categories,
          { "Number of Job Categories",    "ndps.num_job_categories",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_page_selects,
          { "Number of Page Select Items",    "ndps.num_page_selects",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_page_informations,
          { "Number of Page Information Items",    "ndps.num_page_informations",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_names,
          { "Number of Names",    "ndps.num_names",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_categories,
          { "Number of Categories",    "ndps.num_categories",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_colorants,
          { "Number of Colorants",    "ndps.num_colorants",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_events,
          { "Number of Events",    "ndps.num_events",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_args,
          { "Number of Arguments",    "ndps.num_argss",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_transfer_methods,
          { "Number of Transfer Methods",    "ndps.num_transfer_methods",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_doc_types,
          { "Number of Document Types",    "ndps.num_doc_types",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_destinations,
          { "Number of Destinations",    "ndps.num_destinations",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_qualifier,
          { "Qualifier",    "ndps.qual",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_lib_error,
          { "Library Error",    "ndps.lib_error",
            FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_other_error,
          { "Other Error",    "ndps.other_error",
            FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_other_error_2,
          { "Other Error 2",    "ndps.other_error_2",
            FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_session,
          { "Session Handle",    "ndps.session",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_abort_flag,
          { "Abort?",    "ndps.abort",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_obj_attribute_type,
          { "Value Syntax",    "ndps.attrib_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_attribute_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_attribute_value,
          { "Value",    "ndps.attribue_value",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_lower_range,
          { "Lower Range",    "ndps.lower_range",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_upper_range,
          { "Upper Range",    "ndps.upper_range",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_n64,
          { "Value",    "ndps.n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_lower_range_n64,
          { "Lower Range",    "ndps.lower_range_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_upper_range_n64,
          { "Upper Range",    "ndps.upper_range_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_attrib_boolean,
          { "Value?",    "ndps.attrib_boolean",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_realization,
          { "Realization Type",    "ndps.realization",
            FT_UINT32,    BASE_HEX,   VALS(ndps_realization_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_xdimension_n64,
          { "X Dimension",    "ndps.xdimension_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ydimension_n64,
          { "Y Dimension",    "ndps.ydimension_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_dim_value,
          { "Dimension Value Type",    "ndps.dim_value",
            FT_UINT32,    BASE_HEX,   VALS(ndps_dim_value_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_dim_flag,
          { "Dimension Flag",    "ndps.dim_falg",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_xydim_value,
          { "XY Dimension Value Type",    "ndps.xydim_value",
            FT_UINT32,    BASE_HEX,   VALS(ndps_xydim_value_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_location_value,
          { "Location Value Type",    "ndps.location_value",
            FT_UINT32,    BASE_HEX,   VALS(ndps_location_value_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_xmin_n64,
          { "Minimum X Dimension",    "ndps.xmin_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_xmax_n64,
          { "Maximum X Dimension",    "ndps.xmax_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ymin_n64,
          { "Minimum Y Dimension",    "ndps.ymin_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ymax_n64,
          { "Maximum Y Dimension",    "ndps.ymax_n64",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_edge_value,
          { "Edge Value",    "ndps.edge_value",
            FT_UINT32,    BASE_HEX,   VALS(ndps_edge_value_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_cardinal_or_oid,
          { "Cardinal or OID",    "ndps.car_or_oid",
            FT_UINT32,    BASE_HEX,   VALS(ndps_card_or_oid_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_cardinal_name_or_oid,
          { "Cardinal Name or OID",    "ndps.car_name_or_oid",
            FT_UINT32,    BASE_HEX,   VALS(ndps_card_name_or_oid_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_integer_or_oid,
          { "Integer or OID",    "ndps.integer_or_oid",
            FT_UINT32,    BASE_HEX,   VALS(ndps_integer_or_oid_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_profile_id,
          { "Profile ID",    "ndps.profile_id",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_persistence,
          { "Persistence",    "ndps.persistence",
            FT_UINT32,    BASE_HEX,   VALS(ndps_persistence_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_language_count,
          { "Number of Languages",    "ndps.language_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_language_id,
          { "Language ID",    "ndps.lang_id",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_address_type,
          { "Address Type",    "ndps.address_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_address_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_address,
          { "Address",    "ndps.address",
            FT_UINT32,    BASE_HEX,   VALS(ndps_address_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_add_bytes,
          { "Address Bytes",    "ndps.add_bytes",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_event_type,
          { "Event Type",    "ndps.event_type",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_event_object_identifier,
          { "Event Object Type",    "ndps.event_object_identifier",
            FT_UINT32,    BASE_HEX,   VALS(ndps_event_object_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_octet_string,
          { "Octet String",    "ndps.octet_string",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_scope,
          { "Scope",    "ndps.scope",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_address_len,
          { "Address Length",    "ndps.addr_len",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_net,
          { "IPX Network",    "ndps.net",
            FT_IPXNET,    BASE_NONE,   NULL,   0x0,
            "Scope", HFILL }},

        { &hf_ndps_node,
          { "Node",    "ndps.node",
            FT_ETHER,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_socket,
          { "IPX Socket",    "ndps.socket",
            FT_UINT16,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_port,
          { "IP Port",    "ndps.port",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ip,
          { "IP Address",    "ndps.ip",
            FT_IPv4,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_server_type,
          { "NDPS Server Type",    "ndps.server_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_server_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_services,
          { "Number of Services",    "ndps.num_services",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_service_type,
          { "NDPS Service Type",    "ndps.service_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_service_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_service_enabled,
          { "Service Enabled?",    "ndps.service_enabled",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_method_name,
          { "Method Name",    "ndps.method_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_method_ver,
          { "Method Version",    "ndps.method_ver",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_file_name,
          { "File Name",    "ndps.file_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_admin_submit,
          { "Admin Submit Flag?",    "ndps.admin_submit_flag",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_oid,
          { "Object ID",    "ndps.oid",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_object_op,
          { "Operation",    "ndps.object_op",
            FT_UINT32,    BASE_HEX,   VALS(ndps_object_op_enum),   0x0,
            NULL, HFILL }},

        { &hf_answer_time,
          { "Answer Time",    "ndps.answer_time",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_oid_asn1_type,
          { "ASN.1 Type",    "ndps.asn1_type",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_item_ptr,
          { "Item Pointer",    "ndps.item_ptr",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_len,
          { "Length",    "ndps.len",
            FT_UINT16,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_limit_enc,
          { "Limit Encountered",    "ndps.limit_enc",
            FT_UINT32,    BASE_HEX,   VALS(ndps_limit_enc_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_delivery_add_count,
          { "Number of Delivery Addresses",    "ndps.delivery_add_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_delivery_add_type,
          { "Delivery Address Type",    "ndps.delivery_add_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_delivery_add_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_criterion_type,
          { "Criterion Type",    "ndps.criterion_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_attribute_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_ignored_attributes,
          { "Number of Ignored Attributes",    "ndps.num_ignored_attributes",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ignored_type,
          { "Ignored Type",    "ndps.ignored_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_attribute_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_resources,
          { "Number of Resources",    "ndps.num_resources",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_resource_type,
          { "Resource Type",    "ndps.resource_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_resource_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_identifier_type,
          { "Identifier Type",    "ndps.identifier_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_identifier_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_page_flag,
          { "Page Flag",    "ndps.page_flag",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_media_type,
          { "Media Type",    "ndps.media_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_media_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_page_size,
          { "Page Size",    "ndps.page_size",
            FT_UINT32,    BASE_HEX,   VALS(ndps_page_size_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_direction,
          { "Direction",    "ndps.direction",
            FT_UINT32,    BASE_HEX,   VALS(ndps_pres_direction_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_page_order,
          { "Page Order",    "ndps.page_order",
            FT_UINT32,    BASE_HEX,   VALS(ndps_page_order_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_medium_size,
          { "Medium Size",    "ndps.medium_size",
            FT_UINT32,    BASE_HEX,   VALS(ndps_medium_size_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_long_edge_feeds,
          { "Long Edge Feeds?",    "ndps.long_edge_feeds",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_inc_across_feed,
          { "Increment Across Feed",    "ndps.inc_across_feed",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_size_inc_in_feed,
          { "Size Increment in Feed",    "ndps.size_inc_in_feed",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_page_orientation,
          { "Page Orientation",    "ndps.page_orientation",
            FT_UINT32,    BASE_HEX,   VALS(ndps_page_orientation_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_numbers_up,
          { "Numbers Up",    "ndps.numbers_up",
            FT_UINT32,    BASE_HEX,   VALS(ndps_numbers_up_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_xdimension,
          { "X Dimension",    "ndps.xdimension",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ydimension,
          { "Y Dimension",    "ndps.ydimension",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_state_severity,
          { "State Severity",    "ndps.state_severity",
            FT_UINT32,    BASE_HEX,   VALS(ndps_state_severity_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_training,
          { "Training",    "ndps.training",
            FT_UINT32,    BASE_HEX,   VALS(ndps_training_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_colorant_set,
          { "Colorant Set",    "ndps.colorant_set",
            FT_UINT32,    BASE_HEX,   VALS(ndps_colorant_set_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_card_enum_time,
          { "Cardinal, Enum, or Time",    "ndps.card_enum_time",
            FT_UINT32,    BASE_HEX,   VALS(ndps_card_enum_time_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_attrs_arg,
          { "List Attribute Operation",    "ndps.attrs_arg",
            FT_UINT32,    BASE_HEX,   VALS(ndps_attrs_arg_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_context_len,
          { "Context Length",    "ndps.context_len",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_context,
          { "Context",    "ndps.context",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_filter,
          { "Filter Type",    "ndps.filter",
            FT_UINT32,    BASE_HEX,   VALS(ndps_filter_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_item_filter,
          { "Filter Item Operation",    "ndps.filter_item",
            FT_UINT32,    BASE_HEX,   VALS(ndps_filter_item_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_substring_match,
          { "Substring Match",    "ndps.substring_match",
            FT_UINT32,    BASE_HEX,   VALS(ndps_match_criteria_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_time_limit,
          { "Time Limit",    "ndps.time_limit",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_count_limit,
          { "Count Limit",    "ndps.count_limit",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_operator,
          { "Operator Type",    "ndps.operator",
            FT_UINT32,    BASE_DEC,   VALS(ndps_operator_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_password,
          { "Password",    "ndps.password",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_retrieve_restrictions,
          { "Retrieve Restrictions",    "ndps.ret_restrict",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_bind_security_option_count,
          { "Number of Bind Security Options",    "ndps.bind_security_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_bind_security,
          { "Bind Security Options",    "ndps.bind_security",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_max_items,
          { "Maximum Items in List",    "ndps.max_items",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_status_flags,
          { "Status Flag",    "ndps.status_flags",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_resource_list_type,
          { "Resource Type",    "ndps.resource_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_resource_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_os_count,
          { "Number of OSes",    "ndps.os_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_os_type,
          { "OS Type",    "ndps.os_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_os_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_printer_type_count,
          { "Number of Printer Types",    "ndps.printer_type_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_printer_type,
          { "Printer Type",    "ndps.prn_type",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_printer_manuf,
          { "Printer Manufacturer",    "ndps.prn_manuf",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_inf_file_name,
          { "INF File Name",    "ndps.inf_file_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_vendor_dir,
          { "Vendor Directory",    "ndps.vendor_dir",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_banner_type,
          { "Banner Type",    "ndps.banner_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_banner_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_font_type,
          { "Font Type",    "ndps.font_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_font_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_printer_id,
          { "Printer ID",    "ndps.printer_id",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_font_name,
          { "Font Name",    "ndps.font_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_return_code,
          { "Return Code",    "ndps.ret_code",
            FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
            NULL, HFILL }},

        { &hf_ndps_banner_count,
          { "Number of Banners",    "ndps.banner_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_banner_name,
          { "Banner Name",    "ndps.banner_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_font_type_count,
          { "Number of Font Types",    "ndps.font_type_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_font_type_name,
          { "Font Type Name",    "ndps.font_type_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_font_file_count,
          { "Number of Font Files",    "ndps.font_file_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_font_file_name,
          { "Font File Name",    "ndps.font_file_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_printer_def_count,
          { "Number of Printer Definitions",    "ndps.printer_def_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_prn_file_name,
          { "Printer File Name",    "ndps.print_file_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_prn_dir_name,
          { "Printer Directory Name",    "ndps.print_dir_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_def_file_name,
          { "Printer Definition Name",    "ndps.print_def_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_win31_keys,
          { "Number of Windows 3.1 Keys",    "ndps.num_win31_keys",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_win95_keys,
          { "Number of Windows 95 Keys",    "ndps.num_win95_keys",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_windows_keys,
          { "Number of Windows Keys",    "ndps.num_windows_keys",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_windows_key,
          { "Windows Key",    "ndps.windows_key",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_archive_type,
          { "Archive Type",    "ndps.archive_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_archive_enum),   0x0,
            NULL, HFILL }},

        { &hf_archive_file_size,
          { "Archive File Size",    "ndps.archive_size",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_segment_overlap,
          { "Segment overlap",  "ndps.segment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Segment overlaps with other segments", HFILL }},

        { &hf_ndps_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "ndps.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Overlapping segments contained conflicting data", HFILL }},

        { &hf_ndps_segment_multiple_tails,
          { "Multiple tail segments found", "ndps.segment.multipletails",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Several tails were found when desegmenting the packet", HFILL }},

        { &hf_ndps_segment_too_long_segment,
          { "Segment too long", "ndps.segment.toolongsegment", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Segment contained data past end of packet", HFILL }},

        { &hf_ndps_segment_error,
          {"Desegmentation error",      "ndps.segment.error", FT_FRAMENUM, BASE_NONE,
           NULL, 0x0, "Desegmentation error due to illegal segments", HFILL }},

        { &hf_ndps_segment_count,
          {"Segment count",     "ndps.segment.count", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

        { &hf_ndps_reassembled_length,
          {"Reassembled NDPS length",   "ndps.reassembled.length", FT_UINT32, BASE_DEC,
           NULL, 0x0, "The total length of the reassembled payload", HFILL }},

        { &hf_ndps_segment,
          { "NDPS Fragment",            "ndps.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ndps_segments,
          { "NDPS Fragments",   "ndps.fragments", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ndps_data,
          { "[Data]",   "ndps.data", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_get_status_flag,
          { "Get Status Flag",    "ndps.get_status_flags",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_res_type,
          { "Resource Type",    "ndps.res_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_res_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_file_timestamp,
          { "File Time Stamp",    "ndps.file_time_stamp",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_print_arg,
          { "Print Type",    "ndps.print_arg",
            FT_UINT32,    BASE_DEC,   VALS(ndps_print_arg_enum),   0x0,
            NULL, HFILL }},

        { &hf_sub_complete,
          { "Submission Complete?",     "ndps.sub_complete", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_doc_content,
          { "Document Content",    "ndps.doc_content",
            FT_UINT32,    BASE_DEC,   VALS(ndps_doc_content_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_doc_name,
          { "Document Name",    "ndps.doc_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_local_id,
          { "Local ID",    "ndps.local_id",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_included_doc_len,
          { "Included Document Length",    "ndps.included_doc_len",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_included_doc,
          { "Included Document",    "ndps.included_doc",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ref_name,
          { "Referenced Document Name",    "ndps.ref_doc_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_interrupt_job_type,
          { "Interrupt Job Identifier",    "ndps.interrupt_job_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_interrupt_job_enum),   0x0,
            NULL, HFILL }},

        { &hf_pause_job_type,
          { "Pause Job Identifier",    "ndps.pause_job_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_pause_job_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_force,
          { "Force?",    "ndps.force",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_resubmit_op_type,
          { "Resubmit Operation Type",    "ndps.resubmit_op_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_resubmit_op_enum),   0x0,
            NULL, HFILL }},

        { &hf_shutdown_type,
          { "Shutdown Type",    "ndps.shutdown_type",
            FT_UINT32,    BASE_DEC,   VALS(ndps_shutdown_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_supplier_flag,
          { "Supplier Data?",    "ndps.supplier_flag",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_language_flag,
          { "Language Data?",    "ndps.language_flag",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_method_flag,
          { "Method Data?",    "ndps.method_flag",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_delivery_address_flag,
          { "Delivery Address Data?",    "ndps.delivery_flag",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_list_profiles_type,
          { "List Profiles Type",    "ndps.list_profiles_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_attrs_arg_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_list_profiles_choice_type,
          { "List Profiles Choice Type",    "ndps.list_profiles_choice_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_list_profiles_choice_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_list_profiles_result_type,
          { "List Profiles Result Type",    "ndps.list_profiles_result_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_list_profiles_result_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_integer_type_flag,
          { "Integer Type Flag",    "ndps.integer_type_flag",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_integer_type_value,
          { "Integer Type Value",    "ndps.integer_type_value",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_continuation_option,
          { "Continuation Option",    "ndps.continuation_option",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_ds_info_type,
          { "DS Info Type",    "ndps.ds_info_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_ds_info_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_guid,
          { "GUID",    "ndps.guid",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_list_services_type,
          { "Services Type",    "ndps.list_services_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_list_services_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_item_bytes,
          { "Item Ptr",    "ndps.item_bytes",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_certified,
          { "Certified",    "ndps.certified",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_attribute_set,
          { "Attribute Set",    "ndps.attribute_set",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_data_item_type,
          { "Item Type",    "ndps.data_item_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_data_item_enum),   0x0,
            NULL, HFILL }},

        { &hf_info_int,
          { "Integer Value",    "ndps.info_int",
            FT_UINT8,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_info_int16,
          { "16 Bit Integer Value",    "ndps.info_int16",
            FT_UINT16,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_info_int32,
          { "32 Bit Integer Value",    "ndps.info_int32",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_info_boolean,
          { "Boolean Value",    "ndps.info_boolean",
            FT_BOOLEAN,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_info_string,
          { "String Value",    "ndps.info_string",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_info_bytes,
          { "Byte Value",    "ndps.info_bytes",
            FT_BYTES,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_list_local_servers_type,
          { "Server Type",    "ndps.list_local_server_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_list_local_servers_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_registry_name,
          { "Registry Name",    "ndps.registry_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_client_server_type,
          { "Client/Server Type",    "ndps.client_server_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_client_server_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_session_type,
          { "Session Type",    "ndps.session_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_session_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_time,
          { "Time",    "ndps.time",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_supplier_name,
          { "Supplier Name",    "ndps.supplier_name",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_message,
          { "Message",    "ndps.message",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_delivery_method_count,
          { "Number of Delivery Methods",    "ndps.delivery_method_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_delivery_method_type,
          { "Delivery Method Type",    "ndps.delivery_method_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_delivery_method_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_get_session_type,
          { "Session Type",    "ndps.get_session_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_get_session_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_packet_count,
          { "Packet Count",    "ndps.packet_count",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_last_packet_flag,
          { "Last Packet Flag",    "ndps.last_packet_flag",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_get_resman_session_type,
          { "Session Type",    "ndps.get_resman_session_type",
            FT_UINT32,    BASE_HEX,   VALS(ndps_get_resman_session_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_problem_type,
          { "Problem Type",    "ndps.problem_type",
            FT_UINT32,    BASE_HEX,   VALS(problem_type_enum),   0x0,
            NULL, HFILL }},

        { &hf_ndps_num_values,
          { "Number of Values",    "ndps.num_values",
            FT_UINT32,    BASE_DEC,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_ndps_object_ids_7,
          { "Object ID Definition",    "ndps.objectid_def7",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_8,
          { "Object ID Definition",    "ndps.objectid_def8",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_9,
          { "Object ID Definition",    "ndps.objectid_def9",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_10,
          { "Object ID Definition",    "ndps.objectid_def10",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_11,
          { "Object ID Definition",    "ndps.objectid_def11",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_12,
          { "Object ID Definition",    "ndps.objectid_def12",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_13,
          { "Object ID Definition",    "ndps.objectid_def13",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_14,
          { "Object ID Definition",    "ndps.objectid_def14",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_15,
          { "Object ID Definition",    "ndps.objectid_def15",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_object_ids_16,
          { "Object ID Definition",    "ndps.objectid_def16",
            FT_NONE,    BASE_NONE,   NULL,
            0x0, NULL, HFILL }},

        { &hf_ndps_attribute_time,
          { "Time",    "ndps.attribute_time",
            FT_ABSOLUTE_TIME,    ABSOLUTE_TIME_LOCAL,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_print_security,
          { "Printer Security",    "ndps.print_security",
            FT_UINT32,    BASE_HEX,   VALS(ndps_print_security),   0x0,
            NULL, HFILL }},

        { &hf_notify_time_interval,
          { "Notify Time Interval",    "ndps.notify_time_interval",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_notify_sequence_number,
          { "Notify Sequence Number",    "ndps.notify_seq_number",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_notify_lease_exp_time,
          { "Notify Lease Expiration Time",    "ndps.notify_lease_exp_time",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_notify_printer_uri,
          { "Notify Printer URI",    "ndps.notify_printer_uri",
            FT_STRING,    BASE_NONE,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_level,
          { "Level",    "ndps.level",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},

        { &hf_interval,
          { "Interval",    "ndps.interval",
            FT_UINT32,    BASE_HEX,   NULL,   0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ndps,
        &ett_ndps_segments,
        &ett_ndps_segment,
    };
    module_t *ndps_module;

    proto_ndps = proto_register_protocol("Novell Distributed Print System", "NDPS", "ndps");
    proto_register_field_array(proto_ndps, hf_ndps, array_length(hf_ndps));
    proto_register_subtree_array(ett, array_length(ett));

    ndps_module = prefs_register_protocol(proto_ndps, NULL);
    prefs_register_bool_preference(ndps_module, "desegment_tcp",
                                   "Reassemble NDPS messages spanning multiple TCP segments",
                                   "Whether the NDPS dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &ndps_desegment);
    prefs_register_bool_preference(ndps_module, "desegment_spx",
                                   "Reassemble fragmented NDPS messages spanning multiple SPX packets",
                                   "Whether the NDPS dissector should reassemble fragmented NDPS messages spanning multiple SPX packets",
                                   &ndps_defragment);
    prefs_register_bool_preference(ndps_module, "show_oid",
                                   "Display NDPS Details",
                                   "Whether or not the NDPS dissector should show object id's and other details",
                                   &ndps_show_oids);

    register_init_routine(&ndps_init_protocol);
    register_postseq_cleanup_routine(&ndps_postseq_cleanup);
}

void
proto_reg_handoff_ndps(void)
{
    dissector_handle_t ndps_handle, ndps_tcp_handle;

    ndps_handle = create_dissector_handle(dissect_ndps_ipx, proto_ndps);
    ndps_tcp_handle = create_dissector_handle(dissect_ndps_tcp, proto_ndps);

    dissector_add_uint("spx.socket", SPX_SOCKET_PA, ndps_handle);
    dissector_add_uint("spx.socket", SPX_SOCKET_BROKER, ndps_handle);
    dissector_add_uint("spx.socket", SPX_SOCKET_SRS, ndps_handle);
    dissector_add_uint("spx.socket", SPX_SOCKET_ENS, ndps_handle);
    dissector_add_uint("spx.socket", SPX_SOCKET_RMS, ndps_handle);
    dissector_add_uint("spx.socket", SPX_SOCKET_NOTIFY_LISTENER, ndps_handle);
    dissector_add_uint("tcp.port", TCP_PORT_PA, ndps_tcp_handle);
    dissector_add_uint("tcp.port", TCP_PORT_BROKER, ndps_tcp_handle);
    dissector_add_uint("tcp.port", TCP_PORT_SRS, ndps_tcp_handle);
    dissector_add_uint("tcp.port", TCP_PORT_ENS, ndps_tcp_handle);
    dissector_add_uint("tcp.port", TCP_PORT_RMS, ndps_tcp_handle);
    dissector_add_uint("tcp.port", TCP_PORT_NOTIFY_LISTENER, ndps_tcp_handle);
    ndps_data_handle = find_dissector("data");
}
