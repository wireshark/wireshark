/* packet-ndps.c
 * Routines for NetWare's NDPS
 * Greg Morris <gmorris@novell.com>
 *
 * $Id: packet-ndps.c,v 1.7 2002/10/22 06:09:06 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ipx.h"
#include <epan/conversation.h>
#include "packet-ndps.h"

#define NDPS_PACKET_INIT_COUNT	200

static void dissect_ndps_request(tvbuff_t*, packet_info*, proto_tree*, guint32, guint32, guint32, int);

static void dissect_ndps_reply(tvbuff_t *, packet_info*, proto_tree*, guint32, int);

static int proto_ndps = -1;
static int hf_ndps_record_mark = -1;
static int hf_ndps_length = -1;
static int hf_ndps_xid = -1;
static int hf_ndps_packet_type = -1;
static int hf_ndps_rpc_version = -1;
static int hf_ndps_error = -1;
static int hf_ndps_items = -1;
static int hf_ndps_sbuffer = -1;
static int hf_ndps_rbuffer = -1;
static int hf_ndps_pa_name = -1;
static int hf_ndps_context = -1;
static int hf_ndps_tree = -1;
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
static int hf_local_object_name = -1;
static int hf_printer_name = -1;
static int hf_ndps_qualified_name = -1;
static int hf_ndps_item_count = -1;
static int hf_ndps_qualifier = -1;
static int hf_ndps_lib_error = -1;
static int hf_ndps_other_error = -1;
static int hf_ndps_other_error_2 = -1;
static int hf_ndps_session = -1;
static int hf_ndps_abort_flag = -1;
static int hf_obj_attribute_type = -1;
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
static int hf_ndps_language_id = -1;
static int hf_address_type = -1;
static int hf_ndps_address = -1;
static int hf_ndps_add_bytes = -1;
static int hf_ndps_event_type = -1;
static int hf_ndps_event_object_identifier = -1;
static int hf_ndps_octet_string = -1;
static int hf_ndps_scope = -1;

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

static const value_string true_false[] = {
    { 0x00000000, "Accept" },
    { 0x00000001, "Deny" },
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
    { 0x00000000, "None" },
    { 0x00000001, "Printer Contained Object ID" },
    { 0x00000002, "Document Identifier" },
    { 0x00000003, "Object Identifier" },
    { 0x00000004, "Object Name" },
    { 0x00000005, "Name or Object ID" },
    { 0x00000006, "Simple Name" },
    { 0x00000007, "Printer Configuration Object ID" },
    { 0x00000008, "Qualified Name" },
    { 0x00000009, "Event Object ID" },
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


static const value_string spx_ndps_program_vals[] = {
    { 0x00060976, "Print Program " },
    { 0x00060977, "Broker Program " },
    { 0x00060978, "Registry Program " },
    { 0x00060979, "Notify Program " },
    { 0x0006097a, "Resource Manager Program " },
    { 0x0006097b, "Programatic Delivery Program " },
    { 0,          NULL }
};

static const value_string spx_ndps_print_func_vals[] = {
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
    { 0,          NULL }
};

static const value_string spx_ndps_notify_func_vals[] = {
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
    { 0x00000001, "Delivery Bind" },
    { 0x00000002, "Delivery Unbind" },
    { 0x00000003, "Delivery Send" },
    { 0x00000004, "Delivery Send2" },
    { 0,          NULL }
};

static const value_string spx_ndps_registry_func_vals[] = {
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
    { 0x00000001, "Bind" },
    { 0x00000002, "Unbind" },
    { 0x00000003, "Add Resource File" },
    { 0x00000004, "Delete Resource File" },
    { 0x00000005, "List Resources" },
    { 0x00000006, "Get Resource File" },
    { 0x00000007, "Get Resource File Data" },
    { 0x00000008, "Get Resource Manager NDS Object Name" },
    { 0x00000009, "Get Resource Manager Session Information" },
    { 0x0000000a, "Set Resource Language Context" },
    { 0,          NULL }
};

static const value_string spx_ndps_broker_func_vals[] = {
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
    { 0x00000000, "ID" },
    { 0x00000001, "Name" },
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
    { 0x00000011, "Groupwise User" },
    { 0,          NULL }
};

static const value_string ndps_address_enum[] = {
    { 0x00000000, "IPX" },
    { 0x00000001, "IP" },
    { 0x00000002, "SDLC" },
    { 0x00000003, "Token Ring to Ethernet" },
    { 0x00000004, "OSI" },
    { 0x00000005, "Appletalk" },
    { 0x00000006, "Count" },
    { 0,          NULL }
};

static const value_string ndps_event_object_enum[] = {
    { 0x00000000, "Object" },
    { 0x00000001, "Filter" },
    { 0x00000002, "Detail" },
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
    { 0x00000007, "Distinguished Name" },
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
    { 0xFFFFFC18, "NWDP_OE_BK_OUT_OF_MEMORY" },      /* Broker Errors */
    { 0xFFFFFC17, "NWDP_OE_BK_BAD_NETWARE_VERSION" },
    { 0xFFFFFC16, "NWDP_OE_BK_WRONG_CMD_LINE_ARGS" },
    { 0xFFFFFC15, "NWDP_OE_BK_BROKER_NAME_NOT_GIVN" },
    { 0xFFFFFC14, "NWDP_OE_BK_NOT_BROKER_CLASS" },
    { 0xFFFFFC13, "NWDP_OE_BK_INVALID_BROKER_PWORD" },
    { 0xFFFFFC12, "NWDP_OE_BK_INVALID_BROKER_NAME" },
    { 0xFFFFFC11, "NWDP_OE_BK_FAILED_TO_CRTE_THRED" },
    { 0xFFFFFC10, "NWDP_OE_BK_FAILED_TO_INIT_NUT" },
    { 0xFFFFFC0F, "NWDP_OE_BK_FAILED_TO_GET_MSGS" },
    { 0xFFFFFC0E, "NWDP_OE_BK_FAILED_TO_ALLOC_RES" },
    { 0xFFFFFC0D, "NWDP_OE_BK_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFC0C, "NWDP_OE_BK_UNINITIALIZED_MODULE" },
    { 0xFFFFFC0B, "NWDP_OE_BK_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFC0A, "NWDP_OE_BK_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFC09, "NWDP_OE_BK_UNKNOWN_SESSION" },
    { 0xFFFFFC08, "NWDP_OE_BK_SERVICE_DISABLED" },
    { 0xFFFFFC07, "NWDP_OE_BK_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFC06, "NWDP_OE_BK_INVALID_ARGUMENTS" },
    { 0xFFFFFC05, "NWDP_OE_BK_DUPLICATE_SESSION_ID" },
    { 0xFFFFFC04, "NWDP_OE_BK_UNKNOWN_SERVICE" },
    { 0xFFFFFC03, "NWDP_OE_BK_SRVC_ALREADY_ENABLED" },
    { 0xFFFFFC02, "NWDP_OE_BK_SRVC_ALREADY_DISABLD" },
    { 0xFFFFFC01, "NWDP_OE_BK_INVALID_CREDENTIAL" },
    { 0xFFFFFC00, "NWDP_OE_BK_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFBFF, "NWDP_OE_BK_FAIL_MAKE_CHG_PERMNT" },
    { 0xFFFFFBFE, "NWDP_OE_BK_NOT_ADMIN_TYPE_SESN" },
    { 0xFFFFFBFD, "NWDP_OE_BK_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFBFC, "NWDP_OE_BK_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFBFB, "NWDP_OE_BK_COULD_NOT_FIND_FILE" },
    { 0xFFFFFBFA, "NWDP_OE_BK_ERROR_READING_FILE" },
    { 0xFFFFFBF9, "NWDP_OE_BK_NOT_NLM_FILE_FORMAT" },
    { 0xFFFFFBF8, "NWDP_OE_BK_WRONG_NLM_FILE_VER" },
    { 0xFFFFFBF7, "NWDP_OE_BK_REENTRANT_INIT_FAIL" },
    { 0xFFFFFBF6, "NWDP_OE_BK_ALREADY_IN_PROGRESS" },
    { 0xFFFFFBF5, "NWDP_OE_BK_INITIALIZE_FAILURE" },
    { 0xFFFFFBF4, "NWDP_OE_BK_INCONSISTNT_FILE_FMT" },
    { 0xFFFFFBF3, "NWDP_OE_BK_CANT_LOAD_AT_STARTUP" },
    { 0xFFFFFBF2, "NWDP_OE_BK_AUTO_MODULS_NOT_LOAD" },
    { 0xFFFFFBF1, "NWDP_OE_BK_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFBF0, "NWDP_OE_BK_PUBLIC_ALREADY_DEFND" },
    { 0xFFFFFBEF, "NWDP_OE_BK_OTHER_BRKR_USING_OBJ" },
    { 0xFFFFFBEE, "NWDP_OE_BK_SRVC_FAILED_TO_INIT" },
    { 0xFFFFFBB4, "NWDP_OE_RG_OUT_OF_MEMORY" },       /* SRS Errors */
    { 0xFFFFFBB3, "NWDP_OE_RG_BAD_NETWARE_VERSION" },
    { 0xFFFFFBB2, "NWDP_OE_RG_FAIL_CREATE_CONTEXT" },
    { 0xFFFFFBB1, "NWDP_OE_RG_FAIL_LOGIN" },
    { 0xFFFFFBB0, "NWDP_OE_RG_FAIL_CREATE_THREAD" },
    { 0xFFFFFBAF, "NWDP_OE_RG_FAIL_GET_MSGS" },
    { 0xFFFFFBAE, "NWDP_OE_RG_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFBAD, "NWDP_OE_RG_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFBAC, "NWDP_OE_RG_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFBAB, "NWDP_OE_RG_UNKNOWN_SESSION" },
    { 0xFFFFFBAA, "NWDP_OE_RG_SERVICE_DISABLED" },
    { 0xFFFFFBA9, "NWDP_OE_RG_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFBA8, "NWDP_OE_RG_CANT_START_ADVERTISE" },
    { 0xFFFFFBA7, "NWDP_OE_RG_DUP_SERVER_ENTRY" },
    { 0xFFFFFBA6, "NWDP_OE_RG_CANT_BIND_2_REGISTRY" },
    { 0xFFFFFBA5, "NWDP_OE_RG_CANT_CREATE_CLIENT" },
    { 0xFFFFFBA4, "NWDP_OE_RG_INVALID_ARGUMENTS" },
    { 0xFFFFFBA3, "NWDP_OE_RG_DUPLICATE_SESSION_ID" },
    { 0xFFFFFBA2, "NWDP_OE_RG_UNKNOWN_SERVER_ENTRY" },
    { 0xFFFFFBA1, "NWDP_OE_RG_INVALID_CREDENTIAL" },
    { 0xFFFFFBA0, "NWDP_OE_RG_REGIST_TYPE_SESN" },
    { 0xFFFFFB9F, "NWDP_OE_RG_SERVER_TYPE_SESN" },
    { 0xFFFFFB9E, "NWDP_OE_RG_NOT_SERVER_TYPE_SESN" },
    { 0xFFFFFB9D, "NWDP_OE_RG_NOT_REGIST_TYPE_SESN" },
    { 0xFFFFFB9C, "NWDP_OE_RG_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFB9B, "NWDP_OE_RG_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFB9A, "NWDP_OE_RG_NOT_IN_LST_ITERATION" },
    { 0xFFFFFB99, "NWDP_OE_RG_INVLD_CONTNUATN_HNDL" },
    { 0xFFFFFB50, "NWDP_OE_NF_OUT_OF_MEMORY" },        /* Notification Service Errors */
    { 0xFFFFFB4F, "NWDP_OE_NF_BAD_NETWARE_VERSION" },
    { 0xFFFFFB4E, "NWDP_OE_NF_FAIL_CREATE_THREAD" },
    { 0xFFFFFB4D, "NWDP_OE_NF_FAIL_GET_MSGS" },
    { 0xFFFFFB4C, "NWDP_OE_NF_FAIL_CREATE_CONTEXT" },
    { 0xFFFFFB4B, "NWDP_OE_NF_FAIL_LOGIN" },
    { 0xFFFFFB4A, "NWDP_OE_NF_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFB49, "NWDP_OE_NF_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFB48, "NWDP_OE_NF_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFB47, "NWDP_OE_NF_UNKNOWN_SESSION" },
    { 0xFFFFFB46, "NWDP_OE_NF_UNKNOWN_NOTIFY_PROF" },
    { 0xFFFFFB45, "NWDP_OE_NF_ERROR_READING_FILE" },
    { 0xFFFFFB44, "NWDP_OE_NF_ERROR_WRITING_FILE" },
    { 0xFFFFFB43, "NWDP_OE_NF_WRONG_NOTIFY_DB_VERS" },
    { 0xFFFFFB42, "NWDP_OE_NF_CORRUPTED_NOTIFY_DB" },
    { 0xFFFFFB41, "NWDP_OE_NF_UNKNOWN_EVENT_OID" },
    { 0xFFFFFB40, "NWDP_OE_NF_METHOD_ALREADY_INST" },
    { 0xFFFFFB3F, "NWDP_OE_NF_UNKNOWN_METHOD" },
    { 0xFFFFFB3E, "NWDP_OE_NF_SERVICE_DISABLED" },
    { 0xFFFFFB3D, "NWDP_OE_NF_UNKNOWN_MODIFY_OP" },
    { 0xFFFFFB3C, "NWDP_OE_NF_OUT_OF_NOTIFY_ENTRYS" },
    { 0xFFFFFB3B, "NWDP_OE_NF_UNKNOWN_LANGUAGE_ID" },
    { 0xFFFFFB3A, "NWDP_OE_NF_NOTIFY_QUEUE_EMPTY" },
    { 0xFFFFFB39, "NWDP_OE_NF_CANT_LOAD_DELVR_METH" },
    { 0xFFFFFB38, "NWDP_OE_NF_INVALID_ARGUMENTS" },
    { 0xFFFFFB37, "NWDP_OE_NF_DUPLICATE_SESSION_ID" },
    { 0xFFFFFB36, "NWDP_OE_NF_INVALID_CREDENTIAL" },
    { 0xFFFFFB35, "NWDP_OE_NF_UNKNOWN_CHOICE" },
    { 0xFFFFFB34, "NWDP_OE_NF_UNKNOWN_ATTR_VALUE" },
    { 0xFFFFFB33, "NWDP_OE_NF_ERROR_WRITING_DB" },
    { 0xFFFFFB32, "NWDP_OE_NF_UNKNOWN_OBJECT_ID" },
    { 0xFFFFFB31, "NWDP_OE_NF_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFB30, "NWDP_OE_NF_FAIL_MAKE_CHG_PERMNT" },
    { 0xFFFFFB2F, "NWDP_OE_NF_UI_NOT_SUPPORTED" },
    { 0xFFFFFB2E, "NWDP_OE_NF_NOT_SUPPLY_TYPE_SESN" },
    { 0xFFFFFB2D, "NWDP_OE_NF_NOT_ADMIN_TYPE_SESN" },
    { 0xFFFFFB2C, "NWDP_OE_NF_NO_SRVC_REGIST_AVAIL" },
    { 0xFFFFFB2B, "NWDP_OE_NF_FAIL_TO_REG_W_ANY_SR" },
    { 0xFFFFFB2A, "NWDP_OE_NF_EMPTY_EVENT_OBJ_SET" },
    { 0xFFFFFB29, "NWDP_OE_NF_UNKNOWN_NTFY_HANDLE" },
    { 0xFFFFFB28, "NWDP_OE_NF_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFB27, "NWDP_OE_NF_UNKNOWN_RPC_SESSION" },
    { 0xFFFFFB26, "NWDP_OE_NF_INITIALIZATION_ERROR" },
    { 0xFFFFFB25, "NWDP_OE_NF_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFB24, "NWDP_OE_NF_NO_PERSISTENT_STORAG" },
    { 0xFFFFFB23, "NWDP_OE_NF_BAD_METHOD_FILENAME" },
    { 0xFFFFFB22, "NWDP_OE_NF_UNKNOWN_CONT_HANDLE" },
    { 0xFFFFFB21, "NWDP_OE_NF_INVALID_CONT_HANDLE" },
    { 0xFFFFFB20, "NWDP_OE_NF_COULD_NOT_FIND_FILE" },
    { 0xFFFFFB1F, "NWDP_OE_NF_L_ERROR_READING_FILE" },
    { 0xFFFFFB1E, "NWDP_OE_NF_NOT_NLM_FILE_FORMAT" },
    { 0xFFFFFB1D, "NWDP_OE_NF_WRONG_NLM_FILE_VER" },
    { 0xFFFFFB1C, "NWDP_OE_NF_REENTRANT_INIT_FAIL" },
    { 0xFFFFFB1B, "NWDP_OE_NF_ALREADY_IN_PROGRESS" },
    { 0xFFFFFB1A, "NWDP_OE_NF_INITIALIZE_FAILURE" },
    { 0xFFFFFB19, "NWDP_OE_NF_INCONSISTNT_FILE_FMT" },
    { 0xFFFFFB18, "NWDP_OE_NF_CANT_LOAD_AT_STARTUP" },
    { 0xFFFFFB17, "NWDP_OE_NF_AUTO_MODULS_NOT_LOAD" },
    { 0xFFFFFB16, "NWDP_OE_NF_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFB15, "NWDP_OE_NF_PUBLIC_ALREADY_DEFND" },
    { 0xFFFFFB14, "NWDP_OE_NF_USING_UNKNOWN_METHDS" },
    { 0xFFFFFB13, "NWDP_OE_NF_SRVC_NOT_FULL_ENABLD" },
    { 0xFFFFFB12, "NWDP_OE_NF_FOREIGN_NDS_TREE_NAM" },
    { 0xFFFFFB11, "NWDP_OE_NF_DLVYMETH_REJCTD_ADDR" },
    { 0xFFFFFB10, "NWDP_OE_NF_UNSUPRT_DLVYADDRTYPE" },
    { 0xFFFFFB0F, "NWDP_OE_NF_USR_OBJ_NO_DEFLTSERV" },
    { 0xFFFFFB0E, "NWDP_OE_NF_FAILED_TO_SEND_NOTIF" },
    { 0xFFFFFB0D, "NWDP_OE_NF_BAD_VOLUME_IN_ADDR" },
    { 0xFFFFFB0C, "NWDP_OE_NF_BROKER_NO_FILE_RIGHT" },
    { 0xFFFFFB0B, "NWDP_OE_NF_MAX_METHDS_SUPPORTED" },
    { 0xFFFFFB0A, "NWDP_OE_NF_NO_FILTER_PROVIDED" },
    { 0xFFFFFB09, "NE_IPX_NOT_SUPPORTED_BY_METHOD" },
    { 0xFFFFFB08, "NE_IP_NOT_SUPPORTED_BY_METHOD" },
    { 0xFFFFFB07, "NE_FAILED_TO_STARTUP_WINSOCK" },
    { 0xFFFFFB06, "NE_NO_PROTOCOLS_AVAILABLE" },
    { 0xFFFFFB05, "NE_FAILED_TO_LAUNCH_RPC_SERVER" },
    { 0xFFFFFB04, "NE_INVALID_SLP_ATTR_FORMAT" },
    { 0xFFFFFB03, "NE_INVALID_SLP_URL_FORMAT" },
    { 0xFFFFFB02, "NE_UNKNOWN_ATTRIBUTE_OID" },
    { 0xFFFFFB01, "NE_DUPLICATE_SESSION_ID" },
    { 0xFFFFFB00, "NE_FAILED_TO_AUTHENTICATE" },
    { 0xFFFFFAFF, "NE_FAILED_TO_AUTH_PROTOCOL_MISMATCH" },
    { 0xFFFFFAFE, "NE_FAILED_TO_AUTH_INTERNAL_ERROR" },
    { 0xFFFFFAFD, "NE_FAILED_TO_AUTH_CONNECTION_ERROR" },
    { 0xFFFFFC7C, "NWDP_OE_RM_OUT_OF_MEMORY" },  /* ResMan Errors */
    { 0xFFFFFC7B, "NWDP_OE_RM_BAD_NETWARE_VERSION" },
    { 0xFFFFFC7A, "NWDP_OE_RM_WRONG_CMD_LINE_ARGS" },
    { 0xFFFFFC79, "NWDP_OE_RM_BROKER_NAME_NOT_GIVN" },
    { 0xFFFFFC78, "NWDP_OE_RM_INVALID_BROKER_PWORD" },
    { 0xFFFFFC77, "NWDP_OE_RM_INVALID_BROKER_NAME" },
    { 0xFFFFFC76, "NWDP_OE_RM_FAILED_TO_CRTE_THRED" },
    { 0xFFFFFC75, "NWDP_OE_RM_SVC_MUST_BE_FULL_DIS" },
    { 0xFFFFFC74, "NWDP_OE_RM_DS_VAL_SIZE_TOO_LARG" },
    { 0xFFFFFC73, "NWDP_OE_RM_NO_ATTRIBUTE_VALUES" },
    { 0xFFFFFC72, "NWDP_OE_RM_UNKNOWN_SESSION" },
    { 0xFFFFFC71, "NWDP_OE_RM_ERROR_READING_FILE" },
    { 0xFFFFFC70, "NWDP_OE_RM_ERROR_WRITING_FILE" },
    { 0xFFFFFC6F, "NWDP_OE_RM_SERVICE_DISABLED" },
    { 0xFFFFFC6E, "NWDP_OE_RM_UNKNOWN_MODIFY_OPER" },
    { 0xFFFFFC6D, "NWDP_OE_RM_DUPLICATE_SESSION_ID" },
    { 0xFFFFFC6C, "NWDP_OE_RM_INVALID_CREDENTIAL" },
    { 0xFFFFFC6B, "NWDP_OE_RM_NO_SRVC_REGIST_AVAIL" },
    { 0xFFFFFC6A, "NWDP_OE_RM_FAIL_TO_REG_W_ANY_SR" },
    { 0xFFFFFC69, "NWDP_OE_RM_FAIL_TO_GET_MSGS" },
    { 0xFFFFFC68, "NWDP_OE_RM_FAIL_TO_CRTE_CONTEXT" },
    { 0xFFFFFC67, "NWDP_OE_RM_FAIL_TO_LOGIN" },
    { 0xFFFFFC66, "NWDP_OE_RM_NPD_FILE_GEN_ERR" },
    { 0xFFFFFC65, "NWDP_OE_RM_INF_FILE_FORMAT_ERR" },
    { 0xFFFFFC64, "NWDP_OE_RM_NO_PRT_TYPE_IN_INF" },
    { 0xFFFFFC63, "NWDP_OE_RM_NO_INF_FILES_PRESENT" },
    { 0xFFFFFC62, "NWDP_OE_RM_FILE_OPEN_ERROR" },
    { 0xFFFFFC61, "NWDP_OE_RM_READ_FILE_ERROR" },
    { 0xFFFFFC60, "NWDP_OE_RM_WRITE_FILE_ERROR" },
    { 0xFFFFFC5F, "NWDP_OE_RM_RESRC_TYPE_INVALID" },
    { 0xFFFFFC5E, "NWDP_OE_RM_NO_SUCH_FILENAME" },
    { 0xFFFFFC5D, "NWDP_OE_RM_BANR_TYPE_INVALID" },
    { 0xFFFFFC5C, "NWDP_OE_RM_LIST_TYPE_UNKNOWN" },
    { 0xFFFFFC5B, "NWDP_OE_RM_OS_NOT_SUPPORTED" },
    { 0xFFFFFC5A, "NWDP_OE_RM_NO_BANR_FILES_PRESNT" },
    { 0xFFFFFC59, "NWDP_OE_RM_PRN_DEF_TYPE_UNKNOWN" },
    { 0xFFFFFC58, "NWDP_OE_RM_NO_PRN_TYPES_IN_LIST" },
    { 0xFFFFFC57, "NWDP_OE_RM_OPTION_NOT_SUPPORTED" },
    { 0xFFFFFC56, "NWDP_OE_RM_UNICODE_CONV_ERR" },
    { 0xFFFFFC55, "NWDP_OE_RM_INVALID_ARGUMENTS" },
    { 0xFFFFFC54, "NWDP_OE_RM_INITIALIZATION_ERROR" },
    { 0xFFFFFC53, "NWDP_OE_RM_NO_SRV_REG_AVAILABLE" },
    { 0xFFFFFC52, "NWDP_OE_RM_FAIL_RGSTR_TO_ANY_SR" },
    { 0xFFFFFC51, "NWDP_OE_RM_UNKNOWN_DESIGNATOR" },
    { 0xFFFFFC50, "NWDP_OE_RM_NOT_ADMIN_SESSION" },
    { 0xFFFFFC4F, "NWDP_OE_RM_NO_EFFECTIVE_RIGHTS" },
    { 0xFFFFFC4E, "NWDP_OE_RM_BAD_FILE_ATTRIBUTE" },
    { 0xFFFFFC4D, "NWDP_OE_RM_DID_FORMAT_ERROR" },
    { 0xFFFFFC4C, "NWDP_OE_RM_UNKNOWN_RPC_SESSION" },
    { 0xFFFFFC4B, "NWDP_OE_RM_SESSN_BEING_REMOVED" },
    { 0xFFFFFC49, "NWDP_OE_RM_FMGR_IO_ERROR" },
    { 0xFFFFFC48, "NWDP_OE_RM_FMGR_REENTRANCY" },
    { 0xFFFFFC47, "NWDP_OE_RM_FMGR_SEQ_ERROR" },
    { 0xFFFFFC46, "NWDP_OE_RM_FMGR_CRPT_INDEX_FILE" },
    { 0xFFFFFC45, "NWDP_OE_RM_FMGR_NO_SUCH_FONT" },
    { 0xFFFFFC44, "NWDP_OE_RM_FMGR_NOT_INITIALIZED" },
    { 0xFFFFFC43, "NWDP_OE_RM_FMGR_SYSTEM_ERROR" },
    { 0xFFFFFC42, "NWDP_OE_RM_FMGR_BAD_PARM" },
    { 0xFFFFFC41, "NWDP_OE_RM_FMGR_PATH_TOO_LONG" },
    { 0xFFFFFC40, "NWDP_OE_RM_FMGR_FAILURE" },
    { 0xFFFFFC3F, "NWDP_OE_RM_DUP_TIRPC_SESSION" },
    { 0xFFFFFC3E, "NWDP_OE_RM_CONN_LOST_RMS_DATA" },
    { 0xFFFFFC3D, "NWDP_OE_RM_FAIL_START_WINSOCK" },
    { 0xFFFFFC3C, "NWDP_OE_RM_NO_PROTOCOLS_AVAIL" },
    { 0xFFFFFC3B, "NWDP_OE_RM_FAIL_LNCH_RPC_SRVR" },
    { 0xFFFFFC3A, "NWDP_OE_RM_INVALID_SLP_ATTR_FMT" },
    { 0xFFFFFC39, "NWDP_OE_RM_INVALID_SLP_URL_FMT" },
    { 0xFFFFFC38, "NWDP_OE_RM_UNRESOLVED_EXTERNAL" },
    { 0xFFFFFC37, "NWDP_OE_RM_FAILED_TO_AUTHENT" },
    { 0xFFFFFC36, "NWDP_OE_RM_FAIL_AUTH_PROT_MISMA" },
    { 0xFFFFFC35, "NWDP_OE_RM_FAIL_AUTH_INT_ERR" },
    { 0xFFFFFC34, "NWDP_OE_RM_FAIL_AUTH_CONN_ERR" },
    { 0xFFFFFC33, "NWDP_OE_RM_NO_RIGHTS_REM_RESDIR" },
    { 0xFFFFFC32, "NWDP_OE_RM_CANT_INIT_NDPS_LIB" },
    { 0xFFFFFC31, "NWDP_OE_RM_CANT_CREAT_RESREF" },
    { 0xFFFFFC30, "NWDP_OE_RM_FILE_ZERO_LENGTH" },
    { 0xFFFFFC2F, "NWDP_OE_RM_FAIL_WRI_INF_IN_ADD" },
    { 0xFFFFFCDF, "NDPS_E_NO_MEMORY" },               /* NDPSM Errors */
    { 0xFFFFFCDE, "NDPS_E_MEMORY_NOT_FOUND" },
    { 0xFFFFFCDD, "NDPS_E_JOB_STORAGE_LIMIT" },
    { 0xFFFFFCDC, "NDPS_E_JOB_RETENTION_LIMIT" },
    { 0xFFFFFCDB, "NDPS_E_UNSUPPORTED_TYPE" },
    { 0xFFFFFCDA, "NDPS_E_UNDEFINED_TYPE" },
    { 0xFFFFFCD9, "NDPS_E_UNSUPPORTED_OP" },
    { 0xFFFFFCD8, "NDPS_E_ACCESSING_DB" },
    { 0xFFFFFCD7, "NDPS_E_NO_PDS" },
    { 0xFFFFFCD6, "NDPS_E_INVALID_CLASS" },
    { 0xFFFFFCD5, "NDPS_E_BAD_PARAMETER" },
    { 0xFFFFFCD4, "NDPS_E_OBJECT_NOT_FOUND" },
    { 0xFFFFFCD3, "NDPS_E_ATTRIBUTE_NOT_FOUND" },
    { 0xFFFFFCD2, "NDPS_E_VALUE_NOT_FOUND" },
    { 0xFFFFFCD1, "NDPS_E_VALUES_NOT_COMPARABLE" },
    { 0xFFFFFCD0, "NDPS_E_INVALID_VALUE_SYNTAX" },
    { 0xFFFFFCCF, "NDPS_E_JOB_NOT_FOUND" },
    { 0xFFFFFCCE, "NDPS_E_COMMUNICATION" },
    { 0xFFFFFCCD, "NDPS_E_PA_INITIALIZING" },
    { 0xFFFFFCCC, "NDPS_E_PA_GOING_DOWN" },
    { 0xFFFFFCCB, "NDPS_E_PA_DISABLED" },
    { 0xFFFFFCCA, "NDPS_E_PA_PAUSED" },
    { 0xFFFFFCC9, "NDPS_E_BAD_PA_HANDLE" },
    { 0xFFFFFCC8, "NDPS_E_OBJECT_NOT_LOCKED" },
    { 0xFFFFFCC7, "NDPS_E_VERSION_INCOMPATIBLE" },
    { 0xFFFFFCC6, "NDPS_E_PSM_INITIALIZING" },
    { 0xFFFFFCC5, "NDPS_E_PSM_GOING_DOWN" },
    { 0xFFFFFCC4, "NDPS_E_NOTIF_SVC_ERROR" },
    { 0xFFFFFCC3, "NDPS_E_MEDIUM_NEEDS_MOUNTED" },
    { 0xFFFFFCC2, "NDPS_E_PDS_NOT_RESPONDING" },
    { 0xFFFFFCC1, "NDPS_E_SESSION_NOT_FOUND" },
    { 0xFFFFFCC0, "NDPS_E_RPC_FAILURE" },
    { 0xFFFFFCBF, "NDPS_E_DUPLICATE_VALUE" },
    { 0xFFFFFCBE, "NDPS_E_PDS_REFUSES_RENAME" },
    { 0xFFFFFCBD, "NDPS_E_NO_MANDATORY_ATTR" },
    { 0xFFFFFCBC, "NDPS_E_ALREADY_ATTACHED" },
    { 0xFFFFFCBB, "NDPS_E_CANT_ATTACH" },
    { 0xFFFFFCBA, "NDPS_E_TOO_MANY_NW_SERVERS" },
    { 0xFFFFFCB9, "NDPS_E_CANT_CREATE_DOC_FILE" },
    { 0xFFFFFCB8, "NDPS_E_CANT_DELETE_DOC_FILE" },
    { 0xFFFFFCB7, "NDPS_E_CANT_OPEN_DOC_FILE" },
    { 0xFFFFFCB6, "NDPS_E_CANT_WRITE_DOC_FILE" },
    { 0xFFFFFCB5, "NDPS_E_JOB_IS_ACTIVE" },
    { 0xFFFFFCB4, "NDPS_E_NO_SCHEDULER" },
    { 0xFFFFFCB3, "NDPS_E_CHANGING_CONNECTION" },
    { 0xFFFFFCB2, "NDPS_E_COULD_NOT_CREATE_ACC_REF" },
    { 0xFFFFFCB1, "NDPS_E_ACCTG_SVC_ERROR" },
    { 0xFFFFFCB0, "NDPS_E_RMS_SVC_ERROR" },
    { 0xFFFFFCAF, "NDPS_E_FAILED_VALIDATION" },
    { 0xFFFFFCAE, "NDPS_E_BROKER_SRVR_CONNECTING" },
    { 0xFFFFFCAD, "NDPS_E_SRS_SVC_ERROR" },
    { 0xFFFFFD44, "JPM_W_EXECUTE_REQUEST_LATER" },
    { 0xFFFFFD43, "JPM_E_FAILED_TO_OPEN_DOC" },
    { 0xFFFFFD42, "JPM_E_FAILED_READ_DOC_FILE" },
    { 0xFFFFFD41, "JPM_E_BAD_PA_HANDLE" },
    { 0xFFFFFD40, "JPM_E_BAD_JOB_HANDLE" },
    { 0xFFFFFD3F, "JPM_E_BAD_DOC_HANDLE" },
    { 0xFFFFFD3E, "JPM_E_UNSUPPORTED_OP" },
    { 0xFFFFFD3D, "JPM_E_REQUEST_QUEUE_FULL" },
    { 0xFFFFFD3C, "JPM_E_PA_NOT_FOUND" },
    { 0xFFFFFD3B, "JPM_E_INVALID_REQUEST" },
    { 0xFFFFFD3A, "JPM_E_NOT_ACCEPTING_REQ" },
    { 0xFFFFFD39, "JPM_E_PA_ALREADY_SERVICED_BY_PDS" },
    { 0xFFFFFD38, "JPM_E_NO_JOB" },
    { 0xFFFFFD37, "JPM_E_JOB_NOT_FOUND" },
    { 0xFFFFFD36, "JPM_E_COULD_NOT_ACCESS_DATA_BASE" },
    { 0xFFFFFD35, "JPM_E_BAD_OBJ_TYPE" },
    { 0xFFFFFD34, "JPM_E_JOB_ALREADY_CLOSED" },
    { 0xFFFFFD33, "JPM_E_DOC_ALREADY_CLOSED" },
    { 0xFFFFFD32, "JPM_E_PH_NOT_REGISTERED" },
    { 0xFFFFFD31, "JPM_E_VERSION_INCOMPATIBLE" },
    { 0xFFFFFD30, "JPM_E_PA_PAUSED" },
    { 0xFFFFFD2F, "JPM_E_PA_SHUTDOWN" },
    { 0xFFFFFD2E, "JPM_E_NO_CLIB_CONTEXT" },
    { 0xFFFFFD2D, "JPM_E_ACCOUNTING_ALREADY_SERVICE" },
    { 0xFFFFFC7B, "DB_E_CANT_CREATE_FILE" },
    { 0xFFFFFC7A, "DB_E_CANT_FIND_DATA_FILE" },
    { 0xFFFFFC79, "DB_E_CANT_OPEN_DATA_FILE" },
    { 0xFFFFFC78, "DB_E_CANT_OPEN_INDEX_FILE" },
    { 0xFFFFFC77, "DB_E_INDEX_FILE_NOT_OPEN" },
    { 0xFFFFFC76, "DB_E_CANT_RENAME_FILE" },
    { 0xFFFFFC75, "DB_E_CANT_READ_DATA_FILE" },
    { 0xFFFFFC74, "DB_E_CANT_READ_INDEX_FILE" },
    { 0xFFFFFC73, "DB_E_CANT_WRITE_DATA_FILE" },
    { 0xFFFFFC72, "DB_E_CANT_WRITE_INDEX_FILE" },
    { 0xFFFFFC71, "DB_E_CANT_DELETE_PA_DIR" },
    { 0xFFFFFC70, "DB_E_ALREADY_DELETED" },
    { 0xFFFFFC6F, "DB_E_OBJECT_EXISTS" },
    { 0xFFFFFC6E, "DB_E_DESCRIPTOR_IN_USE" },
    { 0xFFFFFC6D, "DB_E_DESCRIPTOR_BEING_DELETED" },
    { 0,          NULL }
};

static const value_string ndps_credential_enum[] = {
	{ 0, "SIMPLE" },
    { 1, "CERTIFIED" },
    { 2, "NDPS 0" },
    { 3, "NDPS 1" },
    { 4, "NDPS 2" },
    { 0,          NULL }
};

static void
get_string(tvbuff_t* tvb, guint offset, guint str_length, char *dest_buf)
{
        guint32 i;
        guint16 c_char;
        guint32 length_remaining = 0;
        
        length_remaining = tvb_length_remaining(tvb, offset);
        if(str_length > length_remaining || str_length > 1024)
        {
                strcpy(dest_buf, "<String to long to process>");
                return;
        }
        if(str_length == 0)
        {
            strcpy(dest_buf, "<Not Specified>");
            return;
        }
        for ( i = 0; i < str_length; i++ )
        {
                c_char = tvb_get_guint8(tvb, offset );
                if (c_char<0x20 || c_char>0x7e)
                {
                        if (c_char != 0x00)
                        { 
                        c_char = 0x2e;
                        dest_buf[i] = c_char & 0xff;
                        }
                        else
                        {
                                i--;
                                str_length--;
                        }
                }
                else
                {
                        dest_buf[i] = c_char & 0xff;
                }
                offset++;
                length_remaining--;
                
                if(length_remaining==1)
                {
                        dest_buf[i+1] = '\0';
                        return;
                }        
        }
dest_buf[i] = '\0';
return;
}

static guint32
align_4(tvbuff_t *tvb, guint32 aoffset)
{
       if(tvb_length_remaining(tvb, aoffset) > 4 )
       {
                return (aoffset%4);
       }
       return 0;
}


static guint32
objectident(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint8      h;
    guint8      object_count;
    guint32     name_len=0;
    guint32     object_type=0;
    char        buffer[1024];
    proto_tree  *atree;
    proto_item  *aitem;

    /*proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, FALSE);*/
    object_count = tvb_get_ntohl(tvb, foffset);
    

    foffset += 4;
    object_type = tvb_get_ntohl(tvb, foffset); 
    aitem = proto_tree_add_item(ndps_tree, hf_obj_id_type, tvb, foffset, 4, FALSE);
    atree = proto_item_add_subtree(aitem, ett_ndps);
    foffset += 4;
    for (h = 1 ; h <= object_count; h++ )
    {
        switch(object_type)
        {
        case 0:         /* None */
            break;
        case 1:         /* Printer Contained Object ID */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_object, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            foffset += 4;
            break;
        case 2:         /* Document Identifier */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_object, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            foffset += 4;
            proto_tree_add_uint(atree, hf_ndps_document_number, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            foffset += 4;
            break;
        case 3:         /* Object Identifier */
            proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                return foffset;
            }
            foffset += 4;
            break;
        case 4:         /* Object Name */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                return foffset;
            }
            proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 5:         /* Name or Object ID */
            proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 6:         /* Simple Name */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 7:         /* Printer Configuration Object ID */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_qualified_name, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            if (tvb_get_ntohl(tvb, foffset) != 0) {
               if (tvb_get_ntohl(tvb, foffset) == 1) {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
                    name_len, buffer);
                }
                else
                {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_context, tvb, foffset, 
                    name_len, buffer);
                    foffset += name_len;
                    foffset += align_4(tvb, foffset);
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_tree, tvb, foffset, 
                    name_len, buffer);
                }
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            break;
        case 8:         /* Qualified Name */
            proto_tree_add_uint(atree, hf_ndps_qualified_name, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            if (tvb_get_ntohl(tvb, foffset) != 0) {
                if (tvb_get_ntohl(tvb, foffset) == 1) {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
                    name_len, buffer);
                }
                else
                {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_context, tvb, foffset, 
                    name_len, buffer);
                    foffset += name_len;
                    foffset += align_4(tvb, foffset);
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_tree, tvb, foffset, 
                    name_len, buffer);
                }
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            break;
        case 9:         /* Event Object ID */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                return foffset;
            }
            foffset += 4;
        default:
            break;
        }
    }
    return foffset;
}

static guint32
address_item(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint32     address_type=0;
    guint32     transport_type=0;
    guint32     name_len=0;
    guint32     octet_len=0;
    char        buffer[1024];

    address_type = tvb_get_ntohl(tvb, foffset); 
    proto_tree_add_item(ndps_tree, hf_address_type, tvb, foffset, 4, FALSE);
    foffset += 4;
    switch(address_type)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
        proto_tree_add_uint(ndps_tree, hf_ndps_qualified_name, tvb, foffset, 
        4, tvb_get_ntohl(tvb, foffset));
        if (tvb_get_ntohl(tvb, foffset) != 0) {
            if (tvb_get_ntohl(tvb, foffset) == 1) {
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(ndps_tree, hf_printer_name, tvb, foffset, 
                name_len, buffer);
            }
            else
            {
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(ndps_tree, hf_ndps_context, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(ndps_tree, hf_ndps_tree, tvb, foffset, 
                name_len, buffer);
            }
            foffset += name_len;
            foffset += align_4(tvb, foffset);
        }
        break;
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
        name_len = tvb_get_ntohl(tvb, foffset);
        foffset += 4;
        get_string(tvb, foffset, name_len, buffer);
        proto_tree_add_string(ndps_tree, hf_object_name, tvb, foffset, 
        name_len, buffer);
        foffset += name_len;
        foffset += align_4(tvb, foffset);
        break;
    case 13:
        proto_tree_add_item(ndps_tree, hf_ndps_attrib_boolean, tvb, foffset, 4, FALSE);
        foffset += 4;
        break;
    case 14:
        proto_tree_add_item(ndps_tree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
        foffset += 4;
        break;
    case 15:
        transport_type=tvb_get_ntohl(tvb, foffset);
        proto_tree_add_item(ndps_tree, hf_ndps_address, tvb, foffset, 4, FALSE);
        foffset += 4;
        octet_len = tvb_get_ntohl(tvb, foffset);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_ndps_add_bytes, tvb, foffset, octet_len, FALSE);
        foffset += octet_len;
        break;
    case 16:
    case 17:
    default:
        name_len = tvb_get_ntohl(tvb, foffset);
        foffset += 4;
        get_string(tvb, foffset, name_len, buffer);
        proto_tree_add_string(ndps_tree, hf_object_name, tvb, foffset, 
        name_len, buffer);
        foffset += name_len;
        foffset += align_4(tvb, foffset);
        break;
    }
    return foffset;
}

static guint32
attribute_value(tvbuff_t* tvb, proto_tree *ndps_tree, int foffset)
{
    guint8      h;
    guint8      i;
    guint8      j;
    guint8      number_of_values=0;
    guint8      number_of_items=0;
    guint8      number_of_items2=0;
    guint32     name_len=0;
    guint32     attribute_type=0;
    char        buffer[1024];
    proto_tree  *atree;
    proto_item  *aitem;
    proto_tree  *btree;
    proto_item  *bitem;
    proto_tree  *ctree;
    proto_item  *citem;

    number_of_values = tvb_get_ntohl(tvb, foffset);
    foffset += 4;
    attribute_type = tvb_get_ntohl(tvb, foffset); 
    aitem = proto_tree_add_item(ndps_tree, hf_obj_attribute_type, tvb, foffset, 4, FALSE);
    atree = proto_item_add_subtree(aitem, ett_ndps);
    foffset += 4;
    for (h = 1 ; h <= number_of_values; h++ )
    {
        switch(attribute_type)
        {
        case 0:         /* Null */
            break;
        case 1:         /* Text */
        case 2:         /* Descriptive Name */
        case 3:         /* Descriptor */
        case 6:         /* Simple Name */
        case 40:         /* Distinguished Name */
        case 50:         /* Font Reference */
        case 58:         /* Locale */
        case 102:         /* File Path */
        case 103:         /* Uniform Resource Identifier */
        case 108:         /* Extended Resource Identifier */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 4:         /* Message */
        case 5:         /* Error Message */
        case 38:         /* Name or OID */
            proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 7:         /* Distinguished Name */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 8:         /* Distinguished Name Seq */
        case 39:         /* Name or OID Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(btree, hf_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 9:         /* Delta Time */
        case 10:         /* Time */
        case 11:         /* Integer */
        case 13:         /* Cardinal */
        case 15:         /* Positive Integer */
        case 18:         /* Maximum Integer */
        case 19:         /* Minimum Integer */
        case 35:         /* Percent */
        case 57:         /* Priority */
        case 72:         /* Sides */
        case 95:         /* Enumeration */
            proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 12:         /* Integer Seq */
        case 14:         /* Cardinal Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_item(btree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
                foffset += 4;
            }
            break;
        case 16:         /* Integer Range */
        case 17:         /* Cardinal Range */
            proto_tree_add_item(atree, hf_ndps_lower_range, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_upper_range, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 20:         /* Integer 64 */
        case 22:         /* Cardinal 64 */
        case 24:         /* Positive Integer 64 */
        case 31:         /* Non-Negative Real */
        case 29:         /* Real */
            proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            break;
        case 21:         /* Integer 64 Seq */
        case 23:         /* Cardinal 64 Seq */
        case 30:         /* Real Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_item(btree, hf_ndps_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
            }
            break;
        case 25:         /* Integer 64 Range */
        case 26:         /* Cardinal 64 Range */
        case 32:         /* Real Range */
        case 33:         /* Non-Negative Real Range */
            proto_tree_add_item(atree, hf_ndps_lower_range_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            proto_tree_add_item(atree, hf_ndps_upper_range_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            break;
        case 27:         /* Maximum Integer 64 */
            proto_tree_add_item(atree, hf_ndps_lower_range_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            break;
        case 28:         /* Minimum Integer 64 */
            proto_tree_add_item(atree, hf_ndps_upper_range_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            break;
        case 34:         /* Boolean */
            proto_tree_add_item(atree, hf_ndps_attrib_boolean, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 36:         /* Object Identifier */
            proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            foffset += 4;
            break;
        case 37:         /* Object Identifier Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_uint(btree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                if (foffset > tvb_length_remaining(tvb, foffset)) {
                    break;
                }
                foffset += 4;
            }
            break;
        case 41:         /* Relative Distinguished Name Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(btree, hf_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            break;
        case 42:         /* Realization */
            proto_tree_add_item(atree, hf_ndps_realization, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 43:         /* Medium Dimensions */
            proto_tree_add_item(atree, hf_ndps_xdimension_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            proto_tree_add_item(atree, hf_ndps_ydimension_n64, tvb, foffset, 4, FALSE);
            foffset += 8;
            break;
        case 44:         /* Dimension */
            proto_tree_add_item(atree, hf_ndps_dim_value, tvb, foffset, 8, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4) == 0) {
                proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
            }
            else
            {
                proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            proto_tree_add_item(atree, hf_ndps_dim_flag, tvb, foffset, 8, FALSE);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            break;
        case 45:         /* XY Dimensions */
            proto_tree_add_item(atree, hf_ndps_xydim_value, tvb, foffset, 8, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4) == 1) {
                proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            else
            {
                proto_tree_add_item(atree, hf_ndps_xdimension_n64, tvb, foffset, 4, FALSE);
                foffset += 8;
                proto_tree_add_item(atree, hf_ndps_ydimension_n64, tvb, foffset, 4, FALSE);
                foffset += 8;
            }
            proto_tree_add_item(atree, hf_ndps_dim_flag, tvb, foffset, 8, FALSE);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            break;
        case 46:         /* Locations */
            proto_tree_add_item(atree, hf_ndps_location_value, tvb, foffset, 8, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4) == 0) {
                bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
                btree = proto_item_add_subtree(bitem, ett_ndps);
                number_of_items = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    proto_tree_add_item(btree, hf_ndps_n64, tvb, foffset, 8, FALSE);
                    foffset += 8;
                }
            }
            else
            {
                proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            proto_tree_add_item(atree, hf_ndps_dim_flag, tvb, foffset, 8, FALSE);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            break;
        case 47:         /* Area */
            proto_tree_add_item(atree, hf_ndps_xmin_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            proto_tree_add_item(atree, hf_ndps_xmax_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            proto_tree_add_item(atree, hf_ndps_ymin_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            proto_tree_add_item(atree, hf_ndps_ymax_n64, tvb, foffset, 8, FALSE);
            foffset += 8;
            break;
        case 48:         /* Area Seq */
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_item(btree, hf_ndps_xmin_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
                proto_tree_add_item(btree, hf_ndps_xmax_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
                proto_tree_add_item(btree, hf_ndps_ymin_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
                proto_tree_add_item(btree, hf_ndps_ymax_n64, tvb, foffset, 8, FALSE);
                foffset += 8;
            }
            break;
        case 49:         /* Edge */
            proto_tree_add_item(atree, hf_ndps_edge_value, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 51:         /* Cardinal or OID */
            proto_tree_add_item(atree, hf_ndps_cardinal_or_oid, tvb, foffset, 4, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4)==0) {
                proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
                foffset += 4;
            }
            else
            {
                proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                if (foffset > tvb_length_remaining(tvb, foffset)) {
                    break;
                }
                foffset += 4;
            }
            break;
        case 52:         /* OID Cardinal Map */
            proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 53:         /* Cardinal or Name or OID */
            proto_tree_add_item(atree, hf_ndps_cardinal_name_or_oid, tvb, foffset, 4, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4)==0) {
                proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
                foffset += 4;
            }
            else
            {
                proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            break;
        case 54:         /* Positive Integer or OID */
            proto_tree_add_item(atree, hf_ndps_integer_or_oid, tvb, foffset, 4, FALSE);
            foffset += 4;
            if (tvb_get_ntohl(tvb, foffset-4)==0) {
                proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                if (foffset > tvb_length_remaining(tvb, foffset)) {
                    break;
                }
                foffset += 4;
            }
            else
            {
                proto_tree_add_item(atree, hf_ndps_attribute_value, tvb, foffset, 4, FALSE);
                foffset += 4;
            }
            break;
        case 55:         /* Event Handling Profile */
            proto_tree_add_item(atree, hf_ndps_profile_id, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_persistence, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_uint(atree, hf_ndps_qualified_name, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            if (tvb_get_ntohl(tvb, foffset) != 0) {
                if (tvb_get_ntohl(tvb, foffset) == 1) {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_printer_name, tvb, foffset, 
                    name_len, buffer);
                }
                else
                {
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_context, tvb, foffset, 
                    name_len, buffer);
                    foffset += name_len;
                    foffset += align_4(tvb, foffset);
                    name_len = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    get_string(tvb, foffset, name_len, buffer);
                    proto_tree_add_string(atree, hf_ndps_tree, tvb, foffset, 
                    name_len, buffer);
                }
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_item(btree, hf_ndps_language_id, tvb, foffset, 4, FALSE);
                foffset += 4;
                proto_tree_add_uint(btree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(btree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
            }
            bitem = proto_tree_add_item(atree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            btree = proto_item_add_subtree(bitem, ett_ndps);
            number_of_items = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                foffset += address_item(tvb, btree, foffset);
                /*proto_tree_add_item(btree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
                foffset += 4;*/
                proto_tree_add_item(btree, hf_ndps_event_type, tvb, foffset, 4, FALSE);
                foffset += 4;
                proto_tree_add_item(btree, hf_ndps_event_object_identifier, tvb, foffset, 4, FALSE);
                foffset += 4;
                if(tvb_get_ntohl(tvb, foffset-4)==0)
                {
                    proto_tree_add_uint(btree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                    foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                    if (foffset > tvb_length_remaining(tvb, foffset)) {
                        break;
                    }
                    foffset += 4;
                }
                else
                {
                    citem = proto_tree_add_item(btree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
                    ctree = proto_item_add_subtree(citem, ett_ndps);
                    number_of_items2 = tvb_get_ntohl(tvb, foffset);
                    foffset += 4;
                    for (j = 1 ; j <= number_of_items2; j++ )
                    {
                        proto_tree_add_uint(ctree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                        foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                        if (foffset > tvb_length_remaining(tvb, foffset)) {
                            break;
                        }
                        foffset += 4;
                        proto_tree_add_uint(ctree, hf_ndps_qualified_name, tvb, foffset, 
                        4, tvb_get_ntohl(tvb, foffset));
                        if (tvb_get_ntohl(tvb, foffset) != 0) {
                            if (tvb_get_ntohl(tvb, foffset) == 1) {
                                name_len = tvb_get_ntohl(tvb, foffset);
                                foffset += 4;
                                get_string(tvb, foffset, name_len, buffer);
                                proto_tree_add_string(ctree, hf_printer_name, tvb, foffset, 
                                name_len, buffer);
                            }
                            else
                            {
                                name_len = tvb_get_ntohl(tvb, foffset);
                                foffset += 4;
                                get_string(tvb, foffset, name_len, buffer);
                                proto_tree_add_string(ctree, hf_ndps_context, tvb, foffset, 
                                name_len, buffer);
                                foffset += name_len;
                                foffset += align_4(tvb, foffset);
                                name_len = tvb_get_ntohl(tvb, foffset);
                                foffset += 4;
                                get_string(tvb, foffset, name_len, buffer);
                                proto_tree_add_string(ctree, hf_ndps_tree, tvb, foffset, 
                                name_len, buffer);
                            }
                            foffset += name_len;
                            foffset += align_4(tvb, foffset);
                        }
                    }
                }
            }
            break;
        case 56:         /* Octet String */
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            proto_tree_add_item(atree, hf_ndps_octet_string, tvb, foffset, name_len, FALSE);
            break;
        case 59:         /* Method Delivery Address */
        case 60:         /* Object Identification */
        case 61:         /* Results Profile */
        case 62:         /* Criteria */
        case 63:         /* Job Password */
        case 64:         /* Job Level */
        case 65:         /* Job Categories */
        case 66:         /* Print Checkpoint */
        case 67:         /* Ignored Attribute */
        case 68:         /* Resource */
        case 69:         /* Medium Substitution */
        case 70:         /* Font Substitution */
        case 71:         /* Resource Context Seq */
        case 73:         /* Page Select Seq */
        case 74:         /* Page Media Select */
        case 75:         /* Document Content */
        case 76:         /* Page Size */
        case 77:         /* Presentation Direction */
        case 78:         /* Page Order */
        case 79:         /* File Reference */
        case 80:         /* Medium Source Size */
        case 81:         /* Input Tray Medium */
        case 82:         /* Output Bins Chars */
        case 83:         /* Page ID Type */
        case 84:         /* Level Range */
        case 85:         /* Category Set */
        case 86:         /* Numbers Up Supported */
        case 87:         /* Finishing */
        case 88:         /* Print Contained Object ID */
        case 89:         /* Print Config Object ID */
        case 90:         /* Typed Name */
        case 91:         /* Network Address */
        case 92:         /* XY Dimensions Value */
        case 93:         /* Name or OID Dimensions Map */
        case 94:         /* Printer State Reason */
        case 96:         /* Qualified Name */
        case 97:         /* Qualified Name Set */
        case 98:         /* Colorant Set */
        case 99:         /* Resource Printer ID */
        case 100:         /* Event Object ID */
        case 101:         /* Qualified Name Map */
        case 104:         /* Cardinal or Enum or Time */
        case 105:         /* Print Contained Object ID Set */
        case 106:         /* Octet String Pair */
        case 107:         /* Octet String Integer Pair */
        case 109:         /* Event Handling Profile 2 */
        default:
            break;
        }
    }
    return foffset;
}


/* NDPS packets come in request/reply pairs. The request packets tell the 
 * Function and Program numbers. The response, unfortunately, only
 * identifies itself via the Exchange ID; you have to know what type of NDPS
 * request the request packet contained in order to successfully parse the 
 * response. A global method for doing this does not exist in ethereal yet
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
	conversation_t	*conversation;
	guint32		    ndps_xid;
} ndps_req_hash_key;

typedef struct {
        guint32             ndps_prog;
        guint32			    ndps_func;
} ndps_req_hash_value;

static GHashTable *ndps_req_hash = NULL;
static GMemChunk *ndps_req_hash_keys = NULL;
static GMemChunk *ndps_req_hash_values = NULL;

/* Hash Functions */
gint
ndps_equal(gconstpointer v, gconstpointer v2)
{
	ndps_req_hash_key	*val1 = (ndps_req_hash_key*)v;
	ndps_req_hash_key	*val2 = (ndps_req_hash_key*)v2;

	if (val1->conversation == val2->conversation &&
	    val1->ndps_xid  == val2->ndps_xid ) {
		return 1;
	}
	return 0;
}

guint
ndps_hash(gconstpointer v)
{
	ndps_req_hash_key	*ndps_key = (ndps_req_hash_key*)v;
	return GPOINTER_TO_UINT(ndps_key->conversation) + ndps_key->ndps_xid;
}

/* Frees memory used by the ndps_req_hash_value's */
static void
ndps_req_hash_cleanup(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	ndps_req_hash_value	*request_value = (ndps_req_hash_value*) value;

	/*if (request_value->ndps_func) {
		g_free(request_value->ndps_func);
	}*/
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
static void
ndps_init_protocol(void)
{
	if (ndps_req_hash) {
		g_hash_table_foreach(ndps_req_hash, ndps_req_hash_cleanup, NULL);
		g_hash_table_destroy(ndps_req_hash);
	}
	if (ndps_req_hash_keys)
		g_mem_chunk_destroy(ndps_req_hash_keys);
	if (ndps_req_hash_values)
		g_mem_chunk_destroy(ndps_req_hash_values);

	ndps_req_hash = g_hash_table_new(ndps_hash, ndps_equal);
	ndps_req_hash_keys = g_mem_chunk_new("ndps_req_hash_keys",
			sizeof(ndps_req_hash_key),
			NDPS_PACKET_INIT_COUNT * sizeof(ndps_req_hash_key),
			G_ALLOC_ONLY);
	ndps_req_hash_values = g_mem_chunk_new("ndps_req_hash_values",
			sizeof(ndps_req_hash_value),
			NDPS_PACKET_INIT_COUNT * sizeof(ndps_req_hash_value),
			G_ALLOC_ONLY);
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
	if (ndps_req_hash_keys) {
		g_mem_chunk_destroy(ndps_req_hash_keys);
		ndps_req_hash_keys = NULL;
	}
	/* Don't free the ncp_req_hash_values, as they're
	 * needed during random-access processing of the proto_tree.*/
}

ndps_req_hash_value*
ndps_hash_insert(conversation_t *conversation, guint32 ndps_xid)
{
	ndps_req_hash_key		*request_key;
	ndps_req_hash_value		*request_value;

	/* Now remember the request, so we can find it if we later
	   a reply to it. */
	request_key = g_mem_chunk_alloc(ndps_req_hash_keys);
	request_key->conversation = conversation;
	request_key->ndps_xid = ndps_xid;

	request_value = g_mem_chunk_alloc(ndps_req_hash_values);
    request_value->ndps_prog = 0;
	request_value->ndps_func = 0;
       
    g_hash_table_insert(ndps_req_hash, request_key, request_value);

	return request_value;
}

/* Returns the ncp_rec*, or NULL if not found. */
ndps_req_hash_value*
ndps_hash_lookup(conversation_t *conversation, guint32 ndps_xid)
{
	ndps_req_hash_key		request_key;

	request_key.conversation = conversation;
	request_key.ndps_xid = ndps_xid;

	return g_hash_table_lookup(ndps_req_hash, &request_key);
}

/* ================================================================= */
/* NDPS                                                               */
/* ================================================================= */

static void
dissect_ndps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	*ndps_tree = NULL;
    proto_item	*ti;
	
    guint16     record_mark;
    guint16     ndps_length;
    guint32     ndps_xid;
    guint32     ndps_prog;
    guint32     ndps_packet_type;
    guint32     ndps_rpc_version;
    int         foffset;
    guint32     ndps_hfname;
    guint32     ndps_func;
    const char  *ndps_program_string='\0';
    const char  *ndps_func_string='\0';

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDPS");

    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
	
    foffset = 0;
    if (tree) {
        ti = proto_tree_add_item(tree, proto_ndps, tvb, foffset, -1, FALSE);
        ndps_tree = proto_item_add_subtree(ti, ett_ndps);
    }
    if (tvb_length_remaining(tvb, foffset) >= 28)
    {
        record_mark = tvb_get_ntohs(tvb, foffset);
        if (tvb_get_ntohl(tvb, foffset+4) == 0x00000065) /* Check xid if not 65 then fragment packet */
        {
            proto_tree_add_uint(ndps_tree, hf_ndps_record_mark, tvb,
                           foffset, 2, record_mark);
            foffset += 2;
            ndps_length = tvb_get_ntohs(tvb, foffset);
            proto_tree_add_uint_format(ndps_tree, hf_ndps_length, tvb,
                           foffset, 2, ndps_length,
                           "Length of NDPS Packet: %d", ndps_length);
            foffset += 2;
            ndps_xid = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_xid, tvb, foffset, 4, ndps_xid);
            foffset += 4;
            ndps_packet_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_uint(ndps_tree, hf_ndps_packet_type, tvb, foffset, 4, ndps_packet_type);
            foffset += 4;
            if(ndps_packet_type == 0x00000001)          /* Reply packet */
            {
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_set_str(pinfo->cinfo, COL_INFO, "R NDPS ");
                proto_tree_add_item(ndps_tree, hf_ndps_rpc_accept, tvb, foffset, 4, FALSE);
                if (tvb_get_ntohl(tvb, foffset)==0) {
                    foffset += 4;
                    proto_tree_add_item(ndps_tree, hf_ndps_auth_null, tvb, foffset, 8, FALSE);
                    foffset += 8;
                }
                else
                {
                    foffset += 4;
                    proto_tree_add_item(ndps_tree, hf_ndps_rpc_rej_stat, tvb, foffset+4, 4, FALSE);
                    foffset += 4;
                }
                dissect_ndps_reply(tvb, pinfo, ndps_tree, ndps_xid, foffset);
            }
            else
            {
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_set_str(pinfo->cinfo, COL_INFO, "C NDPS ");
                ndps_rpc_version = tvb_get_ntohl(tvb, foffset);
                proto_tree_add_item(ndps_tree, hf_ndps_rpc_version, tvb, foffset, 4, FALSE);
                foffset += 4;
                ndps_prog = tvb_get_ntohl(tvb, foffset);
                ndps_program_string = match_strval(ndps_prog, spx_ndps_program_vals);
                if( ndps_program_string != NULL)
                {
                    proto_tree_add_item(ndps_tree, hf_spx_ndps_program, tvb, foffset, 4, FALSE);
                    foffset += 4;
                    if (check_col(pinfo->cinfo, COL_INFO))
                    {
                        col_append_str(pinfo->cinfo, COL_INFO, (gchar*) ndps_program_string);
                        col_append_str(pinfo->cinfo, COL_INFO, ", ");
                    }
                    proto_tree_add_item(ndps_tree, hf_spx_ndps_version, tvb, foffset, 4, FALSE);
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
                            break;
                    }
                    if(ndps_hfname != 0)
                    {
                        proto_tree_add_item(ndps_tree, ndps_hfname, tvb, foffset, 4, FALSE);
                        if (ndps_func_string != NULL) 
                        {
                            if (check_col(pinfo->cinfo, COL_INFO))
                                col_append_str(pinfo->cinfo, COL_INFO, (gchar*) ndps_func_string);

                            foffset += 4;
                            proto_tree_add_item(ndps_tree, hf_ndps_auth_null, tvb, foffset, 16, FALSE);
                            foffset+=16;
                            dissect_ndps_request(tvb, pinfo, ndps_tree, ndps_xid, ndps_prog, ndps_func, foffset);
                        }
                    }
                }
            }
        }
        else
        {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_append_str(pinfo->cinfo, COL_INFO, "Continuation Fragment");
        }
    }
}

static void
dissect_ndps_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, guint32 ndps_xid, guint32 ndps_prog, guint32 ndps_func, int foffset)
{
    ndps_req_hash_value	*request_value = NULL;
    conversation_t		*conversation;
    guint32             name_len;
    char                buffer[1024];
    guint32             cred_type;

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

        conversation = find_conversation(&pinfo->src, &pinfo->dst,
            PT_NCP, ndps_xid, ndps_xid, 0);

        if (conversation == NULL) 
            {
            /* It's not part of any conversation - create a new one. */
            conversation = conversation_new(&pinfo->src, &pinfo->dst,
                PT_NONE, ndps_xid, ndps_xid, 0);
        }

        request_value = ndps_hash_insert(conversation, ndps_xid);
        request_value->ndps_prog = ndps_prog;
        request_value->ndps_func = ndps_func;
    }
    switch(ndps_prog)
    {
    case 0x060976:  /* Print */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind PSM */
            break;
        case 0x00000002:    /* Bind PA */
            cred_type = tvb_get_ntohl(tvb, foffset);
            proto_tree_add_item(ndps_tree, hf_ndps_cred_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_server_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            if(name_len == 0)
            {
                foffset += 2;
            }
            else
            {
                foffset += 4;
            }
            proto_tree_add_uint(ndps_tree, hf_ndps_connection, tvb, foffset, 
            2, tvb_get_ntohs(tvb, foffset));
            foffset += 2;
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_pa_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            foffset += 8;   /* Don't know what these 8 bytes signify */
            proto_tree_add_uint(ndps_tree, hf_ndps_items, tvb, foffset,
            4, tvb_get_ntohl(tvb, foffset));
            foffset += 4;
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_context, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_tree, tvb, foffset, 
            name_len, buffer);
            break;
        case 0x00000003:    /* Unbind */
            proto_tree_add_uint(ndps_tree, hf_ndps_object, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            break;
        case 0x00000004:    /* Print */
        case 0x00000005:    /* Modify Job */
        case 0x00000006:    /* Cancel Job */
            break;
        case 0x00000007:    /* List Object Attributes */
            proto_tree_add_uint(ndps_tree, hf_ndps_object, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            break;
        case 0x00000008:    /* Promote Job */
        case 0x00000009:    /* Interrupt */
        case 0x0000000a:    /* Pause */
        case 0x0000000b:    /* Resume */
        case 0x0000000c:    /* Clean */
        case 0x0000000d:    /* Create */
        case 0x0000000e:    /* Delete */
        case 0x0000000f:    /* Disable PA */
        case 0x00000010:    /* Enable PA */
        case 0x00000011:    /* Resubmit Jobs */
        case 0x00000012:    /* Set */
        case 0x00000013:    /* Shutdown PA */
        case 0x00000014:    /* Startup PA */
        case 0x00000015:    /* Reorder Job */
        case 0x00000016:    /* Pause PA */
        case 0x00000017:    /* Resume PA */
        case 0x00000018:    /* Transfer Data */
        case 0x00000019:    /* Device Control */
        case 0x0000001a:    /* Add Event Profile */
        case 0x0000001b:    /* Remove Event Profile */
        case 0x0000001c:    /* Modify Event Profile */
        case 0x0000001d:    /* List Event Profiles */
        case 0x0000001e:    /* Shutdown PSM */
        case 0x0000001f:    /* Cancel PSM Shutdown */
        case 0x00000020:    /* Set Printer DS Information */
        case 0x00000021:    /* Clean User Jobs */
        case 0x00000022:    /* Map GUID to NDS Name */
        default:
            break;
        }
        break;
    case 0x060977:  /* Broker */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
        case 0x00000002:    /* Unbind */
        case 0x00000003:    /* List Services */
        case 0x00000004:    /* Enable Service */
        case 0x00000005:    /* Disable Service */
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
        case 0x00000002:    /* Unbind */
        case 0x00000003:    /* Register Server */
        case 0x00000004:    /* Deregister Server */
        case 0x00000005:    /* Register Registry */
        case 0x00000006:    /* Deregister Registry */
        case 0x00000007:    /* Registry Update */
        case 0x00000008:    /* List Local Servers */
        case 0x00000009:    /* List Servers */
        case 0x0000000a:    /* List Known Registries */
        case 0x0000000b:    /* Get Registry NDS Object Name */
        case 0x0000000c:    /* Get Registry Session Information */
        default:
            break;
        }
        break;
    case 0x060979:  /* Notify */
        switch(ndps_func)
        {
        case 0x00000001:    /* Notify Bind */
        case 0x00000002:    /* Notify Unbind */
        case 0x00000003:    /* Register Supplier */
        case 0x00000004:    /* Deregister Supplier */
        case 0x00000005:    /* Add Profile */
        case 0x00000006:    /* Remove Profile */
        case 0x00000007:    /* Modify Profile */
        case 0x00000008:    /* List Profiles */
        case 0x00000009:    /* Report Event */
        case 0x0000000a:    /* List Supported Languages */
        case 0x0000000b:    /* Report Notification */
        case 0x0000000c:    /* Add Delivery Method */
        case 0x0000000d:    /* Remove Delivery Method */
        case 0x0000000e:    /* List Delivery Methods */
        case 0x0000000f:    /* Get Delivery Method Information */
        case 0x00000010:    /* Get Notify NDS Object Name */
        case 0x00000011:    /* Get Notify Session Information */
        default:
            break;
        }
        break;
    case 0x06097a:  /* Resman */
        switch(ndps_func)
        {
        case 0x00000001:    /* Bind */
            proto_tree_add_uint(ndps_tree, hf_ndps_cred_type, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            foffset += 4;
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_server_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            if(name_len == 0)
            {
                foffset += 2;
            }
            foffset += 2;
            proto_tree_add_uint(ndps_tree, hf_ndps_connection, tvb, foffset, 
            2, tvb_get_ntohs(tvb, foffset));
            foffset += 2;
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_ndps_pa_name, tvb, foffset, 
            name_len, buffer);
            break;
        case 0x00000002:    /* Unbind */
        case 0x00000003:    /* Add Resource File */
        case 0x00000004:    /* Delete Resource File */
        case 0x00000005:    /* List Resources */
        case 0x00000006:    /* Get Resource File */
        case 0x00000007:    /* Get Resource File Data */
        case 0x00000008:    /* Get Resource Manager NDS Object Name */
        case 0x00000009:    /* Get Resource Manager Session Information */
        default:
            break;
        }
        break;
    case 0x06097b:  /* Delivery */
        switch(ndps_func)
        {
        case 0x00000001:    /* Delivery Bind */
        case 0x00000002:    /* Delivery Unbind */
        case 0x00000003:    /* Delivery Send */
        case 0x00000004:    /* Delivery Send2 */
        default:
            break;
        }
        break;
    default:
        break;
    }
    /*proto_tree_add_uint_format(ndps_tree, hf_ndps_xid, tvb, 0, 
    0, ndps_xid, "This is a Request Packet, XID %08x, Prog %08x, Func %08x", ndps_xid, ndps_prog, ndps_func);*/
    return;
}

static void
dissect_ndps_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ndps_tree, guint32 ndps_xid, int foffset)
{
    conversation_t			*conversation = NULL;
    ndps_req_hash_value		*request_value = NULL;
    proto_tree              *atree;
    proto_item              *aitem;
    guint8                  i;
    guint8                  number_of_items=0;
    guint32                 ndps_func=0;
    guint32                 ndps_prog=0;
    guint32                 error_val=0;
    guint32                 name_len=0;
    guint32                 problem_type=0;
    char                    buffer[1024];
    
    if (!pinfo->fd->flags.visited) {
        /* Find the conversation whence the request would have come. */
        conversation = find_conversation(&pinfo->src, &pinfo->dst,
            PT_NONE, ndps_xid, ndps_xid, 0);
        if (conversation != NULL) {
            /* find the record telling us the request made that caused
            this reply */
            request_value = ndps_hash_lookup(conversation, ndps_xid);
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
    }
    if (tvb_length_remaining(tvb, foffset) < 12)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
                col_append_str(pinfo->cinfo, COL_INFO, "- Ok");
        return;
    }
    if(ndps_func != 7 && ndps_func != 4 && ndps_func != 8 )
    {
        proto_tree_add_item(ndps_tree, hf_ndps_rpc_acc_stat, tvb, foffset, 4, FALSE);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_ndps_rpc_acc_results, tvb, foffset, 4, FALSE);
        foffset += 4;
    }
    error_val = tvb_get_ntohl(tvb, foffset);
    proto_tree_add_uint(ndps_tree, hf_ndps_error_val, tvb, foffset, 4, error_val);
    foffset += 4;
    if (error_val == 0) {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "- Ok");
        switch(ndps_prog)
        {
        case 0x060976:  /* Print */
            switch(ndps_func)
            {
            case 0x00000001:    /* Bind PSM */
                break;
            case 0x00000002:    /* Bind PA */
                proto_tree_add_item(ndps_tree, hf_ndps_object, tvb, foffset, 4, FALSE);
                foffset += 4;
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(ndps_tree, hf_ndps_pa_name, tvb, foffset, 
                name_len, buffer);
                break;
            case 0x00000003:    /* Unbind */
            case 0x00000004:    /* Print */
            case 0x00000005:    /* Modify Job */
            case 0x00000006:    /* Cancel Job */
                break;
            case 0x00000007:    /* List Object Attributes */
                proto_tree_add_item(ndps_tree, hf_ndps_session, tvb, foffset, 4, FALSE);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
                number_of_items=tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                for (i = 1 ; i <= number_of_items; i++ )
                {
                    foffset += 1;
                }
                foffset += align_4(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(ndps_tree, hf_ndps_abort_flag, tvb, foffset, 4, FALSE);
                foffset += 4;
                foffset = objectident(tvb, ndps_tree, foffset);
                foffset = attribute_value(tvb, ndps_tree, foffset);
                proto_tree_add_item(ndps_tree, hf_ndps_qualifier, tvb, foffset, 4, FALSE);
                foffset += 4;
                /*foffset = attribute_value(tvb, ndps_tree, foffset);
                proto_tree_add_item(ndps_tree, hf_ndps_scope, tvb, foffset, 4, FALSE);
                foffset += 4;
                foffset = objectident(tvb, ndps_tree, foffset);*/
                break;
            case 0x00000008:    /* Promote Job */
            case 0x00000009:    /* Interrupt */
            case 0x0000000a:    /* Pause */
            case 0x0000000b:    /* Resume */
            case 0x0000000c:    /* Clean */
            case 0x0000000d:    /* Create */
            case 0x0000000e:    /* Delete */
            case 0x0000000f:    /* Disable PA */
            case 0x00000010:    /* Enable PA */
            case 0x00000011:    /* Resubmit Jobs */
            case 0x00000012:    /* Set */
            case 0x00000013:    /* Shutdown PA */
            case 0x00000014:    /* Startup PA */
            case 0x00000015:    /* Reorder Job */
            case 0x00000016:    /* Pause PA */
            case 0x00000017:    /* Resume PA */
            case 0x00000018:    /* Transfer Data */
            case 0x00000019:    /* Device Control */
            case 0x0000001a:    /* Add Event Profile */
            case 0x0000001b:    /* Remove Event Profile */
            case 0x0000001c:    /* Modify Event Profile */
            case 0x0000001d:    /* List Event Profiles */
            case 0x0000001e:    /* Shutdown PSM */
            case 0x0000001f:    /* Cancel PSM Shutdown */
            case 0x00000020:    /* Set Printer DS Information */
            case 0x00000021:    /* Clean User Jobs */
            case 0x00000022:    /* Map GUID to NDS Name */
            default:
                break;
            }
            break;
        case 0x060977:  /* Broker */
            switch(ndps_func)
            {
            case 0x00000001:    /* Bind */
            case 0x00000002:    /* Unbind */
            case 0x00000003:    /* List Services */
            case 0x00000004:    /* Enable Service */
            case 0x00000005:    /* Disable Service */
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
            case 0x00000002:    /* Unbind */
            case 0x00000003:    /* Register Server */
            case 0x00000004:    /* Deregister Server */
            case 0x00000005:    /* Register Registry */
            case 0x00000006:    /* Deregister Registry */
            case 0x00000007:    /* Registry Update */
            case 0x00000008:    /* List Local Servers */
            case 0x00000009:    /* List Servers */
            case 0x0000000a:    /* List Known Registries */
            case 0x0000000b:    /* Get Registry NDS Object Name */
            case 0x0000000c:    /* Get Registry Session Information */
            default:
                break;
            }
            break;
        case 0x060979:  /* Notify */
            switch(ndps_func)
            {
            case 0x00000001:    /* Notify Bind */
            case 0x00000002:    /* Notify Unbind */
            case 0x00000003:    /* Register Supplier */
            case 0x00000004:    /* Deregister Supplier */
            case 0x00000005:    /* Add Profile */
            case 0x00000006:    /* Remove Profile */
            case 0x00000007:    /* Modify Profile */
            case 0x00000008:    /* List Profiles */
            case 0x00000009:    /* Report Event */
            case 0x0000000a:    /* List Supported Languages */
            case 0x0000000b:    /* Report Notification */
            case 0x0000000c:    /* Add Delivery Method */
            case 0x0000000d:    /* Remove Delivery Method */
            case 0x0000000e:    /* List Delivery Methods */
            case 0x0000000f:    /* Get Delivery Method Information */
            case 0x00000010:    /* Get Notify NDS Object Name */
            case 0x00000011:    /* Get Notify Session Information */
            default:
                break;
            }
            break;
        case 0x06097a:  /* Resman */
            switch(ndps_func)
            {
            case 0x00000001:    /* Bind */
                break;
            case 0x00000002:    /* Unbind */
            case 0x00000003:    /* Add Resource File */
            case 0x00000004:    /* Delete Resource File */
            case 0x00000005:    /* List Resources */
            case 0x00000006:    /* Get Resource File */
            case 0x00000007:    /* Get Resource File Data */
            case 0x00000008:    /* Get Resource Manager NDS Object Name */
            case 0x00000009:    /* Get Resource Manager Session Information */
            default:
                break;
            }
            break;
        case 0x06097b:  /* Delivery */
            switch(ndps_func)
            {
            case 0x00000001:    /* Delivery Bind */
            case 0x00000002:    /* Delivery Unbind */
            case 0x00000003:    /* Delivery Send */
            case 0x00000004:    /* Delivery Send2 */
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    else
    {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "- Error");
        problem_type = tvb_get_ntohl(tvb, foffset);
        proto_tree_add_item(ndps_tree, hf_ndps_problem_type, tvb, foffset, 4, FALSE);
        foffset += 4;
        proto_tree_add_item(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
        foffset += 4;
        switch(problem_type)
        {
        case 0:                 /* Security Error */
            proto_tree_add_item(ndps_tree, hf_security_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            foffset = objectident(tvb, ndps_tree, foffset);
            break;
        case 1:                 /* Service Error */
            proto_tree_add_item(ndps_tree, hf_service_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            foffset += 8; 
            if (tvb_get_ntohl(tvb, foffset-4) != 0) {
                foffset = objectident(tvb, ndps_tree, foffset);
            }
            proto_tree_add_item(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_qualifier, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_lib_error, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_other_error, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_item(ndps_tree, hf_ndps_other_error_2, tvb, foffset, 4, FALSE);
            foffset += 4;
            break;
        case 2:                 /* Access Error */
            proto_tree_add_item(ndps_tree, hf_access_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            proto_tree_add_uint(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            foffset += 4; 
            foffset = objectident(tvb, ndps_tree, foffset);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 3:                 /* Printer Error */
            proto_tree_add_item(ndps_tree, hf_printer_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            foffset = objectident(tvb, ndps_tree, foffset);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 4:                 /* Selection Error */
            proto_tree_add_item(ndps_tree, hf_selection_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            foffset = objectident(tvb, ndps_tree, foffset);
            /*if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            proto_tree_add_uint(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);*/   /* Need to decode later */
            /*if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            foffset += 4; 
            proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset); */
            break;
        case 5:                 /* Document Access Error */
            proto_tree_add_item(ndps_tree, hf_doc_access_problem_type, tvb, foffset, 4, FALSE);
            foffset = objectident(tvb, ndps_tree, foffset);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        case 6:                 /* Attribute Error */
            proto_tree_add_item(ndps_tree, hf_attribute_problem_type, tvb, foffset, 4, FALSE);
            foffset += 4;
            aitem = proto_tree_add_uint(ndps_tree, hf_ndps_item_count, tvb, foffset, 4, FALSE);
            atree = proto_item_add_subtree(aitem, ett_ndps);
            foffset += 4;
            for (i = 1 ; i <= number_of_items; i++ )
            {
                proto_tree_add_uint(atree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
                foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
                if (foffset > tvb_length_remaining(tvb, foffset)) {
                    break;
                }
                foffset += 4; 
                proto_tree_add_uint(atree, hf_ndps_nameorid, tvb, foffset, 
                4, tvb_get_ntohl(tvb, foffset));
                name_len = tvb_get_ntohl(tvb, foffset);
                foffset += 4;
                get_string(tvb, foffset, name_len, buffer);
                proto_tree_add_string(atree, hf_local_object_name, tvb, foffset, 
                name_len, buffer);
                foffset += name_len;
                foffset += align_4(tvb, foffset);
                foffset = objectident(tvb, atree, foffset);
            }
            break;
        case 7:                 /* Update Error */
            proto_tree_add_item(ndps_tree, hf_update_problem_type, tvb, foffset, 4, FALSE);
            proto_tree_add_uint(ndps_tree, hf_oid_struct_size, tvb, foffset, 4, FALSE);
            foffset += tvb_get_ntohl(tvb, foffset);   /* Need to decode later */
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            foffset += 4; 
            foffset = objectident(tvb, ndps_tree, foffset);
            if (foffset > tvb_length_remaining(tvb, foffset)) {
                break;
            }
            proto_tree_add_uint(ndps_tree, hf_ndps_nameorid, tvb, foffset, 
            4, tvb_get_ntohl(tvb, foffset));
            name_len = tvb_get_ntohl(tvb, foffset);
            foffset += 4;
            get_string(tvb, foffset, name_len, buffer);
            proto_tree_add_string(ndps_tree, hf_local_object_name, tvb, foffset, 
            name_len, buffer);
            foffset += name_len;
            foffset += align_4(tvb, foffset);
            break;
        default:
            break;
        }
    }
    proto_tree_add_uint_format(ndps_tree, hf_ndps_xid, tvb, 0, 
    0, ndps_xid, "This is a Reply Packet, XID %08x, Prog %08x, Func %08x", ndps_xid, ndps_prog, ndps_func);
    return;
}

void
proto_register_ndps(void)
{
	static hf_register_info hf_ndps[] = {
		{ &hf_ndps_record_mark,
		{ "Record Mark",		"ndps.record_mark", FT_UINT16, BASE_HEX, NULL, 0x0,
			"Record Mark", HFILL }},

        { &hf_ndps_packet_type,
        { "Packet Type",    "ndps.packet_type",
          FT_UINT32,    BASE_HEX,   VALS(ndps_packet_types),   0x0,
          "Packet Type", HFILL }},

        { &hf_ndps_length,
        { "Record Length",    "ndps.record_length",
           FT_UINT16,    BASE_HEX,   NULL,   0x0,
           "Record Length", HFILL }},
        
        { &hf_ndps_xid,
        { "Exchange ID",    "ndps.xid",
           FT_UINT32,    BASE_HEX,   NULL,   0x0,
           "Exchange ID", HFILL }},

        { &hf_ndps_rpc_version,
        { "RPC Version",    "ndps.rpc_version",
           FT_UINT32,    BASE_HEX,   NULL,   0x0,
           "RPC Version", HFILL }},

        { &hf_spx_ndps_program,
        { "NDPS Program Number",    "spx.ndps_program",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_program_vals),   0x0,
          "NDPS Program Number", HFILL }},
	
        { &hf_spx_ndps_version,
        { "Program Version",    "spx.ndps_version",
          FT_UINT32,    BASE_DEC,   NULL,   0x0,
          "Program Version", HFILL }}, 
    
        { &hf_ndps_error,
        { "NDPS Error",    "spx.ndps_error",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "NDPS Error", HFILL }}, 
        
        { &hf_spx_ndps_func_print,
        { "Print Program",    "spx.ndps_func_print",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_print_func_vals),   0x0,
          "Print Program", HFILL }},
        
        { &hf_spx_ndps_func_notify,
        { "Notify Program",    "spx.ndps_func_notify",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_notify_func_vals),   0x0,
          "Notify Program", HFILL }},
        
        { &hf_spx_ndps_func_delivery,
        { "Delivery Program",    "spx.ndps_func_delivery",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_deliver_func_vals),   0x0,
          "Delivery Program", HFILL }},
        
        { &hf_spx_ndps_func_registry,
        { "Registry Program",    "spx.ndps_func_registry",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_registry_func_vals),   0x0,
          "Registry Program", HFILL }},
        
        { &hf_spx_ndps_func_resman,
        { "ResMan Program",    "spx.ndps_func_resman",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_resman_func_vals),   0x0,
          "ResMan Program", HFILL }},
        
        { &hf_spx_ndps_func_broker,
        { "Broker Program",    "spx.ndps_func_broker",
          FT_UINT32,    BASE_HEX,   VALS(spx_ndps_broker_func_vals),   0x0,
          "Broker Program", HFILL }},
        
        { &hf_ndps_items,
        { "Number of Items",    "ndps.items",
          FT_UINT32,    BASE_DEC,   NULL,   0x0,
          "Number of Items", HFILL }},

        { &hf_ndps_sbuffer,
        { "Server",    "ndps.sbuffer",
          FT_UINT32,    BASE_DEC,   NULL,   0x0,
          "Server", HFILL }},
        
        { &hf_ndps_rbuffer,
        { "Connection",    "ndps.rbuffer",
          FT_UINT32,    BASE_DEC,   NULL,   0x0,
          "Connection", HFILL }},

        { &hf_ndps_pa_name,
        { "Trustee Name",    "ndps.pa_name",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Trustee Name", HFILL }},

        { &hf_ndps_context,
        { "Printer Name",    "ndps.context",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Printer Name", HFILL }},
        
        { &hf_ndps_tree,
        { "Tree",    "ndps.tree",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Tree", HFILL }},

        { &hf_ndps_error_val,
        { "Return Status",    "ndps.error_val",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Return Status", HFILL }},

        { &hf_ndps_object,
        { "Object ID",    "ndps.object",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Object ID", HFILL }},

        { &hf_ndps_cred_type,
        { "Credential Type",    "ndps.cred_type",
          FT_UINT32,    BASE_HEX,   VALS(ndps_credential_enum),   0x0,
          "Credential Type", HFILL }},

        { &hf_ndps_server_name,
        { "Server Name",    "ndps.server_name",
          FT_STRING,    BASE_DEC,   NULL,   0x0,
          "Server Name", HFILL }},

        { &hf_ndps_connection,
        { "Connection",    "ndps.connection",
          FT_UINT16,    BASE_DEC,   NULL,   0x0,
          "Connection", HFILL }},

        { &hf_ndps_ext_error,
        { "Extended Return Status",    "ndps.ext_error",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Extended Return Status", HFILL }},

        { &hf_ndps_auth_null,
        { "Auth Null",    "ndps.auth_null",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Auth Null", HFILL }},

        { &hf_ndps_rpc_accept,
        { "RPC Accept or Deny",    "ndps.rpc_acc",
          FT_UINT32,    BASE_HEX,   VALS(true_false),   0x0,
          "RPC Accept or Deny", HFILL }},

        { &hf_ndps_rpc_acc_stat,
        { "RPC Accept Status",    "ndps.rpc_acc_stat",
          FT_UINT32,    BASE_HEX,   VALS(accept_stat),   0x0,
          "RPC Accept Status", HFILL }},
        
        { &hf_ndps_rpc_rej_stat,
        { "RPC Reject Status",    "ndps.rpc_rej_stat",
          FT_UINT32,    BASE_HEX,   VALS(reject_stat),   0x0,
          "RPC Reject Status", HFILL }},
        
        { &hf_ndps_rpc_acc_results,
        { "RPC Accept Results",    "ndps.rpc_acc_res",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "RPC Accept Results", HFILL }},

        { &hf_ndps_problem_type,
        { "Problem Type",    "ndps.rpc_prob_type",
          FT_UINT32,    BASE_HEX,   VALS(error_type_enum),   0x0,
          "Problem Type", HFILL }},
    
        { &hf_security_problem_type,
        { "Security Problem",    "ndps.rpc_sec_prob",
          FT_UINT32,    BASE_HEX,   VALS(security_problem_enum),   0x0,
          "Security Problem", HFILL }},

        { &hf_service_problem_type,
        { "Service Problem",    "ndps.rpc_serv_prob",
          FT_UINT32,    BASE_HEX,   VALS(service_problem_enum),   0x0,
          "Service Problem", HFILL }},
        
        { &hf_access_problem_type,
        { "Access Problem",    "ndps.rpc_acc_prob",
          FT_UINT32,    BASE_HEX,   VALS(access_problem_enum),   0x0,
          "Access Problem", HFILL }},
        
        { &hf_printer_problem_type,
        { "Printer Problem",    "ndps.rpc_print_prob",
          FT_UINT32,    BASE_HEX,   VALS(printer_problem_enum),   0x0,
          "Printer Problem", HFILL }},
        
        { &hf_selection_problem_type,
        { "Selection Problem",    "ndps.rpc_sel_prob",
          FT_UINT32,    BASE_HEX,   VALS(selection_problem_enum),   0x0,
          "Selection Problem", HFILL }},
        
        { &hf_doc_access_problem_type,
        { "Document Access Problem",    "ndps.rpc_doc_acc_prob",
          FT_UINT32,    BASE_HEX,   VALS(doc_access_problem_enum),   0x0,
          "Document Access Problem", HFILL }},
        
        { &hf_attribute_problem_type,
        { "Attribute Problem",    "ndps.rpc_attr_prob",
          FT_UINT32,    BASE_HEX,   VALS(attribute_problem_enum),   0x0,
          "Attribute Problem", HFILL }},

        { &hf_update_problem_type,
        { "Update Problem",    "ndps.rpc_update_prob",
          FT_UINT32,    BASE_HEX,   VALS(update_problem_enum),   0x0,
          "Update Problem", HFILL }},
        
        { &hf_obj_id_type,
        { "Object ID Type",    "ndps.rpc_obj_id_type",
          FT_UINT32,    BASE_HEX,   VALS(obj_identification_enum),   0x0,
          "Object ID Type", HFILL }},

        { &hf_oid_struct_size,
        { "OID Struct Size",    "ndps.rpc_oid_struct_size",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "OID Struct Size", HFILL }},
        
        { &hf_object_name,
        { "Object Name",    "ndps.ndps_object_name",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Object Name", HFILL }},

        { &hf_ndps_document_number,
        { "Document Number",    "ndps.ndps_doc_num",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Document Number", HFILL }},

        { &hf_ndps_nameorid,
        { "Name or ID Type",    "ndps.ndps_nameorid",
          FT_UINT32,    BASE_HEX,   VALS(nameorid_enum),   0x0,
          "Name or ID Type", HFILL }},

        { &hf_local_object_name,
        { "Local Object Name",    "ndps.ndps_loc_object_name",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Local Object Name", HFILL }},

        { &hf_printer_name,
        { "Printer Name",    "ndps.ndps_printer_name",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Printer Name", HFILL }},

        { &hf_ndps_qualified_name,
        { "Qualified Name Type",    "ndps.ndps_qual_name_type",
          FT_UINT32,    BASE_HEX,   VALS(qualified_name_enum),   0x0,
          "Qualified Name Type", HFILL }},

        { &hf_ndps_item_count,
        { "Number of Items",    "ndps.ndps_item_count",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Number of Items", HFILL }},

        { &hf_ndps_qualifier,
        { "Qualifier",    "ndps.ndps_qual",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Qualifier", HFILL }},

        { &hf_ndps_lib_error,
        { "Lib Error",    "ndps.ndps_lib_error",
          FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
          "Lib Error", HFILL }},

        { &hf_ndps_other_error,
        { "Other Error",    "ndps.ndps_other_error",
          FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
          "Other Error", HFILL }},

        { &hf_ndps_other_error_2,
        { "Other Error 2",    "ndps.ndps_other_error_2",
          FT_UINT32,    BASE_HEX,   VALS(ndps_error_types),   0x0,
          "Other Error 2", HFILL }},

        { &hf_ndps_session,
        { "Session",    "ndps.ndps_session",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Session", HFILL }},

        { &hf_ndps_abort_flag,
        { "Abort?",    "ndps.ndps_abort",
          FT_BOOLEAN,    BASE_HEX,   NULL,   0x0,
          "Abort?", HFILL }},

        { &hf_obj_attribute_type,
        { "Attribute Type",    "ndps.ndps_attrib_type",
          FT_UINT32,    BASE_HEX,   VALS(ndps_attribute_enum),   0x0,
          "Attribute Type", HFILL }},

        { &hf_ndps_attribute_value,
        { "Value",    "ndps.attribue_value",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Value", HFILL }},

        { &hf_ndps_lower_range,
        { "Lower Range",    "ndps.lower_range",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Lower Range", HFILL }},

        { &hf_ndps_upper_range,
        { "Upper Range",    "ndps.upper_range",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Upper Range", HFILL }},

        { &hf_ndps_n64,
        { "Value",    "ndps.n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Value", HFILL }},

        { &hf_ndps_lower_range_n64,
        { "Lower Range",    "ndps.lower_range_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Lower Range", HFILL }},

        { &hf_ndps_upper_range_n64,
        { "Upper Range",    "ndps.upper_range_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Upper Range", HFILL }},

        { &hf_ndps_attrib_boolean,
        { "Value?",    "ndps.ndps_attrib_boolean",
          FT_BOOLEAN,    BASE_HEX,   NULL,   0x0,
          "Value?", HFILL }},

        { &hf_ndps_realization,
        { "Realization Type",    "ndps.ndps_realization",
          FT_UINT32,    BASE_HEX,   VALS(ndps_realization_enum),   0x0,
          "Realization Type", HFILL }},

        { &hf_ndps_xdimension_n64,
        { "X Dimension",    "ndps.xdimension_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "X Dimension", HFILL }},

        { &hf_ndps_ydimension_n64,
        { "Y Dimension",    "ndps.xdimension_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Y Dimension", HFILL }},

        { &hf_ndps_dim_value,
        { "Dimension Value Type",    "ndps.ndps_dim_value",
          FT_UINT32,    BASE_HEX,   VALS(ndps_dim_value_enum),   0x0,
          "Dimension Value Type", HFILL }},

        { &hf_ndps_dim_flag,
        { "Dimension Flag",    "ndps.ndps_dim_falg",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Dimension Flag", HFILL }},

        { &hf_ndps_xydim_value,
        { "XY Dimension Value Type",    "ndps.ndps_xydim_value",
          FT_UINT32,    BASE_HEX,   VALS(ndps_xydim_value_enum),   0x0,
          "XY Dimension Value Type", HFILL }},

        { &hf_ndps_location_value,
        { "Location Value Type",    "ndps.ndps_location_value",
          FT_UINT32,    BASE_HEX,   VALS(ndps_location_value_enum),   0x0,
          "Location Value Type", HFILL }},

        { &hf_ndps_xmin_n64,
        { "Minimum X Dimension",    "ndps.xmin_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Minimum X Dimension", HFILL }},

        { &hf_ndps_xmax_n64,
        { "Maximum X Dimension",    "ndps.xmax_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Maximum X Dimension", HFILL }},

        { &hf_ndps_ymin_n64,
        { "Minimum Y Dimension",    "ndps.ymin_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Minimum Y Dimension", HFILL }},

        { &hf_ndps_ymax_n64,
        { "Maximum Y Dimension",    "ndps.ymax_n64",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Maximum Y Dimension", HFILL }},

        { &hf_ndps_edge_value,
        { "Edge Value",    "ndps.ndps_edge_value",
          FT_UINT32,    BASE_HEX,   VALS(ndps_edge_value_enum),   0x0,
          "Edge Value", HFILL }},

        { &hf_ndps_cardinal_or_oid,
        { "Cardinal or OID",    "ndps.ndps_car_or_oid",
          FT_UINT32,    BASE_HEX,   VALS(ndps_card_or_oid_enum),   0x0,
          "Cardinal or OID", HFILL }},

        { &hf_ndps_cardinal_name_or_oid,
        { "Cardinal Name or OID",    "ndps.ndps_car_name_or_oid",
          FT_UINT32,    BASE_HEX,   VALS(ndps_card_name_or_oid_enum),   0x0,
          "Cardinal Name or OID", HFILL }},

        { &hf_ndps_integer_or_oid,
        { "Integer or OID",    "ndps.ndps_integer_or_oid",
          FT_UINT32,    BASE_HEX,   VALS(ndps_integer_or_oid_enum),   0x0,
          "Integer or OID", HFILL }},

        { &hf_ndps_profile_id,
        { "Profile ID",    "ndps.ndps_profile_id",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Profile ID", HFILL }},

        { &hf_ndps_persistence,
        { "Persistence",    "ndps.ndps_persistence",
          FT_UINT32,    BASE_HEX,   VALS(ndps_persistence_enum),   0x0,
          "Persistence", HFILL }},

        { &hf_ndps_language_id,
        { "Lanuage ID",    "ndps.ndps_lang_id",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Language ID", HFILL }},

        { &hf_address_type,
        { "Address Type",    "ndps.ndps_address_type",
          FT_UINT32,    BASE_HEX,   VALS(ndps_address_type_enum),   0x0,
          "Address Type", HFILL }},

        { &hf_ndps_address,
        { "Address",    "ndps.ndps_address",
          FT_UINT32,    BASE_HEX,   VALS(ndps_address_enum),   0x0,
          "Address", HFILL }},

        { &hf_ndps_add_bytes,
        { "Address Length",    "ndps.add_bytes",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Address Length", HFILL }},

        { &hf_ndps_event_type,
        { "Event Type",    "ndps.ndps_event_type",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Event Type", HFILL }},

        { &hf_ndps_event_object_identifier,
        { "Event Object Type",    "ndps.ndps_event_object_identifier",
          FT_UINT32,    BASE_HEX,   VALS(ndps_event_object_enum),   0x0,
          "Event Object Type", HFILL }},

        { &hf_ndps_octet_string,
        { "Octet String",    "ndps.octet_string",
          FT_BYTES,    BASE_HEX,   NULL,   0x0,
          "Octet String", HFILL }},

        { &hf_ndps_scope,
        { "Scope",    "ndps.scope",
          FT_UINT32,    BASE_HEX,   NULL,   0x0,
          "Scope", HFILL }},
        
    };


	static gint *ett[] = {
		&ett_ndps,
	};
	

	proto_ndps = proto_register_protocol("Novell Distributed Print System", "NDPS", "ndps");
	proto_register_field_array(proto_ndps, hf_ndps, array_length(hf_ndps));

	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&ndps_init_protocol);
	register_postseq_cleanup_routine(&ndps_postseq_cleanup);
}

void
proto_reg_handoff_ndps(void)
{
	dissector_handle_t ndps_handle;

	ndps_handle = create_dissector_handle(dissect_ndps, proto_ndps);
	
	dissector_add("spx.socket", SPX_SOCKET_PA, ndps_handle);
	dissector_add("spx.socket", SPX_SOCKET_BROKER, ndps_handle);
	dissector_add("spx.socket", SPX_SOCKET_SRS, ndps_handle);
	dissector_add("spx.socket", SPX_SOCKET_ENS, ndps_handle);
	dissector_add("spx.socket", SPX_SOCKET_RMS, ndps_handle);
	dissector_add("spx.socket", SPX_SOCKET_NOTIFY_LISTENER, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_PA, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_BROKER, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_SRS, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_ENS, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_RMS, ndps_handle);
	dissector_add("tcp.port", TCP_PORT_NOTIFY_LISTENER, ndps_handle);
	ndps_data_handle = find_dissector("data");
}
