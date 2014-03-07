/* DO NOT EDIT
	This filter was automatically generated
	from eventlog.idl and eventlog.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl
*/


#include "config.h"
#ifdef _MSC_VER
#pragma warning(disable:4005)
#pragma warning(disable:4013)
#pragma warning(disable:4018)
#pragma warning(disable:4101)
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-eventlog.h"

/* Ett declarations */
static gint ett_dcerpc_eventlog = -1;
static gint ett_eventlog_eventlogReadFlags = -1;
static gint ett_eventlog_eventlogEventTypes = -1;
static gint ett_eventlog_eventlog_OpenUnknown0 = -1;
static gint ett_eventlog_eventlog_Record = -1;
static gint ett_eventlog_eventlog_ChangeUnknown0 = -1;


/* Header field declarations */
static gint hf_eventlog_eventlog_GetLogIntormation_dwInfoLevel = -1;
static gint hf_eventlog_Record_computer_name = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_unknown0 = -1;
static gint hf_eventlog_eventlog_Record_computer_name = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_handle = -1;
static gint hf_eventlog_eventlog_GetNumRecords_handle = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_WARNING_TYPE = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_ERROR_TYPE = -1;
static gint hf_eventlog_eventlog_OpenBackupEventLogW_unknown2 = -1;
static gint hf_eventlog_eventlog_Record_sid_offset = -1;
static gint hf_eventlog_Record_string = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_FAILURE = -1;
static gint hf_eventlog_eventlog_ChangeNotify_unknown2 = -1;
static gint hf_eventlog_eventlog_ReportEventW_event_category = -1;
static gint hf_eventlog_eventlog_ChangeUnknown0_unknown0 = -1;
static gint hf_eventlog_eventlog_Record_data_offset = -1;
static gint hf_eventlog_eventlog_OpenUnknown0_unknown0 = -1;
static gint hf_eventlog_eventlog_BackupEventLogW_backupfilename = -1;
static gint hf_eventlog_eventlog_ClearEventLogW_handle = -1;
static gint hf_eventlog_eventlog_Record_closing_record_number = -1;
static gint hf_eventlog_eventlog_Record_size = -1;
static gint hf_eventlog_eventlog_ReportEventW_computer_name = -1;
static gint hf_eventlog_eventlog_OpenBackupEventLogW_unknown0 = -1;
static gint hf_eventlog_eventlog_Record_event_id = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_handle = -1;
static gint hf_eventlog_eventlog_BackupEventLogW_handle = -1;
static gint hf_eventlog_eventlog_Record_raw_data = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_unknown0 = -1;
static gint hf_eventlog_eventlog_CloseEventLog_handle = -1;
static gint hf_eventlog_eventlog_ChangeUnknown0_unknown1 = -1;
static gint hf_eventlog_eventlog_OpenBackupEventLogW_handle = -1;
static gint hf_eventlog_eventlog_Record_reserved_flags = -1;
static gint hf_eventlog_eventlog_GetLogIntormation_cbBytesNeeded = -1;
static gint hf_eventlog_eventlogReadFlags_EVENTLOG_SEEK_READ = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_MinorVersion = -1;
static gint hf_eventlog_eventlog_Record_source_name = -1;
static gint hf_eventlog_eventlog_GetLogIntormation_handle = -1;
static gint hf_eventlog_Record_length = -1;
static gint hf_eventlog_eventlog_Record_sid_length = -1;
static gint hf_eventlog_eventlog_GetOldestRecord_oldest = -1;
static gint hf_eventlog_eventlog_Record_strings = -1;
static gint hf_eventlog_eventlog_Record_record_number = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_handle = -1;
static gint hf_eventlog_eventlog_GetLogIntormation_lpBuffer = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_logname = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_real_size = -1;
static gint hf_eventlog_eventlog_Record_time_written = -1;
static gint hf_eventlog_eventlog_Record_stringoffset = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_unknown3 = -1;
static gint hf_eventlog_eventlogReadFlags_EVENTLOG_SEQUENTIAL_READ = -1;
static gint hf_eventlog_eventlog_Record_reserved = -1;
static gint hf_eventlog_eventlog_Record_data_length = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_servername = -1;
static gint hf_eventlog_eventlog_ReportEventW_event_id = -1;
static gint hf_eventlog_eventlog_ReportEventW_handle = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_sent_size = -1;
static gint hf_eventlog_eventlog_ChangeNotify_handle = -1;
static gint hf_eventlog_eventlog_OpenBackupEventLogW_logname = -1;
static gint hf_eventlog_Record_source_name = -1;
static gint hf_eventlog_eventlog_Record_event_type = -1;
static gint hf_eventlog_eventlog_Record_num_of_strings = -1;
static gint hf_eventlog_eventlog_RegisterEventSourceW_unknown2 = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_offset = -1;
static gint hf_eventlog_eventlog_Record_event_category = -1;
static gint hf_eventlog_eventlog_GetOldestRecord_handle = -1;
static gint hf_eventlog_eventlog_OpenUnknown0_unknown1 = -1;
static gint hf_eventlog_eventlog_GetNumRecords_number = -1;
static gint hf_eventlog_eventlog_Record_time_generated = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_SUCCESS = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_RegModuleName = -1;
static gint hf_eventlog_eventlog_ReportEventW_data_length = -1;
static gint hf_eventlog_eventlogReadFlags_EVENTLOG_BACKWARDS_READ = -1;
static gint hf_eventlog_Record = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_data = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_INFORMATION_TYPE = -1;
static gint hf_eventlog_eventlog_DeregisterEventSource_handle = -1;
static gint hf_eventlog_opnum = -1;
static gint hf_eventlog_eventlog_ChangeNotify_unknown3 = -1;
static gint hf_eventlog_eventlog_ReportEventW_num_of_strings = -1;
static gint hf_eventlog_eventlog_ReportEventW_time = -1;
static gint hf_eventlog_eventlogReadFlags_EVENTLOG_FORWARDS_READ = -1;
static gint hf_eventlog_status = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_number_of_bytes = -1;
static gint hf_eventlog_eventlog_ClearEventLogW_backupfilename = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_Module = -1;
static gint hf_eventlog_eventlog_FlushEventLog_handle = -1;
static gint hf_eventlog_eventlog_ReportEventW_Type = -1;
static gint hf_eventlog_eventlog_OpenEventLogW_MajorVersion = -1;
static gint hf_eventlog_eventlog_GetLogIntormation_cbBufSize = -1;
static gint hf_eventlog_eventlog_OpenBackupEventLogW_unknown3 = -1;
static gint hf_eventlog_eventlog_ReadEventLogW_flags = -1;
static gint hf_eventlog_eventlogEventTypes_EVENTLOG_SUCCESS = -1;

static gint proto_dcerpc_eventlog = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_eventlog = {
	0x82273fdc, 0xe32a, 0x18c3,
	{ 0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea }
};
static guint16 ver_dcerpc_eventlog = 0;

static const true_false_string eventlogReadFlags_EVENTLOG_SEQUENTIAL_READ_tfs = {
   "EVENTLOG_SEQUENTIAL_READ is SET",
   "EVENTLOG_SEQUENTIAL_READ is NOT SET",
};
static const true_false_string eventlogReadFlags_EVENTLOG_SEEK_READ_tfs = {
   "EVENTLOG_SEEK_READ is SET",
   "EVENTLOG_SEEK_READ is NOT SET",
};
static const true_false_string eventlogReadFlags_EVENTLOG_FORWARDS_READ_tfs = {
   "EVENTLOG_FORWARDS_READ is SET",
   "EVENTLOG_FORWARDS_READ is NOT SET",
};
static const true_false_string eventlogReadFlags_EVENTLOG_BACKWARDS_READ_tfs = {
   "EVENTLOG_BACKWARDS_READ is SET",
   "EVENTLOG_BACKWARDS_READ is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_SUCCESS_tfs = {
   "EVENTLOG_SUCCESS is SET",
   "EVENTLOG_SUCCESS is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_ERROR_TYPE_tfs = {
   "EVENTLOG_ERROR_TYPE is SET",
   "EVENTLOG_ERROR_TYPE is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_WARNING_TYPE_tfs = {
   "EVENTLOG_WARNING_TYPE is SET",
   "EVENTLOG_WARNING_TYPE is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_INFORMATION_TYPE_tfs = {
   "EVENTLOG_INFORMATION_TYPE is SET",
   "EVENTLOG_INFORMATION_TYPE is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_AUDIT_SUCCESS_tfs = {
   "EVENTLOG_AUDIT_SUCCESS is SET",
   "EVENTLOG_AUDIT_SUCCESS is NOT SET",
};
static const true_false_string eventlogEventTypes_EVENTLOG_AUDIT_FAILURE_tfs = {
   "EVENTLOG_AUDIT_FAILURE is SET",
   "EVENTLOG_AUDIT_FAILURE is NOT SET",
};
static int eventlog_dissect_element_OpenUnknown0_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenUnknown0_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_record_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_time_generated(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_time_written(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_event_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_event_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_num_of_strings(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_event_category(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_reserved_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_closing_record_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_stringoffset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_sid_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_sid_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_data_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_data_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_source_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_strings(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_strings_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_Record_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeUnknown0_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeUnknown0_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ClearEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ClearEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ClearEventLogW_backupfilename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ClearEventLogW_backupfilename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_BackupEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_BackupEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_BackupEventLogW_backupfilename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_BackupEventLogW_backupfilename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_CloseEventLog_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_CloseEventLog_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_DeregisterEventSource_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_DeregisterEventSource_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetNumRecords_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetNumRecords_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetNumRecords_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetNumRecords_number_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetOldestRecord_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetOldestRecord_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetOldestRecord_oldest(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetOldestRecord_oldest_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeNotify_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeNotify_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeNotify_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeNotify_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ChangeNotify_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_Module(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_RegModuleName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_MajorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_MinorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_logname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_servername(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_RegisterEventSourceW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_logname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_OpenBackupEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_number_of_bytes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_sent_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_sent_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_real_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReadEventLogW_real_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_Type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_event_category(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_event_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_num_of_strings(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_data_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_ReportEventW_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_dwInfoLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_lpBuffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_lpBuffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_cbBufSize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_cbBytesNeeded(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_GetLogIntormation_cbBytesNeeded_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_FlushEventLog_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int eventlog_dissect_element_FlushEventLog_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
/* Add this one manually until we can compile LSA */
static int
eventlog_dissect_struct_lsa_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info* di, guint8 *drep, int hf_index,int notused _U_)
{
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, di, drep,
			hf_index, 0);
	return offset;
}
static int
eventlog_dissect_element_ReadEventLogW_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 len;
	tvbuff_t *record_tvb;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
		hf_eventlog_Record_length, &len);
	/* Create a new tvb so that we know that offset==0 is the beginning
	 * of the record. We need to know this since the data is not really
	 * NDR encoded at all and there are byte offsets into this buffer
	 * encoded therein.
	 */
	record_tvb=tvb_new_subset(tvb, offset, MIN((gint)len, tvb_length_remaining(tvb, offset)), len);
	eventlog_dissect_struct_Record(record_tvb, 0, pinfo, tree, di, drep, hf_eventlog_Record, 0);
	offset+=len;
	return offset;
}
/* sid_length and sid_offset handled by manual code since this is not NDR
   and we want to dissect the sid from the data blob */
static guint32 sid_length;
static int
eventlog_dissect_element_Record_sid_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	sid_length=0;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_sid_length,&sid_length);
	return offset;
}
static int
eventlog_dissect_element_Record_sid_offset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 sid_offset=0;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_sid_offset,&sid_offset);
	if(sid_offset && sid_length){
		tvbuff_t *sid_tvb;
		/* this blob contains an NT SID. 
		 * tvb starts at the beginning of the record.
		 */
		sid_tvb=tvb_new_subset(tvb, sid_offset, MIN((gint)sid_length, tvb_length_remaining(tvb, offset)), sid_length);
		dissect_nt_sid(sid_tvb, 0, tree, "SID", NULL, -1);
	}
	return offset;
}
static int
eventlog_dissect_element_Record_source_name(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	guint len;

	len=tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_eventlog_Record_source_name, tvb, offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	offset+=len;
	return offset;
}
static int
eventlog_dissect_element_Record_computer_name(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	guint len;

	len=tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_eventlog_Record_computer_name, tvb, offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	offset+=len;
	return offset;
}
static guint16 num_of_strings;
static int
eventlog_dissect_element_Record_num_of_strings(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	num_of_strings=0;
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_num_of_strings,&num_of_strings);
	return offset;
}
static guint32 string_offset;
static int
eventlog_dissect_element_Record_stringoffset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	string_offset=0;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_stringoffset,&string_offset);
	return offset;
}
static int
eventlog_dissect_element_Record_strings(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	while(string_offset && num_of_strings){
		guint len;

		len=tvb_unicode_strsize(tvb, string_offset);
		proto_tree_add_item(tree, hf_eventlog_Record_string, tvb, string_offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		string_offset+=len;
	
		num_of_strings--;
	}


	return offset;
}


/* IDL: bitmap { */
/* IDL: 	EVENTLOG_SEQUENTIAL_READ =  0x0001 , */
/* IDL: 	EVENTLOG_SEEK_READ =  0x0002 , */
/* IDL: 	EVENTLOG_FORWARDS_READ =  0x0004 , */
/* IDL: 	EVENTLOG_BACKWARDS_READ =  0x0008 , */
/* IDL: } */

int
eventlog_dissect_bitmap_eventlogReadFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, DREP_ENC_INTEGER(drep));
		tree = proto_item_add_subtree(item,ett_eventlog_eventlogReadFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_eventlog_eventlogReadFlags_EVENTLOG_SEQUENTIAL_READ, tvb, offset-4, 4, flags);
	if (flags&( 0x0001 )){
		proto_item_append_text(item, "EVENTLOG_SEQUENTIAL_READ");
		if (flags & (~( 0x0001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0001 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogReadFlags_EVENTLOG_SEEK_READ, tvb, offset-4, 4, flags);
	if (flags&( 0x0002 )){
		proto_item_append_text(item, "EVENTLOG_SEEK_READ");
		if (flags & (~( 0x0002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0002 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogReadFlags_EVENTLOG_FORWARDS_READ, tvb, offset-4, 4, flags);
	if (flags&( 0x0004 )){
		proto_item_append_text(item, "EVENTLOG_FORWARDS_READ");
		if (flags & (~( 0x0004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0004 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogReadFlags_EVENTLOG_BACKWARDS_READ, tvb, offset-4, 4, flags);
	if (flags&( 0x0008 )){
		proto_item_append_text(item, "EVENTLOG_BACKWARDS_READ");
		if (flags & (~( 0x0008 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0008 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	EVENTLOG_SUCCESS =  0x0000 , */
/* IDL: 	EVENTLOG_ERROR_TYPE =  0x0001 , */
/* IDL: 	EVENTLOG_WARNING_TYPE =  0x0002 , */
/* IDL: 	EVENTLOG_INFORMATION_TYPE =  0x0004 , */
/* IDL: 	EVENTLOG_AUDIT_SUCCESS =  0x0008 , */
/* IDL: 	EVENTLOG_AUDIT_FAILURE =  0x0010 , */
/* IDL: } */

int
eventlog_dissect_bitmap_eventlogEventTypes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, DREP_ENC_INTEGER(drep));
		tree = proto_item_add_subtree(item,ett_eventlog_eventlogEventTypes);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_SUCCESS, tvb, offset-4, 4, flags);
	if (flags&( 0x0000 )){
		proto_item_append_text(item, "EVENTLOG_SUCCESS");
		if (flags & (~( 0x0000 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0000 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_ERROR_TYPE, tvb, offset-4, 4, flags);
	if (flags&( 0x0001 )){
		proto_item_append_text(item, "EVENTLOG_ERROR_TYPE");
		if (flags & (~( 0x0001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0001 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_WARNING_TYPE, tvb, offset-4, 4, flags);
	if (flags&( 0x0002 )){
		proto_item_append_text(item, "EVENTLOG_WARNING_TYPE");
		if (flags & (~( 0x0002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0002 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_INFORMATION_TYPE, tvb, offset-4, 4, flags);
	if (flags&( 0x0004 )){
		proto_item_append_text(item, "EVENTLOG_INFORMATION_TYPE");
		if (flags & (~( 0x0004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0004 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_SUCCESS, tvb, offset-4, 4, flags);
	if (flags&( 0x0008 )){
		proto_item_append_text(item, "EVENTLOG_AUDIT_SUCCESS");
		if (flags & (~( 0x0008 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0008 ));

	proto_tree_add_boolean(tree, hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_FAILURE, tvb, offset-4, 4, flags);
	if (flags&( 0x0010 )){
		proto_item_append_text(item, "EVENTLOG_AUDIT_FAILURE");
		if (flags & (~( 0x0010 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x0010 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint16 unknown0; */
/* IDL: 	uint16 unknown1; */
/* IDL: } */

static int
eventlog_dissect_element_OpenUnknown0_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenUnknown0_unknown0, 0);

	return offset;
}

static int
eventlog_dissect_element_OpenUnknown0_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenUnknown0_unknown1, 0);

	return offset;
}

int
eventlog_dissect_struct_OpenUnknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_eventlog_eventlog_OpenUnknown0);
	}
	
	offset = eventlog_dissect_element_OpenUnknown0_unknown0(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_OpenUnknown0_unknown1(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);


	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_2_BYTES;
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 size; */
/* IDL: 	uint32 reserved; */
/* IDL: 	uint32 record_number; */
/* IDL: 	uint32 time_generated; */
/* IDL: 	uint32 time_written; */
/* IDL: 	uint32 event_id; */
/* IDL: 	uint16 event_type; */
/* IDL: 	uint16 num_of_strings; */
/* IDL: 	uint16 event_category; */
/* IDL: 	uint16 reserved_flags; */
/* IDL: 	uint32 closing_record_number; */
/* IDL: 	uint32 stringoffset; */
/* IDL: 	uint32 sid_length; */
/* IDL: 	uint32 sid_offset; */
/* IDL: 	uint32 data_length; */
/* IDL: 	uint32 data_offset; */
/* IDL: 	[flag(LIBNDR_FLAG_STR_NULLTERM)] string source_name; */
/* IDL: 	[flag(LIBNDR_FLAG_STR_NULLTERM)] string computer_name; */
/* IDL: 	[flag(LIBNDR_FLAG_STR_NULLTERM)] string strings[num_of_strings]; */
/* IDL: 	[flag(LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM)] string raw_data; */
/* IDL: } */

static int
eventlog_dissect_element_Record_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_size, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_reserved, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_record_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_record_number, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_time_generated(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_time_generated, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_time_written(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_time_written, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_event_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_event_id, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_event_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_event_type, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_event_category(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_event_category, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_reserved_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_reserved_flags, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_closing_record_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_closing_record_number, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_data_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_data_length, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_data_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_Record_data_offset, 0);

	return offset;
}

static int
eventlog_dissect_element_Record_strings_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_null_term_wstring(tvb, offset, pinfo, tree, drep, hf_eventlog_eventlog_Record_strings , 0);

	return offset;
}

static int
eventlog_dissect_element_Record_raw_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_null_term_string(tvb, offset, pinfo, tree, drep, hf_eventlog_eventlog_Record_raw_data , 0);

	return offset;
}

int
eventlog_dissect_struct_Record(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_eventlog_eventlog_Record);
	}
	
	offset = eventlog_dissect_element_Record_size(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_reserved(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_record_number(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_time_generated(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_time_written(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_event_id(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_event_type(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_num_of_strings(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_event_category(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_reserved_flags(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_closing_record_number(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_stringoffset(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_sid_length(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_sid_offset(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_data_length(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_data_offset(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_source_name(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_computer_name(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_strings(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_Record_raw_data(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);


	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_4_BYTES;
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 unknown0; */
/* IDL: 	uint32 unknown1; */
/* IDL: } */

static int
eventlog_dissect_element_ChangeUnknown0_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ChangeUnknown0_unknown0, 0);

	return offset;
}

static int
eventlog_dissect_element_ChangeUnknown0_unknown1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ChangeUnknown0_unknown1, 0);

	return offset;
}

int
eventlog_dissect_struct_ChangeUnknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_eventlog_eventlog_ChangeUnknown0);
	}
	
	offset = eventlog_dissect_element_ChangeUnknown0_unknown0(tvb, offset, pinfo, tree, di, drep);

	offset = eventlog_dissect_element_ChangeUnknown0_unknown1(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);


	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_4_BYTES;
	}

	return offset;
}

static int
eventlog_dissect_element_ClearEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ClearEventLogW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_ClearEventLogW_handle);

	return offset;
}

static int
eventlog_dissect_element_ClearEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ClearEventLogW_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_ClearEventLogW_backupfilename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ClearEventLogW_backupfilename_, NDR_POINTER_UNIQUE, "Pointer to Backupfilename (lsa_String)",hf_eventlog_eventlog_ClearEventLogW_backupfilename);

	return offset;
}

static int
eventlog_dissect_element_ClearEventLogW_backupfilename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_ClearEventLogW_backupfilename,0);

	return offset;
}

/* IDL: NTSTATUS eventlog_ClearEventLogW( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [unique(1)] [in] lsa_String *backupfilename */
/* IDL: ); */

static int
eventlog_dissect_ClearEventLogW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ClearEventLogW";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ClearEventLogW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ClearEventLogW";
	offset = eventlog_dissect_element_ClearEventLogW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ClearEventLogW_backupfilename(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_BackupEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_BackupEventLogW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_BackupEventLogW_handle);

	return offset;
}

static int
eventlog_dissect_element_BackupEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_BackupEventLogW_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_BackupEventLogW_backupfilename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_BackupEventLogW_backupfilename_, NDR_POINTER_UNIQUE, "Pointer to Backupfilename (lsa_String)",hf_eventlog_eventlog_BackupEventLogW_backupfilename);

	return offset;
}

static int
eventlog_dissect_element_BackupEventLogW_backupfilename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_BackupEventLogW_backupfilename,0);

	return offset;
}

/* IDL: NTSTATUS eventlog_BackupEventLogW( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [unique(1)] [in] lsa_String *backupfilename */
/* IDL: ); */

static int
eventlog_dissect_BackupEventLogW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="BackupEventLogW";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_BackupEventLogW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="BackupEventLogW";
	offset = eventlog_dissect_element_BackupEventLogW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_BackupEventLogW_backupfilename(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_CloseEventLog_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_CloseEventLog_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_CloseEventLog_handle);

	return offset;
}

static int
eventlog_dissect_element_CloseEventLog_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_CloseEventLog_handle, PIDL_POLHND_CLOSE);

	return offset;
}

/* IDL: NTSTATUS eventlog_CloseEventLog( */
/* IDL: [out] [ref] [in] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_CloseEventLog_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="CloseEventLog";
	offset = eventlog_dissect_element_CloseEventLog_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_CloseEventLog_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="CloseEventLog";
	offset = eventlog_dissect_element_CloseEventLog_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_DeregisterEventSource_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_DeregisterEventSource_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_DeregisterEventSource_handle);

	return offset;
}

static int
eventlog_dissect_element_DeregisterEventSource_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_DeregisterEventSource_handle, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_DeregisterEventSource( */
/* IDL: [out] [ref] [in] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_DeregisterEventSource_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="DeregisterEventSource";
	offset = eventlog_dissect_element_DeregisterEventSource_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_DeregisterEventSource_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="DeregisterEventSource";
	offset = eventlog_dissect_element_DeregisterEventSource_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_GetNumRecords_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetNumRecords_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_GetNumRecords_handle);

	return offset;
}

static int
eventlog_dissect_element_GetNumRecords_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetNumRecords_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_GetNumRecords_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetNumRecords_number_, NDR_POINTER_REF, "Pointer to Number (uint32)",hf_eventlog_eventlog_GetNumRecords_number);

	return offset;
}

static int
eventlog_dissect_element_GetNumRecords_number_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetNumRecords_number, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_GetNumRecords( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [out] [ref] uint32 *number */
/* IDL: ); */

static int
eventlog_dissect_GetNumRecords_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="GetNumRecords";
	offset = eventlog_dissect_element_GetNumRecords_number(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_GetNumRecords_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="GetNumRecords";
	offset = eventlog_dissect_element_GetNumRecords_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_GetOldestRecord_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetOldestRecord_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_GetOldestRecord_handle);

	return offset;
}

static int
eventlog_dissect_element_GetOldestRecord_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetOldestRecord_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_GetOldestRecord_oldest(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetOldestRecord_oldest_, NDR_POINTER_REF, "Pointer to Oldest (uint32)",hf_eventlog_eventlog_GetOldestRecord_oldest);

	return offset;
}

static int
eventlog_dissect_element_GetOldestRecord_oldest_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetOldestRecord_oldest, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_GetOldestRecord( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [out] [ref] uint32 *oldest */
/* IDL: ); */

static int
eventlog_dissect_GetOldestRecord_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="GetOldestRecord";
	offset = eventlog_dissect_element_GetOldestRecord_oldest(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_GetOldestRecord_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="GetOldestRecord";
	offset = eventlog_dissect_element_GetOldestRecord_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_ChangeNotify_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ChangeNotify_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_ChangeNotify_handle);

	return offset;
}

static int
eventlog_dissect_element_ChangeNotify_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ChangeNotify_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_ChangeNotify_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ChangeNotify_unknown2_, NDR_POINTER_REF, "Pointer to Unknown2 (eventlog_ChangeUnknown0)",hf_eventlog_eventlog_ChangeNotify_unknown2);

	return offset;
}

static int
eventlog_dissect_element_ChangeNotify_unknown2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_ChangeUnknown0(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_ChangeNotify_unknown2,0);

	return offset;
}

static int
eventlog_dissect_element_ChangeNotify_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ChangeNotify_unknown3, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_ChangeNotify( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [in] [ref] eventlog_ChangeUnknown0 *unknown2, */
/* IDL: [in] uint32 unknown3 */
/* IDL: ); */

static int
eventlog_dissect_ChangeNotify_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ChangeNotify";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ChangeNotify_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ChangeNotify";
	offset = eventlog_dissect_element_ChangeNotify_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ChangeNotify_unknown2(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ChangeNotify_unknown3(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_OpenEventLogW_unknown0_, NDR_POINTER_UNIQUE, "Pointer to Unknown0 (eventlog_OpenUnknown0)",hf_eventlog_eventlog_OpenEventLogW_unknown0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_OpenUnknown0(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_OpenEventLogW_unknown0,0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_Module(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_OpenEventLogW_Module,0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_RegModuleName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_OpenEventLogW_RegModuleName,0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_MajorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenEventLogW_MajorVersion, 0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_MinorVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenEventLogW_MinorVersion, 0);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_OpenEventLogW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_OpenEventLogW_handle);

	return offset;
}

static int
eventlog_dissect_element_OpenEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenEventLogW_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: NTSTATUS eventlog_OpenEventLogW( */
/* IDL: [unique(1)] [in] eventlog_OpenUnknown0 *unknown0, */
/* IDL: [in] lsa_String Module, */
/* IDL: [in] lsa_String RegModuleName, */
/* IDL: [in] uint32 MajorVersion, */
/* IDL: [in] uint32 MinorVersion, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_OpenEventLogW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="OpenEventLogW";
	offset = eventlog_dissect_element_OpenEventLogW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_OpenEventLogW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="OpenEventLogW";
	offset = eventlog_dissect_element_OpenEventLogW_unknown0(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenEventLogW_Module(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenEventLogW_RegModuleName(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenEventLogW_MajorVersion(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenEventLogW_MinorVersion(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_RegisterEventSourceW_unknown0_, NDR_POINTER_UNIQUE, "Pointer to Unknown0 (eventlog_OpenUnknown0)",hf_eventlog_eventlog_RegisterEventSourceW_unknown0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_OpenUnknown0(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_RegisterEventSourceW_unknown0,0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_logname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_RegisterEventSourceW_logname,0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_servername(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_RegisterEventSourceW_servername,0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_RegisterEventSourceW_unknown2, 0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_RegisterEventSourceW_unknown3, 0);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_RegisterEventSourceW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_RegisterEventSourceW_handle);

	return offset;
}

static int
eventlog_dissect_element_RegisterEventSourceW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_RegisterEventSourceW_handle, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_RegisterEventSourceW( */
/* IDL: [unique(1)] [in] eventlog_OpenUnknown0 *unknown0, */
/* IDL: [in] lsa_String logname, */
/* IDL: [in] lsa_String servername, */
/* IDL: [in] uint32 unknown2, */
/* IDL: [in] uint32 unknown3, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_RegisterEventSourceW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="RegisterEventSourceW";
	offset = eventlog_dissect_element_RegisterEventSourceW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_RegisterEventSourceW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="RegisterEventSourceW";
	offset = eventlog_dissect_element_RegisterEventSourceW_unknown0(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_RegisterEventSourceW_logname(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_RegisterEventSourceW_servername(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_RegisterEventSourceW_unknown2(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_RegisterEventSourceW_unknown3(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_unknown0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_OpenBackupEventLogW_unknown0_, NDR_POINTER_UNIQUE, "Pointer to Unknown0 (eventlog_OpenUnknown0)",hf_eventlog_eventlog_OpenBackupEventLogW_unknown0);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_unknown0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_OpenUnknown0(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_OpenBackupEventLogW_unknown0,0);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_logname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_OpenBackupEventLogW_logname,0);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenBackupEventLogW_unknown2, 0);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_unknown3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenBackupEventLogW_unknown3, 0);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_OpenBackupEventLogW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_OpenBackupEventLogW_handle);

	return offset;
}

static int
eventlog_dissect_element_OpenBackupEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_OpenBackupEventLogW_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: NTSTATUS eventlog_OpenBackupEventLogW( */
/* IDL: [unique(1)] [in] eventlog_OpenUnknown0 *unknown0, */
/* IDL: [in] lsa_String logname, */
/* IDL: [in] uint32 unknown2, */
/* IDL: [in] uint32 unknown3, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_OpenBackupEventLogW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="OpenBackupEventLogW";
	offset = eventlog_dissect_element_OpenBackupEventLogW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_OpenBackupEventLogW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="OpenBackupEventLogW";
	offset = eventlog_dissect_element_OpenBackupEventLogW_unknown0(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenBackupEventLogW_logname(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenBackupEventLogW_unknown2(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_OpenBackupEventLogW_unknown3(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ReadEventLogW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_ReadEventLogW_handle);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_bitmap_eventlogReadFlags(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_flags, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_offset, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_number_of_bytes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_number_of_bytes, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ReadEventLogW_data_, NDR_POINTER_REF, "Pointer to Data (uint8)",hf_eventlog_eventlog_ReadEventLogW_data);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_data, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_sent_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ReadEventLogW_sent_size_, NDR_POINTER_REF, "Pointer to Sent Size (uint32)",hf_eventlog_eventlog_ReadEventLogW_sent_size);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_sent_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_sent_size, 0);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_real_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ReadEventLogW_real_size_, NDR_POINTER_REF, "Pointer to Real Size (uint32)",hf_eventlog_eventlog_ReadEventLogW_real_size);

	return offset;
}

static int
eventlog_dissect_element_ReadEventLogW_real_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReadEventLogW_real_size, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_ReadEventLogW( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [in] eventlogReadFlags flags, */
/* IDL: [in] uint32 offset, */
/* IDL: [in] uint32 number_of_bytes, */
/* IDL: [out] [ref] [size_is(number_of_bytes)] uint8 *data, */
/* IDL: [out] [ref] uint32 *sent_size, */
/* IDL: [out] [ref] uint32 *real_size */
/* IDL: ); */

static int
eventlog_dissect_ReadEventLogW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ReadEventLogW";
	offset = eventlog_dissect_element_ReadEventLogW_data(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = eventlog_dissect_element_ReadEventLogW_sent_size(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = eventlog_dissect_element_ReadEventLogW_real_size(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ReadEventLogW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ReadEventLogW";
	offset = eventlog_dissect_element_ReadEventLogW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReadEventLogW_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReadEventLogW_offset(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReadEventLogW_number_of_bytes(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_ReportEventW_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_ReportEventW_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_ReportEventW_handle);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_time, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_Type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_bitmap_eventlogEventTypes(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_Type, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_event_category(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_event_category, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_event_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_event_id, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_num_of_strings(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_num_of_strings, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_data_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_ReportEventW_data_length, 0);

	return offset;
}

static int
eventlog_dissect_element_ReportEventW_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = eventlog_dissect_struct_lsa_String(tvb,offset,pinfo,tree,di,drep,hf_eventlog_eventlog_ReportEventW_computer_name,0);

	return offset;
}

/* IDL: NTSTATUS eventlog_ReportEventW( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [in] uint32 time, */
/* IDL: [in] eventlogEventTypes Type, */
/* IDL: [in] uint16 event_category, */
/* IDL: [in] uint32 event_id, */
/* IDL: [in] uint16 num_of_strings, */
/* IDL: [in] uint32 data_length, */
/* IDL: [in] lsa_String computer_name */
/* IDL: ); */

static int
eventlog_dissect_ReportEventW_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ReportEventW";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ReportEventW_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ReportEventW";
	offset = eventlog_dissect_element_ReportEventW_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_time(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_Type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_event_category(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_event_id(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_num_of_strings(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_data_length(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_ReportEventW_computer_name(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

/* IDL: NTSTATUS eventlog_ClearEventLogA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_ClearEventLogA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ClearEventLogA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ClearEventLogA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ClearEventLogA";
	return offset;
}

/* IDL: NTSTATUS eventlog_BackupEventLogA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_BackupEventLogA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="BackupEventLogA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_BackupEventLogA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="BackupEventLogA";
	return offset;
}

/* IDL: NTSTATUS eventlog_OpenEventLogA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_OpenEventLogA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="OpenEventLogA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_OpenEventLogA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="OpenEventLogA";
	return offset;
}

/* IDL: NTSTATUS eventlog_RegisterEventSourceA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_RegisterEventSourceA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="RegisterEventSourceA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_RegisterEventSourceA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="RegisterEventSourceA";
	return offset;
}

/* IDL: NTSTATUS eventlog_OpenBackupEventLogA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_OpenBackupEventLogA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="OpenBackupEventLogA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_OpenBackupEventLogA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="OpenBackupEventLogA";
	return offset;
}

/* IDL: NTSTATUS eventlog_ReadEventLogA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_ReadEventLogA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ReadEventLogA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ReadEventLogA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ReadEventLogA";
	return offset;
}

/* IDL: NTSTATUS eventlog_ReportEventA( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_ReportEventA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="ReportEventA";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_ReportEventA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="ReportEventA";
	return offset;
}

/* IDL: NTSTATUS eventlog_RegisterClusterSvc( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_RegisterClusterSvc_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="RegisterClusterSvc";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_RegisterClusterSvc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="RegisterClusterSvc";
	return offset;
}

/* IDL: NTSTATUS eventlog_DeregisterClusterSvc( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_DeregisterClusterSvc_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="DeregisterClusterSvc";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_DeregisterClusterSvc_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="DeregisterClusterSvc";
	return offset;
}

/* IDL: NTSTATUS eventlog_WriteClusterEvents( */
/* IDL:  */
/* IDL: ); */

static int
eventlog_dissect_WriteClusterEvents_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="WriteClusterEvents";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_WriteClusterEvents_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="WriteClusterEvents";
	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetLogIntormation_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_GetLogIntormation_handle);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetLogIntormation_handle, 0);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_dwInfoLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetLogIntormation_dwInfoLevel, 0);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_lpBuffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetLogIntormation_lpBuffer_);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_lpBuffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetLogIntormation_lpBuffer, 0);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_cbBufSize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetLogIntormation_cbBufSize, 0);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_cbBytesNeeded(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_GetLogIntormation_cbBytesNeeded_, NDR_POINTER_REF, "Pointer to Cbbytesneeded (int32)",hf_eventlog_eventlog_GetLogIntormation_cbBytesNeeded);

	return offset;
}

static int
eventlog_dissect_element_GetLogIntormation_cbBytesNeeded_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_GetLogIntormation_cbBytesNeeded, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_GetLogIntormation( */
/* IDL: [ref] [in] policy_handle *handle, */
/* IDL: [in] uint32 dwInfoLevel, */
/* IDL: [out] [size_is(cbBufSize)] uint8 lpBuffer[*], */
/* IDL: [in] uint32 cbBufSize, */
/* IDL: [out] [ref] int32 *cbBytesNeeded */
/* IDL: ); */

static int
eventlog_dissect_GetLogIntormation_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="GetLogIntormation";
	offset = eventlog_dissect_element_GetLogIntormation_lpBuffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = eventlog_dissect_element_GetLogIntormation_cbBytesNeeded(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_GetLogIntormation_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="GetLogIntormation";
	offset = eventlog_dissect_element_GetLogIntormation_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_GetLogIntormation_dwInfoLevel(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = eventlog_dissect_element_GetLogIntormation_cbBufSize(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
eventlog_dissect_element_FlushEventLog_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, eventlog_dissect_element_FlushEventLog_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_eventlog_eventlog_FlushEventLog_handle);

	return offset;
}

static int
eventlog_dissect_element_FlushEventLog_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_eventlog_eventlog_FlushEventLog_handle, 0);

	return offset;
}

/* IDL: NTSTATUS eventlog_FlushEventLog( */
/* IDL: [ref] [in] policy_handle *handle */
/* IDL: ); */

static int
eventlog_dissect_FlushEventLog_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="FlushEventLog";
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_eventlog_status, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, NT_errors, "Unknown NT status 0x%08x"));

	return offset;
}

static int
eventlog_dissect_FlushEventLog_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FlushEventLog";
	offset = eventlog_dissect_element_FlushEventLog_handle(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}


static dcerpc_sub_dissector eventlog_dissectors[] = {
	{ 0, "ClearEventLogW",
	   eventlog_dissect_ClearEventLogW_request, eventlog_dissect_ClearEventLogW_response},
	{ 1, "BackupEventLogW",
	   eventlog_dissect_BackupEventLogW_request, eventlog_dissect_BackupEventLogW_response},
	{ 2, "CloseEventLog",
	   eventlog_dissect_CloseEventLog_request, eventlog_dissect_CloseEventLog_response},
	{ 3, "DeregisterEventSource",
	   eventlog_dissect_DeregisterEventSource_request, eventlog_dissect_DeregisterEventSource_response},
	{ 4, "GetNumRecords",
	   eventlog_dissect_GetNumRecords_request, eventlog_dissect_GetNumRecords_response},
	{ 5, "GetOldestRecord",
	   eventlog_dissect_GetOldestRecord_request, eventlog_dissect_GetOldestRecord_response},
	{ 6, "ChangeNotify",
	   eventlog_dissect_ChangeNotify_request, eventlog_dissect_ChangeNotify_response},
	{ 7, "OpenEventLogW",
	   eventlog_dissect_OpenEventLogW_request, eventlog_dissect_OpenEventLogW_response},
	{ 8, "RegisterEventSourceW",
	   eventlog_dissect_RegisterEventSourceW_request, eventlog_dissect_RegisterEventSourceW_response},
	{ 9, "OpenBackupEventLogW",
	   eventlog_dissect_OpenBackupEventLogW_request, eventlog_dissect_OpenBackupEventLogW_response},
	{ 10, "ReadEventLogW",
	   eventlog_dissect_ReadEventLogW_request, eventlog_dissect_ReadEventLogW_response},
	{ 11, "ReportEventW",
	   eventlog_dissect_ReportEventW_request, eventlog_dissect_ReportEventW_response},
	{ 12, "ClearEventLogA",
	   eventlog_dissect_ClearEventLogA_request, eventlog_dissect_ClearEventLogA_response},
	{ 13, "BackupEventLogA",
	   eventlog_dissect_BackupEventLogA_request, eventlog_dissect_BackupEventLogA_response},
	{ 14, "OpenEventLogA",
	   eventlog_dissect_OpenEventLogA_request, eventlog_dissect_OpenEventLogA_response},
	{ 15, "RegisterEventSourceA",
	   eventlog_dissect_RegisterEventSourceA_request, eventlog_dissect_RegisterEventSourceA_response},
	{ 16, "OpenBackupEventLogA",
	   eventlog_dissect_OpenBackupEventLogA_request, eventlog_dissect_OpenBackupEventLogA_response},
	{ 17, "ReadEventLogA",
	   eventlog_dissect_ReadEventLogA_request, eventlog_dissect_ReadEventLogA_response},
	{ 18, "ReportEventA",
	   eventlog_dissect_ReportEventA_request, eventlog_dissect_ReportEventA_response},
	{ 19, "RegisterClusterSvc",
	   eventlog_dissect_RegisterClusterSvc_request, eventlog_dissect_RegisterClusterSvc_response},
	{ 20, "DeregisterClusterSvc",
	   eventlog_dissect_DeregisterClusterSvc_request, eventlog_dissect_DeregisterClusterSvc_response},
	{ 21, "WriteClusterEvents",
	   eventlog_dissect_WriteClusterEvents_request, eventlog_dissect_WriteClusterEvents_response},
	{ 22, "GetLogIntormation",
	   eventlog_dissect_GetLogIntormation_request, eventlog_dissect_GetLogIntormation_response},
	{ 23, "FlushEventLog",
	   eventlog_dissect_FlushEventLog_request, eventlog_dissect_FlushEventLog_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_eventlog(void)
{
	static hf_register_info hf[] = {
	{ &hf_eventlog_eventlog_GetLogIntormation_dwInfoLevel, 
	  { "Dwinfolevel", "eventlog.eventlog_GetLogIntormation.dwInfoLevel", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_Record_computer_name, 
	  { "Computer Name", "eventlog.Record.computer_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_unknown0, 
	  { "Unknown0", "eventlog.eventlog_OpenEventLogW.unknown0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_computer_name, 
	  { "Computer Name", "eventlog.eventlog_Record.computer_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_handle, 
	  { "Handle", "eventlog.eventlog_RegisterEventSourceW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetNumRecords_handle, 
	  { "Handle", "eventlog.eventlog_GetNumRecords.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_WARNING_TYPE, 
	  { "Eventlog Warning Type", "eventlog.eventlogEventTypes.EVENTLOG_WARNING_TYPE", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_WARNING_TYPE_tfs), ( 0x0002 ), NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_ERROR_TYPE, 
	  { "Eventlog Error Type", "eventlog.eventlogEventTypes.EVENTLOG_ERROR_TYPE", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_ERROR_TYPE_tfs), ( 0x0001 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenBackupEventLogW_unknown2, 
	  { "Unknown2", "eventlog.eventlog_OpenBackupEventLogW.unknown2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_sid_offset, 
	  { "Sid Offset", "eventlog.eventlog_Record.sid_offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_Record_string, 
	  { "string", "eventlog.Record.string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_FAILURE, 
	  { "Eventlog Audit Failure", "eventlog.eventlogEventTypes.EVENTLOG_AUDIT_FAILURE", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_AUDIT_FAILURE_tfs), ( 0x0010 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_ChangeNotify_unknown2, 
	  { "Unknown2", "eventlog.eventlog_ChangeNotify.unknown2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_event_category, 
	  { "Event Category", "eventlog.eventlog_ReportEventW.event_category", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ChangeUnknown0_unknown0, 
	  { "Unknown0", "eventlog.eventlog_ChangeUnknown0.unknown0", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_data_offset, 
	  { "Data Offset", "eventlog.eventlog_Record.data_offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenUnknown0_unknown0, 
	  { "Unknown0", "eventlog.eventlog_OpenUnknown0.unknown0", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_BackupEventLogW_backupfilename, 
	  { "Backupfilename", "eventlog.eventlog_BackupEventLogW.backupfilename", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ClearEventLogW_handle, 
	  { "Handle", "eventlog.eventlog_ClearEventLogW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_closing_record_number, 
	  { "Closing Record Number", "eventlog.eventlog_Record.closing_record_number", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_size, 
	  { "Size", "eventlog.eventlog_Record.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_computer_name, 
	  { "Computer Name", "eventlog.eventlog_ReportEventW.computer_name", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenBackupEventLogW_unknown0, 
	  { "Unknown0", "eventlog.eventlog_OpenBackupEventLogW.unknown0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_event_id, 
	  { "Event Id", "eventlog.eventlog_Record.event_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_handle, 
	  { "Handle", "eventlog.eventlog_ReadEventLogW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_BackupEventLogW_handle, 
	  { "Handle", "eventlog.eventlog_BackupEventLogW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_raw_data, 
	  { "Raw Data", "eventlog.eventlog_Record.raw_data", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_unknown0, 
	  { "Unknown0", "eventlog.eventlog_RegisterEventSourceW.unknown0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_CloseEventLog_handle, 
	  { "Handle", "eventlog.eventlog_CloseEventLog.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ChangeUnknown0_unknown1, 
	  { "Unknown1", "eventlog.eventlog_ChangeUnknown0.unknown1", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenBackupEventLogW_handle, 
	  { "Handle", "eventlog.eventlog_OpenBackupEventLogW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_reserved_flags, 
	  { "Reserved Flags", "eventlog.eventlog_Record.reserved_flags", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetLogIntormation_cbBytesNeeded, 
	  { "Cbbytesneeded", "eventlog.eventlog_GetLogIntormation.cbBytesNeeded", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogReadFlags_EVENTLOG_SEEK_READ, 
	  { "Eventlog Seek Read", "eventlog.eventlogReadFlags.EVENTLOG_SEEK_READ", FT_BOOLEAN, 32, TFS(&eventlogReadFlags_EVENTLOG_SEEK_READ_tfs), ( 0x0002 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_MinorVersion, 
	  { "Minorversion", "eventlog.eventlog_OpenEventLogW.MinorVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_source_name, 
	  { "Source Name", "eventlog.eventlog_Record.source_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetLogIntormation_handle, 
	  { "Handle", "eventlog.eventlog_GetLogIntormation.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_Record_length, 
	  { "Record Length", "eventlog.Record.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_sid_length, 
	  { "Sid Length", "eventlog.eventlog_Record.sid_length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetOldestRecord_oldest, 
	  { "Oldest", "eventlog.eventlog_GetOldestRecord.oldest", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_strings, 
	  { "Strings", "eventlog.eventlog_Record.strings", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_record_number, 
	  { "Record Number", "eventlog.eventlog_Record.record_number", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_handle, 
	  { "Handle", "eventlog.eventlog_OpenEventLogW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetLogIntormation_lpBuffer, 
	  { "Lpbuffer", "eventlog.eventlog_GetLogIntormation.lpBuffer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_logname, 
	  { "Logname", "eventlog.eventlog_RegisterEventSourceW.logname", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_real_size, 
	  { "Real Size", "eventlog.eventlog_ReadEventLogW.real_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_time_written, 
	  { "Time Written", "eventlog.eventlog_Record.time_written", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_stringoffset, 
	  { "Stringoffset", "eventlog.eventlog_Record.stringoffset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_unknown3, 
	  { "Unknown3", "eventlog.eventlog_RegisterEventSourceW.unknown3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogReadFlags_EVENTLOG_SEQUENTIAL_READ, 
	  { "Eventlog Sequential Read", "eventlog.eventlogReadFlags.EVENTLOG_SEQUENTIAL_READ", FT_BOOLEAN, 32, TFS(&eventlogReadFlags_EVENTLOG_SEQUENTIAL_READ_tfs), ( 0x0001 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_reserved, 
	  { "Reserved", "eventlog.eventlog_Record.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_data_length, 
	  { "Data Length", "eventlog.eventlog_Record.data_length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_servername, 
	  { "Servername", "eventlog.eventlog_RegisterEventSourceW.servername", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_event_id, 
	  { "Event Id", "eventlog.eventlog_ReportEventW.event_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_handle, 
	  { "Handle", "eventlog.eventlog_ReportEventW.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_sent_size, 
	  { "Sent Size", "eventlog.eventlog_ReadEventLogW.sent_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ChangeNotify_handle, 
	  { "Handle", "eventlog.eventlog_ChangeNotify.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenBackupEventLogW_logname, 
	  { "Logname", "eventlog.eventlog_OpenBackupEventLogW.logname", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_Record_source_name, 
	  { "Source Name", "eventlog.Record.source_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_event_type, 
	  { "Event Type", "eventlog.eventlog_Record.event_type", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_num_of_strings, 
	  { "Num Of Strings", "eventlog.eventlog_Record.num_of_strings", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_RegisterEventSourceW_unknown2, 
	  { "Unknown2", "eventlog.eventlog_RegisterEventSourceW.unknown2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_offset, 
	  { "Offset", "eventlog.eventlog_ReadEventLogW.offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_event_category, 
	  { "Event Category", "eventlog.eventlog_Record.event_category", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetOldestRecord_handle, 
	  { "Handle", "eventlog.eventlog_GetOldestRecord.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenUnknown0_unknown1, 
	  { "Unknown1", "eventlog.eventlog_OpenUnknown0.unknown1", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetNumRecords_number, 
	  { "Number", "eventlog.eventlog_GetNumRecords.number", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_Record_time_generated, 
	  { "Time Generated", "eventlog.eventlog_Record.time_generated", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_AUDIT_SUCCESS, 
	  { "Eventlog Audit Success", "eventlog.eventlogEventTypes.EVENTLOG_AUDIT_SUCCESS", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_AUDIT_SUCCESS_tfs), ( 0x0008 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_RegModuleName, 
	  { "Regmodulename", "eventlog.eventlog_OpenEventLogW.RegModuleName", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_data_length, 
	  { "Data Length", "eventlog.eventlog_ReportEventW.data_length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogReadFlags_EVENTLOG_BACKWARDS_READ, 
	  { "Eventlog Backwards Read", "eventlog.eventlogReadFlags.EVENTLOG_BACKWARDS_READ", FT_BOOLEAN, 32, TFS(&eventlogReadFlags_EVENTLOG_BACKWARDS_READ_tfs), ( 0x0008 ), NULL, HFILL }},
	{ &hf_eventlog_Record, 
	  { "Record", "eventlog.Record", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_data, 
	  { "Data", "eventlog.eventlog_ReadEventLogW.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_INFORMATION_TYPE, 
	  { "Eventlog Information Type", "eventlog.eventlogEventTypes.EVENTLOG_INFORMATION_TYPE", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_INFORMATION_TYPE_tfs), ( 0x0004 ), NULL, HFILL }},
	{ &hf_eventlog_eventlog_DeregisterEventSource_handle, 
	  { "Handle", "eventlog.eventlog_DeregisterEventSource.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_opnum, 
	  { "Operation", "eventlog.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ChangeNotify_unknown3, 
	  { "Unknown3", "eventlog.eventlog_ChangeNotify.unknown3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_num_of_strings, 
	  { "Num Of Strings", "eventlog.eventlog_ReportEventW.num_of_strings", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_time, 
	  { "Time", "eventlog.eventlog_ReportEventW.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogReadFlags_EVENTLOG_FORWARDS_READ, 
	  { "Eventlog Forwards Read", "eventlog.eventlogReadFlags.EVENTLOG_FORWARDS_READ", FT_BOOLEAN, 32, TFS(&eventlogReadFlags_EVENTLOG_FORWARDS_READ_tfs), ( 0x0004 ), NULL, HFILL }},
	{ &hf_eventlog_status, 
	  { "NT Error", "eventlog.status", FT_UINT32, BASE_HEX, VALS(NT_errors), 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_number_of_bytes, 
	  { "Number Of Bytes", "eventlog.eventlog_ReadEventLogW.number_of_bytes", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ClearEventLogW_backupfilename, 
	  { "Backupfilename", "eventlog.eventlog_ClearEventLogW.backupfilename", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_Module, 
	  { "Module", "eventlog.eventlog_OpenEventLogW.Module", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_FlushEventLog_handle, 
	  { "Handle", "eventlog.eventlog_FlushEventLog.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReportEventW_Type, 
	  { "Type", "eventlog.eventlog_ReportEventW.Type", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenEventLogW_MajorVersion, 
	  { "Majorversion", "eventlog.eventlog_OpenEventLogW.MajorVersion", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_GetLogIntormation_cbBufSize, 
	  { "Cbbufsize", "eventlog.eventlog_GetLogIntormation.cbBufSize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_OpenBackupEventLogW_unknown3, 
	  { "Unknown3", "eventlog.eventlog_OpenBackupEventLogW.unknown3", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlog_ReadEventLogW_flags, 
	  { "Flags", "eventlog.eventlog_ReadEventLogW.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_eventlog_eventlogEventTypes_EVENTLOG_SUCCESS, 
	  { "Eventlog Success", "eventlog.eventlogEventTypes.EVENTLOG_SUCCESS", FT_BOOLEAN, 32, TFS(&eventlogEventTypes_EVENTLOG_SUCCESS_tfs), ( 0x0000 ), NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_eventlog,
		&ett_eventlog_eventlogReadFlags,
		&ett_eventlog_eventlogEventTypes,
		&ett_eventlog_eventlog_OpenUnknown0,
		&ett_eventlog_eventlog_Record,
		&ett_eventlog_eventlog_ChangeUnknown0,
	};

	proto_dcerpc_eventlog = proto_register_protocol("Event Logger", "EVENTLOG", "eventlog");
	proto_register_field_array(proto_dcerpc_eventlog, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_eventlog(void)
{
	dcerpc_init_uuid(proto_dcerpc_eventlog, ett_dcerpc_eventlog,
		&uuid_dcerpc_eventlog, ver_dcerpc_eventlog,
		eventlog_dissectors, hf_eventlog_opnum);
}
