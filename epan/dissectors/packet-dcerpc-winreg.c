/* DO NOT EDIT
	This filter was automatically generated
	from winreg.idl and winreg.cnf.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl

	$Id$
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
#include "packet-dcerpc-winreg.h"

/* Ett declarations */
static gint ett_dcerpc_winreg = -1;
static gint ett_winreg_winreg_AccessMask = -1;
static gint ett_winreg_winreg_String = -1;
static gint ett_winreg_KeySecurityData = -1;
static gint ett_winreg_winreg_SecBuf = -1;
static gint ett_winreg_winreg_StringBuf = -1;
static gint ett_winreg_KeySecurityAttribute = -1;
static gint ett_winreg_QueryMultipleValue = -1;


/* Header field declarations */
static gint hf_winreg_winreg_AccessMask_KEY_ENUMERATE_SUB_KEYS = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_string2 = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_message = -1;
static gint hf_winreg_KeySecurityData_size = -1;
static gint hf_winreg_winreg_String_name = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_message = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_reboot = -1;
static gint hf_winreg_winreg_EnumValue_enum_index = -1;
static gint hf_winreg_access_mask = -1;
static gint hf_winreg_winreg_QueryMultipleValues_key_handle = -1;
static gint hf_winreg_winreg_LoadKey_keyname = -1;
static gint hf_winreg_winreg_EnumKey_name = -1;
static gint hf_winreg_winreg_CreateKey_options = -1;
static gint hf_winreg_winreg_EnumValue_type = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_timeout = -1;
static gint hf_winreg_winreg_EnumKey_last_changed_time = -1;
static gint hf_winreg_winreg_QueryValue_size = -1;
static gint hf_winreg_winreg_EnumValue_size = -1;
static gint hf_winreg_handle = -1;
static gint hf_winreg_winreg_SaveKey_sec_attrib = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_valnamelen = -1;
static gint hf_winreg_winreg_SecBuf_length = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_reboot = -1;
static gint hf_winreg_sd = -1;
static gint hf_winreg_winreg_SaveKey_filename = -1;
static gint hf_winreg_winreg_QueryMultipleValues_buffer_size = -1;
static gint hf_winreg_winreg_QueryValue_data = -1;
static gint hf_winreg_winreg_CreateKey_new_handle = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_subkeysize = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_hostname = -1;
static gint hf_winreg_KeySecurityData_data = -1;
static gint hf_winreg_KeySecurityAttribute_sec_data = -1;
static gint hf_winreg_winreg_OpenKey_access_mask = -1;
static gint hf_winreg_QueryMultipleValue_name = -1;
static gint hf_winreg_winreg_GetKeySecurity_sec_info = -1;
static gint hf_winreg_winreg_StringBuf_size = -1;
static gint hf_winreg_winreg_SecBuf_sd = -1;
static gint hf_winreg_winreg_QueryInfoKey_secdescsize = -1;
static gint hf_winreg_winreg_OpenKey_keyname = -1;
static gint hf_winreg_QueryMultipleValue_type = -1;
static gint hf_winreg_winreg_SetValue_name = -1;
static gint hf_winreg_winreg_RestoreKey_flags = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree = -1;
static gint hf_winreg_winreg_CreateKey_secdesc = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_force_apps = -1;
static gint hf_winreg_winreg_SetValue_type = -1;
static gint hf_winreg_winreg_CreateKey_name = -1;
static gint hf_winreg_KeySecurityData_len = -1;
static gint hf_winreg_winreg_String_name_len = -1;
static gint hf_winreg_opnum = -1;
static gint hf_winreg_winreg_DeleteKey_key = -1;
static gint hf_winreg_winreg_EnumValue_name = -1;
static gint hf_winreg_winreg_LoadKey_filename = -1;
static gint hf_winreg_winreg_AccessMask_KEY_CREATE_LINK = -1;
static gint hf_winreg_winreg_DeleteValue_value = -1;
static gint hf_winreg_system_name = -1;
static gint hf_winreg_QueryMultipleValue_length = -1;
static gint hf_winreg_winreg_QueryMultipleValues_num_values = -1;
static gint hf_winreg_winreg_AccessMask_KEY_NOTIFY = -1;
static gint hf_winreg_KeySecurityAttribute_data_size = -1;
static gint hf_winreg_winreg_OpenKey_parent_handle = -1;
static gint hf_winreg_winreg_StringBuf_name = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_unknown2 = -1;
static gint hf_winreg_winreg_QueryInfoKey_num_subkeys = -1;
static gint hf_winreg_sd_offset = -1;
static gint hf_winreg_winreg_AccessMask_KEY_WOW64_32KEY = -1;
static gint hf_winreg_winreg_StringBuf_length = -1;
static gint hf_winreg_winreg_QueryInfoKey_last_changed_time = -1;
static gint hf_winreg_winreg_OpenHKPD_access_mask = -1;
static gint hf_winreg_winreg_AbortSystemShutdown_server = -1;
static gint hf_winreg_winreg_QueryValue_type = -1;
static gint hf_winreg_sd_actual_size = -1;
static gint hf_winreg_winreg_String_name_size = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_unknown = -1;
static gint hf_winreg_winreg_QueryValue_length = -1;
static gint hf_winreg_winreg_AccessMask_KEY_CREATE_SUB_KEY = -1;
static gint hf_winreg_winreg_OpenKey_unknown = -1;
static gint hf_winreg_winreg_RestoreKey_filename = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_valbufsize = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_reason = -1;
static gint hf_winreg_winreg_SecBuf_inherit = -1;
static gint hf_winreg_winreg_SetValue_size = -1;
static gint hf_winreg_winreg_EnumValue_length = -1;
static gint hf_winreg_winreg_QueryMultipleValues_values = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_subkeylen = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_timeout = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_hostname = -1;
static gint hf_winreg_winreg_SaveKey_handle = -1;
static gint hf_winreg_KeySecurityAttribute_inherit = -1;
static gint hf_winreg_werror = -1;
static gint hf_winreg_winreg_GetVersion_version = -1;
static gint hf_winreg_winreg_AccessMask_KEY_QUERY_VALUE = -1;
static gint hf_winreg_winreg_CreateKey_action_taken = -1;
static gint hf_winreg_winreg_QueryInfoKey_num_values = -1;
static gint hf_winreg_winreg_EnumKey_keyclass = -1;
static gint hf_winreg_winreg_AccessMask_KEY_SET_VALUE = -1;
static gint hf_winreg_winreg_EnumKey_enum_index = -1;
static gint hf_winreg_winreg_RestoreKey_handle = -1;
static gint hf_winreg_winreg_SetValue_data = -1;
static gint hf_winreg_winreg_CreateKey_keyclass = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_force_apps = -1;
static gint hf_winreg_winreg_EnumValue_value = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_string1 = -1;
static gint hf_winreg_winreg_QueryMultipleValues_buffer = -1;
static gint hf_winreg_winreg_SetKeySecurity_access_mask = -1;
static gint hf_winreg_winreg_QueryValue_value_name = -1;
static gint hf_winreg_winreg_QueryInfoKey_classname = -1;
static gint hf_winreg_winreg_AccessMask_KEY_WOW64_64KEY = -1;
static gint hf_winreg_winreg_OpenHKCU_access_mask = -1;
static gint hf_winreg_sd_max_size = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_notify_filter = -1;
static gint hf_winreg_QueryMultipleValue_offset = -1;

static gint proto_dcerpc_winreg = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_winreg = {
	0x338cd001, 0x2244, 0x31f1,
	{ 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 }
};
static guint16 ver_dcerpc_winreg = 1;

static const true_false_string winreg_AccessMask_KEY_QUERY_VALUE_tfs = {
   "KEY_QUERY_VALUE is SET",
   "KEY_QUERY_VALUE is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_SET_VALUE_tfs = {
   "KEY_SET_VALUE is SET",
   "KEY_SET_VALUE is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_CREATE_SUB_KEY_tfs = {
   "KEY_CREATE_SUB_KEY is SET",
   "KEY_CREATE_SUB_KEY is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_ENUMERATE_SUB_KEYS_tfs = {
   "KEY_ENUMERATE_SUB_KEYS is SET",
   "KEY_ENUMERATE_SUB_KEYS is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_NOTIFY_tfs = {
   "KEY_NOTIFY is SET",
   "KEY_NOTIFY is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_CREATE_LINK_tfs = {
   "KEY_CREATE_LINK is SET",
   "KEY_CREATE_LINK is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_WOW64_64KEY_tfs = {
   "KEY_WOW64_64KEY is SET",
   "KEY_WOW64_64KEY is NOT SET",
};
static const true_false_string winreg_AccessMask_KEY_WOW64_32KEY_tfs = {
   "KEY_WOW64_32KEY is SET",
   "KEY_WOW64_32KEY is NOT SET",
};
const value_string winreg_winreg_Type_vals[] = {
	{ REG_NONE, "REG_NONE" },
	{ REG_SZ, "REG_SZ" },
	{ REG_EXPAND_SZ, "REG_EXPAND_SZ" },
	{ REG_BINARY, "REG_BINARY" },
	{ REG_DWORD, "REG_DWORD" },
	{ REG_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN" },
	{ REG_LINK, "REG_LINK" },
	{ REG_MULTI_SZ, "REG_MULTI_SZ" },
	{ REG_RESOURCE_LIST, "REG_RESOURCE_LIST" },
	{ REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR" },
	{ REG_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST" },
	{ REG_QWORD, "REG_QWORD" },
{ 0, NULL }
};
static int winreg_dissect_element_String_name_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_String_name_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_String_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_String_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityData_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityData_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityData_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityData_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityData_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SecBuf_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SecBuf_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SecBuf_inherit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string winreg_winreg_CreateAction_vals[] = {
	{ REG_ACTION_NONE, "REG_ACTION_NONE" },
	{ REG_CREATED_NEW_KEY, "REG_CREATED_NEW_KEY" },
	{ REG_OPENED_EXISTING_KEY, "REG_OPENED_EXISTING_KEY" },
{ 0, NULL }
};
static int winreg_dissect_element_StringBuf_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_StringBuf_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_StringBuf_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_StringBuf_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_StringBuf_name__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityAttribute_data_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityAttribute_sec_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_KeySecurityAttribute_inherit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValue_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValue_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCR_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCR_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCR_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCR_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCR_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCU_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCU_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCU_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCU_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCU_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKLM_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKLM_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKLM_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKLM_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKLM_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPD_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPD_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPD_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPD_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPD_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKU_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKU_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKU_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKU_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKU_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CloseKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CloseKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_keyclass(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_options(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_secdesc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_secdesc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_new_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_new_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_action_taken(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_CreateKey_action_taken_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteKey_key(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_DeleteValue_value(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_enum_index(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_keyclass(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_keyclass_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_last_changed_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumKey_last_changed_time_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_enum_index(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_value(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_value_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_value__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_EnumValue_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_FlushKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_FlushKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetKeySecurity_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetKeySecurity_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetKeySecurity_sec_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetKeySecurity_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetKeySecurity_sd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_keyname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_keyname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_LoadKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_watch_subtree(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_notify_filter(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_string1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_string2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_NotifyChangeKeyValue_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_parent_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_parent_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_keyname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_classname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_classname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_num_subkeys(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_num_subkeys_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_subkeylen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_subkeylen_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_subkeysize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_subkeysize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_num_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_num_values_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_valnamelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_valnamelen_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_valbufsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_max_valbufsize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_secdescsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_secdescsize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_last_changed_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryInfoKey_last_changed_time_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_value_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryValue_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_RestoreKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_RestoreKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_RestoreKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_RestoreKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_RestoreKey_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_sec_attrib(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SaveKey_sec_attrib_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetKeySecurity_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetKeySecurity_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetKeySecurity_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetKeySecurity_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetKeySecurity_sd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_SetValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdown_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_AbortSystemShutdown_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_AbortSystemShutdown_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetVersion_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetVersion_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetVersion_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_GetVersion_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCC_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCC_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCC_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCC_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKCC_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKDD_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKDD_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKDD_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKDD_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKDD_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_key_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_key_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_values_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_values__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_num_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_buffer_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_QueryMultipleValues_buffer_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_InitiateSystemShutdownEx_reason(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPT_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPT_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPT_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPT_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPT_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPN_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPN_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPN_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPN_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int winreg_dissect_element_OpenHKPN_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static void
winreg_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree, guint32 access)
{
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_WOW64_32KEY, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_WOW64_64KEY, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_CREATE_LINK, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_NOTIFY, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_ENUMERATE_SUB_KEYS, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_CREATE_SUB_KEY, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_SET_VALUE, tvb, offset, 4, access);
	proto_tree_add_boolean(tree, hf_winreg_winreg_AccessMask_KEY_QUERY_VALUE, tvb, offset, 4, access);
}
struct access_mask_info winreg_access_mask_info = {
	"WINREG",		/* Name of specific rights */
	winreg_specific_rights,	/* Dissection function */
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};
static int
winreg_dissect_element_KeySecurityData_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 len;
	dcerpc_info *di;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	/* this is a varying and conformant array */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_winreg_sd_max_size, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_winreg_sd_offset, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_winreg_sd_actual_size, &len);
	dissect_nt_sec_desc(tvb, offset, pinfo, tree, drep, TRUE, len,
		&winreg_access_mask_info);
	offset += len;
	return offset;
}
int
winreg_dissect_bitmap_AccessMask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index _U_, guint32 param _U_)
{
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_winreg_access_mask,
		&winreg_access_mask_info, NULL);
	return offset;
}
/* FIXME: pidl generates the wrong name for external symbols */
static int
winreg_dissect_struct_initshutdown_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param)
{
        #include "packet-dcerpc-initshutdown.h"
	return initshutdown_dissect_struct_String(tvb, offset, pinfo, parent_tree, drep, hf_index, param);
}
/* winreg_String :
 *	typedef [public,noejs] struct {
 *		[value(strlen_m_term(name)*2)] uint16 name_len;
 *		[value(strlen_m_term(name)*2)] uint16 name_size;
 *		[string,charset(UTF16)] uint16 *name;
 *	} winreg_String;
 */
static int
cnf_dissect_winreg_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, guint32 param, int hfindex)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	header_field_info *hf_info;
	ALIGN_TO_4_BYTES;
	old_offset = offset;
	hf_info=proto_registrar_get_nth(hfindex);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 0, "%s: ", hf_info->name);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_String);
	}
	
	offset = winreg_dissect_element_String_name_len(tvb, offset, pinfo, tree, drep);
	offset = winreg_dissect_element_String_name_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		hf_info->name, hfindex, cb_wstr_postprocess,
		GINT_TO_POINTER(param));
	proto_item_set_len(item, offset-old_offset);
	return offset;
}


/* IDL: bitmap { */
/* IDL: 	KEY_QUERY_VALUE =  0x00001 , */
/* IDL: 	KEY_SET_VALUE =  0x00002 , */
/* IDL: 	KEY_CREATE_SUB_KEY =  0x00004 , */
/* IDL: 	KEY_ENUMERATE_SUB_KEYS =  0x00008 , */
/* IDL: 	KEY_NOTIFY =  0x00010 , */
/* IDL: 	KEY_CREATE_LINK =  0x00020 , */
/* IDL: 	KEY_WOW64_64KEY =  0x00100 , */
/* IDL: 	KEY_WOW64_32KEY =  0x00200 , */
/* IDL: } */


/* IDL: enum { */
/* IDL: 	REG_NONE=0, */
/* IDL: 	REG_SZ=1, */
/* IDL: 	REG_EXPAND_SZ=2, */
/* IDL: 	REG_BINARY=3, */
/* IDL: 	REG_DWORD=4, */
/* IDL: 	REG_DWORD_BIG_ENDIAN=5, */
/* IDL: 	REG_LINK=6, */
/* IDL: 	REG_MULTI_SZ=7, */
/* IDL: 	REG_RESOURCE_LIST=8, */
/* IDL: 	REG_FULL_RESOURCE_DESCRIPTOR=9, */
/* IDL: 	REG_RESOURCE_REQUIREMENTS_LIST=10, */
/* IDL: 	REG_QWORD=11, */
/* IDL: } */

int
winreg_dissect_enum_Type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_len; */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_size; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: } */

static int
winreg_dissect_element_String_name_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_String_name_len, 0);

	return offset;
}

static int
winreg_dissect_element_String_name_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_String_name_size, 0);

	return offset;
}

static int
winreg_dissect_element_String_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_String_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_winreg_winreg_String_name);

	return offset;
}

static int
winreg_dissect_element_String_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_winreg_winreg_String_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
winreg_dissect_struct_String(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_String);
	}
	
	offset = winreg_dissect_element_String_name_len(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_String_name_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_String_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [length_is(len)] [size_is(size)] uint8 *data; */
/* IDL: 	uint32 size; */
/* IDL: 	uint32 len; */
/* IDL: } */

static int
winreg_dissect_element_KeySecurityData_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_KeySecurityData_data_, NDR_POINTER_UNIQUE, "Pointer to Data (uint8)",hf_winreg_KeySecurityData_data);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_data, 0);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_size, 0);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_len, 0);

	return offset;
}

int
winreg_dissect_struct_KeySecurityData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_KeySecurityData);
	}
	
	offset = winreg_dissect_element_KeySecurityData_data(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityData_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityData_len(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 length; */
/* IDL: 	KeySecurityData sd; */
/* IDL: 	uint8 inherit; */
/* IDL: } */

static int
winreg_dissect_element_SecBuf_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SecBuf_length, 0);

	return offset;
}

static int
winreg_dissect_element_SecBuf_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_SecBuf_sd,0);

	return offset;
}

static int
winreg_dissect_element_SecBuf_inherit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SecBuf_inherit, 0);

	return offset;
}

int
winreg_dissect_struct_SecBuf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_SecBuf);
	}
	
	offset = winreg_dissect_element_SecBuf_length(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_SecBuf_sd(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_SecBuf_inherit(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	REG_ACTION_NONE=0, */
/* IDL: 	REG_CREATED_NEW_KEY=1, */
/* IDL: 	REG_OPENED_EXISTING_KEY=2, */
/* IDL: } */

int
winreg_dissect_enum_CreateAction(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 length; */
/* IDL: 	uint16 size; */
/* IDL: 	[unique(1)] [length_is(length/2)] [charset(UTF16)] [size_is(size/2)] uint16 *name; */
/* IDL: } */

static int
winreg_dissect_element_StringBuf_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_length, 0);

	return offset;
}

static int
winreg_dissect_element_StringBuf_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_size, 0);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_StringBuf_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_winreg_winreg_StringBuf_name);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_StringBuf_name__);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_name, 0);

	return offset;
}

int
winreg_dissect_struct_StringBuf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_StringBuf);
	}
	
	offset = winreg_dissect_element_StringBuf_length(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_StringBuf_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_StringBuf_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 data_size; */
/* IDL: 	KeySecurityData sec_data; */
/* IDL: 	uint8 inherit; */
/* IDL: } */

static int
winreg_dissect_element_KeySecurityAttribute_data_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityAttribute_data_size, 0);

	return offset;
}

static int
winreg_dissect_element_KeySecurityAttribute_sec_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_KeySecurityAttribute_sec_data,0);

	return offset;
}

static int
winreg_dissect_element_KeySecurityAttribute_inherit(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityAttribute_inherit, 0);

	return offset;
}

int
winreg_dissect_struct_KeySecurityAttribute(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_KeySecurityAttribute);
	}
	
	offset = winreg_dissect_element_KeySecurityAttribute_data_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityAttribute_sec_data(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityAttribute_inherit(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] winreg_String *name; */
/* IDL: 	winreg_Type type; */
/* IDL: 	uint32 offset; */
/* IDL: 	uint32 length; */
/* IDL: } */

static int
winreg_dissect_element_QueryMultipleValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValue_name_, NDR_POINTER_UNIQUE, "Pointer to Name (winreg_String)",hf_winreg_QueryMultipleValue_name);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_QueryMultipleValue_name);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_offset(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_offset, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_length, 0);

	return offset;
}

int
winreg_dissect_struct_QueryMultipleValue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_QueryMultipleValue);
	}
	
	offset = winreg_dissect_element_QueryMultipleValue_name(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_QueryMultipleValue_type(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_QueryMultipleValue_offset(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_QueryMultipleValue_length(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCR_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCR_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCR( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCR_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKCR";
	offset = winreg_dissect_element_OpenHKCR_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCR_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKCR";
	offset = winreg_dissect_element_OpenHKCR_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCR_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKCU_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCU_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKCU_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCU_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCU( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCU_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKCU";
	offset = winreg_dissect_element_OpenHKCU_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCU_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKCU";
	offset = winreg_dissect_element_OpenHKCU_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCU_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKLM_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKLM_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKLM_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKLM( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKLM_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKLM";
	offset = winreg_dissect_element_OpenHKLM_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKLM_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKLM";
	offset = winreg_dissect_element_OpenHKLM_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKLM_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKPD_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPD_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKPD_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPD_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPD( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKPD";
	offset = winreg_dissect_element_OpenHKPD_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKPD";
	offset = winreg_dissect_element_OpenHKPD_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKPD_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKU_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKU_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKU_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKU( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKU_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKU";
	offset = winreg_dissect_element_OpenHKU_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKU_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKU";
	offset = winreg_dissect_element_OpenHKU_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKU_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_CloseKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CloseKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_CloseKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_CLOSE);

	return offset;
}

/* IDL: WERROR winreg_CloseKey( */
/* IDL: [out] [in] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_CloseKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="CloseKey";
	offset = winreg_dissect_element_CloseKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_CloseKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="CloseKey";
	offset = winreg_dissect_element_CloseKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_CreateKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_CreateKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 2|PIDL_SET_COL_INFO, hf_winreg_winreg_CreateKey_name);

	return offset;
}

static int
winreg_dissect_element_CreateKey_keyclass(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_CreateKey_keyclass);

	return offset;
}

static int
winreg_dissect_element_CreateKey_options(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_options, 0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_secdesc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_secdesc_, NDR_POINTER_UNIQUE, "Pointer to Secdesc (winreg_SecBuf)",hf_winreg_winreg_CreateKey_secdesc);

	return offset;
}

static int
winreg_dissect_element_CreateKey_secdesc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_SecBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_CreateKey_secdesc,0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_new_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_new_handle_, NDR_POINTER_REF, "Pointer to New Handle (policy_handle)",hf_winreg_winreg_CreateKey_new_handle);

	return offset;
}

static int
winreg_dissect_element_CreateKey_new_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_new_handle, PIDL_POLHND_OPEN);

	return offset;
}

static int
winreg_dissect_element_CreateKey_action_taken(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_action_taken_, NDR_POINTER_UNIQUE, "Pointer to Action Taken (winreg_CreateAction)",hf_winreg_winreg_CreateKey_action_taken);

	return offset;
}

static int
winreg_dissect_element_CreateKey_action_taken_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_enum_CreateAction(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_action_taken, 0);

	return offset;
}

/* IDL: WERROR winreg_CreateKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String name, */
/* IDL: [in] winreg_String keyclass, */
/* IDL: [in] uint32 options, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [unique(1)] [in] winreg_SecBuf *secdesc, */
/* IDL: [out] [ref] policy_handle *new_handle, */
/* IDL: [out] [unique(1)] [in] winreg_CreateAction *action_taken */
/* IDL: ); */

static int
winreg_dissect_CreateKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="CreateKey";
	offset = winreg_dissect_element_CreateKey_new_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_CreateKey_action_taken(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_CreateKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="CreateKey";
	offset = winreg_dissect_element_CreateKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_keyclass(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_options(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_secdesc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_action_taken(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_DeleteKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_DeleteKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_DeleteKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_DeleteKey_key(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 2|PIDL_SET_COL_INFO, hf_winreg_winreg_DeleteKey_key);

	return offset;
}

/* IDL: WERROR winreg_DeleteKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String key */
/* IDL: ); */

static int
winreg_dissect_DeleteKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DeleteKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_DeleteKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DeleteKey";
	offset = winreg_dissect_element_DeleteKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_DeleteKey_key(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_DeleteValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_DeleteValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_DeleteValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_DeleteValue_value(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_DeleteValue_value);

	return offset;
}

/* IDL: WERROR winreg_DeleteValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String value */
/* IDL: ); */

static int
winreg_dissect_DeleteValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="DeleteValue";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_DeleteValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="DeleteValue";
	offset = winreg_dissect_element_DeleteValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_DeleteValue_value(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_EnumKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_EnumKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_enum_index(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumKey_enum_index, 0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_name_, NDR_POINTER_REF, "Pointer to Name (winreg_StringBuf)",hf_winreg_winreg_EnumKey_name);

	return offset;
}

static int
winreg_dissect_element_EnumKey_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumKey_name,0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_keyclass(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_keyclass_, NDR_POINTER_UNIQUE, "Pointer to Keyclass (winreg_StringBuf)",hf_winreg_winreg_EnumKey_keyclass);

	return offset;
}

static int
winreg_dissect_element_EnumKey_keyclass_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumKey_keyclass,0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_last_changed_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_last_changed_time_, NDR_POINTER_UNIQUE, "Pointer to Last Changed Time (NTTIME)",hf_winreg_winreg_EnumKey_last_changed_time);

	return offset;
}

static int
winreg_dissect_element_EnumKey_last_changed_time_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumKey_last_changed_time);

	return offset;
}

/* IDL: WERROR winreg_EnumKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint32 enum_index, */
/* IDL: [out] [in] [ref] winreg_StringBuf *name, */
/* IDL: [out] [unique(1)] [in] winreg_StringBuf *keyclass, */
/* IDL: [out] [unique(1)] [in] NTTIME *last_changed_time */
/* IDL: ); */

static int
winreg_dissect_EnumKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EnumKey";
	offset = winreg_dissect_element_EnumKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumKey_keyclass(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumKey_last_changed_time(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_EnumKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EnumKey";
	offset = winreg_dissect_element_EnumKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_enum_index(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_keyclass(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_last_changed_time(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_EnumValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_EnumValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_enum_index(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_enum_index, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_name_, NDR_POINTER_REF, "Pointer to Name (winreg_StringBuf)",hf_winreg_winreg_EnumValue_name);

	return offset;
}

static int
winreg_dissect_element_EnumValue_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumValue_name,0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_type_, NDR_POINTER_UNIQUE, "Pointer to Type (winreg_Type)",hf_winreg_winreg_EnumValue_type);

	return offset;
}

static int
winreg_dissect_element_EnumValue_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_value_, NDR_POINTER_UNIQUE, "Pointer to Value (uint8)",hf_winreg_winreg_EnumValue_value);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_value__);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_value, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_size_, NDR_POINTER_UNIQUE, "Pointer to Size (uint32)",hf_winreg_winreg_EnumValue_size);

	return offset;
}

static int
winreg_dissect_element_EnumValue_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_size, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_length_, NDR_POINTER_UNIQUE, "Pointer to Length (uint32)",hf_winreg_winreg_EnumValue_length);

	return offset;
}

static int
winreg_dissect_element_EnumValue_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_length, 0);

	return offset;
}

/* IDL: WERROR winreg_EnumValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint32 enum_index, */
/* IDL: [out] [in] [ref] winreg_StringBuf *name, */
/* IDL: [out] [unique(1)] [in] winreg_Type *type, */
/* IDL: [out] [unique(1)] [in] [length_is(*length)] [size_is(*size)] uint8 *value, */
/* IDL: [out] [unique(1)] [in] uint32 *size, */
/* IDL: [out] [unique(1)] [in] uint32 *length */
/* IDL: ); */

static int
winreg_dissect_EnumValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EnumValue";
	offset = winreg_dissect_element_EnumValue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumValue_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumValue_value(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumValue_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumValue_length(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_EnumValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EnumValue";
	offset = winreg_dissect_element_EnumValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_enum_index(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_value(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumValue_length(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_FlushKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_FlushKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_FlushKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

/* IDL: WERROR winreg_FlushKey( */
/* IDL: [in] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_FlushKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="FlushKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_FlushKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="FlushKey";
	offset = winreg_dissect_element_FlushKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetKeySecurity_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sec_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_GetKeySecurity_sec_info, NULL);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetKeySecurity_sd_, NDR_POINTER_REF, "Pointer to Sd (KeySecurityData)",hf_winreg_sd);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_sd,0);

	return offset;
}

/* IDL: WERROR winreg_GetKeySecurity( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] security_secinfo sec_info, */
/* IDL: [out] [in] [ref] KeySecurityData *sd */
/* IDL: ); */

static int
winreg_dissect_GetKeySecurity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="GetKeySecurity";
	offset = winreg_dissect_element_GetKeySecurity_sd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_GetKeySecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="GetKeySecurity";
	offset = winreg_dissect_element_GetKeySecurity_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_GetKeySecurity_sec_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_GetKeySecurity_sd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_LoadKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_LoadKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_LoadKey_keyname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_keyname_, NDR_POINTER_UNIQUE, "Pointer to Keyname (winreg_String)",hf_winreg_winreg_LoadKey_keyname);

	return offset;
}

static int
winreg_dissect_element_LoadKey_keyname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_LoadKey_keyname);

	return offset;
}

static int
winreg_dissect_element_LoadKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_filename_, NDR_POINTER_UNIQUE, "Pointer to Filename (winreg_String)",hf_winreg_winreg_LoadKey_filename);

	return offset;
}

static int
winreg_dissect_element_LoadKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_LoadKey_filename);

	return offset;
}

/* IDL: WERROR winreg_LoadKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [unique(1)] [in] winreg_String *keyname, */
/* IDL: [unique(1)] [in] winreg_String *filename */
/* IDL: ); */

static int
winreg_dissect_LoadKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="LoadKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_LoadKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="LoadKey";
	offset = winreg_dissect_element_LoadKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_LoadKey_keyname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_LoadKey_filename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_NotifyChangeKeyValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_watch_subtree(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree, 0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_notify_filter(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_notify_filter, 0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_unknown, 0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_string1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_NotifyChangeKeyValue_string1);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_string2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_NotifyChangeKeyValue_string2);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_unknown2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_unknown2, 0);

	return offset;
}

/* IDL: WERROR winreg_NotifyChangeKeyValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint8 watch_subtree, */
/* IDL: [in] uint32 notify_filter, */
/* IDL: [in] uint32 unknown, */
/* IDL: [in] winreg_String string1, */
/* IDL: [in] winreg_String string2, */
/* IDL: [in] uint32 unknown2 */
/* IDL: ); */

static int
winreg_dissect_NotifyChangeKeyValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NotifyChangeKeyValue";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_NotifyChangeKeyValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NotifyChangeKeyValue";
	offset = winreg_dissect_element_NotifyChangeKeyValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_watch_subtree(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_notify_filter(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_unknown(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_string1(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_string2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_NotifyChangeKeyValue_unknown2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenKey_parent_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenKey_parent_handle_, NDR_POINTER_REF, "Pointer to Parent Handle (policy_handle)",hf_winreg_winreg_OpenKey_parent_handle);

	return offset;
}

static int
winreg_dissect_element_OpenKey_parent_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenKey_parent_handle, 0);

	return offset;
}

static int
winreg_dissect_element_OpenKey_keyname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 2|PIDL_SET_COL_INFO|PIDL_STR_SAVE, hf_winreg_winreg_OpenKey_keyname);

	return offset;
}

static int
winreg_dissect_element_OpenKey_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenKey_unknown, 0);

	return offset;
}

static int
winreg_dissect_element_OpenKey_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenKey_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenKey( */
/* IDL: [in] [ref] policy_handle *parent_handle, */
/* IDL: [in] winreg_String keyname, */
/* IDL: [in] uint32 unknown, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenKey";
	offset = winreg_dissect_element_OpenKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenKey";
	offset = winreg_dissect_element_OpenKey_parent_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenKey_keyname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenKey_unknown(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenKey_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_classname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_classname_, NDR_POINTER_REF, "Pointer to Classname (winreg_String)",hf_winreg_winreg_QueryInfoKey_classname);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_classname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_QueryInfoKey_classname);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_subkeys(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_num_subkeys_, NDR_POINTER_REF, "Pointer to Num Subkeys (uint32)",hf_winreg_winreg_QueryInfoKey_num_subkeys);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_subkeys_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_num_subkeys, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeylen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_max_subkeylen_, NDR_POINTER_REF, "Pointer to Max Subkeylen (uint32)",hf_winreg_winreg_QueryInfoKey_max_subkeylen);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeylen_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_subkeylen, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeysize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_max_subkeysize_, NDR_POINTER_REF, "Pointer to Max Subkeysize (uint32)",hf_winreg_winreg_QueryInfoKey_max_subkeysize);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeysize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_subkeysize, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_num_values_, NDR_POINTER_REF, "Pointer to Num Values (uint32)",hf_winreg_winreg_QueryInfoKey_num_values);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_values_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_num_values, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valnamelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_max_valnamelen_, NDR_POINTER_REF, "Pointer to Max Valnamelen (uint32)",hf_winreg_winreg_QueryInfoKey_max_valnamelen);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valnamelen_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_valnamelen, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valbufsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_max_valbufsize_, NDR_POINTER_REF, "Pointer to Max Valbufsize (uint32)",hf_winreg_winreg_QueryInfoKey_max_valbufsize);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valbufsize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_valbufsize, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_secdescsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_secdescsize_, NDR_POINTER_REF, "Pointer to Secdescsize (uint32)",hf_winreg_winreg_QueryInfoKey_secdescsize);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_secdescsize_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_secdescsize, 0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_last_changed_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_last_changed_time_, NDR_POINTER_REF, "Pointer to Last Changed Time (NTTIME)",hf_winreg_winreg_QueryInfoKey_last_changed_time);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_last_changed_time_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_last_changed_time);

	return offset;
}

/* IDL: WERROR winreg_QueryInfoKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [out] [in] [ref] winreg_String *classname, */
/* IDL: [out] [ref] uint32 *num_subkeys, */
/* IDL: [out] [ref] uint32 *max_subkeylen, */
/* IDL: [out] [ref] uint32 *max_subkeysize, */
/* IDL: [out] [ref] uint32 *num_values, */
/* IDL: [out] [ref] uint32 *max_valnamelen, */
/* IDL: [out] [ref] uint32 *max_valbufsize, */
/* IDL: [out] [ref] uint32 *secdescsize, */
/* IDL: [out] [ref] NTTIME *last_changed_time */
/* IDL: ); */

static int
winreg_dissect_QueryInfoKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="QueryInfoKey";
	offset = winreg_dissect_element_QueryInfoKey_classname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_num_subkeys(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_max_subkeylen(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_max_subkeysize(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_num_values(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_max_valnamelen(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_max_valbufsize(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_secdescsize(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryInfoKey_last_changed_time(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryInfoKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="QueryInfoKey";
	offset = winreg_dissect_element_QueryInfoKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryInfoKey_classname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_QueryValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_QueryValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_value_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 2|PIDL_SET_COL_INFO, hf_winreg_winreg_QueryValue_value_name);

	return offset;
}

static int
winreg_dissect_element_QueryValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_type_, NDR_POINTER_UNIQUE, "Pointer to Type (winreg_Type)",hf_winreg_winreg_QueryValue_type);

	return offset;
}

static int
winreg_dissect_element_QueryValue_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_data_, NDR_POINTER_UNIQUE, "Pointer to Data (uint8)",hf_winreg_winreg_QueryValue_data);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_data__);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_data, 0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_size_, NDR_POINTER_UNIQUE, "Pointer to Size (uint32)",hf_winreg_winreg_QueryValue_size);

	return offset;
}

static int
winreg_dissect_element_QueryValue_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_size, 0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_length_, NDR_POINTER_UNIQUE, "Pointer to Length (uint32)",hf_winreg_winreg_QueryValue_length);

	return offset;
}

static int
winreg_dissect_element_QueryValue_length_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_length, 0);

	return offset;
}

/* IDL: WERROR winreg_QueryValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String value_name, */
/* IDL: [unique(1)] [out] [in] winreg_Type *type, */
/* IDL: [unique(1)] [out] [in] [length_is(*length)] [size_is(*size)] uint8 *data, */
/* IDL: [unique(1)] [out] [in] uint32 *size, */
/* IDL: [unique(1)] [out] [in] uint32 *length */
/* IDL: ); */

static int
winreg_dissect_QueryValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="QueryValue";
	offset = winreg_dissect_element_QueryValue_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryValue_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryValue_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryValue_length(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="QueryValue";
	offset = winreg_dissect_element_QueryValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryValue_value_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryValue_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryValue_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryValue_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryValue_length(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR winreg_ReplaceKey( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_ReplaceKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="ReplaceKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_ReplaceKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="ReplaceKey";
	return offset;
}

static int
winreg_dissect_element_RestoreKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_RestoreKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_winreg_RestoreKey_handle);

	return offset;
}

static int
winreg_dissect_element_RestoreKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_RestoreKey_handle, 0);

	return offset;
}

static int
winreg_dissect_element_RestoreKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_RestoreKey_filename_, NDR_POINTER_REF, "Pointer to Filename (winreg_String)",hf_winreg_winreg_RestoreKey_filename);

	return offset;
}

static int
winreg_dissect_element_RestoreKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_RestoreKey_filename);

	return offset;
}

static int
winreg_dissect_element_RestoreKey_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_RestoreKey_flags, 0);

	return offset;
}

/* IDL: WERROR winreg_RestoreKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] [ref] winreg_String *filename, */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
winreg_dissect_RestoreKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="RestoreKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_RestoreKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="RestoreKey";
	offset = winreg_dissect_element_RestoreKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_RestoreKey_filename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_RestoreKey_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_SaveKey_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SaveKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_winreg_SaveKey_handle);

	return offset;
}

static int
winreg_dissect_element_SaveKey_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SaveKey_handle, 0);

	return offset;
}

static int
winreg_dissect_element_SaveKey_filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SaveKey_filename_, NDR_POINTER_REF, "Pointer to Filename (winreg_String)",hf_winreg_winreg_SaveKey_filename);

	return offset;
}

static int
winreg_dissect_element_SaveKey_filename_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 0, hf_winreg_winreg_SaveKey_filename);

	return offset;
}

static int
winreg_dissect_element_SaveKey_sec_attrib(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SaveKey_sec_attrib_, NDR_POINTER_UNIQUE, "Pointer to Sec Attrib (KeySecurityAttribute)",hf_winreg_winreg_SaveKey_sec_attrib);

	return offset;
}

static int
winreg_dissect_element_SaveKey_sec_attrib_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_KeySecurityAttribute(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_SaveKey_sec_attrib,0);

	return offset;
}

/* IDL: WERROR winreg_SaveKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] [ref] winreg_String *filename, */
/* IDL: [unique(1)] [in] KeySecurityAttribute *sec_attrib */
/* IDL: ); */

static int
winreg_dissect_SaveKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="SaveKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SaveKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="SaveKey";
	offset = winreg_dissect_element_SaveKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SaveKey_filename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SaveKey_sec_attrib(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetKeySecurity_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetKeySecurity_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetKeySecurity_sd_, NDR_POINTER_REF, "Pointer to Sd (KeySecurityData)",hf_winreg_sd);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_sd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_sd,0);

	return offset;
}

/* IDL: WERROR winreg_SetKeySecurity( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [in] [ref] KeySecurityData *sd */
/* IDL: ); */

static int
winreg_dissect_SetKeySecurity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="SetKeySecurity";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SetKeySecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="SetKeySecurity";
	offset = winreg_dissect_element_SetKeySecurity_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetKeySecurity_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetKeySecurity_sd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_SetValue_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_SetValue_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_SetValue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_winreg_String(tvb, offset, pinfo, tree, drep, 2|PIDL_SET_COL_INFO, hf_winreg_winreg_SetValue_name);

	return offset;
}

static int
winreg_dissect_element_SetValue_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_SetValue_data(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_data_, NDR_POINTER_REF, "Pointer to Data (uint8)",hf_winreg_winreg_SetValue_data);

	return offset;
}

static int
winreg_dissect_element_SetValue_data_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_data__);

	return offset;
}

static int
winreg_dissect_element_SetValue_data__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_data, 0);

	return offset;
}

static int
winreg_dissect_element_SetValue_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_size, 0);

	return offset;
}

/* IDL: WERROR winreg_SetValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String name, */
/* IDL: [in] winreg_Type type, */
/* IDL: [in] [ref] [size_is(size)] uint8 *data, */
/* IDL: [in] uint32 size */
/* IDL: ); */

static int
winreg_dissect_SetValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="SetValue";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SetValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="SetValue";
	offset = winreg_dissect_element_SetValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetValue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetValue_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetValue_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetValue_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR winreg_UnLoadKey( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_UnLoadKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="UnLoadKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_UnLoadKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="UnLoadKey";
	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdown_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_winreg_winreg_InitiateSystemShutdown_hostname);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_hostname, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdown_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_winreg_winreg_InitiateSystemShutdown_message);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_initshutdown_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_InitiateSystemShutdown_message,0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_timeout, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_force_apps, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_reboot, 0);

	return offset;
}

/* IDL: WERROR winreg_InitiateSystemShutdown( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] initshutdown_String *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 reboot */
/* IDL: ); */

static int
winreg_dissect_InitiateSystemShutdown_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="InitiateSystemShutdown";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_InitiateSystemShutdown_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="InitiateSystemShutdown";
	offset = winreg_dissect_element_InitiateSystemShutdown_hostname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdown_message(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdown_timeout(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdown_force_apps(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdown_reboot(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_AbortSystemShutdown_server(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_AbortSystemShutdown_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_winreg_winreg_AbortSystemShutdown_server);

	return offset;
}

static int
winreg_dissect_element_AbortSystemShutdown_server_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_AbortSystemShutdown_server, 0);

	return offset;
}

/* IDL: WERROR winreg_AbortSystemShutdown( */
/* IDL: [unique(1)] [in] uint16 *server */
/* IDL: ); */

static int
winreg_dissect_AbortSystemShutdown_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="AbortSystemShutdown";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_AbortSystemShutdown_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="AbortSystemShutdown";
	offset = winreg_dissect_element_AbortSystemShutdown_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_GetVersion_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetVersion_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_GetVersion_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, 0);

	return offset;
}

static int
winreg_dissect_element_GetVersion_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetVersion_version_, NDR_POINTER_REF, "Pointer to Version (uint32)",hf_winreg_winreg_GetVersion_version);

	return offset;
}

static int
winreg_dissect_element_GetVersion_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_GetVersion_version, 0);

	return offset;
}

/* IDL: WERROR winreg_GetVersion( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [out] [ref] uint32 *version */
/* IDL: ); */

static int
winreg_dissect_GetVersion_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="GetVersion";
	offset = winreg_dissect_element_GetVersion_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_GetVersion_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="GetVersion";
	offset = winreg_dissect_element_GetVersion_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKCC_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCC_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCC_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCC( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCC_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKCC";
	offset = winreg_dissect_element_OpenHKCC_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCC_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKCC";
	offset = winreg_dissect_element_OpenHKCC_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCC_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKDD_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKDD_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKDD_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKDD( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKDD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKDD";
	offset = winreg_dissect_element_OpenHKDD_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKDD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKDD";
	offset = winreg_dissect_element_OpenHKDD_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKDD_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_key_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_key_handle_, NDR_POINTER_REF, "Pointer to Key Handle (policy_handle)",hf_winreg_winreg_QueryMultipleValues_key_handle);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_key_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_key_handle, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_values_, NDR_POINTER_REF, "Pointer to Values (QueryMultipleValue)",hf_winreg_winreg_QueryMultipleValues_values);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_values__);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_QueryMultipleValue(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_QueryMultipleValues_values,0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_num_values(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_num_values, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer_, NDR_POINTER_UNIQUE, "Pointer to Buffer (uint8)",hf_winreg_winreg_QueryMultipleValues_buffer);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer__);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_buffer, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer_size_, NDR_POINTER_REF, "Pointer to Buffer Size (uint32)",hf_winreg_winreg_QueryMultipleValues_buffer_size);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_size_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_buffer_size, 0);

	return offset;
}

/* IDL: WERROR winreg_QueryMultipleValues( */
/* IDL: [in] [ref] policy_handle *key_handle, */
/* IDL: [out] [in] [ref] [length_is(num_values)] [size_is(num_values)] QueryMultipleValue *values, */
/* IDL: [in] uint32 num_values, */
/* IDL: [unique(1)] [out] [in] [length_is(*buffer_size)] [size_is(*buffer_size)] uint8 *buffer, */
/* IDL: [out] [in] [ref] uint32 *buffer_size */
/* IDL: ); */

static int
winreg_dissect_QueryMultipleValues_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="QueryMultipleValues";
	offset = winreg_dissect_element_QueryMultipleValues_values(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryMultipleValues_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryMultipleValues_buffer_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryMultipleValues_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="QueryMultipleValues";
	offset = winreg_dissect_element_QueryMultipleValues_key_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryMultipleValues_values(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryMultipleValues_num_values(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryMultipleValues_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryMultipleValues_buffer_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_hostname(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdownEx_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_winreg_winreg_InitiateSystemShutdownEx_hostname);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_hostname_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_hostname, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_message(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdownEx_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_winreg_winreg_InitiateSystemShutdownEx_message);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_message_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_struct_initshutdown_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_InitiateSystemShutdownEx_message,0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_timeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_timeout, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_force_apps(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_force_apps, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_reboot(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_reboot, 0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_reason(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_reason, 0);

	return offset;
}

/* IDL: WERROR winreg_InitiateSystemShutdownEx( */
/* IDL: [unique(1)] [in] uint16 *hostname, */
/* IDL: [unique(1)] [in] initshutdown_String *message, */
/* IDL: [in] uint32 timeout, */
/* IDL: [in] uint8 force_apps, */
/* IDL: [in] uint8 reboot, */
/* IDL: [in] uint32 reason */
/* IDL: ); */

static int
winreg_dissect_InitiateSystemShutdownEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="InitiateSystemShutdownEx";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_InitiateSystemShutdownEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="InitiateSystemShutdownEx";
	offset = winreg_dissect_element_InitiateSystemShutdownEx_hostname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdownEx_message(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdownEx_timeout(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdownEx_force_apps(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdownEx_reboot(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_InitiateSystemShutdownEx_reason(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR winreg_SaveKeyEx( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_SaveKeyEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="SaveKeyEx";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SaveKeyEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="SaveKeyEx";
	return offset;
}

static int
winreg_dissect_element_OpenHKPT_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPT_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPT_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPT( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPT_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKPT";
	offset = winreg_dissect_element_OpenHKPT_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPT_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKPT";
	offset = winreg_dissect_element_OpenHKPT_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKPT_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKPN_system_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPN_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_system_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_access_mask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_bitmap_AccessMask(tvb, offset, pinfo, tree, drep, hf_winreg_access_mask, 0);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPN_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, PIDL_POLHND_OPEN);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPN( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] winreg_AccessMask access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPN_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="OpenHKPN";
	offset = winreg_dissect_element_OpenHKPN_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPN_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="OpenHKPN";
	offset = winreg_dissect_element_OpenHKPN_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKPN_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR winreg_QueryMultipleValues2( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_QueryMultipleValues2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="QueryMultipleValues2";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryMultipleValues2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="QueryMultipleValues2";
	return offset;
}


static dcerpc_sub_dissector winreg_dissectors[] = {
	{ 0, "OpenHKCR",
	   winreg_dissect_OpenHKCR_request, winreg_dissect_OpenHKCR_response},
	{ 1, "OpenHKCU",
	   winreg_dissect_OpenHKCU_request, winreg_dissect_OpenHKCU_response},
	{ 2, "OpenHKLM",
	   winreg_dissect_OpenHKLM_request, winreg_dissect_OpenHKLM_response},
	{ 3, "OpenHKPD",
	   winreg_dissect_OpenHKPD_request, winreg_dissect_OpenHKPD_response},
	{ 4, "OpenHKU",
	   winreg_dissect_OpenHKU_request, winreg_dissect_OpenHKU_response},
	{ 5, "CloseKey",
	   winreg_dissect_CloseKey_request, winreg_dissect_CloseKey_response},
	{ 6, "CreateKey",
	   winreg_dissect_CreateKey_request, winreg_dissect_CreateKey_response},
	{ 7, "DeleteKey",
	   winreg_dissect_DeleteKey_request, winreg_dissect_DeleteKey_response},
	{ 8, "DeleteValue",
	   winreg_dissect_DeleteValue_request, winreg_dissect_DeleteValue_response},
	{ 9, "EnumKey",
	   winreg_dissect_EnumKey_request, winreg_dissect_EnumKey_response},
	{ 10, "EnumValue",
	   winreg_dissect_EnumValue_request, winreg_dissect_EnumValue_response},
	{ 11, "FlushKey",
	   winreg_dissect_FlushKey_request, winreg_dissect_FlushKey_response},
	{ 12, "GetKeySecurity",
	   winreg_dissect_GetKeySecurity_request, winreg_dissect_GetKeySecurity_response},
	{ 13, "LoadKey",
	   winreg_dissect_LoadKey_request, winreg_dissect_LoadKey_response},
	{ 14, "NotifyChangeKeyValue",
	   winreg_dissect_NotifyChangeKeyValue_request, winreg_dissect_NotifyChangeKeyValue_response},
	{ 15, "OpenKey",
	   winreg_dissect_OpenKey_request, winreg_dissect_OpenKey_response},
	{ 16, "QueryInfoKey",
	   winreg_dissect_QueryInfoKey_request, winreg_dissect_QueryInfoKey_response},
	{ 17, "QueryValue",
	   winreg_dissect_QueryValue_request, winreg_dissect_QueryValue_response},
	{ 18, "ReplaceKey",
	   winreg_dissect_ReplaceKey_request, winreg_dissect_ReplaceKey_response},
	{ 19, "RestoreKey",
	   winreg_dissect_RestoreKey_request, winreg_dissect_RestoreKey_response},
	{ 20, "SaveKey",
	   winreg_dissect_SaveKey_request, winreg_dissect_SaveKey_response},
	{ 21, "SetKeySecurity",
	   winreg_dissect_SetKeySecurity_request, winreg_dissect_SetKeySecurity_response},
	{ 22, "SetValue",
	   winreg_dissect_SetValue_request, winreg_dissect_SetValue_response},
	{ 23, "UnLoadKey",
	   winreg_dissect_UnLoadKey_request, winreg_dissect_UnLoadKey_response},
	{ 24, "InitiateSystemShutdown",
	   winreg_dissect_InitiateSystemShutdown_request, winreg_dissect_InitiateSystemShutdown_response},
	{ 25, "AbortSystemShutdown",
	   winreg_dissect_AbortSystemShutdown_request, winreg_dissect_AbortSystemShutdown_response},
	{ 26, "GetVersion",
	   winreg_dissect_GetVersion_request, winreg_dissect_GetVersion_response},
	{ 27, "OpenHKCC",
	   winreg_dissect_OpenHKCC_request, winreg_dissect_OpenHKCC_response},
	{ 28, "OpenHKDD",
	   winreg_dissect_OpenHKDD_request, winreg_dissect_OpenHKDD_response},
	{ 29, "QueryMultipleValues",
	   winreg_dissect_QueryMultipleValues_request, winreg_dissect_QueryMultipleValues_response},
	{ 30, "InitiateSystemShutdownEx",
	   winreg_dissect_InitiateSystemShutdownEx_request, winreg_dissect_InitiateSystemShutdownEx_response},
	{ 31, "SaveKeyEx",
	   winreg_dissect_SaveKeyEx_request, winreg_dissect_SaveKeyEx_response},
	{ 32, "OpenHKPT",
	   winreg_dissect_OpenHKPT_request, winreg_dissect_OpenHKPT_response},
	{ 33, "OpenHKPN",
	   winreg_dissect_OpenHKPN_request, winreg_dissect_OpenHKPN_response},
	{ 34, "QueryMultipleValues2",
	   winreg_dissect_QueryMultipleValues2_request, winreg_dissect_QueryMultipleValues2_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_winreg(void)
{
	static hf_register_info hf[] = {
	{ &hf_winreg_winreg_AccessMask_KEY_ENUMERATE_SUB_KEYS, 
	  { "Key Enumerate Sub Keys", "winreg.winreg_AccessMask.KEY_ENUMERATE_SUB_KEYS", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_ENUMERATE_SUB_KEYS_tfs), ( 0x00008 ), NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_string2, 
	  { "String2", "winreg.winreg_NotifyChangeKeyValue.string2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_message, 
	  { "Message", "winreg.winreg_InitiateSystemShutdown.message", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_KeySecurityData_size, 
	  { "Size", "winreg.KeySecurityData.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_String_name, 
	  { "Name", "winreg.winreg_String.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_message, 
	  { "Message", "winreg.winreg_InitiateSystemShutdownEx.message", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_reboot, 
	  { "Reboot", "winreg.winreg_InitiateSystemShutdown.reboot", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_enum_index, 
	  { "Enum Index", "winreg.winreg_EnumValue.enum_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_access_mask, 
	  { "Access Mask", "winreg.access_mask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_key_handle, 
	  { "Key Handle", "winreg.winreg_QueryMultipleValues.key_handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_LoadKey_keyname, 
	  { "Keyname", "winreg.winreg_LoadKey.keyname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumKey_name, 
	  { "Name", "winreg.winreg_EnumKey.name", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_options, 
	  { "Options", "winreg.winreg_CreateKey.options", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_type, 
	  { "Type", "winreg.winreg_EnumValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_timeout, 
	  { "Timeout", "winreg.winreg_InitiateSystemShutdownEx.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumKey_last_changed_time, 
	  { "Last Changed Time", "winreg.winreg_EnumKey.last_changed_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryValue_size, 
	  { "Size", "winreg.winreg_QueryValue.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_size, 
	  { "Size", "winreg.winreg_EnumValue.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_handle, 
	  { "Handle", "winreg.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SaveKey_sec_attrib, 
	  { "Sec Attrib", "winreg.winreg_SaveKey.sec_attrib", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_valnamelen, 
	  { "Max Valnamelen", "winreg.winreg_QueryInfoKey.max_valnamelen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SecBuf_length, 
	  { "Length", "winreg.winreg_SecBuf.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_reboot, 
	  { "Reboot", "winreg.winreg_InitiateSystemShutdownEx.reboot", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_sd, 
	  { "KeySecurityData", "winreg.sd", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SaveKey_filename, 
	  { "Filename", "winreg.winreg_SaveKey.filename", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_buffer_size, 
	  { "Buffer Size", "winreg.winreg_QueryMultipleValues.buffer_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryValue_data, 
	  { "Data", "winreg.winreg_QueryValue.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_new_handle, 
	  { "New Handle", "winreg.winreg_CreateKey.new_handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_subkeysize, 
	  { "Max Subkeysize", "winreg.winreg_QueryInfoKey.max_subkeysize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_hostname, 
	  { "Hostname", "winreg.winreg_InitiateSystemShutdown.hostname", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_KeySecurityData_data, 
	  { "Data", "winreg.KeySecurityData.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_KeySecurityAttribute_sec_data, 
	  { "Sec Data", "winreg.KeySecurityAttribute.sec_data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_OpenKey_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenKey.access_mask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_QueryMultipleValue_name, 
	  { "Name", "winreg.QueryMultipleValue.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_GetKeySecurity_sec_info, 
	  { "Sec Info", "winreg.winreg_GetKeySecurity.sec_info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_StringBuf_size, 
	  { "Size", "winreg.winreg_StringBuf.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SecBuf_sd, 
	  { "Sd", "winreg.winreg_SecBuf.sd", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_secdescsize, 
	  { "Secdescsize", "winreg.winreg_QueryInfoKey.secdescsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_OpenKey_keyname, 
	  { "Keyname", "winreg.winreg_OpenKey.keyname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_QueryMultipleValue_type, 
	  { "Type", "winreg.QueryMultipleValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SetValue_name, 
	  { "Name", "winreg.winreg_SetValue.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_RestoreKey_flags, 
	  { "Flags", "winreg.winreg_RestoreKey.flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree, 
	  { "Watch Subtree", "winreg.winreg_NotifyChangeKeyValue.watch_subtree", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_secdesc, 
	  { "Secdesc", "winreg.winreg_CreateKey.secdesc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_force_apps, 
	  { "Force Apps", "winreg.winreg_InitiateSystemShutdownEx.force_apps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SetValue_type, 
	  { "Type", "winreg.winreg_SetValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_name, 
	  { "Name", "winreg.winreg_CreateKey.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_KeySecurityData_len, 
	  { "Len", "winreg.KeySecurityData.len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_String_name_len, 
	  { "Name Len", "winreg.winreg_String.name_len", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_opnum, 
	  { "Operation", "winreg.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_DeleteKey_key, 
	  { "Key", "winreg.winreg_DeleteKey.key", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_name, 
	  { "Name", "winreg.winreg_EnumValue.name", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_LoadKey_filename, 
	  { "Filename", "winreg.winreg_LoadKey.filename", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_CREATE_LINK, 
	  { "Key Create Link", "winreg.winreg_AccessMask.KEY_CREATE_LINK", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_CREATE_LINK_tfs), ( 0x00020 ), NULL, HFILL }},
	{ &hf_winreg_winreg_DeleteValue_value, 
	  { "Value", "winreg.winreg_DeleteValue.value", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_system_name, 
	  { "System Name", "winreg.system_name", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_QueryMultipleValue_length, 
	  { "Length", "winreg.QueryMultipleValue.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_num_values, 
	  { "Num Values", "winreg.winreg_QueryMultipleValues.num_values", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_NOTIFY, 
	  { "Key Notify", "winreg.winreg_AccessMask.KEY_NOTIFY", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_NOTIFY_tfs), ( 0x00010 ), NULL, HFILL }},
	{ &hf_winreg_KeySecurityAttribute_data_size, 
	  { "Data Size", "winreg.KeySecurityAttribute.data_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_OpenKey_parent_handle, 
	  { "Parent Handle", "winreg.winreg_OpenKey.parent_handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_StringBuf_name, 
	  { "Name", "winreg.winreg_StringBuf.name", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_unknown2, 
	  { "Unknown2", "winreg.winreg_NotifyChangeKeyValue.unknown2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_num_subkeys, 
	  { "Num Subkeys", "winreg.winreg_QueryInfoKey.num_subkeys", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_sd_offset, 
	  { "Offset", "winreg.sd.offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_WOW64_32KEY, 
	  { "Key Wow64 32key", "winreg.winreg_AccessMask.KEY_WOW64_32KEY", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_WOW64_32KEY_tfs), ( 0x00200 ), NULL, HFILL }},
	{ &hf_winreg_winreg_StringBuf_length, 
	  { "Length", "winreg.winreg_StringBuf.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_last_changed_time, 
	  { "Last Changed Time", "winreg.winreg_QueryInfoKey.last_changed_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_OpenHKPD_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKPD.access_mask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AbortSystemShutdown_server, 
	  { "Server", "winreg.winreg_AbortSystemShutdown.server", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryValue_type, 
	  { "Type", "winreg.winreg_QueryValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, NULL, HFILL }},
	{ &hf_winreg_sd_actual_size, 
	  { "Actual Size", "winreg.sd.actual_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_String_name_size, 
	  { "Name Size", "winreg.winreg_String.name_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_unknown, 
	  { "Unknown", "winreg.winreg_NotifyChangeKeyValue.unknown", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryValue_length, 
	  { "Length", "winreg.winreg_QueryValue.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_CREATE_SUB_KEY, 
	  { "Key Create Sub Key", "winreg.winreg_AccessMask.KEY_CREATE_SUB_KEY", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_CREATE_SUB_KEY_tfs), ( 0x00004 ), NULL, HFILL }},
	{ &hf_winreg_winreg_OpenKey_unknown, 
	  { "Unknown", "winreg.winreg_OpenKey.unknown", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_RestoreKey_filename, 
	  { "Filename", "winreg.winreg_RestoreKey.filename", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_valbufsize, 
	  { "Max Valbufsize", "winreg.winreg_QueryInfoKey.max_valbufsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_reason, 
	  { "Reason", "winreg.winreg_InitiateSystemShutdownEx.reason", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SecBuf_inherit, 
	  { "Inherit", "winreg.winreg_SecBuf.inherit", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SetValue_size, 
	  { "Size", "winreg.winreg_SetValue.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_length, 
	  { "Length", "winreg.winreg_EnumValue.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_values, 
	  { "Values", "winreg.winreg_QueryMultipleValues.values", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_subkeylen, 
	  { "Max Subkeylen", "winreg.winreg_QueryInfoKey.max_subkeylen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_timeout, 
	  { "Timeout", "winreg.winreg_InitiateSystemShutdown.timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_hostname, 
	  { "Hostname", "winreg.winreg_InitiateSystemShutdownEx.hostname", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SaveKey_handle, 
	  { "Handle", "winreg.winreg_SaveKey.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_KeySecurityAttribute_inherit, 
	  { "Inherit", "winreg.KeySecurityAttribute.inherit", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_werror, 
	  { "Windows Error", "winreg.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_winreg_winreg_GetVersion_version, 
	  { "Version", "winreg.winreg_GetVersion.version", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_QUERY_VALUE, 
	  { "Key Query Value", "winreg.winreg_AccessMask.KEY_QUERY_VALUE", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_QUERY_VALUE_tfs), ( 0x00001 ), NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_action_taken, 
	  { "Action Taken", "winreg.winreg_CreateKey.action_taken", FT_UINT32, BASE_DEC, VALS(winreg_winreg_CreateAction_vals), 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_num_values, 
	  { "Num Values", "winreg.winreg_QueryInfoKey.num_values", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumKey_keyclass, 
	  { "Keyclass", "winreg.winreg_EnumKey.keyclass", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_SET_VALUE, 
	  { "Key Set Value", "winreg.winreg_AccessMask.KEY_SET_VALUE", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_SET_VALUE_tfs), ( 0x00002 ), NULL, HFILL }},
	{ &hf_winreg_winreg_EnumKey_enum_index, 
	  { "Enum Index", "winreg.winreg_EnumKey.enum_index", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_RestoreKey_handle, 
	  { "Handle", "winreg.winreg_RestoreKey.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SetValue_data, 
	  { "Data", "winreg.winreg_SetValue.data", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_CreateKey_keyclass, 
	  { "Keyclass", "winreg.winreg_CreateKey.keyclass", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_force_apps, 
	  { "Force Apps", "winreg.winreg_InitiateSystemShutdown.force_apps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_EnumValue_value, 
	  { "Value", "winreg.winreg_EnumValue.value", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_string1, 
	  { "String1", "winreg.winreg_NotifyChangeKeyValue.string1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_buffer, 
	  { "Buffer", "winreg.winreg_QueryMultipleValues.buffer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_SetKeySecurity_access_mask, 
	  { "Access Mask", "winreg.winreg_SetKeySecurity.access_mask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryValue_value_name, 
	  { "Value Name", "winreg.winreg_QueryValue.value_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_classname, 
	  { "Classname", "winreg.winreg_QueryInfoKey.classname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_AccessMask_KEY_WOW64_64KEY, 
	  { "Key Wow64 64key", "winreg.winreg_AccessMask.KEY_WOW64_64KEY", FT_BOOLEAN, 32, TFS(&winreg_AccessMask_KEY_WOW64_64KEY_tfs), ( 0x00100 ), NULL, HFILL }},
	{ &hf_winreg_winreg_OpenHKCU_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKCU.access_mask", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_sd_max_size, 
	  { "Max Size", "winreg.sd.max_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_notify_filter, 
	  { "Notify Filter", "winreg.winreg_NotifyChangeKeyValue.notify_filter", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_winreg_QueryMultipleValue_offset, 
	  { "Offset", "winreg.QueryMultipleValue.offset", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_winreg,
		&ett_winreg_winreg_AccessMask,
		&ett_winreg_winreg_String,
		&ett_winreg_KeySecurityData,
		&ett_winreg_winreg_SecBuf,
		&ett_winreg_winreg_StringBuf,
		&ett_winreg_KeySecurityAttribute,
		&ett_winreg_QueryMultipleValue,
	};

	proto_dcerpc_winreg = proto_register_protocol("Remote Registry Service", "WINREG", "winreg");
	proto_register_field_array(proto_dcerpc_winreg, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_winreg(void)
{
	dcerpc_init_uuid(proto_dcerpc_winreg, ett_dcerpc_winreg,
		&uuid_dcerpc_winreg, ver_dcerpc_winreg,
		winreg_dissectors, hf_winreg_opnum);
}
