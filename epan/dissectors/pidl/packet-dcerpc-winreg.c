/* DO NOT EDIT
	This filter was automatically generated
	from winreg.idl and winreg.cnf.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Ethereal team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.ethereal.com/Pidl
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
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
static gint ett_winreg_winreg_String = -1;
static gint ett_winreg_KeySecurityData = -1;
static gint ett_winreg_winreg_SecBuf = -1;
static gint ett_winreg_winreg_StringBuf = -1;
static gint ett_winreg_QueryMultipleValue = -1;


/* Header field declarations */
static gint hf_winreg_winreg_QueryInfoKey_max_valbufsize = -1;
static gint hf_winreg_winreg_SecBuf_inherit = -1;
static gint hf_winreg_winreg_QueryMultipleValues_key_handle = -1;
static gint hf_winreg_winreg_CreateKey_options = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_reboot = -1;
static gint hf_winreg_winreg_String_name = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_notify_filter = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_subkeysize = -1;
static gint hf_winreg_winreg_OpenKey_unknown = -1;
static gint hf_winreg_winreg_OpenHKCC_access_mask = -1;
static gint hf_winreg_winreg_SetValue_data = -1;
static gint hf_winreg_winreg_QueryMultipleValues_values = -1;
static gint hf_winreg_winreg_QueryInfoKey_last_changed_time = -1;
static gint hf_winreg_QueryMultipleValue_name = -1;
static gint hf_winreg_winreg_EnumValue_type = -1;
static gint hf_winreg_winreg_CreateKey_class = -1;
static gint hf_winreg_winreg_OpenHKCR_access_mask = -1;
static gint hf_winreg_winreg_SetValue_type = -1;
static gint hf_winreg_winreg_EnumKey_class = -1;
static gint hf_winreg_winreg_CreateKey_secdesc = -1;
static gint hf_winreg_winreg_QueryMultipleValues_buffer = -1;
static gint hf_winreg_winreg_GetVersion_version = -1;
static gint hf_winreg_winreg_SetKeySecurity_access_mask = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_unknown = -1;
static gint hf_winreg_winreg_LoadKey_filename = -1;
static gint hf_winreg_winreg_EnumValue_enum_index = -1;
static gint hf_winreg_winreg_CreateKey_action_taken = -1;
static gint hf_winreg_winreg_QueryValue_size = -1;
static gint hf_winreg_winreg_QueryMultipleValues_buffer_size = -1;
static gint hf_winreg_access_required = -1;
static gint hf_winreg_winreg_CreateKey_access_mask = -1;
static gint hf_winreg_system_name = -1;
static gint hf_winreg_KeySecurityData_size = -1;
static gint hf_winreg_winreg_EnumValue_value = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_message = -1;
static gint hf_winreg_winreg_QueryInfoKey_secdescsize = -1;
static gint hf_winreg_winreg_QueryValue_data = -1;
static gint hf_winreg_winreg_EnumValue_length = -1;
static gint hf_winreg_winreg_SecBuf_length = -1;
static gint hf_winreg_winreg_QueryValue_value_name = -1;
static gint hf_winreg_winreg_QueryInfoKey_num_values = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_reboot = -1;
static gint hf_winreg_winreg_CreateKey_new_handle = -1;
static gint hf_winreg_winreg_OpenHKPT_access_mask = -1;
static gint hf_winreg_winreg_QueryValue_type = -1;
static gint hf_winreg_KeySecurityData_data = -1;
static gint hf_winreg_QueryMultipleValue_length = -1;
static gint hf_winreg_winreg_LoadKey_keyname = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_hostname = -1;
static gint hf_winreg_winreg_StringBuf_name = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_unknown2 = -1;
static gint hf_winreg_winreg_OpenHKDD_access_mask = -1;
static gint hf_winreg_winreg_EnumValue_name = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_reason = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_message = -1;
static gint hf_winreg_winreg_DeleteValue_value = -1;
static gint hf_winreg_winreg_SetValue_name = -1;
static gint hf_winreg_winreg_GetKeySecurity_sd = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree = -1;
static gint hf_winreg_winreg_EnumKey_name = -1;
static gint hf_winreg_winreg_QueryValue_length = -1;
static gint hf_winreg_QueryMultipleValue_offset = -1;
static gint hf_winreg_winreg_SetKeySecurity_data = -1;
static gint hf_winreg_winreg_SecBuf_sd = -1;
static gint hf_winreg_werror = -1;
static gint hf_winreg_QueryMultipleValue_type = -1;
static gint hf_winreg_winreg_String_name_len = -1;
static gint hf_winreg_opnum = -1;
static gint hf_winreg_winreg_QueryInfoKey_num_subkeys = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_timeout = -1;
static gint hf_winreg_handle = -1;
static gint hf_winreg_winreg_GetKeySecurity_sec_info = -1;
static gint hf_winreg_winreg_DeleteKey_key = -1;
static gint hf_winreg_winreg_EnumKey_last_changed_time = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_subkeylen = -1;
static gint hf_winreg_winreg_AbortSystemShutdown_server = -1;
static gint hf_winreg_winreg_OpenHKU_access_mask = -1;
static gint hf_winreg_winreg_EnumKey_enum_index = -1;
static gint hf_winreg_winreg_QueryInfoKey_class = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_hostname = -1;
static gint hf_winreg_winreg_InitiateSystemShutdownEx_force_apps = -1;
static gint hf_winreg_winreg_CreateKey_name = -1;
static gint hf_winreg_winreg_OpenHKLM_access_mask = -1;
static gint hf_winreg_winreg_StringBuf_size = -1;
static gint hf_winreg_winreg_OpenKey_keyname = -1;
static gint hf_winreg_KeySecurityData_len = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_force_apps = -1;
static gint hf_winreg_winreg_OpenHKPD_access_mask = -1;
static gint hf_winreg_winreg_EnumValue_size = -1;
static gint hf_winreg_winreg_SetValue_size = -1;
static gint hf_winreg_winreg_OpenKey_access_mask = -1;
static gint hf_winreg_winreg_OpenHKPN_access_mask = -1;
static gint hf_winreg_winreg_InitiateSystemShutdown_timeout = -1;
static gint hf_winreg_winreg_QueryInfoKey_max_valnamelen = -1;
static gint hf_winreg_winreg_QueryMultipleValues_num_values = -1;
static gint hf_winreg_winreg_OpenHKCU_access_mask = -1;
static gint hf_winreg_winreg_String_name_size = -1;
static gint hf_winreg_winreg_StringBuf_length = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_string1 = -1;
static gint hf_winreg_winreg_NotifyChangeKeyValue_string2 = -1;

static gint proto_dcerpc_winreg = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_winreg = {
	0x338cd001, 0x2244, 0x31f1,
	{ 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 }
};
static guint16 ver_dcerpc_winreg = 1;

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
static int winreg_dissect_element_String_name_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_String_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_String_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_String_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_KeySecurityData_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_KeySecurityData_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_KeySecurityData_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_KeySecurityData_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_KeySecurityData_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SecBuf_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SecBuf_sd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SecBuf_inherit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
const value_string winreg_winreg_CreateAction_vals[] = {
	{ REG_ACTION_NONE, "REG_ACTION_NONE" },
	{ REG_CREATED_NEW_KEY, "REG_CREATED_NEW_KEY" },
	{ REG_OPENED_EXISTING_KEY, "REG_OPENED_EXISTING_KEY" },
{ 0, NULL }
};
static int winreg_dissect_element_StringBuf_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_StringBuf_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_StringBuf_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_StringBuf_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_StringBuf_name__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValue_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValue_offset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCR_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCR_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCR_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCR_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCR_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCU_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCU_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCU_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCU_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCU_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKLM_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKLM_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKLM_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKLM_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKLM_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPD_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPD_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPD_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPD_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPD_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKU_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKU_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKU_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKU_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKU_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CloseKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CloseKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_secdesc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_secdesc_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_new_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_new_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_action_taken(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_CreateKey_action_taken_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteKey_key(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_DeleteValue_value(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_enum_index(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_class_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_last_changed_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumKey_last_changed_time_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_enum_index(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_type_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_value(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_value_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_value__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_EnumValue_length_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_FlushKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_FlushKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetKeySecurity_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetKeySecurity_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetKeySecurity_sec_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetKeySecurity_sd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetKeySecurity_sd_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_keyname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_keyname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_filename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_LoadKey_filename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_watch_subtree(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_notify_filter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_string1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_string2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_NotifyChangeKeyValue_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenKey_keyname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenKey_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenKey_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_num_subkeys(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_max_subkeylen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_max_subkeysize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_num_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_max_valnamelen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_max_valbufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_secdescsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryInfoKey_last_changed_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_value_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_type_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryValue_length_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetKeySecurity_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetKeySecurity_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetKeySecurity_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetKeySecurity_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetKeySecurity_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_SetValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdown_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_AbortSystemShutdown_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_AbortSystemShutdown_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetVersion_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetVersion_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_GetVersion_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCC_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCC_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCC_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCC_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKCC_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKDD_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKDD_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKDD_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKDD_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKDD_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_key_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_key_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_values_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_values__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_num_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_buffer_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_buffer__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_buffer_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_QueryMultipleValues_buffer_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_InitiateSystemShutdownEx_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPT_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPT_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPT_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPT_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPT_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPN_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPN_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPN_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPN_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int winreg_dissect_element_OpenHKPN_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

/* IDL: typedef enum { */
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
/* IDL: } winreg_Type; */

int
winreg_dissect_enum_Type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_len; */
/* IDL: 	[value(strlen_m_term(name)*2)] uint16 name_size; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *name; */
/* IDL: } winreg_String; */

static int
winreg_dissect_element_String_name_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_String_name_len,NULL);

	return offset;
}

static int
winreg_dissect_element_String_name_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_String_name_size,NULL);

	return offset;
}

static int
winreg_dissect_element_String_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_String_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_winreg_winreg_String_name);

	return offset;
}

static int
winreg_dissect_element_String_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_winreg_winreg_String_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
winreg_dissect_struct_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_String);
	}
	
	offset = winreg_dissect_element_String_name_len(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_String_name_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_String_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[size_is(size)] [length_is(len)] [unique(1)] uint8 *data; */
/* IDL: 	uint32 size; */
/* IDL: 	uint32 len; */
/* IDL: } KeySecurityData; */

static int
winreg_dissect_element_KeySecurityData_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_KeySecurityData_data_, NDR_POINTER_UNIQUE, "Pointer to Data (uint8)",hf_winreg_KeySecurityData_data);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_KeySecurityData_data__);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_data,NULL);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_size,NULL);

	return offset;
}

static int
winreg_dissect_element_KeySecurityData_len(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_KeySecurityData_len,NULL);

	return offset;
}

int
winreg_dissect_struct_KeySecurityData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_KeySecurityData);
	}
	
	offset = winreg_dissect_element_KeySecurityData_data(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityData_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_KeySecurityData_len(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 length; */
/* IDL: 	KeySecurityData sd; */
/* IDL: 	uint8 inherit; */
/* IDL: } winreg_SecBuf; */

static int
winreg_dissect_element_SecBuf_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SecBuf_length,NULL);

	return offset;
}

static int
winreg_dissect_element_SecBuf_sd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_SecBuf_sd,0);

	return offset;
}

static int
winreg_dissect_element_SecBuf_inherit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SecBuf_inherit,NULL);

	return offset;
}

int
winreg_dissect_struct_SecBuf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_SecBuf);
	}
	
	offset = winreg_dissect_element_SecBuf_length(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_SecBuf_sd(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_SecBuf_inherit(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef enum { */
/* IDL: 	REG_ACTION_NONE=0, */
/* IDL: 	REG_CREATED_NEW_KEY=1, */
/* IDL: 	REG_OPENED_EXISTING_KEY=2, */
/* IDL: } winreg_CreateAction; */

int
winreg_dissect_enum_CreateAction(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, NULL);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[value(strlen_m(name)*2)] uint16 length; */
/* IDL: 	uint16 size; */
/* IDL: 	[charset(UTF16)] [size_is(size/2)] [length_is(length/2)] [unique(1)] uint16 *name; */
/* IDL: } winreg_StringBuf; */

static int
winreg_dissect_element_StringBuf_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_length,NULL);

	return offset;
}

static int
winreg_dissect_element_StringBuf_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_size,NULL);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_StringBuf_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_winreg_winreg_StringBuf_name);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_StringBuf_name__);

	return offset;
}

static int
winreg_dissect_element_StringBuf_name__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_StringBuf_name,NULL);

	return offset;
}

int
winreg_dissect_struct_StringBuf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_winreg_winreg_StringBuf);
	}
	
	offset = winreg_dissect_element_StringBuf_length(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_StringBuf_size(tvb, offset, pinfo, tree, drep);

	offset = winreg_dissect_element_StringBuf_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[unique(1)] winreg_String *name; */
/* IDL: 	winreg_Type type; */
/* IDL: 	uint32 offset; */
/* IDL: 	uint32 length; */
/* IDL: } QueryMultipleValue; */

static int
winreg_dissect_element_QueryMultipleValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValue_name_, NDR_POINTER_UNIQUE, "Pointer to Name (winreg_String)",hf_winreg_QueryMultipleValue_name);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_QueryMultipleValue_name,0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_offset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_offset,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_QueryMultipleValue_length,NULL);

	return offset;
}

int
winreg_dissect_struct_QueryMultipleValue(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if(parent_tree){
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
winreg_dissect_element_OpenHKCR_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCR_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKCR_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCR_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCR_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCR( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCR_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKCR_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCR_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKCR_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCR_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKCU_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCU_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKCU_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCU_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCU_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCU( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCU_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKCU_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCU_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKCU_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCU_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKLM_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKLM_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKLM_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKLM_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKLM_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKLM( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKLM_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKLM_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKLM_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKLM_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKLM_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKPD_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPD_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKPD_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPD_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPD_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPD( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKPD_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKPD_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKPD_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKU_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKU_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKU_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKU_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKU_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKU( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKU_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKU_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKU_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKU_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKU_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_CloseKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CloseKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_CloseKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_CloseKey( */
/* IDL: [out] [in] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_CloseKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_CloseKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_CloseKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_CloseKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_CreateKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_CreateKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_CreateKey_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_CreateKey_name,0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_CreateKey_class,0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_options,NULL);

	return offset;
}

static int
winreg_dissect_element_CreateKey_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_CreateKey_secdesc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_secdesc_, NDR_POINTER_UNIQUE, "Pointer to Secdesc (winreg_SecBuf)",hf_winreg_winreg_CreateKey_secdesc);

	return offset;
}

static int
winreg_dissect_element_CreateKey_secdesc_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_SecBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_CreateKey_secdesc,0);

	return offset;
}

static int
winreg_dissect_element_CreateKey_new_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_new_handle_, NDR_POINTER_REF, "Pointer to New Handle (policy_handle)",hf_winreg_winreg_CreateKey_new_handle);

	return offset;
}

static int
winreg_dissect_element_CreateKey_new_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_new_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_CreateKey_action_taken(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_CreateKey_action_taken_, NDR_POINTER_UNIQUE, "Pointer to Action Taken (winreg_CreateAction)",hf_winreg_winreg_CreateKey_action_taken);

	return offset;
}

static int
winreg_dissect_element_CreateKey_action_taken_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_enum_CreateAction(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_CreateKey_action_taken, 0);

	return offset;
}

/* IDL: WERROR winreg_CreateKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String name, */
/* IDL: [in] winreg_String class, */
/* IDL: [in] uint32 options, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [in] [unique(1)] winreg_SecBuf *secdesc, */
/* IDL: [out] [ref] policy_handle *new_handle, */
/* IDL: [out] [in] [unique(1)] winreg_CreateAction *action_taken */
/* IDL: ); */

static int
winreg_dissect_CreateKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_CreateKey_new_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_CreateKey_action_taken(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_CreateKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_CreateKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_CreateKey_class(tvb, offset, pinfo, tree, drep);
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
winreg_dissect_element_DeleteKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_DeleteKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_DeleteKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_DeleteKey_key(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_DeleteKey_key,0);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_DeleteKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_DeleteKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_DeleteKey_key(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_DeleteValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_DeleteValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_DeleteValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_DeleteValue_value(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_DeleteValue_value,0);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_DeleteValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_DeleteValue_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_DeleteValue_value(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_EnumKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_EnumKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_EnumKey_enum_index(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumKey_enum_index,NULL);

	return offset;
}

static int
winreg_dissect_element_EnumKey_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_name_, NDR_POINTER_REF, "Pointer to Name (winreg_StringBuf)",hf_winreg_winreg_EnumKey_name);

	return offset;
}

static int
winreg_dissect_element_EnumKey_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumKey_name,0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_class_, NDR_POINTER_UNIQUE, "Pointer to Class (winreg_StringBuf)",hf_winreg_winreg_EnumKey_class);

	return offset;
}

static int
winreg_dissect_element_EnumKey_class_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumKey_class,0);

	return offset;
}

static int
winreg_dissect_element_EnumKey_last_changed_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumKey_last_changed_time_, NDR_POINTER_UNIQUE, "Pointer to Last Changed Time (NTTIME)",hf_winreg_winreg_EnumKey_last_changed_time);

	return offset;
}

static int
winreg_dissect_element_EnumKey_last_changed_time_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumKey_last_changed_time);

	return offset;
}

/* IDL: WERROR winreg_EnumKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint32 enum_index, */
/* IDL: [out] [in] [ref] winreg_StringBuf *name, */
/* IDL: [out] [in] [unique(1)] winreg_StringBuf *class, */
/* IDL: [out] [in] [unique(1)] NTTIME *last_changed_time */
/* IDL: ); */

static int
winreg_dissect_EnumKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_EnumKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumKey_class(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_EnumKey_last_changed_time(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_EnumKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_EnumKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_enum_index(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_class(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_EnumKey_last_changed_time(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_EnumValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_EnumValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_EnumValue_enum_index(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_enum_index,NULL);

	return offset;
}

static int
winreg_dissect_element_EnumValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_name_, NDR_POINTER_REF, "Pointer to Name (winreg_StringBuf)",hf_winreg_winreg_EnumValue_name);

	return offset;
}

static int
winreg_dissect_element_EnumValue_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_StringBuf(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_EnumValue_name,0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_type_, NDR_POINTER_UNIQUE, "Pointer to Type (winreg_Type)",hf_winreg_winreg_EnumValue_type);

	return offset;
}

static int
winreg_dissect_element_EnumValue_type_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_value_, NDR_POINTER_UNIQUE, "Pointer to Value (uint8)",hf_winreg_winreg_EnumValue_value);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_value__);

	return offset;
}

static int
winreg_dissect_element_EnumValue_value__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_value,NULL);

	return offset;
}

static int
winreg_dissect_element_EnumValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_size_, NDR_POINTER_UNIQUE, "Pointer to Size (uint32)",hf_winreg_winreg_EnumValue_size);

	return offset;
}

static int
winreg_dissect_element_EnumValue_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_size,NULL);

	return offset;
}

static int
winreg_dissect_element_EnumValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_EnumValue_length_, NDR_POINTER_UNIQUE, "Pointer to Length (uint32)",hf_winreg_winreg_EnumValue_length);

	return offset;
}

static int
winreg_dissect_element_EnumValue_length_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_EnumValue_length,NULL);

	return offset;
}

/* IDL: WERROR winreg_EnumValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint32 enum_index, */
/* IDL: [out] [in] [ref] winreg_StringBuf *name, */
/* IDL: [out] [in] [unique(1)] winreg_Type *type, */
/* IDL: [size_is(*size)] [length_is(*length)] [out] [in] [unique(1)] uint8 *value, */
/* IDL: [out] [in] [unique(1)] uint32 *size, */
/* IDL: [out] [in] [unique(1)] uint32 *length */
/* IDL: ); */

static int
winreg_dissect_EnumValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_EnumValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
winreg_dissect_element_FlushKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_FlushKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_FlushKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_FlushKey( */
/* IDL: [in] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_FlushKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_FlushKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_FlushKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetKeySecurity_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sec_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_GetKeySecurity_sec_info, NULL);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetKeySecurity_sd_, NDR_POINTER_REF, "Pointer to Sd (KeySecurityData)",hf_winreg_winreg_GetKeySecurity_sd);

	return offset;
}

static int
winreg_dissect_element_GetKeySecurity_sd_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_GetKeySecurity_sd,0);

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

	offset = winreg_dissect_element_GetKeySecurity_sd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_GetKeySecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_GetKeySecurity_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_GetKeySecurity_sec_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_GetKeySecurity_sd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_LoadKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_LoadKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_LoadKey_keyname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_keyname_, NDR_POINTER_UNIQUE, "Pointer to Keyname (winreg_String)",hf_winreg_winreg_LoadKey_keyname);

	return offset;
}

static int
winreg_dissect_element_LoadKey_keyname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_LoadKey_keyname,0);

	return offset;
}

static int
winreg_dissect_element_LoadKey_filename(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_LoadKey_filename_, NDR_POINTER_UNIQUE, "Pointer to Filename (winreg_String)",hf_winreg_winreg_LoadKey_filename);

	return offset;
}

static int
winreg_dissect_element_LoadKey_filename_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_LoadKey_filename,0);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_LoadKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_LoadKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_LoadKey_keyname(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_LoadKey_filename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_NotifyChangeKeyValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_watch_subtree(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree,NULL);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_notify_filter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_notify_filter,NULL);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_unknown,NULL);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_string1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_NotifyChangeKeyValue_string1,0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_string2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_NotifyChangeKeyValue_string2,0);

	return offset;
}

static int
winreg_dissect_element_NotifyChangeKeyValue_unknown2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_NotifyChangeKeyValue_unknown2,NULL);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_NotifyChangeKeyValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
winreg_dissect_element_OpenKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_OpenKey_keyname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_OpenKey_keyname,0);

	return offset;
}

static int
winreg_dissect_element_OpenKey_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenKey_unknown,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenKey_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenKey_access_mask,NULL);

	return offset;
}

/* IDL: WERROR winreg_OpenKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String keyname, */
/* IDL: [in] uint32 unknown, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenKey_handle(tvb, offset, pinfo, tree, drep);
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
winreg_dissect_element_QueryInfoKey_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryInfoKey_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_class(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_QueryInfoKey_class,0);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_subkeys(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_num_subkeys,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeylen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_subkeylen,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_subkeysize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_subkeysize,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_num_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_num_values,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valnamelen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_valnamelen,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_max_valbufsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_max_valbufsize,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_secdescsize(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_secdescsize,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryInfoKey_last_changed_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryInfoKey_last_changed_time);

	return offset;
}

/* IDL: WERROR winreg_QueryInfoKey( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String class, */
/* IDL: [out] winreg_String class, */
/* IDL: [out] uint32 num_subkeys, */
/* IDL: [out] uint32 max_subkeylen, */
/* IDL: [out] uint32 max_subkeysize, */
/* IDL: [out] uint32 num_values, */
/* IDL: [out] uint32 max_valnamelen, */
/* IDL: [out] uint32 max_valbufsize, */
/* IDL: [out] uint32 secdescsize, */
/* IDL: [out] NTTIME last_changed_time */
/* IDL: ); */

static int
winreg_dissect_QueryInfoKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_QueryInfoKey_class(tvb, offset, pinfo, tree, drep);
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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryInfoKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_QueryInfoKey_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_QueryInfoKey_class(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_QueryValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_QueryValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_QueryValue_value_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_QueryValue_value_name,0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_type_, NDR_POINTER_UNIQUE, "Pointer to Type (winreg_Type)",hf_winreg_winreg_QueryValue_type);

	return offset;
}

static int
winreg_dissect_element_QueryValue_type_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_data_, NDR_POINTER_UNIQUE, "Pointer to Data (uint8)",hf_winreg_winreg_QueryValue_data);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_data__);

	return offset;
}

static int
winreg_dissect_element_QueryValue_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_data,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_size_, NDR_POINTER_UNIQUE, "Pointer to Size (uint32)",hf_winreg_winreg_QueryValue_size);

	return offset;
}

static int
winreg_dissect_element_QueryValue_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_size,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryValue_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryValue_length_, NDR_POINTER_UNIQUE, "Pointer to Length (uint32)",hf_winreg_winreg_QueryValue_length);

	return offset;
}

static int
winreg_dissect_element_QueryValue_length_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryValue_length,NULL);

	return offset;
}

/* IDL: WERROR winreg_QueryValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String value_name, */
/* IDL: [out] [unique(1)] [in] winreg_Type *type, */
/* IDL: [size_is(*size)] [length_is(*length)] [out] [unique(1)] [in] uint8 *data, */
/* IDL: [out] [unique(1)] [in] uint32 *size, */
/* IDL: [out] [unique(1)] [in] uint32 *length */
/* IDL: ); */

static int
winreg_dissect_QueryValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

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
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_ReplaceKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR winreg_RestoreKey( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_RestoreKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_RestoreKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR winreg_SaveKey( */
/* IDL:  */
/* IDL: ); */

static int
winreg_dissect_SaveKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SaveKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetKeySecurity_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetKeySecurity_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetKeySecurity_data_, NDR_POINTER_REF, "Pointer to Data (KeySecurityData)",hf_winreg_winreg_SetKeySecurity_data);

	return offset;
}

static int
winreg_dissect_element_SetKeySecurity_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_KeySecurityData(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_SetKeySecurity_data,0);

	return offset;
}

/* IDL: WERROR winreg_SetKeySecurity( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [in] [ref] KeySecurityData *data */
/* IDL: ); */

static int
winreg_dissect_SetKeySecurity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_SetKeySecurity_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SetKeySecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_SetKeySecurity_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetKeySecurity_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_SetKeySecurity_data(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_SetValue_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_SetValue_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_SetValue_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_SetValue_name,0);

	return offset;
}

static int
winreg_dissect_element_SetValue_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_enum_Type(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_type, 0);

	return offset;
}

static int
winreg_dissect_element_SetValue_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_data_, NDR_POINTER_REF, "Pointer to Data (uint8)",hf_winreg_winreg_SetValue_data);

	return offset;
}

static int
winreg_dissect_element_SetValue_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_SetValue_data__);

	return offset;
}

static int
winreg_dissect_element_SetValue_data__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_data,NULL);

	return offset;
}

static int
winreg_dissect_element_SetValue_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_SetValue_size,NULL);

	return offset;
}

/* IDL: WERROR winreg_SetValue( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [in] winreg_String name, */
/* IDL: [in] winreg_Type type, */
/* IDL: [size_is(size)] [in] [ref] uint8 *data, */
/* IDL: [in] uint32 size */
/* IDL: ); */

static int
winreg_dissect_SetValue_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SetValue_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_UnLoadKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdown_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_winreg_winreg_InitiateSystemShutdown_hostname);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_hostname,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdown_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_winreg_winreg_InitiateSystemShutdown_message);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = initshutdown_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_InitiateSystemShutdown_message,0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_timeout,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_force_apps,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdown_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdown_reboot,NULL);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_InitiateSystemShutdown_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
winreg_dissect_element_AbortSystemShutdown_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_AbortSystemShutdown_server_, NDR_POINTER_UNIQUE, "Pointer to Server (uint16)",hf_winreg_winreg_AbortSystemShutdown_server);

	return offset;
}

static int
winreg_dissect_element_AbortSystemShutdown_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_AbortSystemShutdown_server,NULL);

	return offset;
}

/* IDL: WERROR winreg_AbortSystemShutdown( */
/* IDL: [unique(1)] [in] uint16 *server */
/* IDL: ); */

static int
winreg_dissect_AbortSystemShutdown_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_AbortSystemShutdown_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_AbortSystemShutdown_server(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_GetVersion_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_GetVersion_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_GetVersion_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_GetVersion_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_GetVersion_version,NULL);

	return offset;
}

/* IDL: WERROR winreg_GetVersion( */
/* IDL: [in] [ref] policy_handle *handle, */
/* IDL: [out] uint32 version */
/* IDL: ); */

static int
winreg_dissect_GetVersion_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_GetVersion_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_GetVersion_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_GetVersion_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKCC_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCC_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKCC_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKCC_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKCC_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKCC( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKCC_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKCC_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKCC_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKCC_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKCC_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKDD_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKDD_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKDD_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKDD_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKDD_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKDD( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKDD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKDD_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKDD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKDD_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKDD_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_key_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_key_handle_, NDR_POINTER_REF, "Pointer to Key Handle (policy_handle)",hf_winreg_winreg_QueryMultipleValues_key_handle);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_key_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_key_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_values_, NDR_POINTER_REF, "Pointer to Values (QueryMultipleValue)",hf_winreg_winreg_QueryMultipleValues_values);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_values__);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_values__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = winreg_dissect_struct_QueryMultipleValue(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_QueryMultipleValues_values,0);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_num_values(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_num_values,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer_, NDR_POINTER_UNIQUE, "Pointer to Buffer (uint8)",hf_winreg_winreg_QueryMultipleValues_buffer);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer__);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_buffer,NULL);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_size(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_QueryMultipleValues_buffer_size_, NDR_POINTER_REF, "Pointer to Buffer Size (uint32)",hf_winreg_winreg_QueryMultipleValues_buffer_size);

	return offset;
}

static int
winreg_dissect_element_QueryMultipleValues_buffer_size_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_QueryMultipleValues_buffer_size,NULL);

	return offset;
}

/* IDL: WERROR winreg_QueryMultipleValues( */
/* IDL: [in] [ref] policy_handle *key_handle, */
/* IDL: [size_is(num_values)] [length_is(num_values)] [out] [in] [ref] QueryMultipleValue *values, */
/* IDL: [in] uint32 num_values, */
/* IDL: [size_is(*buffer_size)] [length_is(*buffer_size)] [out] [unique(1)] [in] uint8 *buffer, */
/* IDL: [out] [in] [ref] uint32 *buffer_size */
/* IDL: ); */

static int
winreg_dissect_QueryMultipleValues_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_QueryMultipleValues_values(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryMultipleValues_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = winreg_dissect_element_QueryMultipleValues_buffer_size(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryMultipleValues_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
winreg_dissect_element_InitiateSystemShutdownEx_hostname(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdownEx_hostname_, NDR_POINTER_UNIQUE, "Pointer to Hostname (uint16)",hf_winreg_winreg_InitiateSystemShutdownEx_hostname);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_hostname_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_hostname,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_InitiateSystemShutdownEx_message_, NDR_POINTER_UNIQUE, "Pointer to Message (initshutdown_String)",hf_winreg_winreg_InitiateSystemShutdownEx_message);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_message_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = initshutdown_dissect_struct_String(tvb,offset,pinfo,tree,drep,hf_winreg_winreg_InitiateSystemShutdownEx_message,0);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_timeout,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_force_apps(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_force_apps,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_reboot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_reboot,NULL);

	return offset;
}

static int
winreg_dissect_element_InitiateSystemShutdownEx_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_InitiateSystemShutdownEx_reason,NULL);

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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_InitiateSystemShutdownEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_SaveKeyEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
winreg_dissect_element_OpenHKPT_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPT_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKPT_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPT_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPT_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPT( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPT_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKPT_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPT_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = winreg_dissect_element_OpenHKPT_system_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = winreg_dissect_element_OpenHKPT_access_mask(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
winreg_dissect_element_OpenHKPN_system_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPN_system_name_, NDR_POINTER_UNIQUE, "Pointer to System Name (uint16)",hf_winreg_system_name);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_system_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep, hf_winreg_system_name,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_access_mask(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_winreg_OpenHKPN_access_mask,NULL);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, winreg_dissect_element_OpenHKPN_handle_, NDR_POINTER_REF, "Pointer to Handle (policy_handle)",hf_winreg_handle);

	return offset;
}

static int
winreg_dissect_element_OpenHKPN_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_winreg_handle, NULL, NULL, 0&0x01, 0&0x02);

	return offset;
}

/* IDL: WERROR winreg_OpenHKPN( */
/* IDL: [unique(1)] [in] uint16 *system_name, */
/* IDL: [in] uint32 access_mask, */
/* IDL: [out] [ref] policy_handle *handle */
/* IDL: ); */

static int
winreg_dissect_OpenHKPN_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = winreg_dissect_element_OpenHKPN_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_OpenHKPN_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_winreg_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, DOS_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
winreg_dissect_QueryMultipleValues2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
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
	{ &hf_winreg_winreg_QueryInfoKey_max_valbufsize, 
	  { "Max Valbufsize", "winreg.winreg_QueryInfoKey.max_valbufsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SecBuf_inherit, 
	  { "Inherit", "winreg.winreg_SecBuf.inherit", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_key_handle, 
	  { "Key Handle", "winreg.winreg_QueryMultipleValues.key_handle", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_options, 
	  { "Options", "winreg.winreg_CreateKey.options", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_reboot, 
	  { "Reboot", "winreg.winreg_InitiateSystemShutdownEx.reboot", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_String_name, 
	  { "Name", "winreg.winreg_String.name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_notify_filter, 
	  { "Notify Filter", "winreg.winreg_NotifyChangeKeyValue.notify_filter", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_subkeysize, 
	  { "Max Subkeysize", "winreg.winreg_QueryInfoKey.max_subkeysize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenKey_unknown, 
	  { "Unknown", "winreg.winreg_OpenKey.unknown", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKCC_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKCC.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetValue_data, 
	  { "Data", "winreg.winreg_SetValue.data", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_values, 
	  { "Values", "winreg.winreg_QueryMultipleValues.values", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_last_changed_time, 
	  { "Last Changed Time", "winreg.winreg_QueryInfoKey.last_changed_time", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_QueryMultipleValue_name, 
	  { "Name", "winreg.QueryMultipleValue.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_type, 
	  { "Type", "winreg.winreg_EnumValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_class, 
	  { "Class", "winreg.winreg_CreateKey.class", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKCR_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKCR.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetValue_type, 
	  { "Type", "winreg.winreg_SetValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumKey_class, 
	  { "Class", "winreg.winreg_EnumKey.class", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_secdesc, 
	  { "Secdesc", "winreg.winreg_CreateKey.secdesc", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_buffer, 
	  { "Buffer", "winreg.winreg_QueryMultipleValues.buffer", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_GetVersion_version, 
	  { "Version", "winreg.winreg_GetVersion.version", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetKeySecurity_access_mask, 
	  { "Access Mask", "winreg.winreg_SetKeySecurity.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_unknown, 
	  { "Unknown", "winreg.winreg_NotifyChangeKeyValue.unknown", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_LoadKey_filename, 
	  { "Filename", "winreg.winreg_LoadKey.filename", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_enum_index, 
	  { "Enum Index", "winreg.winreg_EnumValue.enum_index", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_action_taken, 
	  { "Action Taken", "winreg.winreg_CreateKey.action_taken", FT_UINT32, BASE_DEC, VALS(winreg_winreg_CreateAction_vals), 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryValue_size, 
	  { "Size", "winreg.winreg_QueryValue.size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_buffer_size, 
	  { "Buffer Size", "winreg.winreg_QueryMultipleValues.buffer_size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_access_required, 
	  { "Access Required", "winreg.access_required", FT_UINT32, BASE_HEX, NULL, 0, " ", HFILL }},
	{ &hf_winreg_winreg_CreateKey_access_mask, 
	  { "Access Mask", "winreg.winreg_CreateKey.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_system_name, 
	  { "System Name", "winreg.system_name", FT_UINT16, BASE_DEC, NULL, 0, " ", HFILL }},
	{ &hf_winreg_KeySecurityData_size, 
	  { "Size", "winreg.KeySecurityData.size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_value, 
	  { "Value", "winreg.winreg_EnumValue.value", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_message, 
	  { "Message", "winreg.winreg_InitiateSystemShutdownEx.message", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_secdescsize, 
	  { "Secdescsize", "winreg.winreg_QueryInfoKey.secdescsize", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryValue_data, 
	  { "Data", "winreg.winreg_QueryValue.data", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_length, 
	  { "Length", "winreg.winreg_EnumValue.length", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SecBuf_length, 
	  { "Length", "winreg.winreg_SecBuf.length", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryValue_value_name, 
	  { "Value Name", "winreg.winreg_QueryValue.value_name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_num_values, 
	  { "Num Values", "winreg.winreg_QueryInfoKey.num_values", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_reboot, 
	  { "Reboot", "winreg.winreg_InitiateSystemShutdown.reboot", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_new_handle, 
	  { "New Handle", "winreg.winreg_CreateKey.new_handle", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKPT_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKPT.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryValue_type, 
	  { "Type", "winreg.winreg_QueryValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, "", HFILL }},
	{ &hf_winreg_KeySecurityData_data, 
	  { "Data", "winreg.KeySecurityData.data", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_QueryMultipleValue_length, 
	  { "Length", "winreg.QueryMultipleValue.length", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_LoadKey_keyname, 
	  { "Keyname", "winreg.winreg_LoadKey.keyname", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_hostname, 
	  { "Hostname", "winreg.winreg_InitiateSystemShutdown.hostname", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_StringBuf_name, 
	  { "Name", "winreg.winreg_StringBuf.name", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_unknown2, 
	  { "Unknown2", "winreg.winreg_NotifyChangeKeyValue.unknown2", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKDD_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKDD.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_name, 
	  { "Name", "winreg.winreg_EnumValue.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_reason, 
	  { "Reason", "winreg.winreg_InitiateSystemShutdownEx.reason", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_message, 
	  { "Message", "winreg.winreg_InitiateSystemShutdown.message", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_DeleteValue_value, 
	  { "Value", "winreg.winreg_DeleteValue.value", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetValue_name, 
	  { "Name", "winreg.winreg_SetValue.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_GetKeySecurity_sd, 
	  { "Sd", "winreg.winreg_GetKeySecurity.sd", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_watch_subtree, 
	  { "Watch Subtree", "winreg.winreg_NotifyChangeKeyValue.watch_subtree", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumKey_name, 
	  { "Name", "winreg.winreg_EnumKey.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryValue_length, 
	  { "Length", "winreg.winreg_QueryValue.length", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_QueryMultipleValue_offset, 
	  { "Offset", "winreg.QueryMultipleValue.offset", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetKeySecurity_data, 
	  { "Data", "winreg.winreg_SetKeySecurity.data", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SecBuf_sd, 
	  { "Sd", "winreg.winreg_SecBuf.sd", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_werror, 
	  { "Windows Error", "winreg.werror", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_winreg_QueryMultipleValue_type, 
	  { "Type", "winreg.QueryMultipleValue.type", FT_UINT32, BASE_DEC, VALS(winreg_winreg_Type_vals), 0, "", HFILL }},
	{ &hf_winreg_winreg_String_name_len, 
	  { "Name Len", "winreg.winreg_String.name_len", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_opnum, 
	  { "Operation", "winreg.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_num_subkeys, 
	  { "Num Subkeys", "winreg.winreg_QueryInfoKey.num_subkeys", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_timeout, 
	  { "Timeout", "winreg.winreg_InitiateSystemShutdownEx.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_handle, 
	  { "Handle", "winreg.handle", FT_BYTES, BASE_NONE, NULL, 0, " ", HFILL }},
	{ &hf_winreg_winreg_GetKeySecurity_sec_info, 
	  { "Sec Info", "winreg.winreg_GetKeySecurity.sec_info", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_DeleteKey_key, 
	  { "Key", "winreg.winreg_DeleteKey.key", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumKey_last_changed_time, 
	  { "Last Changed Time", "winreg.winreg_EnumKey.last_changed_time", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_subkeylen, 
	  { "Max Subkeylen", "winreg.winreg_QueryInfoKey.max_subkeylen", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_AbortSystemShutdown_server, 
	  { "Server", "winreg.winreg_AbortSystemShutdown.server", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKU_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKU.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumKey_enum_index, 
	  { "Enum Index", "winreg.winreg_EnumKey.enum_index", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_class, 
	  { "Class", "winreg.winreg_QueryInfoKey.class", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_hostname, 
	  { "Hostname", "winreg.winreg_InitiateSystemShutdownEx.hostname", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdownEx_force_apps, 
	  { "Force Apps", "winreg.winreg_InitiateSystemShutdownEx.force_apps", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_CreateKey_name, 
	  { "Name", "winreg.winreg_CreateKey.name", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKLM_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKLM.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_StringBuf_size, 
	  { "Size", "winreg.winreg_StringBuf.size", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenKey_keyname, 
	  { "Keyname", "winreg.winreg_OpenKey.keyname", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_KeySecurityData_len, 
	  { "Len", "winreg.KeySecurityData.len", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_force_apps, 
	  { "Force Apps", "winreg.winreg_InitiateSystemShutdown.force_apps", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKPD_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKPD.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_EnumValue_size, 
	  { "Size", "winreg.winreg_EnumValue.size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_SetValue_size, 
	  { "Size", "winreg.winreg_SetValue.size", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenKey_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenKey.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKPN_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKPN.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_InitiateSystemShutdown_timeout, 
	  { "Timeout", "winreg.winreg_InitiateSystemShutdown.timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryInfoKey_max_valnamelen, 
	  { "Max Valnamelen", "winreg.winreg_QueryInfoKey.max_valnamelen", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_QueryMultipleValues_num_values, 
	  { "Num Values", "winreg.winreg_QueryMultipleValues.num_values", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_OpenHKCU_access_mask, 
	  { "Access Mask", "winreg.winreg_OpenHKCU.access_mask", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_String_name_size, 
	  { "Name Size", "winreg.winreg_String.name_size", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_StringBuf_length, 
	  { "Length", "winreg.winreg_StringBuf.length", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_string1, 
	  { "String1", "winreg.winreg_NotifyChangeKeyValue.string1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_winreg_winreg_NotifyChangeKeyValue_string2, 
	  { "String2", "winreg.winreg_NotifyChangeKeyValue.string2", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_winreg,
		&ett_winreg_winreg_String,
		&ett_winreg_KeySecurityData,
		&ett_winreg_winreg_SecBuf,
		&ett_winreg_winreg_StringBuf,
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
