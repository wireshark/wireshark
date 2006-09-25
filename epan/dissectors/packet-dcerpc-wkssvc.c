/* DO NOT EDIT
	This filter was automatically generated
	from wkssvc.idl and wkssvc.cnf.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl
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
#include "packet-dcerpc-wkssvc.h"

/* Ett declarations */
static gint ett_dcerpc_wkssvc = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo100 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo101 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo102 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo502 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1010 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1011 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1012 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1013 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1018 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1023 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1027 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo1033 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaInfo = -1;
static gint ett_wkssvc_USER_INFO_0 = -1;
static gint ett_wkssvc_USER_INFO_0_CONTAINER = -1;
static gint ett_wkssvc_USER_INFO_1 = -1;
static gint ett_wkssvc_USER_INFO_1_CONTAINER = -1;
static gint ett_wkssvc_WKS_USER_ENUM_UNION = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportInfo0 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportCtr0 = -1;
static gint ett_wkssvc_wkssvc_NetWkstaTransportCtr = -1;
static gint ett_wkssvc_wkssvc_PasswordBuffer = -1;
static gint ett_wkssvc_wkssvc_joinflags = -1;
static gint ett_wkssvc_wkssvc_renameflags = -1;


/* Header field declarations */
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_entriesread = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info502 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait = -1;
static gint hf_wkssvc_USER_INFO_0_user = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name = -1;
static gint hf_wkssvc_WKS_USER_ENUM_UNION_user0 = -1;
static gint hf_wkssvc_WKS_USER_ENUM_UNION_user1 = -1;
static gint hf_wkssvc_USER_INFO_1_user_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_level = -1;
static gint hf_wkssvc_USER_INFO_1_other_domains = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_totalentries = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_ctr = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_level = -1;
static gint hf_wkssvc_wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1010 = -1;
static gint hf_wkssvc_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1011 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1012 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1013 = -1;
static gint hf_wkssvc_USER_INFO_0_CONTAINER_user0 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1018 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name = -1;
static gint hf_wkssvc_opnum = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_account = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit = -1;
static gint hf_wkssvc_USER_INFO_1_CONTAINER_user1 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_resumehandle = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_level = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password = -1;
static gint hf_wkssvc_USER_INFO_1_CONTAINER_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1023 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info100 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info101 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info102 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1027 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_version_major = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_users = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching = -1;
static gint hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo_info1033 = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_info = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count = -1;
static gint hf_wkssvc_USER_INFO_1_logon_domain = -1;
static gint hf_wkssvc_werror = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers = -1;
static gint hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo101_version_major = -1;
static gint hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock = -1;
static gint hf_wkssvc_wkssvc_NetWkstaGetInfo_level = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0 = -1;
static gint hf_wkssvc_wkssvc_NetrJoinDomain2_account_name = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle = -1;
static gint hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved = -1;
static gint hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data = -1;
static gint hf_wkssvc_USER_INFO_1_logon_server = -1;
static gint hf_wkssvc_wkssvc_PasswordBuffer_data = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportEnum_totalentries = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking = -1;
static gint hf_wkssvc_USER_INFO_0_CONTAINER_entries_read = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_version_major = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account = -1;
static gint hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address = -1;
static gint hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array = -1;
static gint hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes = -1;
static gint hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time = -1;

static gint proto_dcerpc_wkssvc = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_wkssvc = {
	0x6bffd098, 0xa112, 0x3610,
	{ 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a }
};
static guint16 ver_dcerpc_wkssvc = 1;

static int wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo101_lan_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_lan_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info100_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info101_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info102_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info502(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info502_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1010(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1010_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1011(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1011_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1012(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1012_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1013(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1013_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1018(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1018_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1023(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1023_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1027(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1027_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1033(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaInfo_info1033_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_user(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_user_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_CONTAINER_entries_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_user_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_user_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_logon_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_logon_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_other_domains(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_other_domains_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_logon_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_logon_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_CONTAINER_entries_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_address_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr0_array__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_PasswordBuffer_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_PasswordBuffer_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN_tfs = {
   "Defer setting of servicePrincipalName and dNSHostName attributes on the computer object until a rename operation",
   "Set servicePrincipalName and dNSHostName attributes on the computer object",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED_tfs = {
   "Set the machine password after domain join to passed password",
   "Do not set the machine password after domain join to passed password",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE_tfs = {
   "Performs an unsecured join",
   "Perform a secured join",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED_tfs = {
   "Allow a join to a new domain even if the computer is already joined to a domain",
   "Do not allow join to a new domain if the computer is already joined to a domain",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE_tfs = {
   "The join operation is occuring as part of an upgrade of Windows 9x",
   "The join operation is not part of a Windows 9x upgrade",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE_tfs = {
   "Delete the account when a domain is left",
   "Do not delete the account when a domain is left",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs = {
   "Create the account on the domain",
   "Do not create the account",
};
static const true_false_string wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE_tfs = {
   "Join the computer to a domain",
   "Join the computer to a workgroup",
};
static const true_false_string wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs = {
   "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE is SET",
   "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE is NOT SET",
};
static int wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaGetInfo_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaGetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaGetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaGetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaSetInfo_parm_error_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_users(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_users_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_entriesread(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_entriesread_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_totalentries(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_totalentries_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_ctr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_ctr_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_totalentries(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_account_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_account_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_admin_account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
static int wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);
/* Bug in pidl.  Can not handle these dependencies properly yet */
static int
srvsvc_dissect_struct_PlatformId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	offset = srvsvc_dissect_enum_PlatformId(tvb,offset,pinfo,tree,drep,hf_wkssvc_platform_id,0);
	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *server_name; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: } wkssvc_NetWkstaInfo100; */

static int
wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = srvsvc_dissect_struct_PlatformId(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo100_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo100_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo100_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo100_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo100_version_major,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo100);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo100_platform_id(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_server_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_domain_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_version_major(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo100_version_minor(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *server_name; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *lan_root; */
/* IDL: } wkssvc_NetWkstaInfo101; */

static int
wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = srvsvc_dissect_struct_PlatformId(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo101_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo101_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo101_version_major,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo101_lan_root_, NDR_POINTER_UNIQUE, "Pointer to Lan Root (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo101_lan_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo101);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo101_platform_id(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_server_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_domain_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_version_major(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_version_minor(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo101_lan_root(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *server_name; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *domain_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *lan_root; */
/* IDL: 	uint32 logged_on_users; */
/* IDL: } wkssvc_NetWkstaInfo102; */

static int
wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = srvsvc_dissect_struct_PlatformId(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo102_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo102_domain_name_, NDR_POINTER_UNIQUE, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_version_major(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_version_major,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo102_lan_root_, NDR_POINTER_UNIQUE, "Pointer to Lan Root (uint16)",hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_lan_root_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo102);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo102_platform_id(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_server_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_domain_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_version_major(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_version_minor(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_lan_root(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo102_logged_on_users(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 char_wait; */
/* IDL: 	uint32 collection_time; */
/* IDL: 	uint32 maximum_collection_count; */
/* IDL: 	uint32 keep_connection; */
/* IDL: 	uint32 max_commands; */
/* IDL: 	uint32 session_timeout; */
/* IDL: 	uint32 size_char_buf; */
/* IDL: 	uint32 max_threads; */
/* IDL: 	uint32 lock_quota; */
/* IDL: 	uint32 lock_increment; */
/* IDL: 	uint32 lock_maximum; */
/* IDL: 	uint32 pipe_increment; */
/* IDL: 	uint32 pipe_maximum; */
/* IDL: 	uint32 cache_file_timeout; */
/* IDL: 	uint32 dormant_file_limit; */
/* IDL: 	uint32 read_ahead_throughput; */
/* IDL: 	uint32 num_mailslot_buffers; */
/* IDL: 	uint32 num_srv_announce_buffers; */
/* IDL: 	uint32 max_illegal_dgram_events; */
/* IDL: 	uint32 dgram_event_reset_freq; */
/* IDL: 	uint32 log_election_packets; */
/* IDL: 	uint32 use_opportunistic_locking; */
/* IDL: 	uint32 use_unlock_behind; */
/* IDL: 	uint32 use_close_behind; */
/* IDL: 	uint32 buf_named_pipes; */
/* IDL: 	uint32 use_lock_read_unlock; */
/* IDL: 	uint32 utilize_nt_caching; */
/* IDL: 	uint32 use_raw_read; */
/* IDL: 	uint32 use_raw_write; */
/* IDL: 	uint32 use_write_raw_data; */
/* IDL: 	uint32 use_encryption; */
/* IDL: 	uint32 buf_files_deny_write; */
/* IDL: 	uint32 buf_read_only_files; */
/* IDL: 	uint32 force_core_create_mode; */
/* IDL: 	uint32 use_512_byte_max_transfer; */
/* IDL: } wkssvc_NetWkstaInfo502; */

static int
wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo502(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo502);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo502_char_wait(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_collection_time(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_maximum_collection_count(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_keep_connection(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_commands(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_session_timeout(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_size_char_buf(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_threads(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_quota(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_increment(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_lock_maximum(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_pipe_increment(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_pipe_maximum(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_cache_file_timeout(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_dormant_file_limit(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_read_ahead_throughput(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_num_mailslot_buffers(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_num_srv_announce_buffers(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_max_illegal_dgram_events(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_dgram_event_reset_freq(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_log_election_packets(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_opportunistic_locking(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_unlock_behind(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_close_behind(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_named_pipes(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_lock_read_unlock(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_utilize_nt_caching(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_raw_read(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_raw_write(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_write_raw_data(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_encryption(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_files_deny_write(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_buf_read_only_files(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_force_core_create_mode(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaInfo502_use_512_byte_max_transfer(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 char_wait; */
/* IDL: } wkssvc_NetWkstaInfo1010; */

static int
wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1010(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1010);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1010_char_wait(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 collection_time; */
/* IDL: } wkssvc_NetWkstaInfo1011; */

static int
wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1011(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1011);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1011_collection_time(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 maximum_collection_count; */
/* IDL: } wkssvc_NetWkstaInfo1012; */

static int
wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1012(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1012);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1012_maximum_collection_count(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 keep_connection; */
/* IDL: } wkssvc_NetWkstaInfo1013; */

static int
wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1013(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1013);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1013_keep_connection(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 session_timeout; */
/* IDL: } wkssvc_NetWkstaInfo1018; */

static int
wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1018(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1018);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1018_session_timeout(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 size_char_buf; */
/* IDL: } wkssvc_NetWkstaInfo1023; */

static int
wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1023(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1023);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1023_size_char_buf(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 errorlog_sz; */
/* IDL: } wkssvc_NetWkstaInfo1027; */

static int
wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1027(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1027);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1027_errorlog_sz(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 max_threads; */
/* IDL: } wkssvc_NetWkstaInfo1033; */

static int
wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaInfo1033(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo1033);
	}
	
	offset = wkssvc_dissect_element_NetWkstaInfo1033_max_threads(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef union { */
/* IDL: [case(100)] [unique(1)] [case(100)] wkssvc_NetWkstaInfo100 *info100; */
/* IDL: [case(101)] [unique(1)] [case(101)] wkssvc_NetWkstaInfo101 *info101; */
/* IDL: [case(102)] [unique(1)] [case(102)] wkssvc_NetWkstaInfo102 *info102; */
/* IDL: [case(502)] [unique(1)] [case(502)] wkssvc_NetWkstaInfo502 *info502; */
/* IDL: [case(1010)] [unique(1)] [case(1010)] wkssvc_NetWkstaInfo1010 *info1010; */
/* IDL: [case(1011)] [unique(1)] [case(1011)] wkssvc_NetWkstaInfo1011 *info1011; */
/* IDL: [case(1012)] [unique(1)] [case(1012)] wkssvc_NetWkstaInfo1012 *info1012; */
/* IDL: [case(1013)] [unique(1)] [case(1013)] wkssvc_NetWkstaInfo1013 *info1013; */
/* IDL: [case(1018)] [unique(1)] [case(1018)] wkssvc_NetWkstaInfo1018 *info1018; */
/* IDL: [case(1023)] [unique(1)] [case(1023)] wkssvc_NetWkstaInfo1023 *info1023; */
/* IDL: [case(1027)] [unique(1)] [case(1027)] wkssvc_NetWkstaInfo1027 *info1027; */
/* IDL: [case(1033)] [unique(1)] [case(1033)] wkssvc_NetWkstaInfo1033 *info1033; */
/* IDL: [default] ; */
/* IDL: } wkssvc_NetWkstaInfo; */

static int
wkssvc_dissect_element_NetWkstaInfo_info100(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info100_, NDR_POINTER_UNIQUE, "Pointer to Info100 (wkssvc_NetWkstaInfo100)",hf_wkssvc_wkssvc_NetWkstaInfo_info100);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info100_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo100(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info100,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info101(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info101_, NDR_POINTER_UNIQUE, "Pointer to Info101 (wkssvc_NetWkstaInfo101)",hf_wkssvc_wkssvc_NetWkstaInfo_info101);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info101_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo101(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info101,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info102(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info102_, NDR_POINTER_UNIQUE, "Pointer to Info102 (wkssvc_NetWkstaInfo102)",hf_wkssvc_wkssvc_NetWkstaInfo_info102);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info102_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo102(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info102,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info502(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info502_, NDR_POINTER_UNIQUE, "Pointer to Info502 (wkssvc_NetWkstaInfo502)",hf_wkssvc_wkssvc_NetWkstaInfo_info502);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info502_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo502(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info502,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1010(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1010_, NDR_POINTER_UNIQUE, "Pointer to Info1010 (wkssvc_NetWkstaInfo1010)",hf_wkssvc_wkssvc_NetWkstaInfo_info1010);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1010_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1010(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1010,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1011(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1011_, NDR_POINTER_UNIQUE, "Pointer to Info1011 (wkssvc_NetWkstaInfo1011)",hf_wkssvc_wkssvc_NetWkstaInfo_info1011);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1011_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1011(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1011,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1012(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1012_, NDR_POINTER_UNIQUE, "Pointer to Info1012 (wkssvc_NetWkstaInfo1012)",hf_wkssvc_wkssvc_NetWkstaInfo_info1012);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1012_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1012(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1012,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1013(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1013_, NDR_POINTER_UNIQUE, "Pointer to Info1013 (wkssvc_NetWkstaInfo1013)",hf_wkssvc_wkssvc_NetWkstaInfo_info1013);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1013_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1013(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1013,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1018(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1018_, NDR_POINTER_UNIQUE, "Pointer to Info1018 (wkssvc_NetWkstaInfo1018)",hf_wkssvc_wkssvc_NetWkstaInfo_info1018);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1018_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1018(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1018,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1023(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1023_, NDR_POINTER_UNIQUE, "Pointer to Info1023 (wkssvc_NetWkstaInfo1023)",hf_wkssvc_wkssvc_NetWkstaInfo_info1023);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1023_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1023(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1023,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1027(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1027_, NDR_POINTER_UNIQUE, "Pointer to Info1027 (wkssvc_NetWkstaInfo1027)",hf_wkssvc_wkssvc_NetWkstaInfo_info1027);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1027_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1027(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1027,0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1033(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaInfo_info1033_, NDR_POINTER_UNIQUE, "Pointer to Info1033 (wkssvc_NetWkstaInfo1033)",hf_wkssvc_wkssvc_NetWkstaInfo_info1033);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaInfo_info1033_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaInfo1033(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaInfo_info1033,0);

	return offset;
}

static int
wkssvc_dissect_NetWkstaInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "wkssvc_NetWkstaInfo");
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 100:
			offset = wkssvc_dissect_element_NetWkstaInfo_info100(tvb, offset, pinfo, tree, drep);
		break;

		case 101:
			offset = wkssvc_dissect_element_NetWkstaInfo_info101(tvb, offset, pinfo, tree, drep);
		break;

		case 102:
			offset = wkssvc_dissect_element_NetWkstaInfo_info102(tvb, offset, pinfo, tree, drep);
		break;

		case 502:
			offset = wkssvc_dissect_element_NetWkstaInfo_info502(tvb, offset, pinfo, tree, drep);
		break;

		case 1010:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1010(tvb, offset, pinfo, tree, drep);
		break;

		case 1011:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1011(tvb, offset, pinfo, tree, drep);
		break;

		case 1012:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1012(tvb, offset, pinfo, tree, drep);
		break;

		case 1013:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1013(tvb, offset, pinfo, tree, drep);
		break;

		case 1018:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1018(tvb, offset, pinfo, tree, drep);
		break;

		case 1023:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1023(tvb, offset, pinfo, tree, drep);
		break;

		case 1027:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1027(tvb, offset, pinfo, tree, drep);
		break;

		case 1033:
			offset = wkssvc_dissect_element_NetWkstaInfo_info1033(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *user; */
/* IDL: } USER_INFO_0; */

static int
wkssvc_dissect_element_USER_INFO_0_user(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_0_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_wkssvc_USER_INFO_0_user);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_0_user_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_USER_INFO_0_user, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_USER_INFO_0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_USER_INFO_0);
	}
	
	offset = wkssvc_dissect_element_USER_INFO_0_user(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 entries_read; */
/* IDL: 	[size_is(entries_read)] [unique(1)] USER_INFO_0 *user0; */
/* IDL: } USER_INFO_0_CONTAINER; */

static int
wkssvc_dissect_element_USER_INFO_0_CONTAINER_entries_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_USER_INFO_0_CONTAINER_entries_read,NULL);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0_, NDR_POINTER_UNIQUE, "Pointer to User0 (USER_INFO_0)",hf_wkssvc_USER_INFO_0_CONTAINER_user0);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0__);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_USER_INFO_0(tvb,offset,pinfo,tree,drep,hf_wkssvc_USER_INFO_0_CONTAINER_user0,0);

	return offset;
}

int
wkssvc_dissect_struct_USER_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_USER_INFO_0_CONTAINER);
	}
	
	offset = wkssvc_dissect_element_USER_INFO_0_CONTAINER_entries_read(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_USER_INFO_0_CONTAINER_user0(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *user_name; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *logon_domain; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *other_domains; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *logon_server; */
/* IDL: } USER_INFO_1; */

static int
wkssvc_dissect_element_USER_INFO_1_user_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_user_name_, NDR_POINTER_UNIQUE, "Pointer to User Name (uint16)",hf_wkssvc_USER_INFO_1_user_name);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_user_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_USER_INFO_1_user_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_logon_domain(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_logon_domain_, NDR_POINTER_UNIQUE, "Pointer to Logon Domain (uint16)",hf_wkssvc_USER_INFO_1_logon_domain);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_logon_domain_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_USER_INFO_1_logon_domain, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_other_domains(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_other_domains_, NDR_POINTER_UNIQUE, "Pointer to Other Domains (uint16)",hf_wkssvc_USER_INFO_1_other_domains);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_other_domains_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_USER_INFO_1_other_domains, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_logon_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_logon_server_, NDR_POINTER_UNIQUE, "Pointer to Logon Server (uint16)",hf_wkssvc_USER_INFO_1_logon_server);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_logon_server_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_USER_INFO_1_logon_server, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
wkssvc_dissect_struct_USER_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_USER_INFO_1);
	}
	
	offset = wkssvc_dissect_element_USER_INFO_1_user_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_USER_INFO_1_logon_domain(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_USER_INFO_1_other_domains(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_USER_INFO_1_logon_server(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 entries_read; */
/* IDL: 	[size_is(entries_read)] [unique(1)] USER_INFO_1 *user1; */
/* IDL: } USER_INFO_1_CONTAINER; */

static int
wkssvc_dissect_element_USER_INFO_1_CONTAINER_entries_read(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_USER_INFO_1_CONTAINER_entries_read,NULL);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1_, NDR_POINTER_UNIQUE, "Pointer to User1 (USER_INFO_1)",hf_wkssvc_USER_INFO_1_CONTAINER_user1);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1__);

	return offset;
}

static int
wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_USER_INFO_1(tvb,offset,pinfo,tree,drep,hf_wkssvc_USER_INFO_1_CONTAINER_user1,0);

	return offset;
}

int
wkssvc_dissect_struct_USER_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_USER_INFO_1_CONTAINER);
	}
	
	offset = wkssvc_dissect_element_USER_INFO_1_CONTAINER_entries_read(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_USER_INFO_1_CONTAINER_user1(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef [switch_type(uint32)] union { */
/* IDL: [case(0)] [unique(1)] [case(0)] USER_INFO_0_CONTAINER *user0; */
/* IDL: [case(1)] [unique(1)] [case(1)] USER_INFO_1_CONTAINER *user1; */
/* IDL: } WKS_USER_ENUM_UNION; */

static int
wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0_, NDR_POINTER_UNIQUE, "Pointer to User0 (USER_INFO_0_CONTAINER)",hf_wkssvc_WKS_USER_ENUM_UNION_user0);

	return offset;
}

static int
wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_USER_INFO_0_CONTAINER(tvb,offset,pinfo,tree,drep,hf_wkssvc_WKS_USER_ENUM_UNION_user0,0);

	return offset;
}

static int
wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1_, NDR_POINTER_UNIQUE, "Pointer to User1 (USER_INFO_1_CONTAINER)",hf_wkssvc_WKS_USER_ENUM_UNION_user1);

	return offset;
}

static int
wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_USER_INFO_1_CONTAINER(tvb,offset,pinfo,tree,drep,hf_wkssvc_WKS_USER_ENUM_UNION_user1,0);

	return offset;
}

static int
wkssvc_dissect_WKS_USER_ENUM_UNION(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "WKS_USER_ENUM_UNION");
		tree = proto_item_add_subtree(item, ett_wkssvc_WKS_USER_ENUM_UNION);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_WKS_USER_ENUM_UNION_user0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = wkssvc_dissect_element_WKS_USER_ENUM_UNION_user1(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
/* IDL: typedef struct { */
/* IDL: 	uint32 quality_of_service; */
/* IDL: 	uint32 vc_count; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *name; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *address; */
/* IDL: 	uint32 wan_link; */
/* IDL: } wkssvc_NetWkstaTransportInfo0; */

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportInfo0_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportInfo0_address_, NDR_POINTER_UNIQUE, "Pointer to Address (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_address_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link,NULL);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaTransportInfo0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaTransportInfo0);
	}
	
	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_quality_of_service(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_vc_count(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_name(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_address(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportInfo0_wan_link(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[size_is(count)] [unique(1)] wkssvc_NetWkstaTransportInfo0 *array; */
/* IDL: } wkssvc_NetWkstaTransportCtr0; */

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (wkssvc_NetWkstaTransportInfo0)",hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportCtr0_array__);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr0_array__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportInfo0(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array,0);

	return offset;
}

int
wkssvc_dissect_struct_NetWkstaTransportCtr0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaTransportCtr0);
	}
	
	offset = wkssvc_dissect_element_NetWkstaTransportCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef union { */
/* IDL: [case(0)] [unique(1)] [case(0)] wkssvc_NetWkstaTransportCtr0 *ctr0; */
/* IDL: [default] ; */
/* IDL: } wkssvc_NetWkstaTransportCtr; */

static int
wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (wkssvc_NetWkstaTransportCtr0)",hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportCtr_ctr0_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_NetWkstaTransportCtr0(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0,0);

	return offset;
}

static int
wkssvc_dissect_NetWkstaTransportCtr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "wkssvc_NetWkstaTransportCtr");
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_NetWkstaTransportCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = wkssvc_dissect_element_NetWkstaTransportCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
/* IDL: typedef struct { */
/* IDL: 	uint8 data[524]; */
/* IDL: } wkssvc_PasswordBuffer; */

static int
wkssvc_dissect_element_PasswordBuffer_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	int i;
	for (i = 0; i < 524; i++)
		offset = wkssvc_dissect_element_PasswordBuffer_data_(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
wkssvc_dissect_element_PasswordBuffer_data_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_PasswordBuffer_data,NULL);

	return offset;
}

int
wkssvc_dissect_struct_PasswordBuffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;


	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_wkssvc_wkssvc_PasswordBuffer);
	}
	
	offset = wkssvc_dissect_element_PasswordBuffer_data(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	WKSSVC_JOIN_FLAGS_DEFER_SPN =  0x00000100 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED =  0x00000080 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_UNSECURE =  0x00000040 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED =  0x00000020 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE =  0x00000010 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE =  0x00000004 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE =  0x00000002 , */
/* IDL: 	WKSSVC_JOIN_FLAGS_JOIN_TYPE =  0x00000001 , */
/* IDL: } wkssvc_joinflags; */

int
wkssvc_dissect_bitmap_joinflags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_wkssvc_wkssvc_joinflags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN, tvb, offset-4, 4, flags);
	if (flags&( 0x00000100 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_DEFER_SPN");
		if (flags & (~( 0x00000100 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000100 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED, tvb, offset-4, 4, flags);
	if (flags&( 0x00000080 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED");
		if (flags & (~( 0x00000080 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000080 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000040 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_JOIN_UNSECURE");
		if (flags & (~( 0x00000040 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000040 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED, tvb, offset-4, 4, flags);
	if (flags&( 0x00000020 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED");
		if (flags & (~( 0x00000020 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000020 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000010 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE");
		if (flags & (~( 0x00000010 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000010 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000004 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE");
		if (flags & (~( 0x00000004 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000004 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_JOIN_TYPE");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

/* IDL: typedef bitmap { */
/* IDL: 	WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE =  0x00000002 , */
/* IDL: } wkssvc_renameflags; */

int
wkssvc_dissect_bitmap_renameflags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_wkssvc_wkssvc_renameflags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_wkssvc_wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaGetInfo_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaGetInfo_level,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaInfo)",hf_wkssvc_wkssvc_NetWkstaGetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaGetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_NetWkstaInfo(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaGetInfo( */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [switch_is(level)] [out] [ref] wkssvc_NetWkstaInfo *info */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = wkssvc_dissect_element_NetWkstaGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetWkstaGetInfo_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaSetInfo_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_level,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaSetInfo_info_, NDR_POINTER_REF, "Pointer to Info (wkssvc_NetWkstaInfo)",hf_wkssvc_wkssvc_NetWkstaSetInfo_info);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_info_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_NetWkstaInfo(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_info, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaSetInfo_parm_error_, NDR_POINTER_REF, "Pointer to Parm Error (uint32)",hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaSetInfo_parm_error_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error,NULL);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaSetInfo( */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [switch_is(level)] [in] [ref] wkssvc_NetWkstaInfo *info, */
/* IDL: [out] [in] [ref] uint32 *parm_error */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetWkstaSetInfo_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaEnumUsers_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_level,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_users(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaEnumUsers_users_, NDR_POINTER_REF, "Pointer to Users (WKS_USER_ENUM_UNION)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_users);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_users_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_WKS_USER_ENUM_UNION(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_users, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_entriesread(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaEnumUsers_entriesread_, NDR_POINTER_UNIQUE, "Pointer to Entriesread (uint32)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_entriesread);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_entriesread_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_entriesread,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_totalentries(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaEnumUsers_totalentries_, NDR_POINTER_UNIQUE, "Pointer to Totalentries (uint32)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_totalentries);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_totalentries_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_totalentries,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle_, NDR_POINTER_REF, "Pointer to Resumehandle (uint32)",hf_wkssvc_wkssvc_NetWkstaEnumUsers_resumehandle);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaEnumUsers_resumehandle,NULL);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaEnumUsers( */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server_name, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [in] [ref] WKS_USER_ENUM_UNION *users, */
/* IDL: [in] uint32 prefmaxlen, */
/* IDL: [out] [unique(1)] uint32 *entriesread, */
/* IDL: [out] [unique(1)] uint32 *totalentries, */
/* IDL: [out] [in] [ref] uint32 *resumehandle */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaEnumUsers_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_users(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_entriesread(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaEnumUsers_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_users(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_prefmaxlen(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaEnumUsers_resumehandle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR WKSSVC_NETRWKSTAUSERGETINFO( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRWKSTAUSERGETINFO_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRWKSTAUSERGETINFO_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRWKSTAUSERSETINFO( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRWKSTAUSERSETINFO_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRWKSTAUSERSETINFO_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportEnum_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_level(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_level,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_ctr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (wkssvc_NetWkstaTransportCtr)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_ctr);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_ctr_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_NetWkstaTransportCtr(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_ctr, 0);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_totalentries(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_totalentries,NULL);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle);

	return offset;
}

static int
wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle,NULL);

	return offset;
}

/* IDL: WERROR wkssvc_NetWkstaTransportEnum( */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server_name, */
/* IDL: [out] [in] uint32 level, */
/* IDL: [switch_is(level)] [out] [in] [ref] wkssvc_NetWkstaTransportCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] uint32 totalentries, */
/* IDL: [out] [unique(1)] [in] uint32 *resume_handle */
/* IDL: ); */

static int
wkssvc_dissect_NetWkstaTransportEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetWkstaTransportEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetWkstaTransportEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR WKSSVC_NETRWKSTATRANSPORTADD( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTADD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTADD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRWKSTATRANSPORTDEL( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTDEL_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTDEL_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRUSEADD( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRUSEADD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRUSEADD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRUSEGETINFO( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRUSEGETINFO_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRUSEGETINFO_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRUSEDEL( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRUSEDEL_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRUSEDEL_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRUSEENUM( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRUSEENUM_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRUSEENUM_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRMESSAGEBUFFERSEND( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRMESSAGEBUFFERSEND_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRMESSAGEBUFFERSEND_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRWORKSTATIONSTATISTICSGET( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRWORKSTATIONSTATISTICSGET_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRWORKSTATIONSTATISTICSGET_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRLOGONDOMAINNAMEADD( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEADD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEADD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRLOGONDOMAINNAMEDEL( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEDEL_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEDEL_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRJOINDOMAIN( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRJOINDOMAIN_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRJOINDOMAIN_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRUNJOINDOMAIN( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRUNJOINDOMAIN_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRUNJOINDOMAIN_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRRENAMEMACHINEINDOMAIN( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRRENAMEMACHINEINDOMAIN_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRRENAMEMACHINEINDOMAIN_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRVALIDATENAME( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRVALIDATENAME_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRVALIDATENAME_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRGETJOININFORMATION( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRGETJOININFORMATION_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRGETJOININFORMATION_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRGETJOINABLEOUS( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrJoinDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrJoinDomain2_domain_name_, NDR_POINTER_REF, "Pointer to Domain Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_domain_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_account_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrJoinDomain2_account_name_, NDR_POINTER_UNIQUE, "Pointer to Account Name (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_account_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_account_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_account_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrJoinDomain2_admin_account_, NDR_POINTER_UNIQUE, "Pointer to Admin Account (uint16)",hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_admin_account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_, NDR_POINTER_UNIQUE, "Pointer to Encrypted Password (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_encrypted_password_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrJoinDomain2( */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *server_name, */
/* IDL: [charset(UTF16)] [in] [ref] uint16 *domain_name, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *account_name, */
/* IDL: [charset(UTF16)] [unique(1)] [in] uint16 *admin_account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *encrypted_password, */
/* IDL: [in] wkssvc_joinflags join_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrJoinDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrJoinDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetrJoinDomain2_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_domain_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_account_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_admin_account(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_encrypted_password(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrJoinDomain2_join_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrUnjoinDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrUnjoinDomain2_account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_account);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrUnjoinDomain2_account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_, NDR_POINTER_UNIQUE, "Pointer to Encrypted Password (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_bitmap_joinflags(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrUnjoinDomain2( */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *server_name, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *encrypted_password, */
/* IDL: [in] wkssvc_joinflags unjoin_flags */
/* IDL: ); */

static int
wkssvc_dissect_NetrUnjoinDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrUnjoinDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_account(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_encrypted_password(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrUnjoinDomain2_unjoin_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_, NDR_POINTER_UNIQUE, "Pointer to Newmachinename (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_bitmap_renameflags(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions, 0);

	return offset;
}

/* IDL: WERROR wkssvc_NetrRenameMachineInDomain2( */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *server_name, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *NewMachineName, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] wkssvc_renameflags RenameOptions */
/* IDL: ); */

static int
wkssvc_dissect_NetrRenameMachineInDomain2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrRenameMachineInDomain2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_NewMachineName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_Account(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_EncryptedPassword(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRenameMachineInDomain2_RenameOptions(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR WKSSVC_NETRVALIDATENAME2( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRVALIDATENAME2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRVALIDATENAME2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRGETJOINABLEOUS2( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS2_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS2_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_, NDR_POINTER_UNIQUE, "Pointer to Newalternatemachinename (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved,NULL);

	return offset;
}

/* IDL: WERROR wkssvc_NetrAddAlternateComputerName( */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *server_name, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *NewAlternateMachineName, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
wkssvc_dissect_NetrAddAlternateComputerName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrAddAlternateComputerName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_NewAlternateMachineName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_Account(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_EncryptedPassword(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrAddAlternateComputerName_Reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_, NDR_POINTER_UNIQUE, "Pointer to Alternatemachinenametoremove (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_, NDR_POINTER_UNIQUE, "Pointer to Account (uint16)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_, NDR_POINTER_UNIQUE, "Pointer to Encryptedpassword (wkssvc_PasswordBuffer)",hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = wkssvc_dissect_struct_PasswordBuffer(tvb,offset,pinfo,tree,drep,hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword,0);

	return offset;
}

static int
wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved,NULL);

	return offset;
}

/* IDL: WERROR wkssvc_NetrRemoveAlternateComputerName( */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *server_name, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *AlternateMachineNameToRemove, */
/* IDL: [charset(UTF16)] [in] [unique(1)] uint16 *Account, */
/* IDL: [unique(1)] [in] wkssvc_PasswordBuffer *EncryptedPassword, */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
wkssvc_dissect_NetrRemoveAlternateComputerName_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_NetrRemoveAlternateComputerName_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_server_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_Account(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_EncryptedPassword(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = wkssvc_dissect_element_NetrRemoveAlternateComputerName_Reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR WKSSVC_NETRSETPRIMARYCOMPUTERNAME( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRSETPRIMARYCOMPUTERNAME_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRSETPRIMARYCOMPUTERNAME_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}

/* IDL: WERROR WKSSVC_NETRENUMERATECOMPUTERNAMES( */
/* IDL:  */
/* IDL: ); */

static int
wkssvc_dissect_WKSSVC_NETRENUMERATECOMPUTERNAMES_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
wkssvc_dissect_WKSSVC_NETRENUMERATECOMPUTERNAMES_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	return offset;
}


static dcerpc_sub_dissector wkssvc_dissectors[] = {
	{ 0, "NetWkstaGetInfo",
	   wkssvc_dissect_NetWkstaGetInfo_request, wkssvc_dissect_NetWkstaGetInfo_response},
	{ 1, "NetWkstaSetInfo",
	   wkssvc_dissect_NetWkstaSetInfo_request, wkssvc_dissect_NetWkstaSetInfo_response},
	{ 2, "NetWkstaEnumUsers",
	   wkssvc_dissect_NetWkstaEnumUsers_request, wkssvc_dissect_NetWkstaEnumUsers_response},
	{ 3, "WKSSVC_NETRWKSTAUSERGETINFO",
	   wkssvc_dissect_WKSSVC_NETRWKSTAUSERGETINFO_request, wkssvc_dissect_WKSSVC_NETRWKSTAUSERGETINFO_response},
	{ 4, "WKSSVC_NETRWKSTAUSERSETINFO",
	   wkssvc_dissect_WKSSVC_NETRWKSTAUSERSETINFO_request, wkssvc_dissect_WKSSVC_NETRWKSTAUSERSETINFO_response},
	{ 5, "NetWkstaTransportEnum",
	   wkssvc_dissect_NetWkstaTransportEnum_request, wkssvc_dissect_NetWkstaTransportEnum_response},
	{ 6, "WKSSVC_NETRWKSTATRANSPORTADD",
	   wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTADD_request, wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTADD_response},
	{ 7, "WKSSVC_NETRWKSTATRANSPORTDEL",
	   wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTDEL_request, wkssvc_dissect_WKSSVC_NETRWKSTATRANSPORTDEL_response},
	{ 8, "WKSSVC_NETRUSEADD",
	   wkssvc_dissect_WKSSVC_NETRUSEADD_request, wkssvc_dissect_WKSSVC_NETRUSEADD_response},
	{ 9, "WKSSVC_NETRUSEGETINFO",
	   wkssvc_dissect_WKSSVC_NETRUSEGETINFO_request, wkssvc_dissect_WKSSVC_NETRUSEGETINFO_response},
	{ 10, "WKSSVC_NETRUSEDEL",
	   wkssvc_dissect_WKSSVC_NETRUSEDEL_request, wkssvc_dissect_WKSSVC_NETRUSEDEL_response},
	{ 11, "WKSSVC_NETRUSEENUM",
	   wkssvc_dissect_WKSSVC_NETRUSEENUM_request, wkssvc_dissect_WKSSVC_NETRUSEENUM_response},
	{ 12, "WKSSVC_NETRMESSAGEBUFFERSEND",
	   wkssvc_dissect_WKSSVC_NETRMESSAGEBUFFERSEND_request, wkssvc_dissect_WKSSVC_NETRMESSAGEBUFFERSEND_response},
	{ 13, "WKSSVC_NETRWORKSTATIONSTATISTICSGET",
	   wkssvc_dissect_WKSSVC_NETRWORKSTATIONSTATISTICSGET_request, wkssvc_dissect_WKSSVC_NETRWORKSTATIONSTATISTICSGET_response},
	{ 14, "WKSSVC_NETRLOGONDOMAINNAMEADD",
	   wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEADD_request, wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEADD_response},
	{ 15, "WKSSVC_NETRLOGONDOMAINNAMEDEL",
	   wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEDEL_request, wkssvc_dissect_WKSSVC_NETRLOGONDOMAINNAMEDEL_response},
	{ 16, "WKSSVC_NETRJOINDOMAIN",
	   wkssvc_dissect_WKSSVC_NETRJOINDOMAIN_request, wkssvc_dissect_WKSSVC_NETRJOINDOMAIN_response},
	{ 17, "WKSSVC_NETRUNJOINDOMAIN",
	   wkssvc_dissect_WKSSVC_NETRUNJOINDOMAIN_request, wkssvc_dissect_WKSSVC_NETRUNJOINDOMAIN_response},
	{ 18, "WKSSVC_NETRRENAMEMACHINEINDOMAIN",
	   wkssvc_dissect_WKSSVC_NETRRENAMEMACHINEINDOMAIN_request, wkssvc_dissect_WKSSVC_NETRRENAMEMACHINEINDOMAIN_response},
	{ 19, "WKSSVC_NETRVALIDATENAME",
	   wkssvc_dissect_WKSSVC_NETRVALIDATENAME_request, wkssvc_dissect_WKSSVC_NETRVALIDATENAME_response},
	{ 20, "WKSSVC_NETRGETJOININFORMATION",
	   wkssvc_dissect_WKSSVC_NETRGETJOININFORMATION_request, wkssvc_dissect_WKSSVC_NETRGETJOININFORMATION_response},
	{ 21, "WKSSVC_NETRGETJOINABLEOUS",
	   wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS_request, wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS_response},
	{ 22, "NetrJoinDomain2",
	   wkssvc_dissect_NetrJoinDomain2_request, wkssvc_dissect_NetrJoinDomain2_response},
	{ 23, "NetrUnjoinDomain2",
	   wkssvc_dissect_NetrUnjoinDomain2_request, wkssvc_dissect_NetrUnjoinDomain2_response},
	{ 24, "NetrRenameMachineInDomain2",
	   wkssvc_dissect_NetrRenameMachineInDomain2_request, wkssvc_dissect_NetrRenameMachineInDomain2_response},
	{ 25, "WKSSVC_NETRVALIDATENAME2",
	   wkssvc_dissect_WKSSVC_NETRVALIDATENAME2_request, wkssvc_dissect_WKSSVC_NETRVALIDATENAME2_response},
	{ 26, "WKSSVC_NETRGETJOINABLEOUS2",
	   wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS2_request, wkssvc_dissect_WKSSVC_NETRGETJOINABLEOUS2_response},
	{ 27, "NetrAddAlternateComputerName",
	   wkssvc_dissect_NetrAddAlternateComputerName_request, wkssvc_dissect_NetrAddAlternateComputerName_response},
	{ 28, "NetrRemoveAlternateComputerName",
	   wkssvc_dissect_NetrRemoveAlternateComputerName_request, wkssvc_dissect_NetrRemoveAlternateComputerName_response},
	{ 29, "WKSSVC_NETRSETPRIMARYCOMPUTERNAME",
	   wkssvc_dissect_WKSSVC_NETRSETPRIMARYCOMPUTERNAME_request, wkssvc_dissect_WKSSVC_NETRSETPRIMARYCOMPUTERNAME_response},
	{ 30, "WKSSVC_NETRENUMERATECOMPUTERNAMES",
	   wkssvc_dissect_WKSSVC_NETRENUMERATECOMPUTERNAMES_request, wkssvc_dissect_WKSSVC_NETRENUMERATECOMPUTERNAMES_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_wkssvc(void)
{
	static hf_register_info hf[] = {
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_read, 
	  { "Use Raw Read", "wkssvc.wkssvc_NetWkstaInfo502.use_raw_read", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_entriesread, 
	  { "Entriesread", "wkssvc.wkssvc_NetWkstaEnumUsers.entriesread", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_dgram_event_reset_freq, 
	  { "Dgram Event Reset Freq", "wkssvc.wkssvc_NetWkstaInfo502.dgram_event_reset_freq", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr0_count, 
	  { "Count", "wkssvc.wkssvc_NetWkstaTransportCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_increment, 
	  { "Pipe Increment", "wkssvc.wkssvc_NetWkstaInfo502.pipe_increment", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info502, 
	  { "Info502", "wkssvc.wkssvc_NetWkstaInfo.info502", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_log_election_packets, 
	  { "Log Election Packets", "wkssvc.wkssvc_NetWkstaInfo502.log_election_packets", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_lan_root, 
	  { "Lan Root", "wkssvc.wkssvc_NetWkstaInfo102.lan_root", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_char_wait, 
	  { "Char Wait", "wkssvc.wkssvc_NetWkstaInfo502.char_wait", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_0_user, 
	  { "User", "wkssvc.USER_INFO_0.user", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_files_deny_write, 
	  { "Buf Files Deny Write", "wkssvc.wkssvc_NetWkstaInfo502.buf_files_deny_write", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_force_core_create_mode, 
	  { "Force Core Create Mode", "wkssvc.wkssvc_NetWkstaInfo502.force_core_create_mode", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1013_keep_connection, 
	  { "Keep Connection", "wkssvc.wkssvc_NetWkstaInfo1013.keep_connection", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1011_collection_time, 
	  { "Collection Time", "wkssvc.wkssvc_NetWkstaInfo1011.collection_time", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo101.platform_id", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrRenameMachineInDomain2.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, 
	  { "Wkssvc Join Flags Account Create", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs), ( 0x00000002 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrAddAlternateComputerName.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_logged_on_users, 
	  { "Logged On Users", "wkssvc.wkssvc_NetWkstaInfo102.logged_on_users", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrUnjoinDomain2.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo102.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_vc_count, 
	  { "Vc Count", "wkssvc.wkssvc_NetWkstaTransportInfo0.vc_count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_read_ahead_throughput, 
	  { "Read Ahead Throughput", "wkssvc.wkssvc_NetWkstaInfo502.read_ahead_throughput", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_Account, 
	  { "Account", "wkssvc.wkssvc_NetrRenameMachineInDomain2.Account", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_NewAlternateMachineName, 
	  { "Newalternatemachinename", "wkssvc.wkssvc_NetrAddAlternateComputerName.NewAlternateMachineName", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo100.version_minor", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_num_mailslot_buffers, 
	  { "Num Mailslot Buffers", "wkssvc.wkssvc_NetWkstaInfo502.num_mailslot_buffers", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo102.domain_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_WKS_USER_ENUM_UNION_user0, 
	  { "User0", "wkssvc.WKS_USER_ENUM_UNION.user0", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_WKS_USER_ENUM_UNION_user1, 
	  { "User1", "wkssvc.WKS_USER_ENUM_UNION.user1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_user_name, 
	  { "User Name", "wkssvc.USER_INFO_1.user_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_maximum_collection_count, 
	  { "Maximum Collection Count", "wkssvc.wkssvc_NetWkstaInfo502.maximum_collection_count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_prefmaxlen, 
	  { "Prefmaxlen", "wkssvc.wkssvc_NetWkstaEnumUsers.prefmaxlen", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaEnumUsers.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_other_domains, 
	  { "Other Domains", "wkssvc.USER_INFO_1.other_domains", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE, 
	  { "Wkssvc Join Flags Join Type", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_TYPE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_TYPE_tfs), ( 0x00000001 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED, 
	  { "Wkssvc Join Flags Machine Pwd Passed", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_MACHINE_PWD_PASSED_tfs), ( 0x00000080 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_encryption, 
	  { "Use Encryption", "wkssvc.wkssvc_NetWkstaInfo502.use_encryption", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_totalentries, 
	  { "Totalentries", "wkssvc.wkssvc_NetWkstaEnumUsers.totalentries", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrAddAlternateComputerName.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_quality_of_service, 
	  { "Quality Of Service", "wkssvc.wkssvc_NetWkstaTransportInfo0.quality_of_service", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo100.platform_id", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_ctr, 
	  { "Ctr", "wkssvc.wkssvc_NetWkstaTransportEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrRenameMachineInDomain2.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_admin_account, 
	  { "Admin Account", "wkssvc.wkssvc_NetrJoinDomain2.admin_account", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaGetInfo.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE, 
	  { "Wkssvc Join Flags Account Create", "wkssvc.wkssvc_renameflags.WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE", FT_BOOLEAN, 32, TFS(&wkssvc_renameflags_WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE_tfs), ( 0x00000002 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN, 
	  { "Wkssvc Join Flags Defer Spn", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_DEFER_SPN", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DEFER_SPN_tfs), ( 0x00000100 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1023_size_char_buf, 
	  { "Size Char Buf", "wkssvc.wkssvc_NetWkstaInfo1023.size_char_buf", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1010, 
	  { "Info1010", "wkssvc.wkssvc_NetWkstaInfo.info1010", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_platform_id, 
	  { "Platform Id", "wkssvc.platform_id", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_PlatformId_vals), 0, " ", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetrJoinDomain2.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1011, 
	  { "Info1011", "wkssvc.wkssvc_NetWkstaInfo.info1011", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1012, 
	  { "Info1012", "wkssvc.wkssvc_NetWkstaInfo.info1012", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_maximum, 
	  { "Lock Maximum", "wkssvc.wkssvc_NetWkstaInfo502.lock_maximum", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1013, 
	  { "Info1013", "wkssvc.wkssvc_NetWkstaInfo.info1013", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_0_CONTAINER_user0, 
	  { "User0", "wkssvc.USER_INFO_0_CONTAINER.user0", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo101.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1018, 
	  { "Info1018", "wkssvc.wkssvc_NetWkstaInfo.info1018", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_read_only_files, 
	  { "Buf Read Only Files", "wkssvc.wkssvc_NetWkstaInfo502.buf_read_only_files", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo101.version_minor", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetrJoinDomain2.domain_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_lan_root, 
	  { "Lan Root", "wkssvc.wkssvc_NetWkstaInfo101.lan_root", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE, 
	  { "Wkssvc Join Flags Account Delete", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE_tfs), ( 0x00000004 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo101.domain_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_opnum, 
	  { "Operation", "wkssvc.opnum", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_account, 
	  { "Account", "wkssvc.wkssvc_NetrUnjoinDomain2.account", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED, 
	  { "Wkssvc Join Flags Domain Join If Joined", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED_tfs), ( 0x00000020 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_dormant_file_limit, 
	  { "Dormant File Limit", "wkssvc.wkssvc_NetWkstaInfo502.dormant_file_limit", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_CONTAINER_user1, 
	  { "User1", "wkssvc.USER_INFO_1_CONTAINER.user1", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_unlock_behind, 
	  { "Use Unlock Behind", "wkssvc.wkssvc_NetWkstaInfo502.use_unlock_behind", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_resumehandle, 
	  { "Resumehandle", "wkssvc.wkssvc_NetWkstaEnumUsers.resumehandle", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_EncryptedPassword, 
	  { "Encryptedpassword", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.EncryptedPassword", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_pipe_maximum, 
	  { "Pipe Maximum", "wkssvc.wkssvc_NetWkstaInfo502.pipe_maximum", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_cache_file_timeout, 
	  { "Cache File Timeout", "wkssvc.wkssvc_NetWkstaInfo502.cache_file_timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaTransportEnum.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_encrypted_password, 
	  { "Encrypted Password", "wkssvc.wkssvc_NetrUnjoinDomain2.encrypted_password", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_CONTAINER_entries_read, 
	  { "Entries Read", "wkssvc.USER_INFO_1_CONTAINER.entries_read", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1023, 
	  { "Info1023", "wkssvc.wkssvc_NetWkstaInfo.info1023", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_parm_error, 
	  { "Parm Error", "wkssvc.wkssvc_NetWkstaSetInfo.parm_error", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_raw_write, 
	  { "Use Raw Write", "wkssvc.wkssvc_NetWkstaInfo502.use_raw_write", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info100, 
	  { "Info100", "wkssvc.wkssvc_NetWkstaInfo.info100", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info101, 
	  { "Info101", "wkssvc.wkssvc_NetWkstaInfo.info101", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info102, 
	  { "Info102", "wkssvc.wkssvc_NetWkstaInfo.info102", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1027, 
	  { "Info1027", "wkssvc.wkssvc_NetWkstaInfo.info1027", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_512_byte_max_transfer, 
	  { "Use 512 Byte Max Transfer", "wkssvc.wkssvc_NetWkstaInfo502.use_512_byte_max_transfer", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1018_session_timeout, 
	  { "Session Timeout", "wkssvc.wkssvc_NetWkstaInfo1018.session_timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1033_max_threads, 
	  { "Max Threads", "wkssvc.wkssvc_NetWkstaInfo1033.max_threads", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_name, 
	  { "Name", "wkssvc.wkssvc_NetWkstaTransportInfo0.name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo100.version_major", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_NewMachineName, 
	  { "Newmachinename", "wkssvc.wkssvc_NetrRenameMachineInDomain2.NewMachineName", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaInfo100.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_users, 
	  { "Users", "wkssvc.wkssvc_NetWkstaEnumUsers.users", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Account, 
	  { "Account", "wkssvc.wkssvc_NetrAddAlternateComputerName.Account", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_version_minor, 
	  { "Version Minor", "wkssvc.wkssvc_NetWkstaInfo102.version_minor", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_AlternateMachineNameToRemove, 
	  { "Alternatemachinenametoremove", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.AlternateMachineNameToRemove", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaTransportEnum.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_commands, 
	  { "Max Commands", "wkssvc.wkssvc_NetWkstaInfo502.max_commands", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_utilize_nt_caching, 
	  { "Utilize Nt Caching", "wkssvc.wkssvc_NetWkstaInfo502.utilize_nt_caching", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaEnumUsers_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaEnumUsers.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo100_domain_name, 
	  { "Domain Name", "wkssvc.wkssvc_NetWkstaInfo100.domain_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_threads, 
	  { "Max Threads", "wkssvc.wkssvc_NetWkstaInfo502.max_threads", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_size_char_buf, 
	  { "Size Char Buf", "wkssvc.wkssvc_NetWkstaInfo502.size_char_buf", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo_info1033, 
	  { "Info1033", "wkssvc.wkssvc_NetWkstaInfo.info1033", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_info, 
	  { "Info", "wkssvc.wkssvc_NetWkstaSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1012_maximum_collection_count, 
	  { "Maximum Collection Count", "wkssvc.wkssvc_NetWkstaInfo1012.maximum_collection_count", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_logon_domain, 
	  { "Logon Domain", "wkssvc.USER_INFO_1.logon_domain", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_werror, 
	  { "Windows Error", "wkssvc.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_num_srv_announce_buffers, 
	  { "Num Srv Announce Buffers", "wkssvc.wkssvc_NetWkstaInfo502.num_srv_announce_buffers", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrUnjoinDomain2_unjoin_flags, 
	  { "Unjoin Flags", "wkssvc.wkssvc_NetrUnjoinDomain2.unjoin_flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_close_behind, 
	  { "Use Close Behind", "wkssvc.wkssvc_NetWkstaInfo502.use_close_behind", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_encrypted_password, 
	  { "Encrypted Password", "wkssvc.wkssvc_NetrJoinDomain2.encrypted_password", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo101_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo101.version_major", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaSetInfo_server_name, 
	  { "Server Name", "wkssvc.wkssvc_NetWkstaSetInfo.server_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_lock_read_unlock, 
	  { "Use Lock Read Unlock", "wkssvc.wkssvc_NetWkstaInfo502.use_lock_read_unlock", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaGetInfo_level, 
	  { "Level", "wkssvc.wkssvc_NetWkstaGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_join_flags, 
	  { "Join Flags", "wkssvc.wkssvc_NetrJoinDomain2.join_flags", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1010_char_wait, 
	  { "Char Wait", "wkssvc.wkssvc_NetWkstaInfo1010.char_wait", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_increment, 
	  { "Lock Increment", "wkssvc.wkssvc_NetWkstaInfo502.lock_increment", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE, 
	  { "Wkssvc Join Flags Join Unsecure", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_JOIN_UNSECURE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_JOIN_UNSECURE_tfs), ( 0x00000040 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo1027_errorlog_sz, 
	  { "Errorlog Sz", "wkssvc.wkssvc_NetWkstaInfo1027.errorlog_sz", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr_ctr0, 
	  { "Ctr0", "wkssvc.wkssvc_NetWkstaTransportCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrJoinDomain2_account_name, 
	  { "Account Name", "wkssvc.wkssvc_NetrJoinDomain2.account_name", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_wan_link, 
	  { "Wan Link", "wkssvc.wkssvc_NetWkstaTransportInfo0.wan_link", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_keep_connection, 
	  { "Keep Connection", "wkssvc.wkssvc_NetWkstaInfo502.keep_connection", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_resume_handle, 
	  { "Resume Handle", "wkssvc.wkssvc_NetWkstaTransportEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrAddAlternateComputerName_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrAddAlternateComputerName.Reserved", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRenameMachineInDomain2_RenameOptions, 
	  { "Renameoptions", "wkssvc.wkssvc_NetrRenameMachineInDomain2.RenameOptions", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_write_raw_data, 
	  { "Use Write Raw Data", "wkssvc.wkssvc_NetWkstaInfo502.use_write_raw_data", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_1_logon_server, 
	  { "Logon Server", "wkssvc.USER_INFO_1.logon_server", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_PasswordBuffer_data, 
	  { "Data", "wkssvc.wkssvc_PasswordBuffer.data", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_max_buffer, 
	  { "Max Buffer", "wkssvc.wkssvc_NetWkstaTransportEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_max_illegal_dgram_events, 
	  { "Max Illegal Dgram Events", "wkssvc.wkssvc_NetWkstaInfo502.max_illegal_dgram_events", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportEnum_totalentries, 
	  { "Totalentries", "wkssvc.wkssvc_NetWkstaTransportEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_use_opportunistic_locking, 
	  { "Use Opportunistic Locking", "wkssvc.wkssvc_NetWkstaInfo502.use_opportunistic_locking", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_USER_INFO_0_CONTAINER_entries_read, 
	  { "Entries Read", "wkssvc.USER_INFO_0_CONTAINER.entries_read", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_version_major, 
	  { "Version Major", "wkssvc.wkssvc_NetWkstaInfo102.version_major", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo102_platform_id, 
	  { "Platform Id", "wkssvc.wkssvc_NetWkstaInfo102.platform_id", FT_NONE, BASE_HEX, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_lock_quota, 
	  { "Lock Quota", "wkssvc.wkssvc_NetWkstaInfo502.lock_quota", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Account, 
	  { "Account", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.Account", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE, 
	  { "Wkssvc Join Flags Win9x Upgrade", "wkssvc.wkssvc_joinflags.WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE", FT_BOOLEAN, 32, TFS(&wkssvc_joinflags_WKSSVC_JOIN_FLAGS_WIN9X_UPGRADE_tfs), ( 0x00000010 ), "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_session_timeout, 
	  { "Session Timeout", "wkssvc.wkssvc_NetWkstaInfo502.session_timeout", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportInfo0_address, 
	  { "Address", "wkssvc.wkssvc_NetWkstaTransportInfo0.address", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaTransportCtr0_array, 
	  { "Array", "wkssvc.wkssvc_NetWkstaTransportCtr0.array", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetrRemoveAlternateComputerName_Reserved, 
	  { "Reserved", "wkssvc.wkssvc_NetrRemoveAlternateComputerName.Reserved", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_buf_named_pipes, 
	  { "Buf Named Pipes", "wkssvc.wkssvc_NetWkstaInfo502.buf_named_pipes", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	{ &hf_wkssvc_wkssvc_NetWkstaInfo502_collection_time, 
	  { "Collection Time", "wkssvc.wkssvc_NetWkstaInfo502.collection_time", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_wkssvc,
		&ett_wkssvc_wkssvc_NetWkstaInfo100,
		&ett_wkssvc_wkssvc_NetWkstaInfo101,
		&ett_wkssvc_wkssvc_NetWkstaInfo102,
		&ett_wkssvc_wkssvc_NetWkstaInfo502,
		&ett_wkssvc_wkssvc_NetWkstaInfo1010,
		&ett_wkssvc_wkssvc_NetWkstaInfo1011,
		&ett_wkssvc_wkssvc_NetWkstaInfo1012,
		&ett_wkssvc_wkssvc_NetWkstaInfo1013,
		&ett_wkssvc_wkssvc_NetWkstaInfo1018,
		&ett_wkssvc_wkssvc_NetWkstaInfo1023,
		&ett_wkssvc_wkssvc_NetWkstaInfo1027,
		&ett_wkssvc_wkssvc_NetWkstaInfo1033,
		&ett_wkssvc_wkssvc_NetWkstaInfo,
		&ett_wkssvc_USER_INFO_0,
		&ett_wkssvc_USER_INFO_0_CONTAINER,
		&ett_wkssvc_USER_INFO_1,
		&ett_wkssvc_USER_INFO_1_CONTAINER,
		&ett_wkssvc_WKS_USER_ENUM_UNION,
		&ett_wkssvc_wkssvc_NetWkstaTransportInfo0,
		&ett_wkssvc_wkssvc_NetWkstaTransportCtr0,
		&ett_wkssvc_wkssvc_NetWkstaTransportCtr,
		&ett_wkssvc_wkssvc_PasswordBuffer,
		&ett_wkssvc_wkssvc_joinflags,
		&ett_wkssvc_wkssvc_renameflags,
	};

	proto_dcerpc_wkssvc = proto_register_protocol("Workstation Service", "WKSSVC", "wkssvc");
	proto_register_field_array(proto_dcerpc_wkssvc, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_wkssvc(void)
{
	dcerpc_init_uuid(proto_dcerpc_wkssvc, ett_dcerpc_wkssvc,
		&uuid_dcerpc_wkssvc, ver_dcerpc_wkssvc,
		wkssvc_dissectors, hf_wkssvc_opnum);
}
